"""Hierarchical bug-hunting team: Boss → Managers → Workers.

Implements the HPTSA/PentAGI organisational pattern the research audit called
for (docs/TOP_AUTONOMOUS_AGENTS_RESEARCH.md §4.5, §5):

- **MissionDirector (boss)** owns the mission: decomposes the target into
  workstreams (LLM-planned from the live world model, deterministic fallback),
  spawns/retires lanes, enforces the probe budget, and *reviews* — severity
  rollup + exploit-chain summary over findings that already passed the
  deterministic verification gates. The boss reviews; the boss never bends
  verification.
- **WorkstreamManager (manager)** runs one lane (e.g. an API surface, a
  service family — whatever the boss's dynamic decomposition produced), keeps
  a bounded probe queue and its worker pool, and harvests structured reports.
- **ProbeWorker (employee)** executes one probe at a time through the
  *injected executor* — which is the agent's policy-gated execution path —
  and returns raw evidence (rc + excerpt + duration). Workers never touch
  subprocesses directly, so scope, rate limits and the command gateway apply
  to every team command exactly as to the main loop's.

Nothing about lanes is hardcoded: the boss derives them from what the target
actually exposes. Env knobs: ``X19_TEAM_DISABLE``, ``X19_TEAM_MAX_LANES``,
``X19_TEAM_WORKERS`` (per lane), ``X19_TEAM_PROBES_PER_ITER``.
"""

from __future__ import annotations

import os
import queue
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from logging_utils import log

PROBE_TIMEOUT_DEFAULT = 90
PROBE_TIMEOUT_CAP = 120
REPORT_EXCERPT = 400
CONTEXT_CHAR_CAP = 2600
REPORTS_IN_CONTEXT = 8


def _env_int(name: str, default: int, minimum: int = 1, maximum: int = 16) -> int:
    try:
        v = int((os.getenv(name, "") or "").strip() or default)
    except ValueError:
        v = default
    return max(minimum, min(maximum, v))


def _first_json_object(raw: str) -> Optional[Dict[str, Any]]:
    """First parseable JSON object in `raw` (any shape)."""
    import json
    decoder = json.JSONDecoder()
    idx = raw.find("{")
    while idx != -1:
        try:
            obj, end = decoder.raw_decode(raw, idx)
        except json.JSONDecodeError:
            obj, end = None, idx + 1
        if isinstance(obj, dict):
            return obj
        idx = raw.find("{", end)
    return None


TEAM_SYSTEM_PROMPT = """You are the mission director (boss) of a bug-hunting team.
Decompose THIS target into at most 3 parallel workstream lanes based ONLY on
what the world state below shows the target exposing — no generic playbooks.

For each lane pick: a short kebab-case name, the specific mission (what class
of vulnerabilities that surface usually hides and how to cover it), and how
many workers (1-2). Workers execute shell probes through the same policy
gateway as you; they return raw evidence, not findings.

Respond with EXACTLY one JSON object:
{"lanes": [{"name": "web-api", "mission": "map and test /api/* for IDOR and auth bypass", "workers": 2}]}
If the surface is too small to parallelise, return {"lanes": []}."""


def team_disabled() -> bool:
    return (os.getenv("X19_TEAM_DISABLE", "") or "").strip().lower() in ("1", "true", "yes", "on")


def trajectories_per_iter() -> int:
    """Pre-registered hypothesis probes auto-dispatched per iteration
    (Naptime-style parallel trajectories). 0 disables the feature."""
    return _env_int("X19_TEAM_TRAJECTORIES", 2, 0, 6)


@dataclass
class ProbeSpec:
    """One unit of work a manager hands to a worker."""
    lane: str
    cmd: str
    why: str = ""
    timeout: int = PROBE_TIMEOUT_DEFAULT


@dataclass
class WorkerReport:
    """Raw evidence returned by a worker. Not a finding — the boss and the
    main loop's verification gates decide what (if anything) it proves."""
    lane: str
    cmd: str
    rc: int
    excerpt: str
    duration: float
    why: str = ""
    ts: float = field(default_factory=time.time)

    def line(self) -> str:
        head = f"[{self.lane}] $ {self.cmd[:110]} -> rc {self.rc} ({self.duration:.1f}s)"
        if self.excerpt.strip():
            first = self.excerpt.strip().splitlines()[0][:120]
            if first:
                head += f" | {first}"
        return head


class ProbeWorker(threading.Thread):
    """Employee: pulls probes from its lane queue, runs them, reports back."""

    def __init__(self, name: str, lane: str, jobs: "queue.Queue",
                 reports: deque, rlock: threading.Lock,
                 executor: Callable[[str, int], Any], idle: threading.Event):
        super().__init__(name=name, daemon=True)
        self.lane = lane
        self._jobs = jobs
        self._reports = reports
        self._rlock = rlock
        self._executor = executor
        self._idle = idle          # set when the lane has no pending work
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                spec = self._jobs.get(timeout=0.4)
            except queue.Empty:
                self._idle.set()
                continue
            self._idle.clear()
            if spec is None:            # shutdown sentinel
                return
            t0 = time.monotonic()
            rc, excerpt = 1, ""
            try:
                result = self._executor(spec.cmd, min(max(5, spec.timeout), PROBE_TIMEOUT_CAP))
                rc = int(getattr(result, "returncode", 1) or 0)
                excerpt = str(getattr(result, "text", "") or "")[:REPORT_EXCERPT]
            except Exception as e:
                excerpt = f"error: {e}"[:REPORT_EXCERPT]
            rep = WorkerReport(lane=self.lane, cmd=spec.cmd, rc=rc, excerpt=excerpt,
                               duration=time.monotonic() - t0, why=spec.why)
            with self._rlock:
                self._reports.append(rep)  # deque(maxlen) caps itself


class WorkstreamManager:
    """Manager: one dynamic lane with its own queue and worker pool."""

    def __init__(self, name: str, mission: str, n_workers: int,
                 executor: Callable[[str, int], Any]):
        self.name = name
        self.mission = mission
        self.jobs: "queue.Queue" = queue.Queue()
        self.reports: deque = deque(maxlen=64)
        self.rlock = threading.Lock()
        # NOTE: `idle` is a best-effort hint for single-worker lanes — with
        # several workers any idling one can set it while another still runs.
        # Do not use it for correctness; only queues and reports are exact.
        self.idle = threading.Event()
        self.idle.set()
        self.probes_submitted = 0
        self.workers = [
            ProbeWorker(f"{name}-w{i}", name, self.jobs, self.reports,
                        self.rlock, executor, self.idle)
            for i in range(max(1, n_workers))
        ]
        for w in self.workers:
            w.start()

    def submit(self, cmd: str, why: str = "", timeout: int = PROBE_TIMEOUT_DEFAULT) -> None:
        self.jobs.put(ProbeSpec(lane=self.name, cmd=cmd, why=why, timeout=timeout))
        self.probes_submitted += 1
        self.idle.clear()

    def pending(self) -> int:
        return self.jobs.qsize()

    def harvest(self) -> List[WorkerReport]:
        with self.rlock:
            out = list(self.reports)
            self.reports.clear()
        return out

    def status(self) -> str:
        return (f"{self.name}: mission={self.mission[:60]} "
                f"workers={len(self.workers)} queued={self.jobs.qsize()} "
                f"probes={self.probes_submitted}")

    def shutdown(self) -> None:
        for _ in self.workers:
            self.jobs.put(None)
        for w in self.workers:
            w.stop()
        for w in self.workers:
            try:
                w.join(timeout=3)
            except Exception:
                pass


class MissionDirector:
    """Boss: dynamic lanes, probe budget, harvest, and deterministic review."""

    def __init__(self, executor: Callable[[str, int], Any],
                 ai: Any = None, chain_engine: Any = None):
        self.ai = ai
        self.chain_engine = chain_engine
        self._executor = executor
        self.lanes: Dict[str, WorkstreamManager] = {}
        self.notes: List[str] = []          # boss decisions, for the transcript
        self._rlock = threading.Lock()
        self._iter_probes = 0
        self.max_lanes = _env_int("X19_TEAM_MAX_LANES", 3, 1, 8)
        self.workers_per_lane = _env_int("X19_TEAM_WORKERS", 2, 1, 6)
        self.probes_per_iter = _env_int("X19_TEAM_PROBES_PER_ITER", 6, 1, 24)
        self.last_review: Dict[str, Any] = {}
        self._pending: List[WorkerReport] = []

    # -- org management --------------------------------------------------
    def spawn(self, lane: str, mission: str, workers: int = 0) -> str:
        lane = str(lane or "").strip().lower().replace(" ", "-")[:24]
        if not lane:
            return "spawn rejected: empty lane name"
        if team_disabled():
            return "team disabled (X19_TEAM_DISABLE)"
        if lane in self.lanes:
            return f"lane '{lane}' already active"
        if len(self.lanes) >= self.max_lanes:
            return f"spawn rejected: max {self.max_lanes} lanes"
        n = max(1, min(int(workers or self.workers_per_lane), self.workers_per_lane))
        self.lanes[lane] = WorkstreamManager(lane, mission or "no mission set", n, self._executor)
        note = f"spawned lane '{lane}' ({n} workers): {self.lanes[lane].mission}"
        self.notes.append(note)
        return note

    def assign(self, lane: str, cmd: str, why: str = "",
               timeout: int = PROBE_TIMEOUT_DEFAULT) -> str:
        cmd = str(cmd or "").strip()
        lane = str(lane or "").strip().lower()
        if not cmd:
            return "assign rejected: empty probe"
        mgr = self.lanes.get(lane)
        if mgr is None:
            return f"assign rejected: unknown lane '{lane}'"
        if self._iter_probes >= self.probes_per_iter:
            return f"assign deferred: iteration probe budget ({self.probes_per_iter}) used"
        self._iter_probes += 1
        mgr.submit(cmd, why=why, timeout=timeout)
        return f"→ {lane}: {cmd[:80]}"

    def retire(self, lane: str) -> str:
        mgr = self.lanes.pop(str(lane or "").strip().lower(), None)
        if mgr is None:
            return f"retire: unknown lane '{lane}'"
        mgr.shutdown()
        note = f"retired lane '{mgr.name}' after {mgr.probes_submitted} probes"
        self.notes.append(note)
        return note

    def apply_decision(self, team_obj: Any) -> List[str]:
        """Apply the boss-model's team actions from the decision JSON."""
        out: List[str] = []
        if isinstance(team_obj, dict):
            team_obj = [team_obj]
        if not isinstance(team_obj, list):
            return out
        for action in team_obj:
            if not isinstance(action, dict):
                continue
            op = str(action.get("action") or action.get("op") or "").strip().lower()
            if op == "spawn":
                out.append(self.spawn(action.get("lane"), action.get("mission"),
                                      action.get("workers")))
            elif op in ("assign", "probe"):
                out.append(self.assign(action.get("lane"), action.get("cmd")
                                       or action.get("probe"), action.get("why", "")))
            elif op == "retire":
                out.append(self.retire(action.get("lane")))
            elif op:
                out.append(f"unknown team action '{op}'")
        return out

    def new_iteration(self) -> None:
        self._iter_probes = 0

    # -- harvest + review --------------------------------------------------
    def pending_reports(self) -> List[WorkerReport]:
        """Peek at staged reports without draining them (render_context drains)."""
        return list(self._pending)

    def harvest_all(self) -> int:
        """Drain every lane's reports into the staged pending buffer."""
        n = 0
        for mgr in self.lanes.values():
            reps = mgr.harvest()
            self._pending.extend(reps)
            n += len(reps)
        del self._pending[:-32]
        return n

    def review(self, findings: List[Any]) -> Dict[str, Any]:
        """Boss review over *verified* findings: rollup + chain summary."""
        sev: Dict[str, int] = {}
        for f in findings or []:
            s = str(getattr(f, "severity", "info") or "info").lower()
            sev[s] = sev.get(s, 0) + 1
        chain_summary: Dict[str, Any] = {}
        if self.chain_engine is not None:
            try:
                chain_summary = self.chain_engine.summarize(findings or [])
            except Exception as e:
                log(f"[TEAM] chain summary failed: {e}")
        self.last_review = {
            "findings_total": len(findings or []),
            "severity": sev,
            "chains": chain_summary.get("chains", 0),
            "deepest_chain": chain_summary.get("deepest", 0),
            "highest_impact": chain_summary.get("highest_impact", ""),
        }
        return self.last_review

    # -- context rendering --------------------------------------------------
    def render_context(self) -> str:
        if not self.lanes and not self.notes and not self.last_review:
            return ""
        lines = ["TEAM STATUS (your org: you are the boss; lanes are your managers):"]
        for mgr in self.lanes.values():
            lines.append(f"  - {mgr.status()}")
        if self.last_review:
            r = self.last_review
            lines.append(f"BOSS REVIEW: findings={r.get('findings_total', 0)} "
                         f"severity={r.get('severity', {})} "
                         f"chains={r.get('chains', 0)} "
                         f"(deepest {r.get('deepest_chain', 0)}, impact: {r.get('highest_impact') or '—'})")
        reports, self._pending = self._pending, []
        if reports:
            lines.append("LANE REPORTS (raw worker evidence — verify before filing findings):")
            for rep in reports[-REPORTS_IN_CONTEXT:]:
                lines.append(f"  · {rep.line()}")
                if rep.excerpt.strip():
                    first = rep.excerpt.strip().splitlines()[0][:140]
                    if first and first not in lines[-1]:
                        lines.append(f"      └ {first}")
        if self.notes:
            lines.append("RECENT ORG ACTIONS: " + " | ".join(self.notes[-3:]))
        block = "\n".join(lines)
        if len(block) > CONTEXT_CHAR_CAP:
            block = block[:CONTEXT_CHAR_CAP - 3].rstrip() + "..."
        return block

    # -- dynamic decomposition ---------------------------------------------
    def plan_with_ai(self, world_summary: str, system_prompt: str) -> List[str]:
        """Ask the boss model to decompose the target into lanes. Dynamic —
        the plan comes from what the target exposes, not a fixed playbook.
        Falls back to a surface-derived plan on any failure."""
        if team_disabled() or self.ai is None:
            return []
        try:
            raw = self.ai.chat(system_prompt, world_summary[:4000])
            obj = _first_json_object(raw or "")
            notes: List[str] = []
            for lane in (obj or {}).get("lanes", []) or []:
                if isinstance(lane, dict):
                    notes.append(self.spawn(lane.get("name"), lane.get("mission"),
                                            lane.get("workers")))
            return [n for n in notes if n]
        except Exception as e:
            log(f"[TEAM] boss planning failed: {e}")
            return []

    def plan_from_surface(self, model: Any) -> List[str]:
        """Deterministic fallback: one lane per exposed surface family,
        derived from the live world model (data-driven, not a playbook)."""
        if team_disabled() or not self.lanes:
            ports = list(getattr(model, "ports", []) or [])[:6]
            web = [p for p in ports if int(p.get("port", 0) or 0) in (80, 443, 8080, 8443, 8000, 8888)]
            other = [p for p in ports if p not in web]
            notes: List[str] = []
            if web:
                notes.append(self.spawn("web", f"test http surface on ports "
                                                 f"{[p.get('port') for p in web]}", self.workers_per_lane))
            if other:
                notes.append(self.spawn("services", f"enumerate services on ports "
                                                    f"{[p.get('port') for p in other][:4]}", 1))
            return notes

    def shutdown(self) -> None:
        for mgr in list(self.lanes.values()):
            mgr.shutdown()
        self.lanes.clear()

