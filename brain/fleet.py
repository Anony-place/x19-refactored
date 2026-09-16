"""Fleet mode: one supervisor, many targets — the XBOW scale pattern.

The last roadmap gap from the research audit
(docs/TOP_AUTONOMOUS_AGENTS_RESEARCH.md §5): X19 ran one target per process.
The FleetSupervisor runs a *pool* of independent assessments concurrently —
each unit is a full X19 agent on its own target with its own session, so the
scope gate, policy engine, verification gates and team org are inherited
per-unit, unchanged. The supervisor adds only what a fleet needs:

- bounded concurrency (``X19_FLEET_CONCURRENCY``, default 2, max 8) —
  each unit is API- and tool-hungry, so the pool stays small;
- per-unit lifecycle (queued → running → done / failed / stopped) with
  failure isolation: one target's crash never touches the others;
- ``stop(target)`` / ``stop_all()`` — cooperative, via the agent's stop flag;
- a fleet summary: severities aggregated across targets plus *shared tech
  stacks* (the same stack on several targets → intel and confirmed
  hypotheses transfer — cross-target correlation);
- optional event bus wiring so terminals can render fleet progress live.

The unit factory is injectable: headless runs and tests substitute fakes, the
workspace and CLI use the real X19. Nothing about the fleet is hardcoded —
targets come from the operator, concurrency from env, results from the same
verified pipeline as any single-target run.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from logging_utils import log


def fleet_concurrency() -> int:
    try:
        return max(1, min(8, int((os.getenv("X19_FLEET_CONCURRENCY", "") or "2").strip())))
    except ValueError:
        return 2


@dataclass
class FleetUnit:
    """State of one target's assessment inside the fleet."""
    target: str
    status: str = "queued"            # queued | running | done | failed | stopped
    session_id: str = ""
    error: str = ""
    started: float = 0.0
    finished: float = 0.0
    severity: Dict[str, int] = field(default_factory=dict)
    tech: List[str] = field(default_factory=list)
    agent: Any = None                 # the unit's X19 (or fake in tests)

    def elapsed(self) -> float:
        if not self.started:
            return 0.0
        return (self.finished or time.time()) - self.started

    def row(self) -> Dict[str, Any]:
        crit = self.severity.get("critical", 0)
        high = self.severity.get("high", 0)
        return {
            "target": self.target,
            "status": self.status,
            "secs": round(self.elapsed(), 1),
            "findings": sum(self.severity.values()),
            "crit_high": crit + high,
            "error": self.error[:80],
            "session": self.session_id,
        }


class FleetSupervisor:
    """Runs independent assessments over a bounded worker pool."""

    def __init__(self, unit_factory: Optional[Callable[[str], Any]] = None,
                 max_concurrency: Optional[int] = None,
                 bus: Any = None):
        self._factory = unit_factory or self._default_factory
        self.max_concurrency = max(1, int(max_concurrency or fleet_concurrency()))
        self.bus = bus                    # optional AgentEventBus for fleet events
        self.units: Dict[str, FleetUnit] = {}
        self._queue: List[str] = []
        self._threads: List[threading.Thread] = []
        self._lock = threading.RLock()
        self._stop_all_flag = threading.Event()
        self._done_signal = threading.Event()

    # -- factory -----------------------------------------------------------
    @staticmethod
    def _default_factory(target: str) -> Any:
        from agent import X19
        return X19(target=target)

    # -- submission ----------------------------------------------------------
    def submit(self, targets: List[str]) -> List[str]:
        """Queue targets (deduped, skips ones already known). Returns new ones."""
        added: List[str] = []
        with self._lock:
            for t in targets or []:
                t = str(t or "").strip()
                if not t or t in self.units:
                    continue
                self.units[t] = FleetUnit(target=t)
                self._queue.append(t)
                added.append(t)
        return added

    # -- lifecycle -----------------------------------------------------------
    def run(self, wait: bool = True, on_status: Optional[Callable[[str], None]] = None,
            timeout: Optional[float] = None) -> None:
        """Start the pool (``wait=False`` returns immediately; poll status())."""
        with self._lock:
            if self._threads:
                return  # already running
            n = min(self.max_concurrency, max(1, len(self._queue)))
            self._done_signal.clear()
            for i in range(n):
                th = threading.Thread(target=self._worker, args=(on_status,),
                                      name=f"fleet-w{i}", daemon=True)
                self._threads.append(th)
                th.start()
        if wait:
            self.wait(timeout)

    def wait(self, timeout: Optional[float] = None) -> bool:
        return self._done_signal.wait(timeout)

    def _emit(self, text: str, **detail) -> None:
        if self.bus is None:
            return
        try:
            self.bus.publish("fleet", text, **detail)
        except Exception:
            pass

    def _worker(self, on_status: Optional[Callable[[str], None]]) -> None:
        while not self._stop_all_flag.is_set():
            with self._lock:
                if not self._queue:
                    break
                target = self._queue.pop(0)
                unit = self.units[target]
                if unit.status != "queued":
                    continue   # stopped/cancelled before start — skip it
                unit.status = "running"
                unit.started = time.time()
            self._emit(f"start {target}", target=target)
            self._notify(on_status, target)
            try:
                agent = self._factory(target)
                unit.agent = agent
                session = getattr(agent, "session", None)
                try:
                    unit.session_id = str(getattr(session, "id", "") or "")
                except Exception:
                    pass
                agent.autonomous_loop(target)
                self._collect(agent, unit)
                unit.status = "stopped" if getattr(agent, "stop", False) else "done"
            except Exception as e:
                unit.status = "failed"
                unit.error = f"{type(e).__name__}: {e}"[:200]
                log(f"[FLEET] {target} failed: {e}")
            unit.finished = time.time()
            self._emit(f"{unit.status} {target} "
                       f"({sum(unit.severity.values())} findings)", target=target,
                       severity=dict(unit.severity))
            self._notify(on_status, target)
        with self._lock:
            if all(u.status not in ("queued", "running") for u in self.units.values()):
                self._done_signal.set()

    def _notify(self, cb: Optional[Callable[[str], None]], target: str) -> None:
        if cb is None:
            return
        try:
            cb(target)
        except Exception:
            pass

    def _collect(self, agent: Any, unit: FleetUnit) -> None:
        """Harvest severities + tech stack off the finished agent's model."""
        try:
            model = getattr(agent, "model", None)
            for f in (getattr(model, "findings", None) or []):
                sev = str(getattr(f, "severity", "info") or "info").lower()
                unit.severity[sev] = unit.severity.get(sev, 0) + 1
            unit.tech = [str(k) for k in (getattr(model, "tech_stack", {}) or {})][:8]
        except Exception as e:
            log(f"[FLEET] collect {unit.target}: {e}")

    # -- control ---------------------------------------------------------------
    def stop(self, target: str) -> bool:
        unit = self.units.get(str(target or "").strip())
        if unit is None:
            return False
        if unit.agent is None:
            # Not started yet: a queued unit is stopped by flipping its state;
            # the worker will pop it, see the terminal status, and move on.
            with self._lock:
                if unit.status == "queued":
                    unit.status = "stopped"
                    unit.finished = time.time()
                    self._queue.remove(unit.target)
                    return True
            return False
        try:
            unit.agent.stop = True
            return True
        except Exception:
            return False

    def stop_all(self) -> int:
        self._stop_all_flag.set()
        n = 0
        for unit in self.units.values():
            if unit.status in ("queued", "running") and unit.agent is not None:
                try:
                    unit.agent.stop = True
                    n += 1
                except Exception:
                    pass
        # queued-but-not-started units are marked stopped immediately
        with self._lock:
            for unit in self.units.values():
                if unit.status == "queued":
                    unit.status = "stopped"
                    unit.finished = time.time()
        return n

    # -- reporting ---------------------------------------------------------------
    def status_rows(self) -> List[Dict[str, Any]]:
        return [u.row() for u in self.units.values()]

    def active_count(self) -> int:
        return sum(1 for u in self.units.values() if u.status in ("queued", "running"))

    def summary(self) -> Dict[str, Any]:
        """Fleet-level rollup: severities, shared stacks, stragglers."""
        sev: Dict[str, int] = {}
        tech_seen: Dict[str, List[str]] = {}
        done = failed = 0
        for u in self.units.values():
            for k, v in u.severity.items():
                sev[k] = sev.get(k, 0) + v
            if u.status == "done":
                done += 1
            elif u.status == "failed":
                failed += 1
            for t in u.tech:
                tech_seen.setdefault(t.lower(), []).append(u.target)
        shared = {t: hosts for t, hosts in tech_seen.items() if len(hosts) >= 2}
        return {
            "targets": len(self.units),
            "done": done,
            "failed": failed,
            "active": self.active_count(),
            "severity": sev,
            "shared_stacks": {t: sorted(set(h)) for t, h in shared.items()},
        }


# ---------------------------------------------------------------------------
# Headless CLI: x19 fleet -t t1,t2,t3 [--max N]
# ---------------------------------------------------------------------------
def cli(argv: List[str]) -> int:
    targets: List[str] = []
    max_c = 0
    args = list(argv)
    while args:
        a = args.pop(0)
        if a in ("-t", "--targets") and args:
            targets.extend(x.strip() for x in args.pop(0).split(",") if x.strip())
        elif a.startswith("--targets="):
            targets.extend(x.strip() for x in a.split("=", 1)[1].split(",") if x.strip())
        elif a in ("--max", "-c") and args:
            try:
                max_c = int(args.pop(0))
            except ValueError:
                print("[!] --max needs a number")
                return 2
        elif a in ("-h", "--help"):
            print(__doc__ or "")
            print("usage: x19 fleet -t target1,target2 [--max 3]")
            return 0
    if not targets:
        print("usage: x19 fleet -t target1,target2 [--max 3]")
        return 2
    sup = FleetSupervisor(max_concurrency=max_c or None)
    sup.submit(targets)

    def status_line(t: str) -> None:
        rows = sup.status_rows()
        active = sum(1 for r in rows if r["status"] in ("queued", "running"))
        print(f"[FLEET] {t}: {active} active · "
              + " ".join(f"{r['target']}={r['status']}" for r in rows), flush=True)

    sup.run(wait=True, on_status=status_line)
    s = sup.summary()
    print(f"[FLEET] done: {s['done']}/{s['targets']} targets · severity={s['severity']}")
    if s["shared_stacks"]:
        print("[FLEET] shared stacks (intel transfers): "
              + "; ".join(f"{t} on {', '.join(h)}" for t, h in s["shared_stacks"].items()))
    for r in sup.status_rows():
        if r["status"] == "failed":
            print(f"[FLEET] FAILED {r['target']}: {r['error']}")
    return 0 if s["failed"] == 0 else 1
