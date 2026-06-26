import hashlib
import json
import os
import re
import shutil
import threading
import time
from datetime import datetime
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any, Set

from constants import C, ICO
from loop import LoopSignal
from reporting import Finding
from storage import FailureMemory, JsonFileStore
from config import CONFIG, CONFIG_DIR, load_config, save_config
from logging_utils import log


class GoalNode:
    def __init__(self, node: str, parent: Optional[str], kind: str, description: str):
        self.node = node
        self.parent = parent
        self.kind = kind  # recon|web|exploit|validate|report
        self.description = description
        self.active = True


class GoalTree:
    """Goal tree drives what we ask next (structured autonomy)."""
    def __init__(self):
        # Minimal but extensible tree
        self.nodes: Dict[str, GoalNode] = {}
        self._build()

    def _build(self):
        def add(node, parent, kind, desc):
            self.nodes[node] = GoalNode(node=node, parent=parent, kind=kind, description=desc)

        add("assessment", None, "root", "Decide best path based on target model + evidence")
        add("recon_ports", "assessment", "recon", "Discover services/ports and infer likely attack surface")
        add("recon_web", "assessment", "recon", "Discover endpoints/tech stack for web/API targets")
        add("recon_ad", "assessment", "recon", "Enumerate AD surface if applicable")
        add("exploit_web", "assessment", "exploit", "Exploit discovered web/API weaknesses (auth, injection, RCE)")
        add("exploit_smb", "assessment", "exploit", "Exploit SMB/windows weaknesses if exposed")
        add("validate", "assessment", "validate", "Verify exploit impact and capture evidence")
        add("report", "assessment", "report", "Produce final verified PoC/report")
        add("self_debug", "assessment", "diagnose", "Run self-diagnostic and recovery procedures when stuck in a loop")

    def select_active_node(
        self,
        model: "TargetModel",
        target_type: str,
        forced_exploit: bool,
        loop_sig: LoopSignal,
        autonomy_profile: Optional["AutonomyProfile"] = None,
    ) -> str:
        # Hard pivot if we are stuck/looping
        if loop_sig.state == "hard":
            return "self_debug"

        if autonomy_profile:
            suggestion = autonomy_profile.recommend_goal(model, target_type, forced_exploit, loop_sig)
            if suggestion:
                return suggestion

        # If forced exploit mode, bias towards exploit nodes
        if forced_exploit:
            if any(p.get("port") in (80, 443, 8080, 8443) for p in model.ports):
                return "exploit_web"
            if any(p.get("port") == 445 for p in model.ports):
                return "exploit_smb"
            return "validate"

        # Choose based on observed ports/services
        open_ports = {p.get("port") for p in model.ports}
        if any(pt in open_ports for pt in (80, 443, 8080, 8443)):
            return "recon_web" if not model.endpoints else "exploit_web"
        if any(pt in open_ports for pt in (389, 445, 3389)):
            # heuristic: AD-ish ports -> recon_ad, windows exploit if evidence
            if any(pt == 389 for pt in open_ports):
                return "recon_ad"
            return "exploit_smb" if any(f.severity in ("medium", "high", "critical") for f in model.findings) else "validate"
        # Default: recon ports
        if not model.ports:
            return "recon_ports"
        # If we have ports but no endpoints/findings -> decide web/ad based on endpoints
        if model.endpoints:
            return "exploit_web"
        return "recon_ports"


class ConfidenceScorer:
    """Computes confidence for suggested next actions/findings."""
    def score_action(self, category: str, model: "TargetModel", failure_memory: FailureMemory) -> float:
        # Base confidence depends on how often a category succeeded recently (proxy via failure memory + evidence)
        is_blocked_any, _ = failure_memory.is_blocked(f"{category}")
        # punish heavy failure signatures generally
        base = 0.62
        if is_blocked_any:
            base -= 0.25

        # reward having relevant evidence already
        if category in ("web", "web_scanner", "web_dirbust", "web_exploit") and any(
            p.get("port") in (80, 443, 8080, 8443) for p in model.ports
        ):
            base += 0.1
        if category in ("smb",) and any(p.get("port") == 445 for p in model.ports):
            base += 0.1
        if category.startswith("subdomain") and model.subdomains:
            base += 0.07
        if any(f.severity in ("medium", "high", "critical") for f in model.findings):
            base += 0.05
        return max(0.05, min(0.98, base))

    def score_finding(self, evidence_text: str) -> float:
        # Quick heuristic: more exploit keywords -> higher confidence
        if not evidence_text:
            return 0.05
        e = evidence_text.lower()
        hits = 0
        for kw in ["vulnerable", "exposed", "success", "rce", "shell", "root", "flag{", "ctf{", "sql syntax", "xss", "unauthorized", "authenticated", "app_key", ".env", "private key", "credentials"]:
            if kw in e:
                hits += 1
        return max(0.05, min(0.98, 0.25 + hits * 0.1))


class LoopDetector:
    """Goal-aware loop detection combining output hash, category stagnation, and goal stagnation."""
    def __init__(self):
        self.last_cmd_signatures: List[str] = []
        self.last_goal_nodes: List[str] = []
        self.last_categories: List[str] = []

    def observe(self, command: str, category: str, goal_node: str):
        # normalize signature
        s = re.sub(r'/tmp/[a-zA-Z0-9_\.\-]+', '/tmp/_', command.strip())
        s = re.sub(r'\s+', ' ', s)
        sig = hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()[:10]
        self.last_cmd_signatures.append(sig)
        self.last_cmd_signatures = self.last_cmd_signatures[-12:]
        self.last_goal_nodes.append(goal_node)
        self.last_goal_nodes = self.last_goal_nodes[-12:]
        self.last_categories.append(category)
        self.last_categories = self.last_categories[-12:]

    def detect(self, output_hash_recent: List[int], category_streak: int, goal_stagnant: int) -> LoopSignal:
        if len(output_hash_recent) >= 3 and output_hash_recent[-3:] == [output_hash_recent[-1]] * 3:
            return LoopSignal(state="hard", category="output_hash", reason="Last 3 outputs identical")
        if len(output_hash_recent) >= 2 and output_hash_recent[-2:] == [output_hash_recent[-1]] * 2:
            return LoopSignal(state="soft", category="output_hash", reason="Last 2 outputs identical")
        cat_run = self._trailing_run(self.last_categories)
        goal_run = self._trailing_run(self.last_goal_nodes)
        if cat_run >= max(3, category_streak - 1) and goal_run >= max(2, goal_stagnant - 1):
            return LoopSignal(state="hard", category=self.last_categories[-1] if self.last_categories else "stagnation",
                              reason=f"Category streak {cat_run} + goal stagnant {goal_run}")
        if cat_run >= max(2, category_streak - 2):
            return LoopSignal(state="soft", category=self.last_categories[-1] if self.last_categories else "stagnation",
                              reason=f"Category streak {cat_run}")
        return LoopSignal(state="none", reason="")

    @staticmethod
    def _trailing_run(seq: List[str]) -> int:
        if not seq:
            return 0
        last, n = seq[-1], 0
        for x in reversed(seq):
            if x == last:
                n += 1
            else:
                break
        return n


@dataclass
class AutonomyProfile:
    """Persistent autonomy state used to bias goals and surface self-introspection."""

    goal_node: str = "assessment"
    pivot_bias: str = "recon"
    last_target: str = ""
    last_target_type: str = ""
    last_signal: str = ""
    last_learning_note: str = ""
    recent_signals: List[str] = field(default_factory=list)
    task_queue: List[Dict[str, str]] = field(default_factory=list)
    task_history: List[str] = field(default_factory=list)
    memory_counts: Dict[str, int] = field(default_factory=dict)
    failure_counts: Dict[str, int] = field(default_factory=dict)
    updated_ts: float = 0.0

    def __post_init__(self):
        self.store = JsonFileStore(CONFIG_DIR / "autonomy_profile.json")
        data = self.store.load()
        if data:
            self._load(data)

    def _load(self, data: dict):
        self.goal_node = data.get("goal_node", self.goal_node)
        self.pivot_bias = data.get("pivot_bias", self.pivot_bias)
        self.last_target = data.get("last_target", self.last_target)
        self.last_target_type = data.get("last_target_type", self.last_target_type)
        self.last_signal = data.get("last_signal", self.last_signal)
        self.last_learning_note = data.get("last_learning_note", self.last_learning_note)
        self.recent_signals = list(data.get("recent_signals", []) or [])[-12:]
        self.task_queue = [t for t in (data.get("task_queue", []) or []) if isinstance(t, dict)]
        self.task_history = list(data.get("task_history", []) or [])[-40:]
        self.memory_counts = dict(data.get("memory_counts", {}) or {})
        self.failure_counts = dict(data.get("failure_counts", {}) or {})
        self.updated_ts = float(data.get("updated_ts", 0.0) or 0.0)

    def _save(self):
        try:
            self.store.save({
                "goal_node": self.goal_node,
                "pivot_bias": self.pivot_bias,
                "last_target": self.last_target,
                "last_target_type": self.last_target_type,
                "last_signal": self.last_signal,
                "last_learning_note": self.last_learning_note,
                "recent_signals": self.recent_signals[-12:],
                "task_queue": self.task_queue[-20:],
                "task_history": self.task_history[-40:],
                "memory_counts": self.memory_counts,
                "failure_counts": self.failure_counts,
                "updated_ts": self.updated_ts,
            })
        except Exception as e:
            log(f"[AutonomyProfile] save failed: {e}")

    def observe(self, **kwargs) -> str:
        """Update autonomy profile from current execution state and return a context string."""
        if kwargs.get("target"):
            self.last_target = kwargs["target"]
        if kwargs.get("target_type"):
            self.last_target_type = kwargs["target_type"]
        if kwargs.get("goal_node"):
            self.goal_node = kwargs["goal_node"]
        if kwargs.get("loop_sig"):
            self.last_signal = kwargs["loop_sig"][:120]
        if kwargs.get("memory_counts"):
            self.memory_counts = kwargs["memory_counts"]
        if kwargs.get("failure_memory"):
            self.failure_counts = dict(kwargs["failure_memory"])
        self.updated_ts = time.time()
        self._save()
        parts = []
        parts.append(f"GOAL: {self.goal_node}")
        parts.append(f"PIVOT BIAS: {self.pivot_bias}")
        parts.append(f"LAST TARGET: {self.last_target}")
        if self.last_signal:
            sig = self.last_signal.replace("\n", " ")[:80]
            parts.append(f"LOOP SIGNAL: {sig}")
        if self.task_queue:
            parts.append(f"TASKS QUEUED: {len(self.task_queue)}")
        if self.recent_signals:
            parts.append(f"RECENT SIGNALS: {', '.join(s[:40] for s in self.recent_signals[-3:])}")
        if self.last_learning_note:
            ln = self.last_learning_note.replace("\n", " ")[:120]
            parts.append(f"LAST LEARNING: {ln}")
        if kwargs.get("self_summary"):
            parts.append(f"SELF: {kwargs['self_summary']}")
        if kwargs.get("perf_summary"):
            parts.append(f"PERF: {kwargs['perf_summary']}")
        return "\n".join(parts)

    @staticmethod
    def _task_key(task: Dict[str, str]) -> str:
        raw = f"{task.get('goal', '')}|{task.get('category', '')}|{task.get('command', '')}|{task.get('mode', '')}"
        return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]

    def push_tasks(self, tasks: List[Dict[str, str]]):
        if not tasks:
            return
        seen = {self._task_key(t) for t in self.task_queue}
        seen.update(self.task_history)
        for task in tasks:
            if not isinstance(task, dict):
                continue
            key = task.get("key") or self._task_key(task)
            if not key or key in seen:
                continue
            task = dict(task)
            task["key"] = key
            self.task_queue.append(task)
            seen.add(key)
        self.task_queue = self.task_queue[-20:]
        self._save()

    def pop_task(self, key: Optional[str] = None) -> Optional[Dict[str, str]]:
        if not self.task_queue:
            return None
        index = 0
        if key:
            for idx, task in enumerate(self.task_queue):
                if (task.get("key") or self._task_key(task)) == key:
                    index = idx
                    break
            else:
                return None
        task = self.task_queue.pop(index)
        task_key = task.get("key") or self._task_key(task)
        if task_key:
            self.task_history.append(task_key)
            self.task_history = self.task_history[-40:]
        self._save()
        return task

    def clear_tasks(self):
        self.task_queue = []
        self._save()

    def task_summary(self, limit: int = 4) -> str:
        if not self.task_queue:
            return "TASK QUEUE: empty"
        lines = ["TASK QUEUE:"]
        for task in self.task_queue[:limit]:
            goal = task.get("goal", "task")
            mode = task.get("mode", "task")
            command = task.get("command", "")[:140]
            lines.append(f"  [{mode}] {goal} -> {command}")
        if len(self.task_queue) > limit:
            lines.append(f"  ... and {len(self.task_queue) - limit} more queued")
        return "\n".join(lines)

    def recommend_goal(
        self,
        model: "TargetModel",
        target_type: str,
        forced_exploit: bool,
        loop_sig: "LoopSignal",
    ) -> Optional[str]:
        if loop_sig.state == "hard" or self.pivot_bias == "self_debug":
            return "self_debug"
        if self.task_queue:
            head_mode = (self.task_queue[0].get("mode") or "").lower()
            if head_mode == "self_debug":
                return "self_debug"
            if head_mode == "validate":
                return "validate"
            if head_mode == "recon_web":
                return "recon_web"
            if head_mode == "hypothesis":
                return "exploit_web" if model.endpoints else "validate"
        if any((f.severity if isinstance(f, Finding) else f.get("severity", "info")) in ("critical", "high") for f in model.findings):
            return "validate"
        if forced_exploit:
            if any(p.get("port") in (80, 443, 8080, 8443) for p in model.ports):
                return "exploit_web"
            if any(p.get("port") == 445 for p in model.ports):
                return "exploit_smb"
            return "validate"
        if self.pivot_bias == "validate" and model.findings:
            return "validate"
        if self.pivot_bias == "exploit" and any(p.get("port") in (80, 443, 8080, 8443) for p in model.ports):
            return "exploit_web"
        if self.pivot_bias == "recon_web" and any(p.get("port") in (80, 443, 8080, 8443) for p in model.ports):
            return "recon_web" if not model.endpoints else "exploit_web"
        if self.pivot_bias == "recon_ad" and any(p.get("port") in (389, 445, 3389) for p in model.ports):
            return "recon_ad"
        if target_type == "public_real_world" and self.pivot_bias == "exploit":
            return "validate" if model.findings else "recon_web"
        return None


@dataclass
class MissionTask:
    key: str
    goal: str
    category: str
    command: str
    mode: str = "recon"
    reason: str = ""
    status: str = "queued"
    attempts: int = 0
    evidence: str = ""
    depends_on: List[str] = field(default_factory=list)
    created_ts: float = 0.0
    updated_ts: float = 0.0

    @classmethod
    def from_dict(cls, data: dict) -> "MissionTask":
        return cls(
            key=data.get("key", ""),
            goal=data.get("goal", ""),
            category=data.get("category", "analysis"),
            command=data.get("command", ""),
            mode=data.get("mode", "recon"),
            reason=data.get("reason", ""),
            status=data.get("status", "queued"),
            attempts=int(data.get("attempts", 0) or 0),
            evidence=data.get("evidence", ""),
            depends_on=list(data.get("depends_on", []) or []),
            created_ts=float(data.get("created_ts", 0.0) or 0.0),
            updated_ts=float(data.get("updated_ts", 0.0) or 0.0),
        )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class VerificationVerdict:
    useful: bool
    accepted: bool
    reason: str = ""
    progress_delta: int = 0
    followups: List[Dict[str, str]] = field(default_factory=list)


class TaskGraph:
    """Persistent mission graph with queued, running, completed, and blocked tasks."""

    def __init__(self, base_dir: Path):
        self.store = JsonFileStore(base_dir / "mission_graph.json")
        self._data = self.store.load()
        if not self._data:
            self._data = {
                "target": "",
                "tasks": [],
                "history": [],
                "updated_ts": 0.0,
            }
        self._normalize()

    @staticmethod
    def _task_key(task: Dict[str, str]) -> str:
        raw = f"{task.get('goal', '')}|{task.get('category', '')}|{task.get('command', '')}|{task.get('mode', '')}"
        return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]

    def _normalize(self):
        tasks = self._data.get("tasks", []) or []
        self._data["tasks"] = [MissionTask.from_dict(t).to_dict() for t in tasks if isinstance(t, dict)]
        self._data["history"] = list(self._data.get("history", []) or [])[-80:]

    def _save(self):
        self._data["updated_ts"] = time.time()
        self._normalize()
        self.store.save(self._data)

    def reset(self, target: str):
        self._data = {
            "target": target,
            "tasks": [],
            "history": [],
            "updated_ts": time.time(),
        }
        self._save()

    def add_tasks(self, tasks: List[Dict[str, str]]) -> int:
        if not tasks:
            return 0
        existing = {t.get("key") for t in self._data.get("tasks", [])}
        added = 0
        for task in tasks:
            if not isinstance(task, dict):
                continue
            item = dict(task)
            item["key"] = item.get("key") or self._task_key(item)
            if item["key"] in existing:
                continue
            item.setdefault("status", "queued")
            item.setdefault("attempts", 0)
            item.setdefault("created_ts", time.time())
            item.setdefault("updated_ts", time.time())
            self._data.setdefault("tasks", []).append(MissionTask.from_dict(item).to_dict())
            existing.add(item["key"])
            added += 1
        if added:
            self._save()
        return added

    def open_tasks(self) -> List[MissionTask]:
        return [MissionTask.from_dict(t) for t in self._data.get("tasks", []) if t.get("status") in ("queued", "running")]

    def next_task(self) -> Optional[MissionTask]:
        tasks = self._data.get("tasks", [])
        for idx, task in enumerate(tasks):
            if task.get("status") != "queued":
                continue
            task["status"] = "running"
            task["attempts"] = int(task.get("attempts", 0) or 0) + 1
            task["updated_ts"] = time.time()
            self._data["history"].append({"ts": time.time(), "event": "start", "key": task["key"]})
            self._save()
            return MissionTask.from_dict(task)
        return None

    def mark(self, key: str, status: str, evidence: str = "", reason: str = ""):
        for task in self._data.get("tasks", []):
            if task.get("key") != key:
                continue
            task["status"] = status
            task["evidence"] = evidence[:300]
            task["reason"] = reason[:180]
            task["updated_ts"] = time.time()
            self._data["history"].append({
                "ts": time.time(),
                "event": status,
                "key": key,
                "reason": reason[:180],
            })
            self._save()
            return

    def summary(self, limit: int = 4) -> str:
        tasks = self.open_tasks()
        if not tasks:
            return "MISSION GRAPH: empty"
        lines = [f"MISSION GRAPH: {len(tasks)} open task(s)"]
        for task in tasks[:limit]:
            lines.append(f"  [{task.mode}] {task.goal} -> {task.command[:120]}")
        if len(tasks) > limit:
            lines.append(f"  ... and {len(tasks) - limit} more open")
        return "\n".join(lines)

    def has_open_work(self) -> bool:
        return any(t.get("status") in ("queued", "running") for t in self._data.get("tasks", []))


class Verifier:
    """Evidence and completion verifier for autonomous decisions."""

    def verify_progress(self, before_size: int, after_size: int, output: str, command: str) -> VerificationVerdict:
        """
        More human-like progress classification:
        - Prefer explicit artifact growth (ports/endpoints/findings/creds in the model) via before/after size.
        - Treat 404/403-only/no-results outputs as noise unless we also see clear evidence keywords.
        - Downweight generic "discovered" chatter when it doesn't produce model growth.
        """
        delta = max(0, after_size - before_size)
        low = (output or "").lower()

        # Hard rule: model growth is real progress.
        if delta > 0:
            return VerificationVerdict(
                useful=True,
                accepted=True,
                reason=f"model grew by {delta}",
                progress_delta=delta,
            )

        if not output or not output.strip():
            return VerificationVerdict(useful=False, accepted=False, reason="empty/no output", progress_delta=0)

        # Evidence-like keywords (strong)
        strong_signals = (
            "vulnerab", "exploit", "inject", "rce", "shell", "root",
            "sql syntax", "xss", "ssrf", "idor", "lfi", "rfi",
            "credential", "password", "token", "secret", "api key", "private key",
            "flag{", "ctf{",
            "open port", "service detected", "discovered endpoint",
            "endpoint", "new endpoint", "exposed", "success", "unauthorized", "authenticated",
        )

        # Noise-like (soft dead ends)
        noise_signals = (
            "no results", "not found", "404", "410",
            "403", "access denied", "forbidden",
            "timeout", "timed out", "connection refused",
            "could not resolve", "temporary failure", "no such file",
            "0% ", "0 results", "finished after 0",
        )

        # Artifact hints (medium) - useful when not contradicted by noise
        medium_signals = (
            "status code", "status:", "http", "response",
            "redirect", "moved permanently", "found",
        )

        has_strong = any(sig in low for sig in strong_signals)
        has_noise = any(sig in low for sig in noise_signals)
        has_medium = any(sig in low for sig in medium_signals)

        # If output is clearly dead-end/no-results, don't call it progress.
        if has_noise and not has_strong:
            return VerificationVerdict(useful=False, accepted=False, reason="noise/dead-end (4xx/timeout/no-results)", progress_delta=0)

        # If we saw strong evidence keywords, accept as useful.
        if has_strong:
            return VerificationVerdict(useful=True, accepted=True, reason="output contains strong evidence signals", progress_delta=0)

        # If only medium indicators, treat as tentative (reject for “human-like” behavior).
        if has_medium:
            return VerificationVerdict(useful=False, accepted=False, reason="output lacks strong evidence (medium HTTP/status signals only)", progress_delta=0)

        # Fallback: keyword scan similar to previous behavior, but stricter.
        useful_signals = ("endpoint", "credential", "password", "token", "secret", "rce", "sqli", "xss", "flag{", "ctf{", "vulnerab")
        useful = any(sig in low for sig in useful_signals) and not has_noise
        reason = "output contains useful signal" if useful else "output was noise/unclear"
        return VerificationVerdict(useful=useful, accepted=useful, reason=reason, progress_delta=0)

    def verify_completion(
        self,
        all_exhausted: bool,
        has_open_work: bool,
        findings_count: int,
        iteration: int,
        min_iters: int,
    ) -> Tuple[bool, str]:
        if has_open_work:
            return False, "mission still has open tasks"
        if not all_exhausted and iteration < min_iters and findings_count == 0:
            return False, "mission not yet exhausted and no solid finding"
        if not all_exhausted and findings_count == 0:
            return False, "no confirmed finding yet"
        return True, "completion accepted"


class AutoReplanner:
    """Generates the next autonomy tasks from live target state."""

    def generate(self, agent: "X19", active_node: str, failure_reason: str = "") -> List[Dict[str, str]]:
        tasks: List[Dict[str, str]] = []
        model = agent.model
        host = agent._target_host()
        recent_commands = [c.get("cmd", "") for c in (agent.session.data.get("commands", []) or [])[-20:] if isinstance(c, dict)]
        recent_norms = {agent._normalize_command(cmd) for cmd in recent_commands if cmd}
        open_norms = {agent._normalize_command(task.command) for task in agent.mission_graph.open_tasks() if task.command}
        seed_hypotheses = (agent._generated_hypotheses or agent._generate_structured_hypotheses())[:6]

        def add_task(task: Dict[str, str]):
            command = (task.get("command") or "").strip()
            if not command:
                return
            task_cat = task.get("category") or agent._cmd_category(command)
            banned = agent._banned_categories | agent._banned_plan_categories
            if task_cat in banned:
                return
            norm = agent._normalize_command(command)
            if not norm or norm in recent_norms or norm in open_norms:
                return
            tasks.append(task)
            recent_norms.add(norm)

        def fallback_candidates() -> List[str]:
            candidates = []
            if host:
                candidates.extend([
                    agent._generate_fallback_cmd(),
                    f"nmap -sV -Pn --top-ports 100 --max-rtt-timeout 500ms {host}",
                    f"httpx -follow-redirects -status-code -title -tech-detect -u http://{host} 2>/dev/null | head -20",
                    f"curl -sik --max-time 5 'https://{host}/' | head -30",
                    f"curl -sik --max-time 5 'http://{host}/' | head -30",
                ])
            candidates = [cmd for cmd in candidates if cmd and '{' not in cmd.split('{', 1)[0]]
            banned = agent._banned_categories | agent._banned_plan_categories
            if banned:
                candidates.sort(key=lambda c: 0 if agent._cmd_category(c) not in banned else 1)
            return candidates

        for hyp in seed_hypotheses:
            if hyp.tested or not hyp.command:
                continue
            if agent._info_gain_scorer(hyp.command) < 4:
                continue
            add_task({
                "goal": hyp.title,
                "category": agent._cmd_category(hyp.command),
                "mode": "hypothesis",
                "command": hyp.command,
                "reason": hyp.interpretation[:160],
            })

        if failure_reason:
            add_task({
                "goal": "recover from stalled decision loop",
                "category": "analysis",
                "mode": "self_debug",
                "command": self.pick_fallback(agent),
                "reason": failure_reason[:180],
            })

        if not model.ports:
            add_task({
                "goal": "establish initial surface",
                "category": "recon",
                "mode": "recon",
                "command": self.pick_fallback(agent),
                "reason": "No ports discovered yet, so the agent needs a first real signal.",
            })
        else:
            web_ports = [p for p in model.ports if p.get("port") in (80, 443, 8080, 8443)]
            if web_ports and model.subdomains and not model.endpoints:
                sub = sorted(model.subdomains, key=agent._score_subdomain, reverse=True)[0]
                scheme = "https" if any(p.get("port") in (443, 8443) for p in web_ports) else "http"
                add_task({
                    "goal": f"probe live host {sub}",
                    "category": "web",
                    "mode": "recon_web",
                    "command": f"curl -sik --max-time 5 '{scheme}://{sub}/' | head -30",
                    "reason": "Subdomain exists but endpoints are still missing.",
                })
            if model.endpoints:
                endpoint = max(model.endpoints[-10:], key=agent._score_endpoint)
                add_task({
                    "goal": f"validate endpoint {endpoint.get('url', '')}",
                    "category": "scanner",
                    "mode": "validate",
                    "command": f"nuclei -u '{endpoint.get('url', '')}' -severity medium,high,critical -silent",
                    "reason": "An endpoint is already known, so validation beats more broad recon.",
                })
            elif web_ports:
                add_task({
                    "goal": "fingerprint web surface",
                    "category": "web",
                    "mode": "recon_web",
                    "command": self.pick_fallback(agent),
                    "reason": "The target exposes web ports but no endpoints yet.",
                })
            if any(p.get("port") == 445 for p in model.ports) and host:
                add_task({
                    "goal": "enumerate SMB surface",
                    "category": "smb",
                    "mode": "recon",
                    "command": f"smbclient -L //{host} -N",
                    "reason": "SMB is exposed and could produce an authenticated or anonymous path.",
                })

        if not tasks:
            for command in fallback_candidates():
                norm = agent._normalize_command(command)
                if norm and norm not in recent_norms and norm not in open_norms:
                    tasks.append({
                        "goal": "maintain forward progress",
                        "category": agent._cmd_category(command),
                        "mode": "recon",
                        "command": command,
                        "reason": "No non-duplicate task could be generated, so choose the next distinct probe.",
                    })
                    break
        tasks = [t for t in tasks if t.get("command")]
        return tasks

    _FALLBACK_PHASES = [
        "recon", "web_enum", "dirbust", "vuln_scan", "exploit", "done"
    ]

    def _load_failed_commands(self, agent: "X19") -> set:
        """Load past-session failed command signatures from ChromaDB lessons.
        Returns a set of normalized command prefixes that failed before."""
        failed = set()
        try:
            if not agent.memory.ready:
                return failed
            # Query lessons for failure patterns related to this target
            host = self._get_host(agent)
            lessons = agent.memory.query("lessons", f"failed pentest command {host}", n=15)
            for lesson in lessons:
                text = ""
                if isinstance(lesson, dict):
                    text = lesson.get("text", "") or lesson.get("document", "") or ""
                    meta = lesson.get("metadata", {}) or {}
                    if meta.get("success") is False:
                        cmd = meta.get("command", "")
                        if cmd:
                            failed.add(cmd.split()[0].lower() if cmd.split() else cmd.lower())
                elif isinstance(lesson, str):
                    text = lesson
                # Also extract tool names from lesson text
                for tool in ["nmap", "curl", "gobuster", "hydra", "ssh", "smb",
                             "ffuf", "dirsearch", "nuclei", "whatweb", "wpscan",
                             "searchsploit", "enum4linux", "sqlmap", "msfconsole"]:
                    if f"{tool} " in text.lower() and "fail" in text.lower():
                        failed.add(tool)
            # Also query with port/service context
            ports = self._get_open_ports(agent)
            if ports:
                port_ctx = f"ports: {','.join(str(p) for p in sorted(ports)[:5])}"
                port_lessons = agent.memory.query("lessons", f"failed {port_ctx}", n=10)
                for lesson in port_lessons:
                    if isinstance(lesson, dict):
                        meta = lesson.get("metadata", {}) or {}
                        if meta.get("success") is False:
                            cmd = meta.get("command", "")
                            if cmd:
                                failed.add(cmd.split()[0].lower() if cmd.split() else cmd.lower())
        except Exception:
            pass
        return failed

    def _get_open_ports(self, agent):
        try:
            return {int(p.get("port")) for p in agent.model.ports if p.get("port") is not None}
        except Exception:
            return set()

    def _get_web_port(self, agent, host):
        open_ports = self._get_open_ports(agent)
        for p in [80, 443, 8080, 8443, 8000, 3000, 5000, 9000]:
            if p in open_ports:
                scheme = "https" if p in (443, 8443) else "http"
                return f"{scheme}://{host}:{p}"
        # No confirmed web port — don't assume http://host exists
        return ""

    def _get_host(self, agent):
        host = agent._target_host()
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
            return host
        try:
            import ipaddress
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        return host

    def _last_output_keywords(self, agent) -> set:
        """Extract keywords from last command output to drive phase selection."""
        cmds = agent.session.data.get("commands", []) or []
        if not cmds:
            return set()
        last = cmds[-1]
        if not isinstance(last, dict):
            return set()
        out = (last.get("output") or "") + (last.get("error") or "")
        words = set()
        for kw in ["flag", "ctf{", "open", "filtered", "closed", "http", "ssh",
                    "ftp", "mysql", "apache", "nginx", "iis", "tomcat",
                    "wordpress", "joomla", "drupal", "phpmyadmin",
                    "admin", "login", "dashboard", "api", "vulnerable",
                    "cve-", "exploit", "shell", "upload", "config"]:
            if kw.lower() in out.lower():
                words.add(kw)
        return words

    def _ctf_fallback(self, agent: "X19", host: str, failed_tools: set = None) -> Optional[str]:
        """CTF-specific fallback: flag hunting pipeline."""
        if failed_tools is None:
            failed_tools = set()
        recent = [c.get("cmd", "") for c in (agent.session.data.get("commands", []) or [])[-10:] if isinstance(c, dict)]
        recent_set = set(recent)

        CTF_PHASES = [
            # Phase 1: quick port scan
            lambda: f"nmap -sV -T4 -p- --min-rate=1000 {host}" if "nmap -sV -T4 -p-" not in recent_set else None,
            # Phase 2: check common CTF ports
            lambda: f"nmap -sV -p 22,80,443,8080,8000,8443,21,3306,6379,27017 -A {host}" if "nmap -sV -p" not in recent_set else None,
            # Phase 3: web checks based on open ports
            lambda: next((f"curl -sik --max-time 5 'http://{host}:{p}/' | head -100" for p in [80, 8080, 8000, 443, 8443, 3000, 5000]
                         if f"curl -sik --max-time 5 'http://{host}:{p}/'" not in recent_set), None),
            # Phase 4: HTTP enum + flag check
            lambda: next((f"curl -sik 'http://{host}:{p}/flag' --max-time 5" for p in [80, 8080, 8000, 443, 8443]
                         if f"curl -sik 'http://{host}:{p}/flag'" not in recent_set), None),
            lambda: next((f"curl -sik 'http://{host}:{p}/flag.txt' --max-time 5" for p in [80, 8080, 8000, 443, 8443]
                         if f"curl -sik 'http://{host}:{p}/flag.txt'" not in recent_set), None),
            # Phase 5: gobuster/ffuf for directories
            lambda: f"gobuster dir -u http://{host}:80 -w {CONFIG.WORDLIST_DIR}/dirb/common.txt -q -t 30 -x php,txt,html,zip 2>/dev/null | head -30" if shutil.which("gobuster") else None,
            # Phase 6: check SSH
            lambda: f"ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{host} 2>&1 | head -5" if not any("ssh" in c for c in recent) else None,
            # Phase 7: check FTP
            lambda: f"curl -s --max-time 8 'ftp://anonymous:anonymous@{host}/' --list-only | head -20",
            # Phase 8: full nmap port scan if nothing found yet
            lambda: f"nmap -sV -p- --min-rate=1000 -T4 {host} 2>/dev/null | grep -E 'open|filtered' | head -20",
            # Phase 9: nuclei on any web port
            lambda: next((f"nuclei -u http://{host}:{p} -t cves,misconfigurations,exposures -silent -rl 80 2>/dev/null | head -40"
                         for p in [80, 443, 8080, 8443, 8000, 3000, 5000] if shutil.which("nuclei")), None),
        ]

        for phase_fn in CTF_PHASES:
            if not phase_fn:
                continue
            try:
                cmd = phase_fn()
                if cmd and cmd not in recent_set:
                    tool_name = cmd.split()[0].lower() if cmd.split() else ""
                    if tool_name in failed_tools:
                        continue
                    return cmd
            except Exception:
                continue
        return None

    def pick_fallback(self, agent: "X19") -> str:
        host = self._get_host(agent)
        recent_commands = [c.get("cmd", "") for c in (agent.session.data.get("commands", []) or [])[-20:] if isinstance(c, dict)]
        recent_norms = {agent._normalize_command(cmd) for cmd in recent_commands if cmd}
        open_norms = {agent._normalize_command(task.command) for task in agent.mission_graph.open_tasks() if task.command}
        open_ports = self._get_open_ports(agent)
        web_url = self._get_web_port(agent, host)
        banned = agent._banned_categories | agent._banned_plan_categories
        exhausted = getattr(agent, "_exhausted_techniques", set()) or set()
        target_type = getattr(agent, "target_type", "")
        keywords = self._last_output_keywords(agent)
        is_ctf = target_type == "ctf" or any(kw in ("flag", "ctf{") for kw in keywords)

        # Load past-session failures to avoid repeating them
        failed_tools = self._load_failed_commands(agent)

        # CTF mode: use dedicated flag-hunting pipeline first
        if is_ctf:
            ctf_cmd = self._ctf_fallback(agent, host, failed_tools)
            if ctf_cmd:
                return ctf_cmd

        if not hasattr(agent, "_fallback_phase_idx"):
            agent._fallback_phase_idx = 0
        if not hasattr(agent, "_fallback_cmd_idx"):
            agent._fallback_cmd_idx = {}
        if not hasattr(agent, "_pick_fallback_calls"):
            agent._pick_fallback_calls = 0

        # Smart phase selection based on discovered ports and output keywords
        PHASES = []
        waf_active = bool(getattr(agent, "_cloudflare", False))
        waf_vendor = getattr(agent, "_waf_vendor", "") or "WAF"

        # Phase 0: RECON (always runs first if no ports known)
        recon_phase = []
        if not open_ports or agent._fallback_phase_idx == 0:
            recon_phase.append(("port_scan", f"nmap -sV -T4 --top-ports 1000 {host} 2>/dev/null"))
            if shutil.which("masscan"):
                recon_phase.insert(0, ("port_scan", f"masscan {host} -p1-65535 --rate=1000 2>/dev/null | head -20"))
        if waf_active and host:
            recon_phase.extend([
                ("dns_recon", f"subfinder -d {host} -silent -timeout 8 2>/dev/null | head -30"),
                ("osint", f"curl -s 'https://crt.sh/?q=%25.{host}&output=json' --max-time 10 2>/dev/null | head -50"),
            ])
        for port in sorted(open_ports):
            if port in (80, 443, 8080, 8443, 8000, 3000, 5000, 9000):
                recon_phase.append(("fingerprint", f"curl -sik --max-time 5 'http://{host}:{port}/' | head -30"))
            elif port == 21:
                recon_phase.append(("ftp", f"curl -s --max-time 8 'ftp://anonymous:anonymous@{host}/' --list-only | head -20"))
            elif port == 22:
                recon_phase.append(("ssh", f"ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{host} 2>&1 | head -5"))
        if recon_phase:
            PHASES.append(("recon", recon_phase))

        # Phase 1: WEB ENUM (only if web ports are confirmed)
        web_phase = []
        if web_url:
            web_phase.extend([
                ("web", f"whatweb -a3 {web_url} 2>/dev/null | head -30"),
                ("web", f"curl -sik -L '{web_url}/' | head -100"),
                ("web", f"curl -sik '{web_url}/robots.txt' | head -50"),
                ("web", f"curl -sik '{web_url}/.env' --max-time 5 | head -30"),
            ])
            if "wordpress" in keywords or "wp-" in str(recent_commands):
                web_phase.append(("web", f"wpscan --url {web_url} --no-update 2>/dev/null | head -40"))
        if web_phase:
            PHASES.append(("web_enum", web_phase))

        # Phase 2: DIRBUST (if web ports exist)
        dirb_phase = []
        if web_url:
            wl_dir = CONFIG.WORDLIST_DIR.rstrip("/")
            wordlist = next((p for p in [
                f"{wl_dir}/seclists/Discovery/Web-Content/common.txt",
                f"{wl_dir}/dirb/common.txt",
            ] if Path(p).exists()), f"{wl_dir}/dirb/common.txt")
            if shutil.which("gobuster"):
                dirb_phase.append(("web_dirbust", f"gobuster dir -u {web_url} -w {wordlist} -q -t 30 -x php,txt,html,zip --no-error 2>/dev/null | head -40"))
            elif shutil.which("dirsearch"):
                dirb_phase.append(("web_dirbust", f"dirsearch -u {web_url} -q -t 30 --timeout=5 2>/dev/null | head -40"))
            elif shutil.which("ffuf"):
                dirb_phase.append(("web_dirbust", f"ffuf -u {web_url}/FUZZ -w {wordlist} -mc 200,301,302 -t 50 -c 2>/dev/null | head -40"))
            # Check specific CTF-relevant paths
            for path in ["/flag", "/flag.txt", "/admin", "/login", "/backup",
                         "/config", "/uploads", "/shell", "/cmd", "/exec",
                         "/index.php?cmd=", "/index.php?page="]:
                dirb_phase.append(("web_dirbust", f"curl -sik --max-time 3 -o /dev/null -w '%{{http_code}}' {web_url}{path} 2>&1"))
        if dirb_phase:
            PHASES.append(("dirbust", dirb_phase))

        # Phase 3: VULN SCAN
        vuln_phase = []
        if web_url:
            if shutil.which("nuclei"):
                vuln_phase.append(("vuln_scan", f"nuclei -u {web_url} -t cves,misconfigurations,exposures -silent -rl 80 2>/dev/null | head -40"))
            if shutil.which("whatweb"):
                vuln_phase.append(("vuln_scan", f"whatweb -a 3 {web_url} 2>/dev/null | head -30"))
        if vuln_phase:
            PHASES.append(("vuln_scan", vuln_phase))

        # Phase 4: SSH ATTACK
        ssh_phase = []
        if 22 in open_ports:
            ssh_phase.extend([
                ("ssh", f"nmap -sV --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -p 22 {host} 2>/dev/null | head -20"),
                ("ssh", f"searchsploit openssh 2>/dev/null | head -20"),
            ])
            if shutil.which("hydra"):
                ssh_phase.append(("ssh", f"hydra -l root -P {CONFIG.WORDLIST_DIR.rstrip('/')}/rockyou.txt ssh://{host} -t 4 -o /dev/null 2>/dev/null | head -10"))
        if ssh_phase:
            PHASES.append(("ssh_attack", ssh_phase))

        # Phase 5: EXPLOIT
        exploit_phase = []
        for p in agent.model.ports[:5]:
            svc = p.get("service", "").lower()
            ver = p.get("version", "")
            if svc and ver and shutil.which("searchsploit"):
                exploit_phase.append(("exploit", f"searchsploit {svc} {ver} 2>/dev/null | head -20"))
        if "apache" in keywords:
            exploit_phase.append(("exploit", f"nmap --script http-vuln-* -p {','.join(str(p) for p in sorted(open_ports) if p in (80,443,8080,8443,8000))} {host} 2>/dev/null | head -20"))
        if exploit_phase:
            PHASES.append(("exploit", exploit_phase))

        # Skip tools that failed in past sessions
        if failed_tools:
            print(f"{C.D}[Memo] Avoiding {len(failed_tools)} tool(s) that failed in previous sessions: {', '.join(sorted(failed_tools)[:6])}{C.N}", flush=True)

        # — Normal phase advancement logic —
        if agent._fallback_phase_idx >= len(PHASES):
            agent._fallback_phase_idx = len(PHASES) - 1 if PHASES else 0

        all_banned_cats = banned | exhausted
        for phase_offset in range(len(PHASES)):
            phase_idx = (agent._fallback_phase_idx + phase_offset) % len(PHASES) if PHASES else 0
            if not PHASES:
                break
            phase_name, phase_cmds = PHASES[phase_idx]
            if phase_name in banned or phase_name in exhausted:
                continue
            try:
                if phase_cmds and all(agent._cmd_category(cmd) in all_banned_cats for _, cmd in phase_cmds):
                    continue
            except Exception:
                pass
            cmd_idx = agent._fallback_cmd_idx.get(phase_idx, 0)
            for i in range(len(phase_cmds)):
                check_idx = (cmd_idx + i) % len(phase_cmds)
                _, cmd = phase_cmds[check_idx]
                real_cat = agent._cmd_category(cmd)
                if real_cat in all_banned_cats:
                    continue
                # Skip if this tool failed in past sessions (learned from past mistakes)
                tool_name = cmd.split()[0].lower() if cmd.split() else ""
                if tool_name in failed_tools:
                    continue
                norm = agent._normalize_command(cmd)
                if norm in recent_norms or norm in open_norms:
                    continue
                agent._fallback_cmd_idx[phase_idx] = (check_idx + 1) % len(phase_cmds)
                agent._fallback_phase_idx = phase_idx
                return cmd

            if phase_offset == 0:
                agent._fallback_cmd_idx[phase_idx] = 0
                agent._fallback_phase_idx = (phase_idx + 1) % len(PHASES) if PHASES else 0

        # Ultimate fallback
        if host:
            port_set = {int(p["port"]) for p in agent.model.ports}
            for scheme, port in [("https", 443), ("http", 80), ("http", 8080), ("https", 8443), ("http", 8000), ("http", 3000)]:
                if port not in port_set:
                    continue
                test_cmd = f"curl -sik --max-time 5 '{scheme}://{host}:{port}/' 2>&1 | head -20"
                if agent._cmd_category(test_cmd) in all_banned_cats:
                    continue
                norm = agent._normalize_command(test_cmd)
                if norm in recent_norms or norm in open_norms:
                    continue
                return test_cmd
            skip_cmd = f"echo 'skip: all fallback commands exhausted for {host}'"
            if agent._cmd_category(skip_cmd) not in all_banned_cats:
                return skip_cmd
            return "echo 'no unbanned command available'"
        return "echo 'no target available'"

    def local_decision(
        self,
        agent: "X19",
        target: str,
        active_node: str,
        failure_reason: str,
        last_output: str,
        iteration: int,
    ) -> Dict[str, Any]:
        # Try AI-driven mission graph first; hardcoded fallback is absolute last resort.
        # (AI retry logic in _autonomous_fallback_decision already tried providers 4x.)
        if agent.mission_graph.has_open_work():
            task = agent.mission_manager.next_task(active_node, failure_reason)
            if task:
                return {
                    "thinking": f"Mission task selected: {task.goal}",
                    "reasoning": f"{task.reason or failure_reason or 'autonomous task'} | mission graph selected this because the model stalled.",
                    "next_command": task.command,
                    "finding": None,
                    "plan": None,
                    "completed": False,
                    "_mission_task": task.to_dict(),
                }

        tasks = self.generate(agent, active_node, failure_reason)
        added = agent.mission_graph.add_tasks(tasks)
        if added:
            agent.autonomy_profile.push_tasks(tasks)
            task = agent.mission_graph.next_task()
            if task:
                return {
                    "thinking": f"Autonomy planner seeded {added} tasks and selected: {task.goal}",
                    "reasoning": f"{task.reason or failure_reason or 'autonomous replanning'} | queue was empty or stalled.",
                    "next_command": task.command,
                    "finding": None,
                    "plan": None,
                    "completed": False,
                    "_mission_task": task.to_dict(),
                }

        fallback = self.pick_fallback(agent)
        return {
            "thinking": "Fallback probe chosen from current target state.",
            "reasoning": f"Model failure or weak output ({failure_reason or 'no specific reason'}); use a fresh, target-aware probe.",
            "next_command": fallback,
            "finding": None,
            "plan": None,
            "completed": False,
        }


class MissionManager:
    """Coordinates task graph, verifier, and replanning for autonomous missions."""

    def __init__(self, agent: "X19"):
        self.agent = agent
        self.started_target = agent.target or ""

    def reset_for_target(self, target: str):
        if self.started_target and self.started_target != target:
            self.agent.mission_graph.reset(target)
            self.agent.autonomy_profile.clear_tasks()
        self.started_target = target

    def seed(self, active_node: str, failure_reason: str = "") -> int:
        tasks = self.agent.auto_replanner.generate(self.agent, active_node, failure_reason)
        added = self.agent.mission_graph.add_tasks(tasks)
        if added:
            self.agent.autonomy_profile.push_tasks(tasks)
        return added

    def next_task(self, active_node: str, failure_reason: str = "") -> Optional[MissionTask]:
        task = self.agent.mission_graph.next_task()
        if task:
            self.agent.autonomy_profile.pop_task(task.key)
            return task
        seeded = self.seed(active_node, failure_reason)
        if seeded:
            task = self.agent.mission_graph.next_task()
            if task:
                self.agent.autonomy_profile.pop_task(task.key)
                return task
        return None

    def should_accept_completion(
        self,
        completed: bool,
        all_exhausted: bool,
        iteration: int,
        findings_count: int,
    ) -> Tuple[bool, str]:
        if not completed:
            return False, "AI has not requested completion"
        ok, reason = self.agent.verifier.verify_completion(
            all_exhausted=all_exhausted,
            has_open_work=self.agent.mission_graph.has_open_work(),
            findings_count=findings_count,
            iteration=iteration,
            min_iters=CONFIG.MIN_ITERATIONS if is_bug_bounty_mode() else 15,
        )
        return ok, reason

    def record_outcome(
        self,
        command: str,
        result: "ToolResult",
        before_size: int,
        after_size: int,
        category: str,
        active_node: str,
        task: Optional[MissionTask] = None,
        is_plan: bool = False,
    ) -> VerificationVerdict:
        output = (result.text or "") if result else ""
        verdict = self.agent.verifier.verify_progress(before_size, after_size, output, command)
        if task:
            status = "done" if verdict.useful else "failed"
            self.agent.mission_graph.mark(task.key, status, evidence=output[:300], reason=verdict.reason)
        if verdict.useful:
            followups = self.agent.auto_replanner.generate(self.agent, active_node)
            if followups:
                verdict.followups = followups
                self.agent.mission_graph.add_tasks(followups)
                self.agent.autonomy_profile.push_tasks(followups)
        if is_plan and verdict.useful:
            self.agent._queue_autonomy_tasks(active_node, "mission manager planned follow-ups")
        return verdict

    def summary(self) -> str:
        open_tasks = self.agent.mission_graph.open_tasks()
        if not open_tasks:
            return "MISSION MANAGER: no open tasks"
        head = open_tasks[0]
        return f"MISSION MANAGER: {len(open_tasks)} open | next={head.goal} | mode={head.mode}"

    def observe(
        self,
        target: str,
        target_type: str,
        model: "TargetModel",
        goal_node: str,
        loop_sig: LoopSignal,
        failure_memory: FailureMemory,
        memory_ready: bool,
        memory_counts: Dict[str, int],
        self_summary: str,
        perf_summary: str,
        last_output: str = "",
    ) -> str:
        findings = list(model.findings)
        high_findings = sum(
            1 for f in findings
            if (f.severity if isinstance(f, Finding) else f.get("severity", "info")) in ("medium", "high", "critical")
        )
        ports = len(model.ports)
        endpoints = len(model.endpoints)
        subdomains = len(model.subdomains)
        failures = failure_memory._data.get("categories", {}) if failure_memory else {}
        failure_total = sum(int(v.get("count", 0)) for v in failures.values()) if isinstance(failures, dict) else 0

        if loop_sig.state == "hard":
            pivot_bias = "self_debug"
            signal = f"hard-loop:{loop_sig.category or 'stagnation'}"
        elif high_findings > 0:
            pivot_bias = "exploit"
            signal = "confirmed-finding"
        elif endpoints >= 8 and high_findings == 0:
            pivot_bias = "validate"
            signal = "endpoint-rich"
        elif ports and any(p.get("port") in (80, 443, 8080, 8443) for p in model.ports):
            pivot_bias = "exploit" if endpoints else "recon_web"
            signal = "web-surface"
        elif any(p.get("port") in (389, 445, 3389) for p in model.ports):
            pivot_bias = "recon_ad"
            signal = "directory-or-windows-surface"
        elif failure_total >= 8:
            pivot_bias = "self_debug"
            signal = "failure-pressure"
        elif subdomains and not endpoints:
            pivot_bias = "recon_web"
            signal = "subdomain-rich"
        else:
            pivot_bias = "recon" if ports == 0 else "explore"
            signal = "steady-state"

        self.goal_node = goal_node
        self.pivot_bias = pivot_bias
        self.last_target = target
        self.last_target_type = target_type
        self.last_signal = signal
        self.last_learning_note = (last_output or perf_summary or self_summary or "").strip()[:180]
        self.memory_counts = dict(memory_counts or {})
        self.failure_counts = {k: int(v.get("count", 0)) for k, v in list(failures.items())[:8]} if isinstance(failures, dict) else {}
        self.updated_ts = time.time()
        self.recent_signals.append(f"{self.updated_ts:.0f}:{signal}")
        self.recent_signals = self.recent_signals[-12:]
        self._save()

        mem_bits = ", ".join(f"{k}={v}" for k, v in self.memory_counts.items() if v is not None)
        fail_bits = ", ".join(f"{k}:{v}" for k, v in list(self.failure_counts.items())[:4]) if self.failure_counts else "none"
        return (
            "AUTONOMY PROFILE:\n"
            f"  goal={self.goal_node} bias={self.pivot_bias} signal={signal}\n"
            f"  target={self.last_target} type={self.last_target_type} ports={ports} endpoints={endpoints} subdomains={subdomains} findings={len(findings)} high={high_findings}\n"
            f"  memory={'ready' if memory_ready else 'warming'} {mem_bits or 'none'}\n"
            f"  failures={fail_bits}\n"
            f"  self={self_summary[:120]}\n"
            f"  learn={self.last_learning_note[:120]}"
        )

    def recommend_goal(self, model: "TargetModel", target_type: str, forced_exploit: bool, loop_sig: LoopSignal) -> Optional[str]:
        if loop_sig.state == "hard" or self.pivot_bias == "self_debug":
            return "self_debug"
        if self.task_queue:
            head_mode = (self.task_queue[0].get("mode") or "").lower()
            if head_mode == "self_debug":
                return "self_debug"
            if head_mode == "validate":
                return "validate"
            if head_mode == "recon_web":
                return "recon_web"
            if head_mode == "hypothesis":
                return "exploit_web" if model.endpoints else "validate"
        if any((f.severity if isinstance(f, Finding) else f.get("severity", "info")) in ("critical", "high") for f in model.findings):
            return "validate"
        if forced_exploit:
            if any(p.get("port") in (80, 443, 8080, 8443) for p in model.ports):
                return "exploit_web"
            if any(p.get("port") == 445 for p in model.ports):
                return "exploit_smb"
            return "validate"
        if self.pivot_bias == "validate" and model.findings:
            return "validate"
        if self.pivot_bias == "exploit" and any(p.get("port") in (80, 443, 8080, 8443) for p in model.ports):
            return "exploit_web"
        if self.pivot_bias == "recon_web" and any(p.get("port") in (80, 443, 8080, 8443) for p in model.ports):
            return "recon_web" if not model.endpoints else "exploit_web"
        if self.pivot_bias == "recon_ad" and any(p.get("port") in (389, 445, 3389) for p in model.ports):
            return "recon_ad"
        if target_type == "public_real_world" and self.pivot_bias == "exploit":
            return "validate" if model.findings else "recon_web"
        return None
