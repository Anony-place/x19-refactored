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
from memory import is_bug_bounty_mode


class GoalNode:
    def __init__(self, node: str, parent: Optional[str], kind: str, description: str):
        self.node = node
        self.parent = parent
        self.kind = kind
        self.description = description
        self.active = True


class GoalTree:
    """Goal tree drives what we ask next (structured autonomy)."""
    def __init__(self):
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

    def select_active_node(self, model: "TargetModel", target_type: str, forced_exploit: bool, loop_sig: LoopSignal, autonomy_profile: Optional["AutonomyProfile"] = None) -> str:
        if loop_sig.state == "hard":
            return "self_debug"
        if autonomy_profile:
            suggestion = autonomy_profile.recommend_goal(model, target_type, forced_exploit, loop_sig)
            if suggestion:
                return suggestion
        if forced_exploit:
            if any(p.get("port") in (80, 443, 8080, 8443) for p in model.ports):
                return "exploit_web"
            if any(p.get("port") == 445 for p in model.ports):
                return "exploit_smb"
            return "validate"
        open_ports = {p.get("port") for p in model.ports}
        if any(pt in open_ports for pt in (80, 443, 8080, 8443)):
            return "recon_web" if not model.endpoints else "exploit_web"
        if any(pt in open_ports for pt in (389, 445, 3389)):
            if any(pt == 389 for pt in open_ports):
                return "recon_ad"
            return "exploit_smb" if any(f.severity in ("medium", "high", "critical") for f in model.findings) else "validate"
        if not model.ports:
            return "recon_ports"
        if model.endpoints:
            return "exploit_web"
        return "recon_ports"


class ConfidenceScorer:
    """Computes confidence for suggested next actions/findings."""
    def score_action(self, category: str, model: "TargetModel", failure_memory: FailureMemory) -> float:
        is_blocked_any, _ = failure_memory.is_blocked(f"{category}")
        base = 0.62
        if is_blocked_any:
            base -= 0.25
        if category in ("web", "web_scanner", "web_dirbust", "web_exploit") and any(p.get("port") in (80, 443, 8080, 8443) for p in model.ports):
            base += 0.1
        if category in ("smb",) and any(p.get("port") == 445 for p in model.ports):
            base += 0.1
        if category.startswith("subdomain") and model.subdomains:
            base += 0.07
        if any(f.severity in ("medium", "high", "critical") for f in model.findings):
            base += 0.05
        return max(0.05, min(0.98, base))

    def score_finding(self, evidence_text: str) -> float:
        if not evidence_text:
            return 0.05
        e = evidence_text.lower()
        hits = sum(1 for kw in ["vulnerable", "exposed", "success", "rce", "shell", "root", "flag{", "ctf{", "sql syntax", "xss", "unauthorized", "authenticated", "app_key", ".env", "private key", "credentials"] if kw in e)
        return max(0.05, min(0.98, 0.25 + hits * 0.1))


class LoopDetector:
    """Goal-aware loop detection combining output hash, category stagnation, and goal stagnation."""
    def __init__(self):
        self.last_cmd_signatures: List[str] = []
        self.last_goal_nodes: List[str] = []
        self.last_categories: List[str] = []

    def observe(self, command: str, category: str, goal_node: str):
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
            return LoopSignal(state="hard", category=self.last_categories[-1] if self.last_categories else "stagnation", reason=f"Category streak {cat_run} + goal stagnant {goal_run}")
        if cat_run >= max(2, category_streak - 2):
            return LoopSignal(state="soft", category=self.last_categories[-1] if self.last_categories else "stagnation", reason=f"Category streak {cat_run}")
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
            self.store.save({"goal_node": self.goal_node, "pivot_bias": self.pivot_bias, "last_target": self.last_target, "last_target_type": self.last_target_type, "last_signal": self.last_signal, "last_learning_note": self.last_learning_note, "recent_signals": self.recent_signals[-12:], "task_queue": self.task_queue[-20:], "task_history": self.task_history[-40:], "memory_counts": self.memory_counts, "failure_counts": self.failure_counts, "updated_ts": self.updated_ts})
        except Exception as e:
            log(f"[AutonomyProfile] save failed: {e}")

    def observe(self, **kwargs) -> str:
        if kwargs.get("target"): self.last_target = kwargs["target"]
        if kwargs.get("target_type"): self.last_target_type = kwargs["target_type"]
        if kwargs.get("goal_node"): self.goal_node = kwargs["goal_node"]
        if kwargs.get("loop_sig"): self.last_signal = kwargs["loop_sig"][:120]
        if kwargs.get("memory_counts"): self.memory_counts = kwargs["memory_counts"]
        if kwargs.get("failure_memory"): self.failure_counts = dict(kwargs["failure_memory"])
        self.updated_ts = time.time()
        self._save()
        parts = [f"GOAL: {self.goal_node}", f"PIVOT BIAS: {self.pivot_bias}", f"LAST TARGET: {self.last_target}"]
        if self.last_signal: parts.append(f"LOOP SIGNAL: {self.last_signal.replace(chr(10), ' ')[:80]}")
        if self.task_queue: parts.append(f"TASKS QUEUED: {len(self.task_queue)}")
        if self.recent_signals: parts.append(f"RECENT SIGNALS: {', '.join(s[:40] for s in self.recent_signals[-3:])}")
        if self.last_learning_note: parts.append(f"LAST LEARNING: {self.last_learning_note.replace(chr(10), ' ')[:120]}")
        if kwargs.get("self_summary"): parts.append(f"SELF: {kwargs['self_summary']}")
        if kwargs.get("perf_summary"): parts.append(f"PERF: {kwargs['perf_summary']}")
        return "\n".join(parts)

    @staticmethod
    def _task_key(task: Dict[str, str]) -> str:
        raw = f"{task.get('goal', '')}|{task.get('category', '')}|{task.get('command', '')}|{task.get('mode', '')}"
        return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]

    def push_tasks(self, tasks: List[Dict[str, str]]):
        if not tasks: return
        seen = {self._task_key(t) for t in self.task_queue}; seen.update(self.task_history)
        for task in tasks:
            if not isinstance(task, dict): continue
            key = task.get("key") or self._task_key(task)
            if not key or key in seen: continue
            task = dict(task); task["key"] = key; self.task_queue.append(task); seen.add(key)
        self.task_queue = self.task_queue[-20:]; self._save()

    def pop_task(self, key: Optional[str] = None) -> Optional[Dict[str, str]]:
        if not self.task_queue: return None
        index = 0
        if key:
            for idx, task in enumerate(self.task_queue):
                if (task.get("key") or self._task_key(task)) == key: index = idx; break
            else: return None
        task = self.task_queue.pop(index); task_key = task.get("key") or self._task_key(task)
        if task_key: self.task_history.append(task_key); self.task_history = self.task_history[-40:]
        self._save(); return task

    def clear_tasks(self): self.task_queue = []; self._save()

    def task_summary(self, limit: int = 4) -> str:
        if not self.task_queue: return "TASK QUEUE: empty"
        lines = ["TASK QUEUE:"]
        for task in self.task_queue[:limit]:
            lines.append(f"  [{task.get('mode','task')}] {task.get('goal','task')} -> {task.get('command','')[:140]}")
        if len(self.task_queue) > limit: lines.append(f"  ... and {len(self.task_queue)-limit} more queued")
        return "\n".join(lines)

    def recommend_goal(self, model: "TargetModel", target_type: str, forced_exploit: bool, loop_sig: "LoopSignal") -> Optional[str]:
        if loop_sig.state == "hard" or self.pivot_bias == "self_debug": return "self_debug"
        if self.task_queue:
            mode = (self.task_queue[0].get("mode") or "").lower()
            if mode == "self_debug": return "self_debug"
            if mode == "validate": return "validate"
            if mode == "recon_web": return "recon_web"
            if mode == "hypothesis": return "exploit_web" if model.endpoints else "validate"
        if any((f.severity if isinstance(f, Finding) else f.get("severity", "info")) in ("critical", "high") for f in model.findings): return "validate"
        if forced_exploit:
            if any(p.get("port") in (80,443,8080,8443) for p in model.ports): return "exploit_web"
            if any(p.get("port") == 445 for p in model.ports): return "exploit_smb"
            return "validate"
        if self.pivot_bias == "validate" and model.findings: return "validate"
        if self.pivot_bias == "exploit" and any(p.get("port") in (80,443,8080,8443) for p in model.ports): return "exploit_web"
        if self.pivot_bias == "recon_web" and any(p.get("port") in (80,443,8080,8443) for p in model.ports): return "recon_web" if not model.endpoints else "exploit_web"
        if self.pivot_bias == "recon_ad" and any(p.get("port") in (389,445,3389) for p in model.ports): return "recon_ad"
        if target_type == "public_real_world" and self.pivot_bias == "exploit": return "validate" if model.findings else "recon_web"
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
        return cls(key=data.get("key", ""), goal=data.get("goal", ""), category=data.get("category", "analysis"), command=data.get("command", ""), mode=data.get("mode", "recon"), reason=data.get("reason", ""), status=data.get("status", "queued"), attempts=int(data.get("attempts", 0) or 0), evidence=data.get("evidence", ""), depends_on=list(data.get("depends_on", []) or []), created_ts=float(data.get("created_ts", 0.0) or 0.0), updated_ts=float(data.get("updated_ts", 0.0) or 0.0))

    def to_dict(self) -> dict: return asdict(self)


@dataclass
class VerificationVerdict:
    useful: bool
    accepted: bool
    reason: str = ""
    progress_delta: int = 0
    followups: List[Dict[str, str]] = field(default_factory=list)


class TaskGraph:
    def __init__(self, base_dir: Path):
        self.store = JsonFileStore(base_dir / "mission_graph.json")
        self._data = self.store.load()
        if not self._data: self._data = {"target":"", "tasks":[], "history":[], "updated_ts":0.0}
        self._normalize()
    @staticmethod
    def _task_key(task: Dict[str,str]) -> str:
        return hashlib.sha256(f"{task.get('goal','')}|{task.get('category','')}|{task.get('command','')}|{task.get('mode','')}".encode()).hexdigest()[:16]
    def _normalize(self):
        self._data["tasks"] = [MissionTask.from_dict(t).to_dict() for t in (self._data.get("tasks",[]) or []) if isinstance(t,dict)]
        self._data["history"] = list(self._data.get("history",[]) or [])[-80:]
    def _save(self): self._data["updated_ts"] = time.time(); self._normalize(); self.store.save(self._data)
    def reset(self,target): self._data={"target":target,"tasks":[],"history":[],"updated_ts":time.time()}; self._save()
    def add_tasks(self,tasks):
        if not tasks:return 0
        existing={t.get("key") for t in self._data.get("tasks",[])}; added=0
        for task in tasks:
            if not isinstance(task,dict):continue
            item=dict(task); item["key"]=item.get("key") or self._task_key(item)
            if item["key"] in existing:continue
            item.setdefault("status","queued"); item.setdefault("attempts",0); item.setdefault("created_ts",time.time()); item.setdefault("updated_ts",time.time())
            self._data.setdefault("tasks",[]).append(MissionTask.from_dict(item).to_dict()); existing.add(item["key"]); added+=1
        if added:self._save()
        return added
    def open_tasks(self): return [MissionTask.from_dict(t) for t in self._data.get("tasks",[]) if t.get("status") in ("queued","running")]
    def next_task(self):
        for task in self._data.get("tasks",[]):
            if task.get("status") != "queued": continue
            task["status"]="running"; task["attempts"]=int(task.get("attempts",0) or 0)+1; task["updated_ts"]=time.time(); self._data["history"].append({"ts":time.time(),"event":"start","key":task["key"]}); self._save(); return MissionTask.from_dict(task)
        return None
    def mark(self,key,status,evidence="",reason=""):
        for task in self._data.get("tasks",[]):
            if task.get("key") != key: continue
            task["status"]=status; task["evidence"]=evidence[:300]; task["reason"]=reason[:180]; task["updated_ts"]=time.time(); self._data["history"].append({"ts":time.time(),"event":status,"key":key,"reason":reason[:180]}); self._save(); return
    def summary(self,limit=4):
        tasks=self.open_tasks()
        if not tasks:return "MISSION GRAPH: empty"
        lines=[f"MISSION GRAPH: {len(tasks)} open task(s)"]
        for task in tasks[:limit]: lines.append(f"  [{task.mode}] {task.goal} -> {task.command[:120]}")
        if len(tasks)>limit:lines.append(f"  ... and {len(tasks)-limit} more open")
        return "\n".join(lines)
    def has_open_work(self): return any(t.get("status") in ("queued","running") for t in self._data.get("tasks",[]))


class Verifier:
    def verify_progress(self,before_size,after_size,output,command):
        delta=max(0,after_size-before_size); low=(output or "").lower()
        if delta>0:return VerificationVerdict(True,True,f"model grew by {delta}",delta)
        if not output or not output.strip():return VerificationVerdict(False,False,"empty/no output",0)
        strong=("vulnerab","exploit","inject","rce","shell","root","sql syntax","xss","ssrf","idor","lfi","rfi","credential","password","token","secret","api key","private key","flag{","ctf{","open port","service detected","discovered endpoint","endpoint","new endpoint","exposed","success","unauthorized","authenticated")
        noise=("no results","not found","404","410","403","access denied","forbidden","timeout","timed out","connection refused","could not resolve","temporary failure","no such file","0% ","0 results","finished after 0")
        medium=("status code","status:","http","response","redirect","moved permanently","found")
        has_strong=any(s in low for s in strong); has_noise=any(s in low for s in noise); has_medium=any(s in low for s in medium)
        if has_noise and not has_strong:return VerificationVerdict(False,False,"noise/dead-end (4xx/timeout/no-results)",0)
        if has_strong:return VerificationVerdict(True,True,"output contains strong evidence signals",0)
        if has_medium:return VerificationVerdict(False,False,"output lacks strong evidence (medium HTTP/status signals only)",0)
        useful=any(s in low for s in ("endpoint","credential","password","token","secret","rce","sqli","xss","flag{","ctf{","vulnerab")) and not has_noise
        return VerificationVerdict(useful,useful,"output contains useful signal" if useful else "output was noise/unclear",0)
    def verify_completion(self,all_exhausted,has_open_work,findings_count,iteration,min_iters):
        if has_open_work:return False,"mission still has open tasks"
        if not all_exhausted and iteration<min_iters and findings_count==0:return False,"mission not yet exhausted and no solid finding"
        if not all_exhausted and findings_count==0:return False,"no confirmed finding yet"
        return True,"completion accepted"


class AutoReplanner:
    def generate(self,agent,active_node,failure_reason=""):
        return []


class MissionManager:
    def __init__(self,agent): self.agent=agent; self.started_target=agent.target or ""
    def reset_for_target(self,target):
        if self.started_target and self.started_target != target:
            self.agent.mission_graph.reset(target); self.agent.autonomy_profile.clear_tasks()
        self.started_target=target
    def seed(self,active_node,failure_reason=""):
        tasks=self.agent.auto_replanner.generate(self.agent,active_node,failure_reason); added=self.agent.mission_graph.add_tasks(tasks)
        if added:self.agent.autonomy_profile.push_tasks(tasks)
        return added
    def next_task(self,active_node,failure_reason=""):
        task=self.agent.mission_graph.next_task()
        if task:self.agent.autonomy_profile.pop_task(task.key); return task
        seeded=self.seed(active_node,failure_reason)
        if seeded:
            task=self.agent.mission_graph.next_task()
            if task:self.agent.autonomy_profile.pop_task(task.key); return task
        return None
    def should_accept_completion(self,completed,all_exhausted,iteration,findings_count):
        if not completed:return False,"AI has not requested completion"
        ok,reason=self.agent.verifier.verify_completion(all_exhausted=all_exhausted,has_open_work=self.agent.mission_graph.has_open_work(),findings_count=findings_count,iteration=iteration,min_iters=CONFIG.MIN_ITERATIONS if is_bug_bounty_mode() else 15)
        return ok,reason
    def record_outcome(self,command,result,before_size,after_size,category,active_node,task=None,is_plan=False):
        output=(result.text or "") if result else ""; verdict=self.agent.verifier.verify_progress(before_size,after_size,output,command)
        if task:self.agent.mission_graph.mark(task.key,"done" if verdict.useful else "failed",evidence=output[:300],reason=verdict.reason)
        if verdict.useful:
            followups=self.agent.auto_replanner.generate(self.agent,active_node)
            if followups:
                verdict.followups=followups; self.agent.mission_graph.add_tasks(followups); self.agent.autonomy_profile.push_tasks(followups)
        if is_plan and verdict.useful:self.agent._queue_autonomy_tasks(active_node,"mission manager planned follow-ups")
        return verdict
    def summary(self):
        open_tasks=self.agent.mission_graph.open_tasks()
        if not open_tasks:return "MISSION MANAGER: no open tasks"
        head=open_tasks[0]; return f"MISSION MANAGER: {len(open_tasks)} open | next={head.goal} | mode={head.mode}"
