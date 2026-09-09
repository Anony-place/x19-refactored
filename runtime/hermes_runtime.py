"""Hermes-inspired runtime capabilities for X19.

This module deliberately stays independent of the pentest engines. It provides
platform capabilities that make X19 feel like a persistent agent rather than a
single assessment script:

* Skills are procedural memory stored as Markdown and can be promoted from
  successful mission outcomes.
* SessionRecall builds a small SQLite FTS5 index over X19 session JSON files.
* SubagentPool runs isolated reasoning workers in parallel. Workers receive
  only the supplied goal/context and a private workspace; they do not share
  persistent memory or scheduling side effects.
* CronStore persists one-shot/interval jobs. The CLI daemon executes only
  explicitly allow-listed X19 commands, never arbitrary shell strings.

Security work remains governed by X19's existing ScopeGuard, PolicyEngine,
engagement profiles and verification gates.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from config import CONFIG, CONFIG_DIR


# ---------------------------------------------------------------------------
# Skills / procedural memory
# ---------------------------------------------------------------------------

_SKILL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")


@dataclass
class Skill:
    name: str
    description: str
    body: str
    source: str = "x19"
    version: str = "1.0.0"
    updated_at: float = field(default_factory=time.time)
    uses: int = 0
    successes: int = 0
    failures: int = 0


class SkillStore:
    """Persistent procedural memory compatible with simple SKILL.md files."""

    def __init__(self, root: Optional[str] = None):
        self.root = Path(root or (CONFIG_DIR / "skills")).expanduser()
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    @staticmethod
    def _safe_name(name: str) -> str:
        value = str(name or "").strip().lower()
        if not _SKILL_NAME_RE.fullmatch(value):
            raise ValueError("skill name must match [a-z0-9][a-z0-9._-]{1,63}")
        return value

    def _path(self, name: str) -> Path:
        return self.root / self._safe_name(name) / "SKILL.md"

    @staticmethod
    def _render(skill: Skill) -> str:
        return (
            "---\n"
            f"name: {skill.name}\n"
            f"description: {skill.description.replace(chr(10), ' ')}\n"
            f"source: {skill.source}\n"
            f"version: {skill.version}\n"
            f"updated_at: {skill.updated_at:.3f}\n"
            f"uses: {skill.uses}\n"
            f"successes: {skill.successes}\n"
            f"failures: {skill.failures}\n"
            "---\n\n"
            f"{skill.body.rstrip()}\n"
        )

    @staticmethod
    def _parse(path: Path) -> Optional[Skill]:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return None
        if text.startswith("---"):
            _, front, body = text.split("---", 2)
            meta: Dict[str, str] = {}
            for line in front.splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    meta[key.strip()] = value.strip()
            name = meta.get("name") or path.parent.name
            return Skill(
                name=name,
                description=meta.get("description", ""),
                body=body.lstrip("\n"),
                source=meta.get("source", "x19"),
                version=meta.get("version", "1.0.0"),
                updated_at=float(meta.get("updated_at", path.stat().st_mtime)),
                uses=int(meta.get("uses", 0)),
                successes=int(meta.get("successes", 0)),
                failures=int(meta.get("failures", 0)),
            )
        return Skill(name=path.parent.name, description="", body=text)

    def list(self) -> List[Skill]:
        with self._lock:
            result = []
            for path in sorted(self.root.glob("*/SKILL.md")):
                skill = self._parse(path)
                if skill:
                    result.append(skill)
            return sorted(result, key=lambda s: (-s.successes, -s.uses, s.name))

    def get(self, name: str) -> Optional[Skill]:
        with self._lock:
            path = self._path(name)
            return self._parse(path) if path.exists() else None

    def search(self, query: str, limit: int = 8) -> List[Skill]:
        terms = [t.lower() for t in re.findall(r"[a-z0-9_-]+", query or "")]
        if not terms:
            return self.list()[:limit]
        scored = []
        for skill in self.list():
            hay = f"{skill.name} {skill.description} {skill.body}".lower()
            score = sum(hay.count(term) for term in terms)
            if score:
                scored.append((score + skill.successes * 0.25, skill))
        scored.sort(key=lambda item: (-item[0], item[1].name))
        return [skill for _, skill in scored[:limit]]

    def save(self, skill: Skill) -> Skill:
        skill.name = self._safe_name(skill.name)
        skill.updated_at = time.time()
        path = self._path(skill.name)
        with self._lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(self._render(skill), encoding="utf-8")
        return skill

    def create(self, name: str, description: str, body: str, *, source: str = "user") -> Skill:
        if self.get(name):
            raise FileExistsError(f"skill already exists: {name}")
        return self.save(Skill(name=self._safe_name(name), description=description, body=body, source=source))

    def record_use(self, name: str, success: bool) -> Optional[Skill]:
        skill = self.get(name)
        if not skill:
            return None
        skill.uses += 1
        if success:
            skill.successes += 1
        else:
            skill.failures += 1
        return self.save(skill)

    def promote_outcome(
        self,
        *,
        name: str,
        target_type: str,
        summary: str,
        successful_steps: Sequence[str],
        failed_steps: Sequence[str] = (),
    ) -> Skill:
        """Create/update procedural memory from a completed mission.

        This is intentionally a promotion step, not automatic source-code
        mutation: learned behavior becomes a reviewable skill file first.
        """
        existing = self.get(name)
        steps = "\n".join(f"{i + 1}. {step}" for i, step in enumerate(successful_steps))
        failures = "\n".join(f"- {step}" for step in failed_steps) or "- none recorded"
        body = (
            f"# {name}\n\n"
            f"Target class: `{target_type}`\n\n"
            f"## Outcome\n{summary.strip()}\n\n"
            f"## Reusable approach\n{steps or 'No reusable steps recorded.'}\n\n"
            f"## Avoid\n{failures}\n\n"
            "## Safety\n"
            "Reuse only inside an engagement whose ScopeGuard and rules of engagement permit the action.\n"
        )
        if existing:
            existing.body = body
            existing.description = f"Learned workflow for {target_type} security assessments"
            existing.source = "mission-learning"
            return self.save(existing)
        return self.save(
            Skill(
                name=self._safe_name(name),
                description=f"Learned workflow for {target_type} security assessments",
                body=body,
                source="mission-learning",
            )
        )


# ---------------------------------------------------------------------------
# Session recall
# ---------------------------------------------------------------------------

class SessionRecall:
    """FTS5-backed search over stored X19 sessions."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path or (CONFIG_DIR / "session_index.db")).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS sessions ("
                "session_id TEXT PRIMARY KEY, target TEXT, started TEXT, status TEXT, "
                "content TEXT NOT NULL, path TEXT NOT NULL, indexed_at REAL NOT NULL)"
            )
            conn.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS sessions_fts USING fts5("
                "session_id UNINDEXED, target, content, content='sessions', content_rowid='rowid')"
            )
            conn.execute(
                "CREATE TRIGGER IF NOT EXISTS sessions_ai AFTER INSERT ON sessions BEGIN "
                "INSERT INTO sessions_fts(rowid, session_id, target, content) VALUES (new.rowid,new.session_id,new.target,new.content); END"
            )
            conn.execute(
                "CREATE TRIGGER IF NOT EXISTS sessions_ad AFTER DELETE ON sessions BEGIN "
                "INSERT INTO sessions_fts(sessions_fts,rowid,session_id,target,content) VALUES('delete',old.rowid,old.session_id,old.target,old.content); END"
            )

    def index(self, *, force: bool = False) -> int:
        directory = Path(CONFIG.SESSIONS_DIR).expanduser()
        if not directory.exists():
            return 0
        count = 0
        with self._lock, self._connect() as conn:
            for path in directory.glob("*.json"):
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except Exception:
                    continue
                sid = str(data.get("session_id", path.stem))
                stat = path.stat()
                if not force:
                    row = conn.execute("SELECT indexed_at FROM sessions WHERE session_id=?", (sid,)).fetchone()
                    if row and float(row[0]) >= stat.st_mtime:
                        continue
                content = json.dumps(data, ensure_ascii=False, sort_keys=True, default=str)
                conn.execute("DELETE FROM sessions WHERE session_id=?", (sid,))
                conn.execute(
                    "INSERT INTO sessions(session_id,target,started,status,content,path,indexed_at) VALUES(?,?,?,?,?,?,?)",
                    (sid, str(data.get("target", "")), str(data.get("started", "")), str(data.get("status", "")), content, str(path), stat.st_mtime),
                )
                count += 1
        return count

    def search(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        self.index()
        with self._connect() as conn:
            try:
                rows = conn.execute(
                    "SELECT s.session_id,s.target,s.started,s.status,s.path,bm25(sessions_fts) AS rank "
                    "FROM sessions_fts JOIN sessions s ON s.rowid=sessions_fts.rowid "
                    "WHERE sessions_fts MATCH ? ORDER BY rank LIMIT ?",
                    (query, int(limit)),
                ).fetchall()
            except sqlite3.OperationalError:
                # FTS query syntax is user input; fall back to a safe LIKE query.
                needle = f"%{query}%"
                rows = conn.execute(
                    "SELECT session_id,target,started,status,path,0 AS rank FROM sessions "
                    "WHERE content LIKE ? OR target LIKE ? ORDER BY indexed_at DESC LIMIT ?",
                    (needle, needle, int(limit)),
                ).fetchall()
        return [dict(row) for row in rows]

    def read(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT content FROM sessions WHERE session_id=?", (session_id,)).fetchone()
        if not row:
            self.index()
            with self._connect() as conn:
                row = conn.execute("SELECT content FROM sessions WHERE session_id=?", (session_id,)).fetchone()
        if not row:
            return None
        try:
            return json.loads(row[0])
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Isolated reasoning subagents
# ---------------------------------------------------------------------------

@dataclass
class SubagentResult:
    id: str
    goal: str
    status: str
    summary: str = ""
    error: str = ""
    elapsed: float = 0.0
    workspace: str = ""


class SubagentPool:
    """Hermes-style isolated reasoning workers.

    Workers receive fresh context and a private directory. They do not get
    access to persistent memory, cron, or the parent conversation unless the
    caller explicitly supplies that information in ``context``.
    """

    def __init__(self, ai: Any = None, root: Optional[str] = None, max_workers: int = 3):
        self.ai = ai
        self.root = Path(root or (CONFIG_DIR / "subagents")).expanduser()
        self.root.mkdir(parents=True, exist_ok=True)
        self.max_workers = max(1, int(max_workers))

    def _worker(self, goal: str, context: str = "", *, role: str = "leaf", max_iterations: int = 12) -> SubagentResult:
        started = time.time()
        sid = uuid.uuid4().hex[:12]
        workspace = self.root / sid
        workspace.mkdir(parents=True, exist_ok=True)
        prompt = (
            "You are an isolated X19 subagent.\n"
            f"Role: {role}\n"
            f"Goal: {goal}\n"
            f"Context supplied by parent:\n{context}\n\n"
            "Work only on this goal. Do not assume unseen context. Do not claim commands, "
            "network results, or findings you did not actually observe. Return a concise "
            "handoff summary with: result, evidence, uncertainty, and recommended next step."
        )
        try:
            if self.ai is None:
                return SubagentResult(sid, goal, "failed", error="no AI provider", workspace=str(workspace))
            reply = self.ai.chat(prompt, f"subagent:{sid}")
            return SubagentResult(
                id=sid,
                goal=goal,
                status="completed" if reply else "failed",
                summary=str(reply or "").strip(),
                error="" if reply else "empty model response",
                elapsed=time.time() - started,
                workspace=str(workspace),
            )
        except Exception as exc:
            return SubagentResult(
                id=sid, goal=goal, status="failed", error=f"{type(exc).__name__}: {exc}",
                elapsed=time.time() - started, workspace=str(workspace),
            )

    def run_parallel(self, tasks: Sequence[Dict[str, Any]], max_workers: Optional[int] = None) -> List[SubagentResult]:
        workers = max(1, min(int(max_workers or self.max_workers), len(tasks) or 1))
        results: List[SubagentResult] = []
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="x19-subagent") as pool:
            futures = [
                pool.submit(
                    self._worker,
                    str(task.get("goal", "")),
                    str(task.get("context", "")),
                    role=str(task.get("role", "leaf")),
                    max_iterations=int(task.get("max_iterations", 12) or 12),
                )
                for task in tasks
                if str(task.get("goal", "")).strip()
            ]
            for future in as_completed(futures):
                results.append(future.result())
        return results


# ---------------------------------------------------------------------------
# Durable cron definitions
# ---------------------------------------------------------------------------

@dataclass
class CronJob:
    id: str
    command: List[str]
    interval_seconds: int
    next_run: float
    enabled: bool = True
    repeat: int = 0
    runs: int = 0
    last_status: str = ""
    last_output: str = ""
    created_at: float = field(default_factory=time.time)


_ALLOWED_CRON_COMMANDS = {"doctor", "tools", "report", "run"}


class CronStore:
    """Persistent job store + optional daemon for allow-listed X19 commands."""

    def __init__(self, path: Optional[str] = None):
        self.path = Path(path or (CONFIG_DIR / "cron_jobs.json")).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._stop = threading.Event()

    def _load(self) -> List[CronJob]:
        if not self.path.exists():
            return []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return [CronJob(**item) for item in data.get("jobs", [])]
        except Exception:
            return []

    def _save(self, jobs: Iterable[CronJob]) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"jobs": [asdict(j) for j in jobs]}, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    @staticmethod
    def _validate(command: Sequence[str]) -> List[str]:
        parts = [str(x) for x in command if str(x).strip()]
        if not parts or parts[0] not in _ALLOWED_CRON_COMMANDS:
            raise ValueError(f"cron command must start with one of: {', '.join(sorted(_ALLOWED_CRON_COMMANDS))}")
        if any(x in {"--shell", "--exec", "-c"} for x in parts):
            raise ValueError("shell execution is not allowed in cron jobs")
        return parts

    def list(self) -> List[CronJob]:
        with self._lock:
            return self._load()

    def add(self, command: Sequence[str], interval_seconds: int, *, repeat: int = 0) -> CronJob:
        command = self._validate(command)
        interval_seconds = max(60, int(interval_seconds))
        job = CronJob(
            id=uuid.uuid4().hex[:12],
            command=command,
            interval_seconds=interval_seconds,
            next_run=time.time() + interval_seconds,
            repeat=max(0, int(repeat)),
        )
        with self._lock:
            jobs = self._load()
            jobs.append(job)
            self._save(jobs)
        return job

    def remove(self, job_id: str) -> bool:
        with self._lock:
            jobs = self._load()
            kept = [j for j in jobs if j.id != job_id]
            if len(kept) == len(jobs):
                return False
            self._save(kept)
            return True

    def pause(self, job_id: str) -> bool:
        return self._set_enabled(job_id, False)

    def resume(self, job_id: str) -> bool:
        return self._set_enabled(job_id, True)

    def _set_enabled(self, job_id: str, enabled: bool) -> bool:
        with self._lock:
            jobs = self._load()
            changed = False
            for job in jobs:
                if job.id == job_id:
                    job.enabled = enabled
                    if enabled:
                        job.next_run = time.time() + job.interval_seconds
                    changed = True
                    break
            if changed:
                self._save(jobs)
            return changed

    def run_due(self, *, cwd: Optional[str] = None) -> List[CronJob]:
        now = time.time()
        due: List[CronJob] = []
        with self._lock:
            jobs = self._load()
            for job in jobs:
                if not job.enabled or job.next_run > now:
                    continue
                due.append(job)
                job.runs += 1
                try:
                    proc = subprocess.run(
                        [sys.executable, "-m", "x19", *job.command],
                        cwd=cwd or str(Path(__file__).resolve().parent.parent),
                        capture_output=True,
                        text=True,
                        timeout=max(60, min(job.interval_seconds, 3600)),
                        env={**os.environ, "X19_CRON_JOB": job.id},
                    )
                    job.last_status = "ok" if proc.returncode == 0 else f"exit:{proc.returncode}"
                    job.last_output = (proc.stdout + proc.stderr)[-4000:]
                except Exception as exc:
                    job.last_status = f"error:{type(exc).__name__}"
                    job.last_output = str(exc)[-4000:]
                if job.repeat and job.runs >= job.repeat:
                    job.enabled = False
                else:
                    job.next_run = now + job.interval_seconds
            self._save(jobs)
        return due

    def daemon(self, *, cwd: Optional[str] = None, poll_seconds: int = 5) -> None:
        """Run persisted jobs until interrupted. Designed for `x19 cron daemon`."""
        self._stop.clear()
        while not self._stop.is_set():
            self.run_due(cwd=cwd)
            self._stop.wait(max(1, int(poll_seconds)))

    def stop(self) -> None:
        self._stop.set()


__all__ = ["Skill", "SkillStore", "SessionRecall", "SubagentResult", "SubagentPool", "CronJob", "CronStore"]
