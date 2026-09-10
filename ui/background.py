"""Quiet background task runner for the terminal UI.

Long-running agent work is isolated from the conversation view. Worker stdout
and stderr are discarded so command/tool/provider chatter cannot flood the
operator terminal; structured task state remains available to the UI.
"""
from __future__ import annotations

import sys
import threading
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional


@dataclass
class BackgroundTask:
    id: str
    label: str
    target: str = ""
    status: str = "queued"
    started: str = ""
    finished: str = ""
    result: Any = None
    error: str = ""
    events: List[str] = field(default_factory=list)


class _QuietStream:
    """Drop worker output while preserving normal main-thread terminal output."""
    def __init__(self, original: Any, local: threading.local):
        self.original = original
        self.local = local

    def write(self, data: str) -> int:
        if getattr(self.local, "quiet", False):
            return len(data)
        return self.original.write(data)

    def flush(self) -> None:
        if not getattr(self.local, "quiet", False):
            self.original.flush()

    def isatty(self) -> bool:
        return bool(getattr(self.original, "isatty", lambda: False)())

    def __getattr__(self, name: str) -> Any:
        return getattr(self.original, name)


class BackgroundTaskManager:
    def __init__(self, max_workers: int = 2):
        self.max_workers = max_workers
        self._active = 0
        self._lock = threading.RLock()
        self._tasks: Dict[str, BackgroundTask] = {}
        self._local = threading.local()
        self._stdout = sys.stdout
        self._stderr = sys.stderr
        if not isinstance(sys.stdout, _QuietStream):
            sys.stdout = _QuietStream(sys.stdout, self._local)
        if not isinstance(sys.stderr, _QuietStream):
            sys.stderr = _QuietStream(sys.stderr, self._local)

    def start(self, label: str, fn: Callable[[], Any], *, target: str = "") -> BackgroundTask:
        with self._lock:
            running = sum(1 for t in self._tasks.values() if t.status in {"queued", "running"})
            if running >= self.max_workers:
                raise RuntimeError(f"background worker limit reached ({self.max_workers})")
            task = BackgroundTask(id=uuid.uuid4().hex[:8], label=label, target=target, status="queued")
            self._tasks[task.id] = task

        def worker() -> None:
            with self._lock:
                task.status = "running"
                task.started = datetime.utcnow().isoformat(timespec="seconds") + "Z"
                self._active += 1
            self._local.quiet = True
            try:
                task.result = fn()
                with self._lock:
                    task.status = "completed"
            except Exception as exc:
                task.error = f"{type(exc).__name__}: {exc}"
                task.events.append(traceback.format_exc(limit=3))
                with self._lock:
                    task.status = "failed"
            finally:
                self._local.quiet = False
                with self._lock:
                    task.finished = datetime.utcnow().isoformat(timespec="seconds") + "Z"
                    self._active = max(0, self._active - 1)

        threading.Thread(target=worker, name=f"x19-bg-{task.id}", daemon=True).start()
        return task

    def snapshot(self) -> List[BackgroundTask]:
        with self._lock:
            return list(self._tasks.values())

    def active(self) -> List[BackgroundTask]:
        return [t for t in self.snapshot() if t.status in {"queued", "running"}]

    def recent(self, limit: int = 8) -> List[BackgroundTask]:
        return self.snapshot()[-limit:]
