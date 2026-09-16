"""Quiet background task runner for the terminal UI.

Long-running agent work (assessments, scans, provider probing) is isolated
from the conversation view so the operator can keep typing while the agent
works. Worker chatter never floods the terminal — it is captured per task and
can be inspected on demand (``/tasks log <id>`` inside the app).

Everything tunable comes from the environment / config:

* ``X19_BG_WORKERS`` (config ``BG_WORKERS``) — max concurrent tasks
* ``X19_TASK_LOG_LINES``                       — per-task output ring size
"""
from __future__ import annotations

import os
import sys
import threading
import time
import traceback
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, List, Optional

#: Last-resort concurrency cap when nothing is configured anywhere.
DEFAULT_MAX_WORKERS = 2
DEFAULT_LOG_LINES = 400

ACTIVE_STATES = ("queued", "running")
FINISHED_STATES = ("completed", "failed", "cancelled")

#: The manager whose thread-local capture state decides whether a write from
#: the calling thread reaches the terminal. Set on construction; the prompt's
#: output guard asks this before repainting itself around a foreign write.
_current_manager: Optional["BackgroundTaskManager"] = None


def output_is_captured() -> bool:
    """True when the *calling thread's* stdout/stderr writes are captured.

    Background worker output goes into the task ring buffer instead of the
    terminal, so the terminal UI must not redraw anything for it.
    """
    manager = _current_manager
    if manager is None:
        return False
    try:
        return getattr(manager._local, "task", None) is not None
    except Exception:
        return False


def _env_int(name: str, fallback: int) -> int:
    try:
        value = int(os.getenv(name, "").strip() or "")
        return value if value > 0 else fallback
    except (TypeError, ValueError):
        return fallback


def _configured_workers() -> int:
    env = _env_int("X19_BG_WORKERS", 0)
    if env:
        return env
    try:  # optional config key; absent on stripped installs
        from config import load_config

        configured = int(load_config().get("BG_WORKERS", 0) or 0)
        if configured > 0:
            return configured
    except Exception:
        pass
    return DEFAULT_MAX_WORKERS


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds") + "Z"


@dataclass
class BackgroundTask:
    """One unit of agent work executed off the UI thread."""

    id: str
    label: str
    target: str = ""
    status: str = "queued"
    started: str = ""
    finished: str = ""
    result: Any = None
    error: str = ""
    #: captured worker output, one entry per line (ring buffer)
    output: Deque[str] = field(default_factory=lambda: deque(maxlen=DEFAULT_LOG_LINES))
    #: last meaningful activity line — surfaced by the live status ribbon
    note: str = ""
    #: monotonic timestamps so elapsed works without parsing ISO strings
    _t0: float = 0.0
    _t1: float = 0.0
    _callbacks: List[Callable[["BackgroundTask"], None]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _thread: Optional[threading.Thread] = None

    def elapsed(self) -> float:
        if not self._t0:
            return 0.0
        return (self._t1 or time.time()) - self._t0

    def join(self, timeout: Optional[float] = None) -> None:
        """Wait for the task to finish (mainly for tests/programmatic use)."""
        thread = self._thread
        if thread is not None:
            thread.join(timeout)

    def tail(self, count: int = 20) -> List[str]:
        with self._lock:
            return list(self.output)[-max(1, count):]

    @property
    def active(self) -> bool:
        return self.status in ACTIVE_STATES

    def summary(self) -> Dict[str, Any]:
        """Plain data about the task — for tables, ribbons and JSON output."""
        return {
            "id": self.id,
            "label": self.label,
            "target": self.target,
            "status": self.status,
            "elapsed": round(self.elapsed(), 1),
            "note": self.note,
            "error": self.error,
            "lines": len(self.output),
            "started": self.started,
            "finished": self.finished,
        }


class _QuietStream:
    """Thread-aware stdout/stderr wrapper.

    Main-thread writes pass straight through. Background-worker writes are
    captured into the worker task's ring buffer so nothing is lost (it can be
    replayed with ``/tasks log``) while the operator's terminal stays clean.
    """

    def __init__(self, original: Any, local: "threading.local"):
        self.original = original
        self.local = local

    # -- capture -----------------------------------------------------------
    def _capture(self, data: str) -> None:
        task: Optional[BackgroundTask] = getattr(self.local, "task", None)
        if task is None:
            return
        lines = str(data).splitlines()
        if not lines:
            return
        with task._lock:
            task.output.extend(lines)
            last = lines[-1].strip()
            if last and not last.startswith(("[GATEWAY", "$ ")):
                task.note = last[:120]

    def write(self, data: str) -> int:
        if getattr(self.local, "task", None) is not None:
            self._capture(data)
            return len(data)
        return self.original.write(data)

    def flush(self) -> None:
        if getattr(self.local, "task", None) is None:
            self.original.flush()

    def isatty(self) -> bool:
        return bool(getattr(self.original, "isatty", lambda: False)())

    def __getattr__(self, name: str) -> Any:
        return getattr(self.original, name)


class BackgroundTaskManager:
    """Runs agent work on daemon threads, with live, inspectable state."""

    def __init__(self, max_workers: Optional[int] = None):
        global _current_manager
        self.max_workers = int(max_workers) if max_workers else _configured_workers()
        self._lock = threading.RLock()
        self._tasks: Dict[str, BackgroundTask] = {}
        self._local = threading.local()
        self._stdout = sys.stdout
        self._stderr = sys.stderr
        if not isinstance(sys.stdout, _QuietStream):
            sys.stdout = _QuietStream(sys.stdout, self._local)
        if not isinstance(sys.stderr, _QuietStream):
            sys.stderr = _QuietStream(sys.stderr, self._local)
        _current_manager = self

    # -- lifecycle -----------------------------------------------------------
    def start(
        self,
        label: str,
        fn: Callable[[], Any],
        *,
        target: str = "",
        on_done: Optional[Callable[["BackgroundTask"], None]] = None,
    ) -> BackgroundTask:
        """Run ``fn`` on a worker thread. Raises when the worker pool is full."""
        with self._lock:
            running = sum(1 for t in self._tasks.values() if t.status in ACTIVE_STATES)
            if running >= self.max_workers:
                raise RuntimeError(f"background worker limit reached ({self.max_workers})")
            task = BackgroundTask(
                id=uuid.uuid4().hex[:8],
                label=label,
                target=target,
                status="queued",
                _t0=time.time(),
            )
            if on_done is not None:
                task._callbacks.append(on_done)
            self._tasks[task.id] = task

        def worker() -> None:
            with self._lock:
                task.status = "running"
                task.started = utcnow_iso()
            self._local.task = task
            try:
                task.result = fn()
                with self._lock:
                    task.status = "completed"
            except KeyboardInterrupt:
                task.error = "interrupted"
                with self._lock:
                    task.status = "cancelled"
            except Exception as exc:
                task.error = f"{type(exc).__name__}: {exc}"
                with task._lock:
                    task.output.extend(traceback.format_exc(limit=3).splitlines())
                with self._lock:
                    task.status = "failed"
            finally:
                self._local.task = None
                task._t1 = time.time()
                with self._lock:
                    task.finished = utcnow_iso()
                for callback in list(task._callbacks):
                    try:
                        callback(task)
                    except Exception:
                        pass

        thread = threading.Thread(target=worker, name=f"x19-bg-{task.id}", daemon=True)
        task._thread = thread
        thread.start()
        return task

    # -- introspection -------------------------------------------------------
    def snapshot(self) -> List[BackgroundTask]:
        with self._lock:
            return list(self._tasks.values())

    def get(self, task_id: str) -> Optional[BackgroundTask]:
        for task in self.snapshot():
            if task.id == task_id or task_id.startswith(task.id):
                return task
        return None

    def active(self) -> List[BackgroundTask]:
        return [t for t in self.snapshot() if t.status in ACTIVE_STATES]

    def recent(self, limit: int = 8) -> List[BackgroundTask]:
        return self.snapshot()[-limit:]

    def recently_finished(self) -> List[BackgroundTask]:
        return [t for t in self.snapshot() if t.status in FINISHED_STATES]

    def drain_notifications(self) -> List[BackgroundTask]:
        """Pop finished tasks that the UI has not yet reported."""
        reported: List[BackgroundTask] = []
        with self._lock:
            for task in self.snapshot():
                if task.status in FINISHED_STATES and not getattr(task, "_notified", False):
                    task._notified = True
                    reported.append(task)
        return reported

    # -- structured agent events ---------------------------------------------
    def attach_events(self, task: "BackgroundTask", bus: Any) -> None:
        """Pipe an :class:`~events.AgentEventBus` into ``task``.

        The bus queues events; the UI drains them each prompt poll so agent
        work (commands run, findings verified) appears live in the transcript
        without anyone scraping stdout.
        """
        try:
            token, q = bus.subscribe()
        except Exception:
            return
        task._event_token = token
        task._event_bus = bus
        task._event_q = q

    def drain_events(self, task: "BackgroundTask", limit: int = 20) -> List[Any]:
        """Pop pending events for a task (oldest first, bounded per poll)."""
        q = getattr(task, "_event_q", None)
        if q is None:
            return []
        events: List[Any] = []
        while len(events) < limit:
            try:
                events.append(q.get_nowait())
            except Exception:
                break
        return events

    # -- ribbon ---------------------------------------------------------------
    def status_text(self, width: int = 80) -> str:
        """One compact line describing background work (for the live ribbon)."""
        active = self.active()
        if not active:
            return ""
        parts = []
        for task in active[:2]:
            parts.append(f"● {task.label} {time.strftime('%H:%M:%S', time.gmtime(task.elapsed()))}")
        if len(active) > 2:
            parts.append(f"+{len(active) - 2} more")
        text = "  ".join(parts)
        return text if len(text) <= width else text[: width - 1] + "…"
