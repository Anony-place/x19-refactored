"""Event-driven runtime primitives for X19.

This module deliberately stays independent from X19's large agent implementation.
It provides a persistent session state machine and a background supervisor that can
host the existing agent loop while the control/UI layer remains responsive.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from threading import Event, RLock, Thread
from time import monotonic
from typing import Any, Callable, Dict, Optional


class AgentState(str, Enum):
    IDLE = "IDLE"
    THINKING = "THINKING"
    WAITING_FOR_TOOL = "WAITING_FOR_TOOL"
    TOOL_RUNNING = "TOOL_RUNNING"
    OBSERVING = "OBSERVING"
    DECIDING = "DECIDING"
    WAITING_FOR_USER = "WAITING_FOR_USER"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    STOPPED = "STOPPED"


@dataclass
class RuntimeSnapshot:
    state: AgentState = AgentState.IDLE
    target: str = ""
    step: int = 0
    objective: str = ""
    message: str = ""
    started_at: float = 0.0
    updated_at: float = field(default_factory=monotonic)
    error: str = ""


class AgentRuntime:
    """Persistent lifecycle wrapper around an X19 assessment session.

    The wrapped callable remains responsible for the actual assessment logic.
    Runtime owns lifecycle, cancellation, state transitions and a small event
    stream so the UI does not need to parse terminal output to know what the
    agent is doing.
    """

    def __init__(self, agent: Any):
        self.agent = agent
        self._stop = Event()
        self._lock = RLock()
        self._thread: Optional[Thread] = None
        self._snapshot = RuntimeSnapshot()
        self._events: list[Dict[str, Any]] = []
        self._seq = 0

    @property
    def running(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    def snapshot(self) -> RuntimeSnapshot:
        with self._lock:
            s = self._snapshot
            return RuntimeSnapshot(**s.__dict__)

    def events(self, since: int = 0) -> list[Dict[str, Any]]:
        with self._lock:
            return [dict(e) for e in self._events if e["seq"] > since]

    def transition(self, state: AgentState, message: str = "", **extra: Any) -> None:
        with self._lock:
            self._seq += 1
            now = monotonic()
            self._snapshot.state = state
            self._snapshot.message = message
            self._snapshot.updated_at = now
            for key in ("target", "objective", "step", "error"):
                if key in extra:
                    setattr(self._snapshot, key, extra[key])
            self._events.append({
                "seq": self._seq,
                "state": state.value,
                "message": message,
                "timestamp": now,
                **extra,
            })
            if len(self._events) > 500:
                del self._events[:-500]

    def start(self, target: str, worker: Optional[Callable[[], Any]] = None) -> bool:
        """Start one persistent session in the background.

        Returns False when a session is already active. The worker is normally
        X19's existing autonomous entry point; this wrapper intentionally does
        not duplicate tool execution logic.
        """
        with self._lock:
            if self.running:
                return False
            self._stop.clear()
            self._snapshot = RuntimeSnapshot(
                state=AgentState.THINKING,
                target=target,
                started_at=monotonic(),
                updated_at=monotonic(),
            )
            self._events.clear()
            self._seq = 0

            fn = worker or (lambda: self.agent.autonomous_loop(target))
            self._thread = Thread(target=self._run, args=(fn, target), daemon=True, name="x19-agent")
            self._thread.start()
            return True

    def _run(self, worker: Callable[[], Any], target: str) -> None:
        self.transition(AgentState.THINKING, "Agent session started", target=target)
        try:
            worker()
            if self._stop.is_set():
                self.transition(AgentState.STOPPED, "Stopped by user", target=target)
            else:
                self.transition(AgentState.COMPLETED, "Assessment session ended", target=target)
        except Exception as exc:
            self.transition(AgentState.FAILED, "Agent runtime failed", target=target, error=str(exc))
        finally:
            try:
                self.agent.running = False
            except Exception:
                pass

    def stop(self) -> bool:
        """Request cooperative cancellation and wake the wrapped agent."""
        if not self.running:
            return False
        self._stop.set()
        try:
            self.agent.stop = True
            self.agent.running = False
        except Exception:
            pass
        self.transition(AgentState.STOPPED, "Stop requested")
        return True

    def wait(self, timeout: Optional[float] = None) -> bool:
        thread = self._thread
        if thread is None:
            return True
        thread.join(timeout)
        return not thread.is_alive()


def install_runtime(agent: Any) -> AgentRuntime:
    """Attach one runtime object to an X19 instance without changing its API."""
    runtime = getattr(agent, "runtime", None)
    if isinstance(runtime, AgentRuntime):
        return runtime
    runtime = AgentRuntime(agent)
    agent.runtime = runtime
    return runtime
