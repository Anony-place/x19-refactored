"""X19 organization event bus.

Every meaningful state transition in the organization is published here as a
real event: task lifecycle moves, agent activity observed from the runtime,
manager reports, boss audits, approval requests.

The bus is deliberately small and synchronous-safe:

* in-process listeners (the TUI gateway, the CLI status view, tests),
* a bounded, append-only persisted stream under ``X19_HOME/org/events.jsonl``
  so the audit trail survives a restart and can be replayed,
* a short in-memory ring for cheap "recent activity" projections.

Nothing in here invents events.  Callers publish what actually happened.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Sequence

__all__ = [
    "EventType",
    "OrgEvent",
    "EventBus",
    "get_event_bus",
    "reset_event_bus",
]


class EventType(str, Enum):
    """Event vocabulary for the X19 organization."""

    # --- task lifecycle ---
    TASK_CREATED = "task.created"
    TASK_PLANNED = "task.planned"
    TASK_ASSIGNED = "task.assigned"
    TASK_STARTED = "task.started"
    TASK_PROGRESS = "task.progress"
    TASK_WAITING = "task.waiting"
    TASK_BLOCKED = "task.blocked"
    TASK_UNBLOCKED = "task.unblocked"
    TASK_REVIEW_REQUIRED = "task.review_required"
    TASK_REVIEWED = "task.reviewed"
    TASK_COMPLETED = "task.completed"
    TASK_FAILED = "task.failed"
    TASK_CANCELLED = "task.cancelled"
    TASK_RETRIED = "task.retried"
    TASK_REASSIGNED = "task.reassigned"

    # --- agent activity ---
    AGENT_REGISTERED = "agent.registered"
    AGENT_STARTED = "agent.started"
    AGENT_PROGRESS = "agent.progress"
    AGENT_WAITING = "agent.waiting"
    AGENT_BLOCKED = "agent.blocked"
    AGENT_COMPLETED = "agent.completed"
    AGENT_FAILED = "agent.failed"
    AGENT_INTERRUPTED = "agent.interrupted"

    # --- organization ---
    OBJECTIVE_ACCEPTED = "objective.accepted"
    MANAGER_REPORT = "manager.report"
    BOSS_AUDIT = "boss.audit"
    WORKFLOW_COMPLETED = "workflow.completed"
    ESCALATION = "escalation"

    # --- human authority ---
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_RESOLVED = "approval.resolved"
    OPERATOR_PAUSE = "operator.pause"
    OPERATOR_RESUME = "operator.resume"
    OPERATOR_STOP = "operator.stop"


@dataclass(frozen=True)
class OrgEvent:
    """One observed fact about the organization."""

    seq: int
    ts: float
    type: EventType
    message: str = ""
    task_id: Optional[str] = None
    parent_task_id: Optional[str] = None
    agent_id: Optional[str] = None
    role_id: Optional[str] = None
    manager_id: Optional[str] = None
    objective_id: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["type"] = self.type.value
        return d

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "OrgEvent":
        data = dict(raw)
        data["type"] = EventType(data.get("type", EventType.TASK_PROGRESS.value))
        data.setdefault("payload", {})
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})

    @property
    def iso_ts(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(self.ts)) + "Z"


Listener = Callable[[OrgEvent], None]

_DEFAULT_RING = 500
_DEFAULT_PERSIST = 2000


def _default_root() -> Optional[Path]:
    """``X19_HOME/org`` resolved through the real config layer, or None."""
    try:
        from x19_cli.config import get_x19_home

        return Path(get_x19_home()) / "org"
    except Exception:
        home = os.environ.get("X19_HOME")
        if home:
            return Path(home) / "org"
        return None


class EventBus:
    """Publish/subscribe plus a bounded persisted event stream."""

    def __init__(
        self,
        *,
        persist_dir: Optional[Path] = None,
        ring_size: int = _DEFAULT_RING,
        persist_limit: int = _DEFAULT_PERSIST,
        persist: bool = True,
    ) -> None:
        self._lock = threading.RLock()
        self._listeners: List[Listener] = []
        self._ring: Deque[OrgEvent] = deque(maxlen=max(1, ring_size))
        self._seq = 0
        self._persist = persist
        self._persist_limit = max(0, persist_limit)
        self._persist_dir = persist_dir
        self._persist_path: Optional[Path] = None
        if persist:
            self._load_tail()

    # -- persistence ------------------------------------------------------
    @property
    def persist_path(self) -> Optional[Path]:
        if self._persist_path is None and self._persist:
            root = self._persist_dir or _default_root()
            if root is not None:
                self._persist_path = root / "events.jsonl"
        return self._persist_path

    def _load_tail(self) -> None:
        path = self.persist_path
        if path is None or not path.exists():
            return
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return
        for line in lines[-self._ring.maxlen:]:  # type: ignore[union-attr]
            line = line.strip()
            if not line:
                continue
            try:
                ev = OrgEvent.from_dict(json.loads(line))
            except Exception:
                continue
            self._ring.append(ev)
            self._seq = max(self._seq, ev.seq)

    def _append_persisted(self, event: OrgEvent) -> None:
        path = self.persist_path
        if path is None or not self._persist_limit:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
        except OSError:
            return

    # -- subscription -----------------------------------------------------
    def subscribe(self, listener: Listener) -> Callable[[], None]:
        """Register *listener*; returns an unsubscribe callable."""
        with self._lock:
            self._listeners.append(listener)

        def _unsub() -> None:
            with self._lock:
                if listener in self._listeners:
                    self._listeners.remove(listener)

        return _unsub

    # -- publishing -------------------------------------------------------
    def publish(
        self,
        event_type: EventType,
        message: str = "",
        *,
        task_id: Optional[str] = None,
        parent_task_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        role_id: Optional[str] = None,
        manager_id: Optional[str] = None,
        objective_id: Optional[str] = None,
        **payload: Any,
    ) -> OrgEvent:
        with self._lock:
            self._seq += 1
            event = OrgEvent(
                seq=self._seq,
                ts=time.time(),
                type=event_type,
                message=message,
                task_id=task_id,
                parent_task_id=parent_task_id,
                agent_id=agent_id,
                role_id=role_id,
                manager_id=manager_id,
                objective_id=objective_id,
                payload={k: v for k, v in payload.items() if v is not None},
            )
            self._ring.append(event)
            listeners = list(self._listeners)
        self._append_persisted(event)
        for fn in listeners:
            try:
                fn(event)
            except Exception:  # a broken listener must never break the runtime
                continue
        return event

    # -- projection -------------------------------------------------------
    def recent(self, limit: int = 25, *, types: Optional[Iterable[EventType]] = None) -> List[OrgEvent]:
        wanted = set(types) if types else None
        with self._lock:
            items = list(self._ring)
        if wanted:
            items = [e for e in items if e.type in wanted]
        return items[-limit:]

    def for_task(self, task_id: str, limit: int = 50) -> List[OrgEvent]:
        with self._lock:
            items = [e for e in self._ring if e.task_id == task_id]
        return items[-limit:]

    def for_agent(self, agent_id: str, limit: int = 50) -> List[OrgEvent]:
        with self._lock:
            items = [e for e in self._ring if e.agent_id == agent_id]
        return items[-limit:]

    def counts_by_type(self) -> Dict[str, int]:
        with self._lock:
            items = list(self._ring)
        out: Dict[str, int] = {}
        for e in items:
            out[e.type.value] = out.get(e.type.value, 0) + 1
        return out

    @property
    def last_seq(self) -> int:
        with self._lock:
            return self._seq

    def clear(self) -> None:
        with self._lock:
            self._ring.clear()
            self._seq = 0


_BUS: Optional[EventBus] = None
_BUS_LOCK = threading.Lock()


def get_event_bus() -> EventBus:
    """Process-wide event bus."""
    global _BUS
    with _BUS_LOCK:
        if _BUS is None:
            _BUS = EventBus()
        return _BUS


def reset_event_bus(bus: Optional[EventBus] = None) -> EventBus:
    """Replace the process-wide bus (tests, profile switches)."""
    global _BUS
    with _BUS_LOCK:
        _BUS = bus if bus is not None else EventBus()
        return _BUS
