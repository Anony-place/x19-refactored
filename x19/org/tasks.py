"""X19 task model: a real lifecycle backed by real runtime state.

Phases and statuses are not labels painted on top of the delegation engine —
every transition is triggered by something that actually happened (a dispatch
was accepted, a child started, a child returned a result, a dependency cleared,
an operator paused the run) and every transition emits an event.

Lifecycle::

    QUEUED -> PLANNED -> ASSIGNED -> RUNNING -> IN_REVIEW -> COMPLETED
                                     |    ^         |
                                     v    |         v
                                  BLOCKED/WAITING  FAILED -> (retry) QUEUED
                                     |
                                     v
                                 CANCELLED

Progress is reported as **phase + elapsed + observed notes**, never as an
invented percentage.  If the runtime has not told us anything, the task says so.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .events import EventBus, EventType

__all__ = [
    "TaskPhase",
    "TaskStatus",
    "TaskPriority",
    "ReviewState",
    "TaskMetrics",
    "Task",
    "TaskStore",
    "TERMINAL_STATUSES",
    "ACTIVE_STATUSES",
]


class TaskPhase(str, Enum):
    """Where a task is in its lifecycle (coarse, always increasing unless reset)."""

    QUEUED = "queued"
    PLANNED = "planned"
    ASSIGNED = "assigned"
    RUNNING = "running"
    WAITING = "waiting"
    REVIEW = "review"
    DONE = "done"


class TaskStatus(str, Enum):
    """Fine-grained status.  ``phase`` is derived from this."""

    QUEUED = "queued"
    PLANNED = "planned"
    ASSIGNED = "assigned"
    RUNNING = "running"
    BLOCKED = "blocked"
    WAITING_DEPENDENCY = "waiting_dependency"
    WAITING_APPROVAL = "waiting_approval"
    IN_REVIEW = "in_review"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


_STATUS_TO_PHASE = {
    TaskStatus.QUEUED: TaskPhase.QUEUED,
    TaskStatus.PLANNED: TaskPhase.PLANNED,
    TaskStatus.ASSIGNED: TaskPhase.ASSIGNED,
    TaskStatus.RUNNING: TaskPhase.RUNNING,
    TaskStatus.BLOCKED: TaskPhase.WAITING,
    TaskStatus.WAITING_DEPENDENCY: TaskPhase.WAITING,
    TaskStatus.WAITING_APPROVAL: TaskPhase.WAITING,
    TaskStatus.IN_REVIEW: TaskPhase.REVIEW,
    TaskStatus.COMPLETED: TaskPhase.DONE,
    TaskStatus.FAILED: TaskPhase.DONE,
    TaskStatus.CANCELLED: TaskPhase.DONE,
}

# Structural tasks carry the organization; they are not worker dispatches.
_STRUCTURAL_TAGS = frozenset({"objective", "project"})

TERMINAL_STATUSES = frozenset(
    {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED}
)
ACTIVE_STATUSES = frozenset(
    {TaskStatus.ASSIGNED, TaskStatus.RUNNING, TaskStatus.IN_REVIEW}
)
WAITING_STATUSES = frozenset(
    {TaskStatus.BLOCKED, TaskStatus.WAITING_DEPENDENCY, TaskStatus.WAITING_APPROVAL}
)

# Legal transitions.  Anything not listed is rejected — a task cannot quietly
# jump from QUEUED to COMPLETED.
# A task can be held at any pre-completion point: an approval gate, a missing
# dependency or an external blocker does not wait for the worker to start.
_HOLD = frozenset(
    {TaskStatus.BLOCKED, TaskStatus.WAITING_APPROVAL, TaskStatus.WAITING_DEPENDENCY}
)
_ALLOWED: Dict[TaskStatus, frozenset] = {
    TaskStatus.QUEUED: frozenset(
        {TaskStatus.PLANNED, TaskStatus.ASSIGNED, TaskStatus.CANCELLED} | _HOLD
    ),
    TaskStatus.PLANNED: frozenset(
        {TaskStatus.ASSIGNED, TaskStatus.QUEUED, TaskStatus.CANCELLED} | _HOLD
    ),
    TaskStatus.ASSIGNED: frozenset(
        {TaskStatus.RUNNING, TaskStatus.FAILED, TaskStatus.CANCELLED, TaskStatus.QUEUED} | _HOLD
    ),
    TaskStatus.RUNNING: frozenset(
        {
            TaskStatus.IN_REVIEW,
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.BLOCKED,
            TaskStatus.WAITING_DEPENDENCY,
            TaskStatus.WAITING_APPROVAL,
            TaskStatus.CANCELLED,
        }
    ),
    # A held task can always be escalated to a human decision: asking the
    # operator is legitimate from any non-terminal state, so WAITING_APPROVAL is
    # reachable from BLOCKED and WAITING_DEPENDENCY as well as from the run states.
    TaskStatus.BLOCKED: frozenset(
        {
            TaskStatus.RUNNING,
            TaskStatus.ASSIGNED,
            TaskStatus.QUEUED,
            TaskStatus.WAITING_APPROVAL,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
        }
    ),
    TaskStatus.WAITING_DEPENDENCY: frozenset(
        {
            TaskStatus.RUNNING,
            TaskStatus.ASSIGNED,
            TaskStatus.QUEUED,
            TaskStatus.WAITING_APPROVAL,
            TaskStatus.CANCELLED,
        }
    ),
    TaskStatus.WAITING_APPROVAL: frozenset(
        {TaskStatus.RUNNING, TaskStatus.ASSIGNED, TaskStatus.QUEUED, TaskStatus.CANCELLED, TaskStatus.FAILED}
    ),
    TaskStatus.IN_REVIEW: frozenset(
        {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.RUNNING, TaskStatus.QUEUED, TaskStatus.CANCELLED}
    ),
    TaskStatus.COMPLETED: frozenset({TaskStatus.IN_REVIEW}),  # re-opened for review
    # A failure the Boss decides not to pursue becomes CANCELLED — abandoning
    # work is a real decision, not a way to hide the failure (the failure
    # stays recorded on the task and in the event stream).
    TaskStatus.FAILED: frozenset({TaskStatus.QUEUED, TaskStatus.PLANNED, TaskStatus.CANCELLED}),
    TaskStatus.CANCELLED: frozenset({TaskStatus.QUEUED}),  # explicitly revived
}


class TaskPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


_PRIORITY_ORDER = {
    TaskPriority.CRITICAL: 0,
    TaskPriority.HIGH: 1,
    TaskPriority.NORMAL: 2,
    TaskPriority.LOW: 3,
}


class ReviewState(str, Enum):
    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass
class TaskMetrics:
    """Real numbers observed from the runtime.  Zero/None means 'not observed'."""

    duration_seconds: Optional[float] = None
    api_calls: Optional[int] = None
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    cost_usd: Optional[float] = None
    tool_calls: Optional[int] = None

    def observed(self) -> bool:
        return any(
            v is not None
            for v in (
                self.duration_seconds,
                self.api_calls,
                self.input_tokens,
                self.output_tokens,
                self.cost_usd,
                self.tool_calls,
            )
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Task:
    """One unit of work in the X19 task graph."""

    objective: str
    id: str = field(default_factory=lambda: f"x19-t-{uuid.uuid4().hex[:10]}")
    parent_id: Optional[str] = None
    objective_id: Optional[str] = None

    description: str = ""
    role_id: Optional[str] = None
    manager_id: Optional[str] = None
    assigned_agent_id: Optional[str] = None

    status: TaskStatus = TaskStatus.QUEUED
    priority: TaskPriority = TaskPriority.NORMAL
    depends_on: List[str] = field(default_factory=list)

    created_at: float = field(default_factory=time.time)
    planned_at: Optional[float] = None
    assigned_at: Optional[float] = None
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    updated_at: float = field(default_factory=time.time)

    attempt: int = 0
    max_attempts: int = 3

    outputs: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    failure_reason: Optional[str] = None
    exit_reason: Optional[str] = None
    blockers: List[Dict[str, Any]] = field(default_factory=list)

    review_state: ReviewState = ReviewState.NOT_REQUIRED
    review_note: Optional[str] = None
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[float] = None

    metrics: TaskMetrics = field(default_factory=TaskMetrics)

    # Real runtime linkage — set when a dispatch actually happens.
    delegation_id: Optional[str] = None
    subagent_id: Optional[str] = None
    live_transcript: Optional[str] = None

    requires_approval: bool = False
    tags: List[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    @property
    def phase(self) -> TaskPhase:
        return _STATUS_TO_PHASE[self.status]

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    @property
    def is_active(self) -> bool:
        return self.status in ACTIVE_STATUSES

    @property
    def is_waiting(self) -> bool:
        return self.status in WAITING_STATUSES

    @property
    def can_retry(self) -> bool:
        return self.status is TaskStatus.FAILED and self.attempt < self.max_attempts

    @property
    def elapsed_seconds(self) -> Optional[float]:
        """Wall time spent running, from real timestamps only."""
        if self.started_at is None:
            return None
        end = self.finished_at if self.finished_at is not None else time.time()
        return max(0.0, end - self.started_at)

    @property
    def depth(self) -> int:
        return 0  # resolved by TaskStore, which owns the graph

    def add_note(self, text: str, *, source: str = "runtime", **extra: Any) -> None:
        if not text:
            return
        entry = {"ts": time.time(), "text": text, "source": source}
        entry.update({k: v for k, v in extra.items() if v is not None})
        self.notes.append(entry)
        # bounded: the newest notes are what an operator reads
        if len(self.notes) > 200:
            del self.notes[: len(self.notes) - 200]

    def to_dict(self, *, depth: int = 0) -> Dict[str, Any]:
        d = {
            "id": self.id,
            "objective": self.objective,
            "description": self.description,
            "parent_id": self.parent_id,
            "objective_id": self.objective_id,
            "role_id": self.role_id,
            "manager_id": self.manager_id,
            "assigned_agent_id": self.assigned_agent_id,
            "status": self.status.value,
            "phase": self.phase.value,
            "priority": self.priority.value,
            "depends_on": list(self.depends_on),
            "depth": depth,
            "created_at": self.created_at,
            "planned_at": self.planned_at,
            "assigned_at": self.assigned_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "updated_at": self.updated_at,
            "elapsed_seconds": self.elapsed_seconds,
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "outputs": list(self.outputs),
            "notes": list(self.notes[-20:]),
            "error": self.error,
            "failure_reason": self.failure_reason,
            "exit_reason": self.exit_reason,
            "blockers": list(self.blockers),
            "review": {
                "state": self.review_state.value,
                "note": self.review_note,
                "by": self.reviewed_by,
                "at": self.reviewed_at,
            },
            "metrics": self.metrics.to_dict(),
            "delegation_id": self.delegation_id,
            "subagent_id": self.subagent_id,
            "live_transcript": self.live_transcript,
            "requires_approval": self.requires_approval,
            "tags": list(self.tags),
        }
        return d


class InvalidTransition(ValueError):
    """Raised when a status change is not permitted by the lifecycle."""


class TaskStore:
    """The task graph: creation, transitions, dependency resolution, persistence.

    Thread-safe (the delegation engine runs children on worker threads) and
    event-emitting: every mutation publishes to the org :class:`EventBus`.
    """

    def __init__(self, bus: EventBus, *, persist_path=None, default_max_attempts: int = 3) -> None:
        self._bus = bus
        self._lock = threading.RLock()
        self._tasks: Dict[str, Task] = {}
        self._order: List[str] = []
        self._persist_path = persist_path
        # ``x19.execution.max_attempts`` in config: the retry budget every task
        # is created with unless the caller states its own.
        self._default_max_attempts = max(1, int(default_max_attempts))

    # -- accessors --------------------------------------------------------
    def __len__(self) -> int:
        with self._lock:
            return len(self._tasks)

    def get(self, task_id: Optional[str]) -> Optional[Task]:
        if not task_id:
            return None
        with self._lock:
            return self._tasks.get(task_id)

    def all(self) -> List[Task]:
        with self._lock:
            return [self._tasks[t] for t in self._order if t in self._tasks]

    def children(self, task_id: str) -> List[Task]:
        with self._lock:
            return [t for t in self._tasks.values() if t.parent_id == task_id]

    def descendants(self, task_id: str) -> List[Task]:
        out: List[Task] = []
        stack = [task_id]
        seen = set()
        while stack:
            cur = stack.pop()
            for child in self.children(cur):
                if child.id in seen:
                    continue
                seen.add(child.id)
                out.append(child)
                stack.append(child.id)
        return out

    def subtree(self, task_id: str) -> List[Task]:
        root = self.get(task_id)
        return [root] + self.descendants(task_id) if root else []

    def depth_of(self, task_id: str) -> int:
        depth = 0
        cur = self.get(task_id)
        guard = 0
        while cur and cur.parent_id and guard < 64:
            depth += 1
            cur = self.get(cur.parent_id)
            guard += 1
        return depth

    def by_status(self, *statuses: TaskStatus) -> List[Task]:
        wanted = set(statuses)
        with self._lock:
            return [t for t in self._tasks.values() if t.status in wanted]

    def find_by_subagent(self, subagent_id: Optional[str]) -> Optional[Task]:
        if not subagent_id:
            return None
        with self._lock:
            for tid in reversed(self._order):
                t = self._tasks.get(tid)
                if t and t.subagent_id == subagent_id:
                    return t
        return None

    def find_by_delegation(self, delegation_id: Optional[str]) -> List[Task]:
        if not delegation_id:
            return []
        with self._lock:
            return [t for t in self._tasks.values() if t.delegation_id == delegation_id]

    # -- creation ---------------------------------------------------------
    def create(
        self,
        objective: str,
        *,
        parent_id: Optional[str] = None,
        description: str = "",
        role_id: Optional[str] = None,
        manager_id: Optional[str] = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        depends_on: Optional[Sequence[str]] = None,
        requires_approval: bool = False,
        tags: Optional[Sequence[str]] = None,
        objective_id: Optional[str] = None,
        task_id: Optional[str] = None,
        max_attempts: Optional[int] = None,
    ) -> Task:
        if not objective or not objective.strip():
            raise ValueError("task objective must be non-empty")
        with self._lock:
            if parent_id and parent_id not in self._tasks:
                raise ValueError(f"unknown parent task {parent_id!r}")
            for dep in depends_on or ():
                if dep not in self._tasks:
                    raise ValueError(f"unknown dependency {dep!r}")
            task = Task(
                objective=objective.strip(),
                description=description,
                parent_id=parent_id,
                role_id=role_id,
                manager_id=manager_id,
                priority=priority,
                depends_on=list(depends_on or ()),
                requires_approval=requires_approval,
                tags=list(tags or ()),
                objective_id=objective_id or (self.get(parent_id).objective_id if parent_id else None),
            )
            task.max_attempts = max(1, int(max_attempts or self._default_max_attempts))
            if task_id:
                task.id = task_id
            if requires_approval:
                task.review_state = ReviewState.PENDING
            self._tasks[task.id] = task
            self._order.append(task.id)
        self._emit(EventType.TASK_CREATED, task, "task created")
        self._save()
        return task

    # -- transitions ------------------------------------------------------
    def _transition(
        self,
        task: Task,
        to: TaskStatus,
        *,
        event: EventType,
        message: str,
        note: Optional[str] = None,
        **payload: Any,
    ) -> Task:
        allowed = _ALLOWED.get(task.status, frozenset())
        if to not in allowed and to is not task.status:
            raise InvalidTransition(
                f"task {task.id}: {task.status.value} -> {to.value} is not a legal transition"
            )
        now = time.time()
        task.status = to
        task.updated_at = now
        if to is TaskStatus.PLANNED and task.planned_at is None:
            task.planned_at = now
        elif to is TaskStatus.ASSIGNED and task.assigned_at is None:
            task.assigned_at = now
        elif to is TaskStatus.RUNNING and task.started_at is None:
            task.started_at = now
        elif to in TERMINAL_STATUSES and task.finished_at is None:
            task.finished_at = now
        if note:
            task.add_note(note, **{k: v for k, v in payload.items() if isinstance(v, (str, int, float, bool))})
        self._emit(event, task, message, **payload)
        self._save()
        if to is TaskStatus.COMPLETED:
            # Symmetric with cascade_failure: a dependent must not keep claiming
            # to be blocked by work that has already finished.
            self.release_dependents(task.id)
        return task

    def plan(self, task_id: str, *, description: str = "", depends_on: Optional[Sequence[str]] = None) -> Task:
        with self._lock:
            task = self._require(task_id)
            if description:
                task.description = description
            if depends_on is not None:
                for dep in depends_on:
                    if dep not in self._tasks:
                        raise ValueError(f"unknown dependency {dep!r}")
                task.depends_on = list(depends_on)
            self._transition(
                task, TaskStatus.PLANNED, event=EventType.TASK_PLANNED, message="task planned",
                depends_on=list(task.depends_on),
            )
            # A planned task with outstanding dependencies is *waiting*, not
            # queued: reporting it as ready-to-run would misdescribe the graph.
            # release_dependents() moves it back to QUEUED when they complete.
            blocking = self.blocking_dependencies(task.id)
            if blocking:
                return self.wait_on_dependency(task.id, blocking[0]["task_id"])
            return task

    def assign(
        self,
        task_id: str,
        *,
        role_id: str,
        manager_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> Task:
        with self._lock:
            task = self._require(task_id)
            task.role_id = role_id
            if manager_id is not None:
                task.manager_id = manager_id
            if agent_id:
                task.assigned_agent_id = agent_id
            if task.status is TaskStatus.QUEUED:
                self._transition(task, TaskStatus.PLANNED, event=EventType.TASK_PLANNED, message="task planned")
            return self._transition(
                task, TaskStatus.ASSIGNED, event=EventType.TASK_ASSIGNED,
                message=f"assigned to {role_id}", role_id=role_id, agent_id=agent_id,
            )

    def start(
        self,
        task_id: str,
        *,
        agent_id: Optional[str] = None,
        subagent_id: Optional[str] = None,
        delegation_id: Optional[str] = None,
        live_transcript: Optional[str] = None,
    ) -> Task:
        with self._lock:
            task = self._require(task_id)
            if agent_id:
                task.assigned_agent_id = agent_id
            if subagent_id:
                task.subagent_id = subagent_id
            if delegation_id:
                task.delegation_id = delegation_id
            if live_transcript:
                task.live_transcript = live_transcript
            task.attempt += 1
            return self._transition(
                task, TaskStatus.RUNNING, event=EventType.TASK_STARTED,
                message="worker started", subagent_id=subagent_id, delegation_id=delegation_id,
                attempt=task.attempt,
            )

    def progress(self, task_id: str, note: str, *, source: str = "runtime", **extra: Any) -> Task:
        with self._lock:
            task = self._require(task_id)
            task.add_note(note, source=source, **extra)
            task.updated_at = time.time()
        self._emit(EventType.TASK_PROGRESS, task, note, **extra)
        self._save()
        return task

    def block(self, task_id: str, reason: str, *, requires_approval: bool = False, blocker_id: Optional[str] = None) -> Task:
        with self._lock:
            task = self._require(task_id)
            entry = {
                "id": blocker_id or f"b-{uuid.uuid4().hex[:8]}",
                "reason": reason,
                "raised_at": time.time(),
                "requires_approval": requires_approval,
                "resolved_at": None,
            }
            task.blockers.append(entry)
            task.requires_approval = task.requires_approval or requires_approval
            to = TaskStatus.WAITING_APPROVAL if requires_approval else TaskStatus.BLOCKED
            event = EventType.APPROVAL_REQUESTED if requires_approval else EventType.TASK_BLOCKED
            return self._transition(
                task, to, event=event, message=reason,
                blocker_id=entry["id"], requires_approval=requires_approval,
            )

    def unblock(self, task_id: str, *, blocker_id: Optional[str] = None, resolution: str = "") -> Task:
        with self._lock:
            task = self._require(task_id)
            now = time.time()
            for b in task.blockers:
                if b.get("resolved_at"):
                    continue
                if blocker_id is None or b.get("id") == blocker_id:
                    b["resolved_at"] = now
                    b["resolution"] = resolution
            # ASSIGNED and QUEUED are legal exits from every held state
            # (BLOCKED, WAITING_APPROVAL, WAITING_DEPENDENCY); PLANNED is not,
            # so a released task re-enters the dispatchable queue instead.
            to = TaskStatus.ASSIGNED if task.assigned_agent_id else TaskStatus.QUEUED
            return self._transition(
                task, to, event=EventType.TASK_UNBLOCKED,
                message=resolution or "blocker resolved",
            )

    def wait_on_dependency(self, task_id: str, dependency_id: str) -> Task:
        with self._lock:
            task = self._require(task_id)
            if dependency_id not in task.depends_on:
                task.depends_on.append(dependency_id)
            return self._transition(
                task, TaskStatus.WAITING_DEPENDENCY, event=EventType.TASK_WAITING,
                message=f"waiting on {dependency_id}", dependency_id=dependency_id,
            )

    def request_review(self, task_id: str, *, by: Optional[str] = None) -> Task:
        with self._lock:
            task = self._require(task_id)
            task.review_state = ReviewState.PENDING
            return self._transition(
                task, TaskStatus.IN_REVIEW, event=EventType.TASK_REVIEW_REQUIRED,
                message="output awaiting review", reviewer=by,
            )

    def review(
        self,
        task_id: str,
        *,
        approved: bool,
        reviewer: str,
        note: str = "",
    ) -> Task:
        with self._lock:
            task = self._require(task_id)
            task.review_state = ReviewState.APPROVED if approved else ReviewState.REJECTED
            task.review_note = note or None
            task.reviewed_by = reviewer
            task.reviewed_at = time.time()
            if approved:
                task.blockers = [
                    b for b in task.blockers if not (b.get("requires_approval") and not b.get("resolved_at"))
                ]
                to = TaskStatus.COMPLETED
                msg = f"review approved by {reviewer}"
            else:
                # A rejected output goes back to work, it is not silently passed.
                to = TaskStatus.QUEUED
                msg = f"review rejected by {reviewer}: {note}".strip()
                task.status = TaskStatus.IN_REVIEW  # keep transition table happy
            return self._transition(
                task, to, event=EventType.TASK_REVIEWED, message=msg,
                approved=approved, reviewer=reviewer,
            )

    def complete(
        self,
        task_id: str,
        *,
        outputs: Optional[Sequence[Dict[str, Any]]] = None,
        summary: Optional[str] = None,
        metrics: Optional[Dict[str, Any]] = None,
        review_required: bool = False,
    ) -> Task:
        with self._lock:
            task = self._require(task_id)
            for o in outputs or ():
                task.outputs.append(dict(o))
            if summary:
                task.add_note(summary, source="worker")
            if metrics:
                self._apply_metrics(task, metrics)
            if review_required or task.review_state is ReviewState.PENDING:
                return self.request_review(task_id)
            if task.requires_approval and task.review_state is not ReviewState.APPROVED:
                return self.request_review(task_id)
            return self._transition(
                task, TaskStatus.COMPLETED, event=EventType.TASK_COMPLETED,
                message=summary or "task completed",
            )

    def fail(
        self,
        task_id: str,
        reason: str,
        *,
        failure_reason: Optional[str] = None,
        error: Optional[str] = None,
        metrics: Optional[Dict[str, Any]] = None,
    ) -> Task:
        with self._lock:
            task = self._require(task_id)
            task.error = error or reason
            task.failure_reason = failure_reason or task.failure_reason
            if metrics:
                self._apply_metrics(task, metrics)
            return self._transition(
                task, TaskStatus.FAILED, event=EventType.TASK_FAILED, message=reason,
                failure_reason=failure_reason,
            )

    def cancel(self, task_id: str, reason: str = "cancelled") -> Task:
        with self._lock:
            task = self._require(task_id)
            return self._transition(
                task, TaskStatus.CANCELLED, event=EventType.TASK_CANCELLED, message=reason
            )

    def retry(self, task_id: str, *, reason: str = "") -> Task:
        """Re-queue a failed task.  Refuses when the attempt budget is spent."""
        with self._lock:
            task = self._require(task_id)
            if task.status is not TaskStatus.FAILED:
                raise InvalidTransition(f"task {task.id} is {task.status.value}, not failed")
            if not task.can_retry:
                raise InvalidTransition(
                    f"task {task.id} exhausted its retry budget "
                    f"({task.attempt}/{task.max_attempts})"
                )
            task.error = None
            task.subagent_id = None
            task.delegation_id = None
            task.finished_at = None
            task.started_at = None
            return self._transition(
                task, TaskStatus.QUEUED, event=EventType.TASK_RETRIED,
                message=reason or f"retry {task.attempt + 1}/{task.max_attempts}",
            )

    def reassign(self, task_id: str, *, role_id: str, reason: str = "") -> Task:
        with self._lock:
            task = self._require(task_id)
            previous = task.role_id
            task.role_id = role_id
            task.assigned_agent_id = None
            task.subagent_id = None
            task.delegation_id = None
            if task.status in TERMINAL_STATUSES:
                task.status = TaskStatus.FAILED if task.status is TaskStatus.FAILED else TaskStatus.QUEUED
            return self._transition(
                task, TaskStatus.ASSIGNED, event=EventType.TASK_REASSIGNED,
                message=reason or f"reassigned {previous} -> {role_id}",
                previous_role=previous, role_id=role_id,
            )

    # -- dependency resolution -------------------------------------------
    def ready_tasks(self, *, include_structural: bool = False) -> List[Task]:
        """Tasks whose dependencies have all completed and that can start now.

        Structural tasks (the objective itself, X22's project wrapper) are not
        dispatchable work — they close when their children do — so they are
        excluded unless explicitly requested.
        """
        with self._lock:
            out = []
            for t in self._tasks.values():
                if t.status not in (TaskStatus.QUEUED, TaskStatus.PLANNED, TaskStatus.WAITING_DEPENDENCY):
                    continue
                if not include_structural and set(t.tags or ()) & _STRUCTURAL_TAGS:
                    continue
                if all(self._is_satisfied(d) for d in t.depends_on):
                    out.append(t)
            out.sort(key=lambda t: (_PRIORITY_ORDER[t.priority], t.created_at))
            return out

    def _is_satisfied(self, dep_id: str) -> bool:
        dep = self._tasks.get(dep_id)
        return bool(dep and dep.status is TaskStatus.COMPLETED)

    def blocking_dependencies(self, task_id: str) -> List[Dict[str, Any]]:
        """Dependencies that are *not* satisfied yet — real blockers, with state."""
        task = self.get(task_id)
        if not task:
            return []
        out = []
        for dep_id in task.depends_on:
            dep = self.get(dep_id)
            if dep is None:
                out.append({"task_id": dep_id, "status": "missing"})
            elif dep.status is not TaskStatus.COMPLETED:
                out.append(
                    {
                        "task_id": dep_id,
                        "objective": dep.objective,
                        "status": dep.status.value,
                        "role_id": dep.role_id,
                    }
                )
        return out

    def downstream_of(self, task_id: str) -> List[Task]:
        with self._lock:
            return [t for t in self._tasks.values() if task_id in t.depends_on]

    def release_dependents(self, task_id: str) -> List[str]:
        """Return tasks that were only waiting on *task_id* to a dispatchable state.

        A dependent is released when every one of its dependencies has reached a
        terminal state.  Nothing is invented here: the task keeps its plan,
        priority, attempt count and history — it simply stops reporting itself as
        blocked by work that is already done.

        Returns the released ids.
        """
        released: List[str] = []
        with self._lock:
            for dep in self.downstream_of(task_id):
                if dep.status is not TaskStatus.WAITING_DEPENDENCY:
                    continue
                if self.blocking_dependencies(dep.id):
                    continue  # still waiting on something else
                try:
                    self._transition(
                        dep,
                        TaskStatus.QUEUED,
                        event=EventType.TASK_UNBLOCKED,
                        message=f"dependency {task_id} completed",
                        dependency_id=task_id,
                    )
                except InvalidTransition:
                    continue
                released.append(dep.id)
            if released:
                self._save()
        return released

    def cascade_failure(self, task_id: str, reason: str) -> List[str]:
        """Mark every task that (transitively) depends on a failed task as blocked.

        Returns the ids that were blocked.  This is what keeps a failure honest:
        dependents never show as runnable when their input is gone.
        """
        blocked: List[str] = []
        frontier = [task_id]
        seen = {task_id}
        while frontier:
            cur = frontier.pop()
            for dep in self.downstream_of(cur):
                if dep.id in seen or dep.is_terminal:
                    continue
                seen.add(dep.id)
                try:
                    self.block(dep.id, f"dependency {cur} failed: {reason}")
                    blocked.append(dep.id)
                    frontier.append(dep.id)
                except InvalidTransition:
                    continue
        return blocked

    # -- projection -------------------------------------------------------
    def stats(self) -> Dict[str, int]:
        with self._lock:
            tasks = list(self._tasks.values())
        out = {s.value: 0 for s in TaskStatus}
        for t in tasks:
            out[t.status.value] += 1
        out["total"] = len(tasks)
        out["active"] = sum(1 for t in tasks if t.is_active)
        out["waiting"] = sum(1 for t in tasks if t.is_waiting)
        out["terminal"] = sum(1 for t in tasks if t.is_terminal)
        out["retryable"] = sum(1 for t in tasks if t.can_retry)
        return out

    def tree(self, root_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """The task graph as a nested structure the UI renders dynamically."""
        with self._lock:
            tasks = {t.id: t for t in self._tasks.values()}

        def node(tid: str, depth: int) -> Optional[Dict[str, Any]]:
            t = tasks.get(tid)
            if t is None:
                return None
            kids = sorted(
                (c for c in tasks.values() if c.parent_id == tid),
                key=lambda c: (_PRIORITY_ORDER[c.priority], c.created_at),
            )
            d = t.to_dict(depth=depth)
            d["children"] = [n for n in (node(k.id, depth + 1) for k in kids) if n]
            return d

        if root_id:
            n = node(root_id, 0)
            return [n] if n else []
        roots = [t for t in tasks.values() if not t.parent_id or t.parent_id not in tasks]
        roots.sort(key=lambda t: (_PRIORITY_ORDER[t.priority], t.created_at))
        return [n for n in (node(t.id, 0) for t in roots) if n]

    # -- persistence ------------------------------------------------------
    def set_persist_path(self, path) -> None:
        self._persist_path = path

    def _save(self) -> None:
        path = self._persist_path
        if path is None:
            return
        try:
            import json
            from pathlib import Path

            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            with self._lock:
                payload = {
                    "version": 1,
                    "saved_at": time.time(),
                    "tasks": [self._tasks[t].to_dict() for t in self._order if t in self._tasks],
                }
            tmp = p.with_suffix(p.suffix + ".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            os_replace(tmp, p)
        except Exception:
            # Persistence must never take the orchestration loop down.
            pass

    def _load(self) -> int:
        path = self._persist_path
        if path is None:
            return 0
        try:
            import json
            from pathlib import Path

            p = Path(path)
            if not p.exists():
                return 0
            raw = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return 0
        count = 0
        for entry in raw.get("tasks", []):
            task = _task_from_dict(entry)
            if task is None:
                continue
            with self._lock:
                if task.id in self._tasks:
                    continue
                self._tasks[task.id] = task
                self._order.append(task.id)
            count += 1
        return count

    def reload(self) -> int:
        """Re-read persisted tasks (used on startup / session resume)."""
        return self._load()

    # -- internals --------------------------------------------------------
    def _require(self, task_id: str) -> Task:
        task = self._tasks.get(task_id)
        if task is None:
            raise KeyError(f"unknown task {task_id!r}")
        return task

    def _emit(self, event: EventType, task: Task, message: str, **payload: Any) -> None:
        # Task identity first; an explicit payload value (e.g. the role a task
        # was just reassigned *to*) wins over the recorded field.
        fields: Dict[str, Any] = {
            "task_id": task.id,
            "parent_task_id": task.parent_id,
            "objective_id": task.objective_id,
            "agent_id": task.assigned_agent_id,
            "role_id": task.role_id,
            "manager_id": task.manager_id,
            "status": task.status.value,
            "phase": task.phase.value,
        }
        fields.update({k: v for k, v in payload.items() if v is not None})
        self._bus.publish(event, message, **fields)

    @staticmethod
    def _apply_metrics(task: Task, metrics: Dict[str, Any]) -> None:
        m = task.metrics
        for key in ("duration_seconds", "api_calls", "input_tokens", "output_tokens", "cost_usd", "tool_calls"):
            if key in metrics and metrics[key] is not None:
                setattr(m, key, metrics[key])


def os_replace(src, dst) -> None:
    import os

    os.replace(src, dst)


def _task_from_dict(raw: Dict[str, Any]) -> Optional[Task]:
    try:
        task = Task(objective=raw.get("objective") or "")
        task.id = raw.get("id") or task.id
        task.parent_id = raw.get("parent_id")
        task.objective_id = raw.get("objective_id")
        task.description = raw.get("description") or ""
        task.role_id = raw.get("role_id")
        task.manager_id = raw.get("manager_id")
        task.assigned_agent_id = raw.get("assigned_agent_id")
        task.status = TaskStatus(raw.get("status", "queued"))
        task.priority = TaskPriority(raw.get("priority", "normal"))
        task.depends_on = list(raw.get("depends_on") or [])
        for key in ("created_at", "planned_at", "assigned_at", "started_at", "finished_at", "updated_at"):
            val = raw.get(key)
            if isinstance(val, (int, float)):
                setattr(task, key, val)
        task.attempt = int(raw.get("attempt") or 0)
        task.max_attempts = int(raw.get("max_attempts") or 3)
        task.outputs = list(raw.get("outputs") or [])
        task.notes = list(raw.get("notes") or [])
        task.error = raw.get("error")
        task.failure_reason = raw.get("failure_reason")
        task.exit_reason = raw.get("exit_reason")
        task.blockers = list(raw.get("blockers") or [])
        review = raw.get("review") or {}
        task.review_state = ReviewState(review.get("state", "not_required"))
        task.review_note = review.get("note")
        task.reviewed_by = review.get("by")
        task.reviewed_at = review.get("at")
        md = raw.get("metrics") or {}
        task.metrics = TaskMetrics(**{k: md.get(k) for k in TaskMetrics.__dataclass_fields__ if k in md})
        task.delegation_id = raw.get("delegation_id")
        task.subagent_id = raw.get("subagent_id")
        task.live_transcript = raw.get("live_transcript")
        task.requires_approval = bool(raw.get("requires_approval"))
        task.tags = list(raw.get("tags") or [])
        return task
    except Exception:
        return None
