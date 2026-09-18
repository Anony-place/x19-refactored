"""
X19 Task Definitions — mission decomposition into tasks.

Boss decomposes missions, assigns to Managers/Specialists, tracks state,
prevents duplicate work, detects blocked agents, retries failed work.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Optional, Any
import uuid


class TaskStatus(str, Enum):
    """Task status."""

    PENDING = "pending"  # Created, not yet assigned
    ASSIGNED = "assigned"  # Assigned to agent
    RUNNING = "running"  # Agent working
    COMPLETED = "completed"  # Done with evidence
    FAILED = "failed"  # Failed, needs retry or escalation
    BLOCKED = "blocked"  # Blocked, needs approval or different strategy
    CANCELLED = "cancelled"  # Cancelled by Boss/Operator


class TaskPriority(str, Enum):
    """Task priority."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Task:
    """Single task in mission."""

    id: str = field(default_factory=lambda: f"T-{uuid.uuid4().hex[:6].upper()}")
    mission_id: str = ""
    objective: str = ""  # What to do
    target: str = ""  # Where
    assigned_to: str = ""  # Role ID
    assigned_agent_id: Optional[str] = None  # Actual agent instance ID

    # Scope and constraints
    scope: Dict[str, Any] = field(default_factory=dict)
    allowed_actions: List[str] = field(default_factory=list)
    prohibited_actions: List[str] = field(default_factory=list)
    expected_evidence: List[str] = field(default_factory=list)

    # Status
    status: TaskStatus = TaskStatus.PENDING
    priority: TaskPriority = TaskPriority.MEDIUM
    created_at: datetime = field(default_factory=datetime.utcnow)
    assigned_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    updated_at: datetime = field(default_factory=datetime.utcnow)

    # Progress
    progress: int = 0  # 0-100
    progress_message: str = ""
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)  # Finding IDs
    tool_output_refs: List[str] = field(default_factory=list)

    # Failure handling
    failure_reason: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 2
    blocked_reason: Optional[str] = None
    requires_approval: bool = False

    # Dependencies
    depends_on: List[str] = field(default_factory=list)  # Task IDs this depends on
    blocks: List[str] = field(default_factory=list)  # Task IDs this blocks

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "mission_id": self.mission_id,
            "objective": self.objective,
            "target": self.target,
            "assigned_to": self.assigned_to,
            "assigned_agent_id": self.assigned_agent_id,
            "scope": self.scope,
            "allowed_actions": self.allowed_actions,
            "prohibited_actions": self.prohibited_actions,
            "expected_evidence": self.expected_evidence,
            "status": self.status.value,
            "priority": self.priority.value,
            "created_at": self.created_at.isoformat(),
            "assigned_at": self.assigned_at.isoformat() if self.assigned_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "updated_at": self.updated_at.isoformat(),
            "progress": self.progress,
            "progress_message": self.progress_message,
            "evidence": self.evidence,
            "findings": self.findings,
            "tool_output_refs": self.tool_output_refs,
            "failure_reason": self.failure_reason,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "blocked_reason": self.blocked_reason,
            "requires_approval": self.requires_approval,
            "depends_on": self.depends_on,
            "blocks": self.blocks,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Task":
        # Parse datetimes
        def parse_dt(val):
            if isinstance(val, str):
                try:
                    return datetime.fromisoformat(val)
                except Exception:
                    return None
            return val if isinstance(val, datetime) else None

        try:
            status = TaskStatus(data.get("status", "pending"))
        except ValueError:
            status = TaskStatus.PENDING

        try:
            priority = TaskPriority(data.get("priority", "medium"))
        except ValueError:
            priority = TaskPriority.MEDIUM

        return cls(
            id=data.get("id", f"T-{uuid.uuid4().hex[:6].upper()}"),
            mission_id=data.get("mission_id", ""),
            objective=data.get("objective", ""),
            target=data.get("target", ""),
            assigned_to=data.get("assigned_to", ""),
            assigned_agent_id=data.get("assigned_agent_id"),
            scope=data.get("scope", {}),
            allowed_actions=data.get("allowed_actions", []),
            prohibited_actions=data.get("prohibited_actions", []),
            expected_evidence=data.get("expected_evidence", []),
            status=status,
            priority=priority,
            created_at=parse_dt(data.get("created_at")) or datetime.utcnow(),
            assigned_at=parse_dt(data.get("assigned_at")),
            started_at=parse_dt(data.get("started_at")),
            completed_at=parse_dt(data.get("completed_at")),
            updated_at=parse_dt(data.get("updated_at")) or datetime.utcnow(),
            progress=data.get("progress", 0),
            progress_message=data.get("progress_message", ""),
            evidence=data.get("evidence", []),
            findings=data.get("findings", []),
            tool_output_refs=data.get("tool_output_refs", []),
            failure_reason=data.get("failure_reason"),
            retry_count=data.get("retry_count", 0),
            max_retries=data.get("max_retries", 2),
            blocked_reason=data.get("blocked_reason"),
            requires_approval=data.get("requires_approval", False),
            depends_on=data.get("depends_on", []),
            blocks=data.get("blocks", []),
        )

    def assign(self, agent_role: str, agent_id: Optional[str] = None):
        """Assign task to agent."""
        self.assigned_to = agent_role
        self.assigned_agent_id = agent_id
        self.status = TaskStatus.ASSIGNED
        self.assigned_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()

    def start(self):
        """Mark task as running."""
        self.status = TaskStatus.RUNNING
        self.started_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()

    def complete(self, evidence: Optional[List[Dict[str, Any]]] = None, findings: Optional[List[str]] = None):
        """Mark task as completed."""
        self.status = TaskStatus.COMPLETED
        self.completed_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        self.progress = 100
        if evidence:
            self.evidence.extend(evidence)
        if findings:
            self.findings.extend(findings)

    def fail(self, reason: str):
        """Mark task as failed."""
        self.status = TaskStatus.FAILED
        self.failure_reason = reason
        self.updated_at = datetime.utcnow()

    def block(self, reason: str, requires_approval: bool = False):
        """Mark task as blocked."""
        self.status = TaskStatus.BLOCKED
        self.blocked_reason = reason
        self.requires_approval = requires_approval
        self.updated_at = datetime.utcnow()

    def can_retry(self) -> bool:
        """Check if task can be retried."""
        return self.retry_count < self.max_retries and self.status == TaskStatus.FAILED

    def retry(self):
        """Retry task."""
        if not self.can_retry():
            return False
        self.retry_count += 1
        self.status = TaskStatus.PENDING
        self.failure_reason = None
        self.updated_at = datetime.utcnow()
        return True


class TaskStore:
    """Store for tasks with duplicate prevention."""

    def __init__(self):
        self.tasks: Dict[str, Task] = {}

    def add(self, task: Task) -> str:
        """Add task, check for duplicates."""
        # Check duplicate: same objective + target + assigned_to
        for existing in self.tasks.values():
            if (
                existing.objective == task.objective
                and existing.target == task.target
                and existing.assigned_to == task.assigned_to
                and existing.status not in (TaskStatus.FAILED, TaskStatus.CANCELLED)
            ):
                # Duplicate found
                return existing.id

        self.tasks[task.id] = task
        return task.id

    def get(self, task_id: str) -> Optional[Task]:
        return self.tasks.get(task_id)

    def list_by_status(self, status: TaskStatus) -> List[Task]:
        return [t for t in self.tasks.values() if t.status == status]

    def list_by_assignee(self, role_id: str) -> List[Task]:
        return [t for t in self.tasks.values() if t.assigned_to == role_id]

    def list_blocked(self) -> List[Task]:
        return self.list_by_status(TaskStatus.BLOCKED)

    def list_failed(self) -> List[Task]:
        return self.list_by_status(TaskStatus.FAILED)

    def get_stats(self) -> Dict[str, int]:
        return {
            "total": len(self.tasks),
            "pending": len(self.list_by_status(TaskStatus.PENDING)),
            "assigned": len(self.list_by_status(TaskStatus.ASSIGNED)),
            "running": len(self.list_by_status(TaskStatus.RUNNING)),
            "completed": len(self.list_by_status(TaskStatus.COMPLETED)),
            "failed": len(self.list_by_status(TaskStatus.FAILED)),
            "blocked": len(self.list_by_status(TaskStatus.BLOCKED)),
            "cancelled": len(self.list_by_status(TaskStatus.CANCELLED)),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {tid: t.to_dict() for tid, t in self.tasks.items()}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaskStore":
        store = cls()
        for tid, tdata in data.items():
            try:
                task = Task.from_dict(tdata)
                store.tasks[tid] = task
            except Exception:
                continue
        return store
