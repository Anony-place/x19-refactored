"""
X19 Distributed Task Queue & Worker Orchestration.
Provides prioritized, thread-safe, deduplicated task scheduling with automatic
failure recovery, retry limits, and worker cancellation.
"""

from __future__ import annotations
import hashlib
import heapq
import json
import threading
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Set


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(order=True)
class AgentTask:
    priority: int  # 1 = highest, 10 = lowest (used by heapq)
    task_id: str = field(compare=False)
    task_type: str = field(compare=False)  # "recon", "web_fuzz", "vuln_audit", "verify", "reflect"
    target: str = field(compare=False)
    params: Dict[str, Any] = field(default_factory=dict, compare=False)
    status: TaskStatus = field(default=TaskStatus.PENDING, compare=False)
    retries: int = field(default=0, compare=False)
    max_retries: int = field(default=3, compare=False)
    created_at: float = field(default_factory=time.time, compare=False)
    completed_at: Optional[float] = field(default=None, compare=False)
    error: str = field(default="", compare=False)
    result: Any = field(default=None, compare=False)
    assigned_agent: str = field(default="", compare=False)

    @property
    def signature(self) -> str:
        """Deterministic signature to prevent duplicate work."""
        sig_data = f"{self.task_type}:{self.target}:{json.dumps(self.params, sort_keys=True)}"
        return hashlib.sha256(sig_data.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["signature"] = self.signature
        return d


class TaskQueue:
    """Thread-safe prioritized task queue with deduplication and failure recovery."""

    def __init__(self):
        self._heap: List[AgentTask] = []
        self._tasks: Dict[str, AgentTask] = {}
        self._seen_signatures: Set[str] = set()
        self._failed_signatures: Dict[str, int] = {}  # signature -> fail count
        self._lock = threading.Lock()

    def push(self, task: AgentTask) -> bool:
        """Push a new task to the queue. Returns False if already seen/duplicate."""
        with self._lock:
            sig = task.signature
            # Deduplication: do not re-add if currently active or already completed
            if sig in self._seen_signatures and task.retries == 0:
                return False

            # Check if this task signature has permanently failed previously
            if self._failed_signatures.get(sig, 0) >= task.max_retries:
                return False

            self._seen_signatures.add(sig)
            self._tasks[task.task_id] = task
            heapq.heappush(self._heap, task)
            return True

    def pop(self, allowed_types: Optional[Set[str]] = None) -> Optional[AgentTask]:
        """Pop the highest priority task matching allowed_types."""
        with self._lock:
            if not self._heap:
                return None

            temp: List[AgentTask] = []
            selected: Optional[AgentTask] = None

            while self._heap:
                candidate = heapq.heappop(self._heap)
                if candidate.status == TaskStatus.CANCELLED:
                    continue
                if allowed_types is None or candidate.task_type in allowed_types:
                    selected = candidate
                    selected.status = TaskStatus.RUNNING
                    break
                else:
                    temp.append(candidate)

            # Re-insert non-matching tasks
            for item in temp:
                heapq.heappush(self._heap, item)

            return selected

    def mark_completed(self, task_id: str, result: Any = None) -> Optional[AgentTask]:
        """Mark task as successfully completed."""
        with self._lock:
            task = self._tasks.get(task_id)
            if task:
                task.status = TaskStatus.COMPLETED
                task.completed_at = time.time()
                task.result = result
            return task

    def mark_failed(self, task_id: str, error: str) -> Optional[AgentTask]:
        """Mark task as failed and auto-retry if within max_retries limit."""
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return None

            task.retries += 1
            task.error = error
            sig = task.signature
            self._failed_signatures[sig] = self._failed_signatures.get(sig, 0) + 1

            if task.retries < task.max_retries:
                task.status = TaskStatus.PENDING
                # Lower priority slightly on retry
                task.priority = min(10, task.priority + 1)
                heapq.heappush(self._heap, task)
            else:
                task.status = TaskStatus.FAILED
                task.completed_at = time.time()

            return task

    def cancel_task(self, task_id: str) -> bool:
        """Cancel a specific task."""
        with self._lock:
            task = self._tasks.get(task_id)
            if task and task.status in (TaskStatus.PENDING, TaskStatus.RUNNING):
                task.status = TaskStatus.CANCELLED
                return True
            return False

    def cancel_all(self) -> None:
        """Cancel all pending tasks."""
        with self._lock:
            for task in self._tasks.values():
                if task.status in (TaskStatus.PENDING, TaskStatus.RUNNING):
                    task.status = TaskStatus.CANCELLED
            self._heap.clear()

    def pending_count(self) -> int:
        with self._lock:
            return sum(1 for t in self._tasks.values() if t.status == TaskStatus.PENDING)

    def active_count(self) -> int:
        with self._lock:
            return sum(1 for t in self._tasks.values() if t.status == TaskStatus.RUNNING)

    def get_all_tasks(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [t.to_dict() for t in self._tasks.values()]
