"""X19 execution guards — real failure handling without infinite loops.

Three concrete risks when an orchestrator drives itself:

1. re-dispatching the same failing task forever,
2. creating duplicate tasks for work that is already in flight,
3. reporting a stalled worker as healthy because nothing ever checked.

Each guard here reads real recorded state (attempt counts, prior failure
reasons, live subagent timestamps) and returns a decision the caller must
honour.  Nothing is inferred from prose.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .registry import STALE_ACTIVE_SECONDS as MANAGER_STALE_SECONDS
from .tasks import Task, TaskStatus

__all__ = [
    "GuardDecision",
    "ExecutionGuards",
    "fingerprint",
]


@dataclass(frozen=True)
class GuardDecision:
    """A go/no-go verdict with the reason it was reached."""

    allowed: bool
    reason: str
    guard: str
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"allowed": self.allowed, "reason": self.reason, "guard": self.guard, **self.detail}


def fingerprint(objective: str, role_id: Optional[str], context: str = "") -> str:
    """Stable identity for "this exact piece of work by this exact role"."""
    key = "\x1f".join(
        [
            " ".join((objective or "").split()).lower(),
            (role_id or "").lower(),
            " ".join((context or "").split()).lower(),
        ]
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


class ExecutionGuards:
    """Policy checks over an :class:`x19.org.runtime.OrganizationRuntime`."""

    def __init__(
        self,
        runtime,
        *,
        max_inflight_per_role: int = 3,
        max_duplicate_inflight: int = 1,
        max_failures_per_objective: int = 6,
        stale_seconds: float = MANAGER_STALE_SECONDS,
    ) -> None:
        self.runtime = runtime
        self.max_inflight_per_role = max_inflight_per_role
        self.max_duplicate_inflight = max_duplicate_inflight
        self.max_failures_per_objective = max_failures_per_objective
        self.stale_seconds = stale_seconds
        # fingerprint -> failure signatures already tried, so a retry that would
        # repeat an identical failed dispatch is refused instead of looped.
        self._tried: Dict[str, List[str]] = {}

    # ------------------------------------------------------------------
    def can_dispatch(self, task: Task, *, context: str = "") -> GuardDecision:
        """May this task be dispatched right now?"""
        tasks = self.runtime.tasks

        if task.is_terminal:
            return GuardDecision(False, f"task is {task.status.value}", "terminal",
                                 {"task_id": task.id, "status": task.status.value})

        if task.attempt >= task.max_attempts:
            return GuardDecision(
                False,
                f"retry budget spent ({task.attempt}/{task.max_attempts})",
                "retry_budget",
                {"task_id": task.id, "attempt": task.attempt, "max_attempts": task.max_attempts},
            )

        blocking = tasks.blocking_dependencies(task.id)
        if blocking:
            return GuardDecision(
                False,
                "waiting on " + ", ".join(b["task_id"] for b in blocking[:4]),
                "dependency",
                {"task_id": task.id, "blocking": blocking},
            )

        if task.requires_approval and task.review_state.value != "approved":
            return GuardDecision(
                False,
                "operator approval required before dispatch",
                "approval",
                {"task_id": task.id, "pending": [a["id"] for a in self.runtime.pending_approvals()]},
            )

        # Configured sign-off policy: some roles may not run unsupervised.
        # The decision is read from the task's own recorded review state, which
        # resolve_approval() sets — never from a guess about what was asked.
        if self.runtime.settings.requires_approval(task.role_id) \
                and task.review_state.value != "approved":
            return GuardDecision(
                False,
                f"role {task.role_id} requires operator approval before dispatch (configured policy)",
                "approval_policy",
                {
                    "task_id": task.id,
                    "role_id": task.role_id,
                    "review_state": task.review_state.value,
                    "pending": [a["id"] for a in self.runtime.pending_approvals()],
                },
            )

        if self.runtime.run.paused or self.runtime.run.stopped:
            return GuardDecision(
                False,
                "run is paused" if self.runtime.run.paused else "run is stopped",
                "operator_control",
                {"task_id": task.id},
            )

        if task.role_id:
            inflight = [
                t
                for t in tasks.by_status(TaskStatus.RUNNING, TaskStatus.ASSIGNED)
                if t.role_id == task.role_id and t.id != task.id
            ]
            if len(inflight) >= self.max_inflight_per_role:
                return GuardDecision(
                    False,
                    f"{task.role_id} already has {len(inflight)} task(s) in flight "
                    f"(limit {self.max_inflight_per_role})",
                    "role_concurrency",
                    {"task_id": task.id, "role_id": task.role_id, "inflight": [t.id for t in inflight]},
                )

        fp = fingerprint(task.objective, task.role_id, context)
        duplicates = [
            t
            for t in tasks.all()
            if t.id != task.id
            and not t.is_terminal
            and fingerprint(t.objective, t.role_id) == fp
        ]
        if len(duplicates) >= self.max_duplicate_inflight:
            return GuardDecision(
                False,
                "an identical task is already in flight",
                "duplicate",
                {"task_id": task.id, "duplicates": [t.id for t in duplicates]},
            )

        prior = self._tried.get(fp) or []
        if task.failure_reason and task.failure_reason in prior:
            return GuardDecision(
                False,
                f"the same failure ({task.failure_reason}) was already produced by this exact dispatch; "
                "change the task or the role rather than repeating it",
                "repeated_failure",
                {"task_id": task.id, "failure_reason": task.failure_reason, "tried": prior},
            )

        return GuardDecision(True, "dispatch allowed", "ok", {"task_id": task.id, "fingerprint": fp})

    def record_attempt(self, task: Task, *, context: str = "", failure_reason: Optional[str] = None) -> None:
        """Remember what was tried, so an identical retry can be refused."""
        fp = fingerprint(task.objective, task.role_id, context)
        bucket = self._tried.setdefault(fp, [])
        if failure_reason and failure_reason not in bucket:
            bucket.append(failure_reason)
            if len(bucket) > 12:
                del bucket[: len(bucket) - 12]

    # ------------------------------------------------------------------
    def can_create(self, objective: str, *, role_id: Optional[str] = None, parent_id: Optional[str] = None) -> GuardDecision:
        """Refuse to add a task that duplicates live work."""
        fp = fingerprint(objective, role_id)
        duplicates = [
            t
            for t in self.runtime.tasks.all()
            if not t.is_terminal and fingerprint(t.objective, t.role_id) == fp
        ]
        if duplicates:
            return GuardDecision(
                False,
                "an equivalent task already exists",
                "duplicate_task",
                {"objective": objective, "existing": [t.id for t in duplicates]},
            )
        return GuardDecision(True, "task may be created", "ok", {"objective": objective})

    # ------------------------------------------------------------------
    def objective_health(self) -> Dict[str, Any]:
        """Is the whole run still making progress, or should it stop?"""
        tasks = self.runtime.tasks
        stats = tasks.stats()
        failed = tasks.by_status(TaskStatus.FAILED)
        root_id = self.runtime.run.objective_task_id
        descendants = tasks.descendants(root_id) if root_id else tasks.all()
        workers = [t for t in descendants if "objective" not in (t.tags or [])]
        completed = [t for t in workers if t.status is TaskStatus.COMPLETED]

        stalled = self.stalled_workers()
        reasons: List[str] = []
        should_stop = False

        if len(failed) >= self.max_failures_per_objective:
            should_stop = True
            reasons.append(f"{len(failed)} failures (limit {self.max_failures_per_objective})")
        retryable = [t for t in failed if t.can_retry]
        if failed and not retryable and not any(t.is_active for t in workers):
            should_stop = True
            reasons.append("every remaining failure has exhausted its retry budget")
        if workers and len(completed) == len(workers) and not workers[-1].is_active:
            reasons.append("all planned work completed")

        return {
            "should_stop": should_stop,
            "reasons": reasons,
            "stats": stats,
            "failures": len(failed),
            "retryable_failures": len(retryable),
            "completed": len(completed),
            "workers": len(workers),
            "stalled": stalled,
        }

    def stalled_workers(self) -> List[Dict[str, Any]]:
        """Live children that have gone quiet, from the runtime's own timestamps."""
        live = self.runtime.registry.live_subagents()
        now = time.time()
        out = []
        for r in live:
            started = r.get("started_at")
            if not isinstance(started, (int, float)):
                continue
            age = now - started
            if age > self.stale_seconds:
                out.append(
                    {
                        "subagent_id": r.get("subagent_id"),
                        "goal": r.get("goal"),
                        "running_seconds": round(age, 1),
                        "tool_count": r.get("tool_count"),
                        "model": r.get("model"),
                        "task_id": (
                            self.runtime.tasks.find_by_subagent(r.get("subagent_id")).id
                            if self.runtime.tasks.find_by_subagent(r.get("subagent_id"))
                            else None
                        ),
                    }
                )
        return out

    def snapshot(self) -> Dict[str, Any]:
        return {
            "limits": {
                "max_inflight_per_role": self.max_inflight_per_role,
                "max_duplicate_inflight": self.max_duplicate_inflight,
                "max_failures_per_objective": self.max_failures_per_objective,
                "stale_seconds": self.stale_seconds,
            },
            "objective_health": self.objective_health(),
            "tried_fingerprints": len(self._tried),
        }
