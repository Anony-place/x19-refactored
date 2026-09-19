"""X19 organization runtime.

This is the object that actually holds the organization together at run time.
It owns:

* the event bus (:class:`x19.org.events.EventBus`),
* the task graph (:class:`x19.org.tasks.TaskStore`),
* the agent registry (:class:`x19.org.registry.AgentRegistry`),
* the human-authority gate (:class:`x19.org.authority.AuthorityGate`),
* the current run record (objective, phase, timings).

It is fed by **real** delegation activity: :meth:`record_dispatch` and
:meth:`record_result` are called from the delegation engine's child-run path, so
the task graph mirrors what the runtime actually did.  Nothing here synthesises
progress, completions or agent activity.

The runtime is process-wide but explicitly resettable (profile switches, tests)
and persists under ``X19_HOME/org`` so organizational state outlives a single
conversation turn and survives a restart.
"""

from __future__ import annotations

import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .config import DEFAULT_ORG_SETTINGS, OrgSettings, load_org_settings
from .events import EventBus, EventType, get_event_bus, reset_event_bus
from .registry import AgentRegistry, AgentState
from .roles import BOSS_ROLE_ID, MANAGER_ROLE_ID, RoleKind, get_role, role_catalog
from .tasks import (
    ACTIVE_STATUSES,
    InvalidTransition,
    ReviewState,
    Task,
    TaskPriority,
    TaskStatus,
    TaskStore,
    WAITING_STATUSES,
)

__all__ = [
    "RunRecord",
    "OrganizationRuntime",
    "get_runtime",
    "reset_runtime",
    "set_runtime",
]


class RunRecord:
    """The current run: one user objective and everything executed for it."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.run_id: Optional[str] = None
        self.objective: Optional[str] = None
        self.objective_task_id: Optional[str] = None
        self.project_task_id: Optional[str] = None
        self.started_at: Optional[float] = None
        self.finished_at: Optional[float] = None
        self.phase: str = "idle"
        self.paused: bool = False
        self.stopped: bool = False

    def open(self, objective: str, task_id: str) -> str:
        with self._lock:
            self.run_id = f"x19-run-{uuid.uuid4().hex[:10]}"
            self.objective = objective
            self.objective_task_id = task_id
            self.started_at = time.time()
            self.finished_at = None
            self.phase = "running"
            self.paused = False
            self.stopped = False
            return self.run_id

    def close(self, phase: str = "completed") -> None:
        with self._lock:
            self.finished_at = time.time()
            self.phase = phase

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            elapsed = None
            if self.started_at is not None:
                end = self.finished_at if self.finished_at is not None else time.time()
                elapsed = round(max(0.0, end - self.started_at), 1)
            return {
                "run_id": self.run_id,
                "objective": self.objective,
                "objective_task_id": self.objective_task_id,
                "project_task_id": self.project_task_id,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "elapsed_seconds": elapsed,
                "phase": self.phase,
                "paused": self.paused,
                "stopped": self.stopped,
                "active": self.run_id is not None and self.finished_at is None and not self.stopped,
            }

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "RunRecord":
        rec = cls()
        for key in ("run_id", "objective", "objective_task_id", "project_task_id",
                    "started_at", "finished_at", "phase", "paused", "stopped"):
            if key in raw:
                setattr(rec, key, raw[key])
        return rec


class OrganizationRuntime:
    """Process-wide X19 organization state, wired to the real delegation engine."""

    def __init__(
        self,
        *,
        root: Optional[Path] = None,
        bus: Optional[EventBus] = None,
        registry: Optional[AgentRegistry] = None,
        persist: Optional[bool] = None,
        settings: Optional["OrgSettings"] = None,
    ) -> None:
        from x19.org.config import load_org_settings
        from x19.state.persist import events_path, org_root, state_path

        # Real X19 configuration: state location, persistence, retry budget,
        # staleness window and the roles that need operator sign-off.
        self.settings = settings if settings is not None else load_org_settings()
        if persist is None:
            persist = self.settings.persist
        if root is None and self.settings.state_dir:
            root = Path(self.settings.state_dir).expanduser()
        self._root = Path(root) if root is not None else org_root()
        self._persist = persist
        self.bus = bus if bus is not None else (EventBus(persist_dir=self._root) if persist else EventBus(persist=False))
        self.tasks = TaskStore(
            self.bus,
            persist_path=state_path(self._root) if persist else None,
            default_max_attempts=self.settings.max_attempts,
        )
        self.registry = (
            registry
            if registry is not None
            else AgentRegistry(stale_after_seconds=self.settings.stale_after_seconds)
        )
        self.run = RunRecord()
        self._lock = threading.RLock()
        self._approvals: Dict[str, Dict[str, Any]] = {}
        if persist:
            self._load()

    # ------------------------------------------------------------------
    # persistence
    # ------------------------------------------------------------------
    def _load(self) -> None:
        from x19.state.persist import approvals_path, read_json, run_path

        self.tasks.reload()
        raw_run = read_json(run_path(self._root))
        if isinstance(raw_run, dict):
            self.run = RunRecord.from_dict(raw_run)
        raw_ap = read_json(approvals_path(self._root), default={})
        if isinstance(raw_ap, dict):
            self._approvals = raw_ap

    def _save_run(self) -> None:
        if not self._persist:
            return
        from x19.state.persist import atomic_write_json, run_path

        atomic_write_json(run_path(self._root), self.run.to_dict())

    def _save_approvals(self) -> None:
        if not self._persist:
            return
        from x19.state.persist import approvals_path, atomic_write_json

        atomic_write_json(approvals_path(self._root), self._approvals)

    @property
    def root(self) -> Path:
        return self._root

    # ------------------------------------------------------------------
    # organization construction — X19 -> X22 -> workers
    # ------------------------------------------------------------------
    def accept_objective(
        self,
        objective: str,
        *,
        description: str = "",
        priority: TaskPriority = TaskPriority.NORMAL,
        tags: Optional[Sequence[str]] = None,
    ) -> Task:
        """X19 takes a user objective and opens a run for it."""
        if not objective or not objective.strip():
            raise ValueError("objective must be non-empty")
        root_task = self.tasks.create(
            objective.strip(),
            description=description,
            role_id=BOSS_ROLE_ID,
            manager_id=None,
            priority=priority,
            tags=list(tags or ()) + ["objective"],
        )
        run_id = self.run.open(objective.strip(), root_task.id)
        self.tasks.plan(root_task.id, description=description or objective.strip())
        # X19 owns the objective for the whole run: it is genuinely working it
        # (decomposing, delegating, monitoring) until the graph closes.
        self.tasks.assign(root_task.id, role_id=BOSS_ROLE_ID, manager_id=None, agent_id=BOSS_ROLE_ID)
        self.tasks.start(root_task.id, agent_id=BOSS_ROLE_ID)
        self.registry.mark_active(BOSS_ROLE_ID, task_id=root_task.id, objective=objective.strip())
        self.bus.publish(
            EventType.OBJECTIVE_ACCEPTED,
            f"X19 accepted objective: {objective.strip()[:120]}",
            task_id=root_task.id,
            objective_id=root_task.id,
            role_id=BOSS_ROLE_ID,
            run_id=run_id,
        )
        self._save_run()
        return root_task

    def open_project(
        self,
        objective: str,
        *,
        parent_id: Optional[str] = None,
        manager_id: str = MANAGER_ROLE_ID,
        description: str = "",
        priority: TaskPriority = TaskPriority.NORMAL,
    ) -> Task:
        """X19 delegates an objective to X22, which owns it as a project."""
        parent = parent_id or self.run.objective_task_id
        project = self.tasks.create(
            objective,
            parent_id=parent,
            description=description,
            role_id=manager_id,
            manager_id=BOSS_ROLE_ID,
            priority=priority,
            objective_id=self.run.objective_task_id,
            tags=["project"],
        )
        self.run.project_task_id = project.id
        self.tasks.plan(project.id, description=description)
        self.tasks.assign(project.id, role_id=manager_id, manager_id=BOSS_ROLE_ID, agent_id=manager_id)
        # X22 is coordinating from the moment it owns the project; marking it
        # RUNNING is what the runtime actually does, not a status we wish for.
        self.tasks.start(project.id, agent_id=manager_id)
        self.registry.mark_active(
            manager_id,
            task_id=project.id,
            objective=objective,
        )
        self._save_run()
        return project

    def add_worker_task(
        self,
        objective: str,
        *,
        role_id: str,
        parent_id: Optional[str] = None,
        description: str = "",
        depends_on: Optional[Sequence[str]] = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        requires_approval: bool = False,
        manager_id: str = MANAGER_ROLE_ID,
        tags: Optional[Sequence[str]] = None,
    ) -> Task:
        """X22 turns part of a project into a concrete worker task."""
        role = get_role(role_id)
        if role is None:
            raise ValueError(f"unknown worker role {role_id!r}; registered: {[r.id for r in role_catalog()]}")
        if role.kind is RoleKind.BOSS:
            raise ValueError("the boss role does not execute worker tasks")
        parent = parent_id or self.run.project_task_id or self.run.objective_task_id
        task = self.tasks.create(
            objective,
            parent_id=parent,
            description=description,
            role_id=role_id,
            manager_id=manager_id if role.kind is RoleKind.WORKER else BOSS_ROLE_ID,
            priority=priority,
            depends_on=depends_on,
            requires_approval=requires_approval,
            objective_id=self.run.objective_task_id,
            tags=list(tags or ()),
        )
        self.tasks.plan(task.id, description=description, depends_on=list(depends_on or ()))
        return task

    # ------------------------------------------------------------------
    # real delegation hooks
    # ------------------------------------------------------------------
    def record_dispatch(
        self,
        task_id: str,
        *,
        role_id: str,
        subagent_id: Optional[str] = None,
        delegation_id: Optional[str] = None,
        model: Optional[str] = None,
        goal: Optional[str] = None,
        live_transcript: Optional[str] = None,
        manager_id: Optional[str] = None,
    ) -> Optional[Task]:
        """Called when the delegation engine really spawns a child for a task."""
        task = self.tasks.get(task_id)
        if task is None:
            return None
        with self._lock:
            try:
                if task.status in (TaskStatus.QUEUED, TaskStatus.PLANNED):
                    self.tasks.assign(
                        task_id, role_id=role_id, manager_id=manager_id or task.manager_id, agent_id=role_id
                    )
                self.tasks.start(
                    task_id,
                    agent_id=role_id,
                    subagent_id=subagent_id,
                    delegation_id=delegation_id,
                    live_transcript=live_transcript,
                )
            except InvalidTransition:
                # The task is already past this point (re-dispatch after a steer);
                # record the linkage without forcing an illegal move.
                task.subagent_id = subagent_id or task.subagent_id
                task.delegation_id = delegation_id or task.delegation_id
            self.registry.bind_subagent(
                agent_id=role_id,
                subagent_id=subagent_id or f"pending-{task_id}",
                task_id=task_id,
                objective=goal or task.objective,
                delegation_id=delegation_id,
                model=model,
                live_transcript=live_transcript,
            )
        self.bus.publish(
            EventType.AGENT_STARTED,
            f"{role_id} started on task {task_id}",
            task_id=task_id,
            agent_id=subagent_id,
            role_id=role_id,
            manager_id=manager_id or task.manager_id,
            model=model,
            delegation_id=delegation_id,
        )
        return task

    def record_progress(
        self,
        *,
        subagent_id: Optional[str] = None,
        task_id: Optional[str] = None,
        note: str = "",
        tool_count: Optional[int] = None,
    ) -> None:
        task = self.tasks.get(task_id) if task_id else self.tasks.find_by_subagent(subagent_id)
        if task is None:
            return
        if note:
            self.tasks.progress(task.id, note, source="worker", tool_count=tool_count)
        if task.role_id:
            self.registry.note_activity(task.role_id, tool_count=tool_count)
        self.bus.publish(
            EventType.AGENT_PROGRESS,
            note or "worker progress",
            task_id=task.id,
            agent_id=subagent_id or task.subagent_id,
            role_id=task.role_id,
            tool_count=tool_count,
        )

    def record_result(
        self,
        *,
        task_id: Optional[str] = None,
        subagent_id: Optional[str] = None,
        entry: Optional[Dict[str, Any]] = None,
    ) -> Optional[Task]:
        """Called with the delegation engine's real per-child result entry."""
        entry = entry or {}
        task = self.tasks.get(task_id) if task_id else self.tasks.find_by_subagent(subagent_id)
        if task is None:
            return None
        status = str(entry.get("status") or "").lower()
        role_id = task.role_id or "worker"
        metrics = {
            "duration_seconds": entry.get("duration_seconds"),
            "api_calls": entry.get("api_calls"),
            "input_tokens": (entry.get("tokens") or {}).get("input"),
            "output_tokens": (entry.get("tokens") or {}).get("output"),
            "cost_usd": entry.get("cost_usd"),
            "tool_calls": len(entry.get("tool_trace") or []) or None,
        }
        summary = entry.get("summary") or ""
        with self._lock:
            if status == "completed":
                outputs = [{"kind": "summary", "text": summary, "at": time.time()}]
                if entry.get("schema_valid") is False:
                    outputs.append(
                        {"kind": "schema_violation", "errors": entry.get("schema_errors") or [], "at": time.time()}
                    )
                try:
                    self.tasks.complete(
                        task.id,
                        outputs=outputs,
                        summary=(summary[:400] if summary else None),
                        metrics=metrics,
                        review_required=task.requires_approval,
                    )
                except InvalidTransition:
                    pass
                self.registry.release(role_id, succeeded=True, model=entry.get("model"))
                self.bus.publish(
                    EventType.AGENT_COMPLETED,
                    f"{role_id} completed task {task.id}",
                    task_id=task.id,
                    role_id=role_id,
                    agent_id=subagent_id or task.subagent_id,
                    duration_seconds=metrics["duration_seconds"],
                    exit_reason=entry.get("exit_reason"),
                )
                if entry.get("truncated"):
                    self.tasks.progress(
                        task.id,
                        "worker hit its iteration budget; output is truncated",
                        source="runtime",
                    )
            elif status == "interrupted":
                try:
                    self.tasks.fail(
                        task.id,
                        "interrupted before completion",
                        failure_reason="interrupted",
                        metrics=metrics,
                    )
                except InvalidTransition:
                    pass
                self.registry.release(role_id, succeeded=False, error="interrupted")
                self.bus.publish(
                    EventType.AGENT_INTERRUPTED,
                    f"{role_id} was interrupted on task {task.id}",
                    task_id=task.id,
                    role_id=role_id,
                    agent_id=subagent_id or task.subagent_id,
                )
            else:
                error = entry.get("error") or summary or "worker did not produce a result"
                try:
                    self.tasks.fail(
                        task.id,
                        error[:500],
                        failure_reason=entry.get("failure_reason"),
                        error=error[:2000],
                        metrics=metrics,
                    )
                except InvalidTransition:
                    pass
                self.registry.release(role_id, succeeded=False, error=error[:500], model=entry.get("model"))
                self.bus.publish(
                    EventType.AGENT_FAILED,
                    f"{role_id} failed task {task.id}: {error[:160]}",
                    task_id=task.id,
                    role_id=role_id,
                    agent_id=subagent_id or task.subagent_id,
                    failure_reason=entry.get("failure_reason"),
                )
                blocked = self.tasks.cascade_failure(task.id, error[:200])
                if blocked:
                    self.bus.publish(
                        EventType.ESCALATION,
                        f"{len(blocked)} dependent task(s) blocked by the failure of {task.id}",
                        task_id=task.id,
                        role_id=role_id,
                        blocked=blocked,
                    )
        self._maybe_close_run()
        return task

    def reconcile(self) -> None:
        """Derive the closure of structural tasks from the real task graph.

        Called before every projection so a status read can never show a project
        or an objective as running after all of the work beneath it finished.
        This derives state; it invents none — a structural task closes only when
        every task under it has reached a terminal state.
        """
        self._maybe_close_project()
        self._maybe_close_run()

    def _maybe_close_project(self) -> None:
        """Complete X22's project task when every task under it is terminal."""
        project_id = self.run.project_task_id
        if not project_id:
            return
        project = self.tasks.get(project_id)
        if project is None or project.is_terminal:
            return
        children = self.tasks.descendants(project_id)
        if not children:
            return
        if all(c.is_terminal for c in children):
            failed = [c for c in children if c.status is TaskStatus.FAILED]
            try:
                if failed:
                    self.tasks.fail(
                        project_id,
                        f"{len(failed)} of {len(children)} task(s) failed",
                        failure_reason="subtask_failure",
                    )
                else:
                    self.tasks.complete(
                        project_id,
                        summary=f"all {len(children)} task(s) reached a terminal state",
                    )
                self.registry.release(
                    project.role_id or MANAGER_ROLE_ID,
                    succeeded=not failed,
                    error=(f"{len(failed)} subtask(s) failed" if failed else None),
                )
            except InvalidTransition:
                pass

    def _maybe_close_run(self) -> None:
        """Close the run only when the real task graph says everything is done.

        Activity is measured over the objective's descendants, never over the
        global counters — the objective task itself is active for the whole run
        and must not block its own closure.
        """
        self._maybe_close_project()
        root_id = self.run.objective_task_id
        if not root_id:
            return
        root = self.tasks.get(root_id)
        if root is None or root.is_terminal:
            return
        descendants = self.tasks.descendants(root_id)
        if not descendants:
            return
        work = [t for t in descendants if t.id != self.run.project_task_id]
        unfinished = [t for t in work if not t.is_terminal]
        in_flight = [
            t for t in descendants
            if t.status in ACTIVE_STATUSES or t.status in WAITING_STATUSES
        ]
        if unfinished or in_flight:
            return

        failed = [t for t in work if t.status is TaskStatus.FAILED]
        cancelled = [t for t in work if t.status is TaskStatus.CANCELLED]
        if failed:
            summary = f"{len(failed)} of {len(work)} task(s) failed"
            if cancelled:
                summary += f"; {len(cancelled)} abandoned"
        else:
            summary = f"all {len(work)} task(s) completed"
        try:
            self.tasks.complete(root_id, summary=summary)
        except InvalidTransition:
            return
        self.registry.release(BOSS_ROLE_ID, succeeded=not failed)
        phase = "completed_with_failures" if failed else "completed"
        self.run.close(phase)
        self._save_run()
        self.bus.publish(
            EventType.WORKFLOW_COMPLETED,
            f"workflow {phase}",
            task_id=root_id,
            objective_id=root_id,
            role_id=BOSS_ROLE_ID,
            phase=phase,
            summary=summary,
        )

    # ------------------------------------------------------------------
    # human authority
    # ------------------------------------------------------------------
    def request_approval(
        self,
        task_id: str,
        question: str,
        *,
        options: Optional[Sequence[str]] = None,
        raised_by: Optional[str] = None,
        risk: str = "unspecified",
    ) -> Dict[str, Any]:
        """Pause a task and ask the human.  Never auto-approves."""
        approval_id = f"ap-{uuid.uuid4().hex[:8]}"
        record = {
            "id": approval_id,
            "task_id": task_id,
            "question": question,
            "options": list(options or ()),
            "raised_by": raised_by,
            "risk": risk,
            "requested_at": time.time(),
            "resolved_at": None,
            "decision": None,
            "decided_by": None,
            "note": None,
        }
        with self._lock:
            self._approvals[approval_id] = record
        self.tasks.block(task_id, question, requires_approval=True, blocker_id=approval_id)
        self._save_approvals()
        self.bus.publish(
            EventType.APPROVAL_REQUESTED,
            question,
            task_id=task_id,
            role_id=raised_by,
            approval_id=approval_id,
            risk=risk,
        )
        return record

    def resolve_approval(
        self,
        approval_id: str,
        *,
        approved: bool,
        decided_by: str = "operator",
        note: str = "",
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            record = self._approvals.get(approval_id)
            if record is None:
                return None
            record["resolved_at"] = time.time()
            record["decision"] = "approved" if approved else "denied"
            record["decided_by"] = decided_by
            record["note"] = note or None
            task_id = record.get("task_id")
        task = self.tasks.get(task_id) if task_id else None
        if task is not None:
            if approved:
                if task.status is TaskStatus.IN_REVIEW:
                    # Approval of a delivered output: the work counts as done.
                    self.tasks.review(task_id, approved=True, reviewer=decided_by, note=note)
                elif task.status is TaskStatus.WAITING_APPROVAL:
                    # Approval of a pre-dispatch gate: release the task to run.
                    self.tasks.unblock(
                        task_id, blocker_id=approval_id,
                        resolution=note or f"approved by {decided_by}",
                    )
                task.review_state = ReviewState.APPROVED
                task.reviewed_by = decided_by
                task.reviewed_at = time.time()
                task.review_note = note or None
            else:
                self.tasks.fail(
                    task_id, note or "operator denied the request", failure_reason="approval_denied"
                )
        self._save_approvals()
        self.bus.publish(
            EventType.APPROVAL_RESOLVED,
            f"approval {approval_id} {'approved' if approved else 'denied'} by {decided_by}",
            task_id=task_id,
            approval_id=approval_id,
            approved=approved,
        )
        return record

    def pending_approvals(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [r for r in self._approvals.values() if not r.get("resolved_at")]

    def pause(self, *, reason: str = "operator pause") -> bool:
        """Real pause: blocks NEW spawns in the delegation engine."""
        self.run.paused = True
        self._save_run()
        ok = _set_spawn_paused(True)
        self.bus.publish(EventType.OPERATOR_PAUSE, reason, role_id=BOSS_ROLE_ID, enforced=ok)
        return ok

    def resume(self, *, reason: str = "operator resume") -> bool:
        self.run.paused = False
        self._save_run()
        ok = _set_spawn_paused(False)
        self.bus.publish(EventType.OPERATOR_RESUME, reason, role_id=BOSS_ROLE_ID, enforced=ok)
        return ok

    def stop(self, *, reason: str = "operator stop") -> List[str]:
        """Stop the run: cancel everything not terminal.  Returns cancelled ids."""
        cancelled: List[str] = []
        for task in self.tasks.all():
            if task.is_terminal:
                continue
            try:
                self.tasks.cancel(task.id, reason)
                cancelled.append(task.id)
            except InvalidTransition:
                continue
        self.run.stopped = True
        self.run.close("stopped")
        self._save_run()
        _set_spawn_paused(True)
        self.bus.publish(EventType.OPERATOR_STOP, reason, role_id=BOSS_ROLE_ID, cancelled=len(cancelled))
        return cancelled

    # ------------------------------------------------------------------
    # projection
    # ------------------------------------------------------------------
    def snapshot(self) -> Dict[str, Any]:
        """Everything the UI, the RPC layer and the audit report consume."""
        self.reconcile()
        registry = self.registry.snapshot()
        stats = self.tasks.stats()
        root_id = self.run.objective_task_id
        return {
            "run": self.run.to_dict(),
            "tasks": {
                "stats": stats,
                "tree": self.tasks.tree(root_id) if root_id else self.tasks.tree(),
                "ready": [t.to_dict() for t in self.tasks.ready_tasks()],
                "blocked": [
                    {
                        **t.to_dict(),
                        "blocking_dependencies": self.tasks.blocking_dependencies(t.id),
                    }
                    for t in self.tasks.by_status(
                        TaskStatus.BLOCKED, TaskStatus.WAITING_DEPENDENCY, TaskStatus.WAITING_APPROVAL
                    )
                ],
                "failed": [t.to_dict() for t in self.tasks.by_status(TaskStatus.FAILED)],
                "in_review": [t.to_dict() for t in self.tasks.by_status(TaskStatus.IN_REVIEW)],
                "completed": [t.to_dict() for t in self.tasks.by_status(TaskStatus.COMPLETED)],
            },
            "agents": registry,
            "roles": [r.to_dict() for r in role_catalog()],
            "events": [e.to_dict() for e in self.bus.recent(60)],
            "approvals": self.pending_approvals(),
            "generated_at": time.time(),
        }


def _set_spawn_paused(paused: bool) -> bool:
    try:
        from tools.delegate_tool_registry import set_spawn_paused

        return bool(set_spawn_paused(paused))
    except Exception:
        return False


_RUNTIME: Optional[OrganizationRuntime] = None
_RUNTIME_LOCK = threading.Lock()


def get_runtime(*, persist: Optional[bool] = None) -> OrganizationRuntime:
    """Process-wide organization runtime (settings come from real config)."""
    global _RUNTIME
    with _RUNTIME_LOCK:
        if _RUNTIME is None:
            _RUNTIME = OrganizationRuntime(persist=persist)
        return _RUNTIME


def set_runtime(runtime: Optional[OrganizationRuntime]) -> None:
    global _RUNTIME
    with _RUNTIME_LOCK:
        _RUNTIME = runtime


def reset_runtime(*, root: Optional[Path] = None, persist: Optional[bool] = None) -> OrganizationRuntime:
    """Build a fresh runtime (profile switch, tests, ``/org reset``)."""
    global _RUNTIME
    with _RUNTIME_LOCK:
        _RUNTIME = OrganizationRuntime(root=root, persist=persist)
        return _RUNTIME
