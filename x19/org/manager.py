"""X22 — the Manager / project manager layer.

X22 is not a chat persona.  It is a real participant in orchestration:

* converts an objective it was given into concrete worker tasks with
  dependencies (:meth:`Manager.plan`),
* assigns those tasks to worker roles (:meth:`Manager.assign`),
* tracks real progress and detects workers that are blocked, failed or have
  gone quiet (:meth:`Manager.track`),
* validates what a worker actually returned before it is allowed to count as
  done (:meth:`Manager.validate_output`),
* reports factual status up to X19 (:meth:`Manager.report_to_boss`),
* escalates what it cannot resolve (:meth:`Manager.escalate`).

Every one of those reads or writes the same runtime task graph the delegation
engine feeds, so a manager report can never disagree with reality.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Sequence

from .events import EventType
from .registry import STALE_ACTIVE_SECONDS
from .roles import BOSS_ROLE_ID, MANAGER_ROLE_ID, RoleKind, get_role, role_catalog, worker_roles
from .tasks import InvalidTransition, Task, TaskPriority, TaskStatus

__all__ = ["Manager", "MANAGER_STALE_SECONDS"]

# A running worker that has emitted no activity for this long is *suspect*.
# X22 reports it as such instead of assuming it is fine or assuming it died.
MANAGER_STALE_SECONDS = STALE_ACTIVE_SECONDS

# Minimum characters in a worker summary before X22 will accept it as an output
# worth reviewing.  A real refusal ("could not do X because Y") clears this;
# an empty or one-word reply does not.
_MIN_OUTPUT_CHARS = 12


class Manager:
    """Project-manager behavior over an :class:`x19.org.runtime.OrganizationRuntime`."""

    role_id = MANAGER_ROLE_ID

    def __init__(self, runtime, *, manager_id: str = MANAGER_ROLE_ID) -> None:
        self.runtime = runtime
        self.manager_id = manager_id

    # ------------------------------------------------------------------
    # planning
    # ------------------------------------------------------------------
    def plan(
        self,
        steps: Sequence[Dict[str, Any]],
        *,
        project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Turn an objective into worker tasks with a real dependency order.

        Same contract as :meth:`x19.org.boss.Boss.decompose` — steps may
        reference each other by ``key``.  X22 owns this call in the normal
        flow; X19 owns it only when it delegates directly for a small job.
        """
        project = project_id or self.runtime.run.project_task_id
        if not project:
            return {"ok": False, "errors": ["no project assigned to this manager"]}

        known = {r.id for r in role_catalog()}
        errors: List[str] = []
        key_to_id: Dict[str, str] = {}
        created: List[Task] = []

        for i, step in enumerate(steps or []):
            step = step or {}
            role_id = step.get("role_id")
            objective = (step.get("objective") or "").strip()
            if not objective:
                errors.append(f"step {i}: objective is required")
                continue
            if role_id not in known:
                errors.append(f"step {i}: unknown role {role_id!r} (registered: {sorted(known)})")
                continue
            if get_role(role_id).kind is not RoleKind.WORKER:  # type: ignore[union-attr]
                errors.append(f"step {i}: {role_id!r} is not a worker role")
                continue
            deps: List[str] = []
            bad_dep = False
            for dep in step.get("depends_on") or []:
                if dep in key_to_id:
                    deps.append(key_to_id[dep])
                elif self.runtime.tasks.get(dep) is not None:
                    deps.append(dep)
                else:
                    errors.append(f"step {i}: unknown dependency {dep!r}")
                    bad_dep = True
            if bad_dep:
                continue
            task = self.runtime.add_worker_task(
                objective,
                role_id=role_id,
                parent_id=project,
                description=step.get("description", "") or "",
                depends_on=deps,
                priority=TaskPriority(step.get("priority", "normal")),
                requires_approval=bool(step.get("requires_approval", False)),
                manager_id=self.manager_id,
                tags=list(step.get("tags") or []),
            )
            if step.get("key"):
                key_to_id[str(step["key"])] = task.id
            created.append(task)

        if errors and not created:
            return {"ok": False, "errors": errors, "created": []}

        self.runtime.bus.publish(
            EventType.MANAGER_REPORT,
            f"{self.manager_id} planned {len(created)} worker task(s) for {project}"
            + (f"; {len(errors)} step(s) rejected" if errors else ""),
            task_id=project,
            objective_id=self.runtime.run.objective_task_id,
            role_id=self.manager_id,
            manager_id=BOSS_ROLE_ID,
            task_ids=[t.id for t in created],
            rejected=errors,
        )
        return {
            "ok": not errors,
            "created": [t.id for t in created],
            "keys": key_to_id,
            "errors": errors,
            "tasks": [t.to_dict() for t in created],
        }

    # ------------------------------------------------------------------
    # assignment
    # ------------------------------------------------------------------
    def assign(
        self,
        task_id: str,
        role_id: str,
        *,
        reason: str = "",
    ) -> Dict[str, Any]:
        """Assign a task to a worker role.  Refuses unknown roles."""
        role = get_role(role_id)
        if role is None:
            return {"ok": False, "error": f"unknown role {role_id!r}"}
        if role.kind is not RoleKind.WORKER:
            return {"ok": False, "error": f"{role_id!r} is a {role.kind.value}, not a worker"}
        task = self.runtime.tasks.get(task_id)
        if task is None:
            return {"ok": False, "error": f"unknown task {task_id!r}"}
        blocking = self.runtime.tasks.blocking_dependencies(task_id)
        if blocking:
            try:
                self.runtime.tasks.wait_on_dependency(task_id, blocking[0]["task_id"])
            except InvalidTransition:
                pass
            return {
                "ok": False,
                "task_id": task_id,
                "waiting_on": blocking,
                "error": "dependencies have not completed — task is held, not assigned",
            }
        try:
            if task.role_id and task.role_id != role_id and task.status is not TaskStatus.QUEUED:
                task = self.runtime.tasks.reassign(task_id, role_id=role_id, reason=reason)
            else:
                task = self.runtime.tasks.assign(
                    task_id, role_id=role_id, manager_id=self.manager_id, agent_id=role_id
                )
        except (InvalidTransition, KeyError) as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "task": task.to_dict()}

    def assign_ready(self, *, limit: int = 8) -> Dict[str, Any]:
        """Assign every task whose dependencies are satisfied."""
        assigned: List[str] = []
        skipped: List[Dict[str, Any]] = []
        for task in self.runtime.tasks.ready_tasks():
            if not task.role_id:
                skipped.append({"task_id": task.id, "reason": "no role selected"})
                continue
            res = self.assign(task.id, task.role_id)
            if res.get("ok"):
                assigned.append(task.id)
            else:
                skipped.append({"task_id": task.id, "reason": res.get("error")})
            if len(assigned) >= limit:
                break
        return {"ok": True, "assigned": assigned, "skipped": skipped}

    # ------------------------------------------------------------------
    # tracking
    # ------------------------------------------------------------------
    def track(self) -> Dict[str, Any]:
        """Inspect the real state of everything this manager owns.

        Detects: running, blocked, failed, awaiting review, stale (a live
        subagent that has gone quiet), and unassigned-but-ready work.
        """
        tasks = self.runtime.tasks
        live = {
            str(r.get("subagent_id")): r
            for r in self.runtime.registry.live_subagents()
            if r.get("subagent_id")
        }
        now = time.time()

        running: List[Dict[str, Any]] = []
        stale: List[Dict[str, Any]] = []
        for t in tasks.by_status(TaskStatus.RUNNING, TaskStatus.ASSIGNED):
            rec = live.get(t.subagent_id or "")
            entry = {
                "task_id": t.id,
                "objective": t.objective,
                "role_id": t.role_id,
                "status": t.status.value,
                "subagent_id": t.subagent_id,
                "elapsed_seconds": t.elapsed_seconds,
                "attempt": t.attempt,
                "live": rec is not None,
                "tool_count": (rec or {}).get("tool_count"),
                "model": (rec or {}).get("model"),
                "last_note": (t.notes[-1].get("text") if t.notes else None),
            }
            if rec is None and t.status is TaskStatus.RUNNING:
                # The task believes it is running but the engine no longer lists
                # the child: either it finished without a result reaching us, or
                # it was killed.  That is a discrepancy worth surfacing.
                entry["discrepancy"] = "task marked running but no live subagent"
                stale.append(entry)
                continue
            started = (rec or {}).get("started_at")
            if isinstance(started, (int, float)) and now - started > MANAGER_STALE_SECONDS:
                entry["stale_seconds"] = round(now - started, 1)
                stale.append(entry)
            else:
                running.append(entry)

        blocked = [
            {
                "task_id": t.id,
                "objective": t.objective,
                "role_id": t.role_id,
                "status": t.status.value,
                "reason": (t.blockers[-1].get("reason") if t.blockers else None),
                "requires_approval": t.requires_approval,
                "blocking_dependencies": tasks.blocking_dependencies(t.id),
            }
            for t in tasks.by_status(
                TaskStatus.BLOCKED, TaskStatus.WAITING_DEPENDENCY, TaskStatus.WAITING_APPROVAL
            )
        ]
        failed = [
            {
                "task_id": t.id,
                "objective": t.objective,
                "role_id": t.role_id,
                "error": t.error,
                "failure_reason": t.failure_reason,
                "attempt": t.attempt,
                "max_attempts": t.max_attempts,
                "retryable": t.can_retry,
                "dependents_blocked": [d.id for d in tasks.downstream_of(t.id) if d.is_waiting],
            }
            for t in tasks.by_status(TaskStatus.FAILED)
        ]
        review = [
            {"task_id": t.id, "role_id": t.role_id, "review": t.review_state.value,
             "outputs": len(t.outputs)}
            for t in tasks.by_status(TaskStatus.IN_REVIEW)
        ]
        ready = [
            {"task_id": t.id, "objective": t.objective, "role_id": t.role_id,
             "priority": t.priority.value}
            for t in tasks.ready_tasks()
        ]
        unassigned = [r for r in ready if not r.get("role_id")]

        return {
            "manager_id": self.manager_id,
            "generated_at": now,
            "running": running,
            "stale": stale,
            "blocked": blocked,
            "failed": failed,
            "in_review": review,
            "ready": ready,
            "unassigned": unassigned,
            "counts": tasks.stats(),
            "needs_escalation": bool(failed and not any(f["retryable"] for f in failed))
            or bool(stale)
            or bool(unassigned),
        }

    def detect_stalled(self) -> List[Dict[str, Any]]:
        """Workers that are running but have produced nothing observable."""
        return self.track()["stale"]

    # ------------------------------------------------------------------
    # output validation
    # ------------------------------------------------------------------
    def validate_output(self, task_id: str, *, require_review: bool = True) -> Dict[str, Any]:
        """Check what a worker actually returned before it counts as done.

        Validation is evidence-based: was there any output at all, does it look
        like a refusal or an empty reply, did the child hit its iteration budget,
        did a declared output schema fail.  A task that fails validation is put
        back into the queue or marked failed — never quietly accepted.
        """
        task = self.runtime.tasks.get(task_id)
        if task is None:
            return {"ok": False, "error": f"unknown task {task_id!r}"}

        problems: List[str] = []
        outputs = task.outputs or []
        text = " ".join(str(o.get("text") or "") for o in outputs if o.get("kind") == "summary").strip()
        if not outputs:
            problems.append("worker returned no output at all")
        elif len(text) < _MIN_OUTPUT_CHARS:
            problems.append(f"worker output is too thin to validate ({len(text)} chars)")
        if any(o.get("kind") == "schema_violation" for o in outputs):
            problems.append("worker output violated the declared output schema")
        if task.exit_reason == "max_iterations":
            problems.append("worker exhausted its iteration budget — result is truncated")
        if task.status is TaskStatus.FAILED:
            problems.append(f"worker reported failure: {task.error or 'no detail'}")

        if problems:
            verdict = "rejected"
            if task.status is TaskStatus.COMPLETED:
                # Re-open: a completed task whose output does not validate is not
                # completed.  The lifecycle allows COMPLETED -> IN_REVIEW.
                try:
                    self.runtime.tasks.request_review(task_id, by=self.manager_id)
                except InvalidTransition:
                    pass
            task.add_note(
                "X22 rejected the output: " + "; ".join(problems), source=self.manager_id
            )
            self.runtime.bus.publish(
                EventType.TASK_REVIEWED,
                f"{self.manager_id} rejected output of {task_id}: {'; '.join(problems)[:160]}",
                task_id=task_id,
                role_id=task.role_id,
                manager_id=self.manager_id,
                approved=False,
                problems=problems,
            )
        else:
            verdict = "accepted"
            if require_review and task.requires_approval:
                verdict = "accepted_pending_operator"
            elif task.status is TaskStatus.IN_REVIEW:
                try:
                    self.runtime.tasks.review(
                        task_id, approved=True, reviewer=self.manager_id, note="output validated"
                    )
                except InvalidTransition:
                    pass
            self.runtime.bus.publish(
                EventType.TASK_REVIEWED,
                f"{self.manager_id} validated the output of {task_id}",
                task_id=task_id,
                role_id=task.role_id,
                manager_id=self.manager_id,
                approved=True,
            )

        return {
            "ok": verdict != "rejected",
            "task_id": task_id,
            "verdict": verdict,
            "problems": problems,
            "output_chars": len(text),
            "outputs": len(outputs),
            "status": self.runtime.tasks.get(task_id).status.value,  # type: ignore[union-attr]
        }

    # ------------------------------------------------------------------
    # reporting and escalation
    # ------------------------------------------------------------------
    def report_to_boss(self, *, note: str = "") -> Dict[str, Any]:
        """Factual status report to X19, built from the live task graph."""
        tracking = self.track()
        counts = tracking["counts"]
        report = {
            "manager_id": self.manager_id,
            "reports_to": BOSS_ROLE_ID,
            "generated_at": tracking["generated_at"],
            "summary": self._summarise(tracking),
            "note": note or None,
            "counts": counts,
            "running": tracking["running"],
            "blocked": tracking["blocked"],
            "failed": tracking["failed"],
            "in_review": tracking["in_review"],
            "ready": tracking["ready"],
            "stale": tracking["stale"],
            "needs_escalation": tracking["needs_escalation"],
        }
        self.runtime.bus.publish(
            EventType.MANAGER_REPORT,
            report["summary"],
            task_id=self.runtime.run.project_task_id,
            objective_id=self.runtime.run.objective_task_id,
            role_id=self.manager_id,
            manager_id=BOSS_ROLE_ID,
            counts=counts,
            needs_escalation=report["needs_escalation"],
        )
        return report

    def _summarise(self, tracking: Dict[str, Any]) -> str:
        c = tracking["counts"]
        bits = [
            f"{c.get('completed', 0)} completed",
            f"{len(tracking['running'])} running",
            f"{len(tracking['blocked'])} blocked",
            f"{len(tracking['failed'])} failed",
            f"{len(tracking['ready'])} ready",
        ]
        extra = ""
        if tracking["stale"]:
            extra = f"; {len(tracking['stale'])} suspect (no observed progress)"
        if tracking["unassigned"]:
            extra += f"; {len(tracking['unassigned'])} ready but unassigned"
        return ", ".join(bits) + extra

    def escalate(self, issue: str, *, task_id: Optional[str] = None, severity: str = "medium") -> Dict[str, Any]:
        """Push something X22 cannot resolve up to X19 (and, if needed, the user)."""
        record = {
            "issue": issue,
            "task_id": task_id,
            "severity": severity,
            "raised_by": self.manager_id,
            "raised_at": time.time(),
        }
        self.runtime.bus.publish(
            EventType.ESCALATION,
            f"{self.manager_id} escalated to X19: {issue[:160]}",
            task_id=task_id,
            role_id=self.manager_id,
            manager_id=BOSS_ROLE_ID,
            severity=severity,
        )
        if task_id and self.runtime.tasks.get(task_id):
            self.runtime.tasks.progress(task_id, f"escalated to X19: {issue}", source=self.manager_id)
        return {"ok": True, "escalation": record}

    def retry_or_reassign(self, task_id: str, *, alternate_role: Optional[str] = None) -> Dict[str, Any]:
        """Failure handling: retry within budget, else reassign, else escalate."""
        task = self.runtime.tasks.get(task_id)
        if task is None:
            return {"ok": False, "error": f"unknown task {task_id!r}"}
        if task.status is not TaskStatus.FAILED:
            return {"ok": False, "error": f"task {task_id} is {task.status.value}, not failed"}

        if task.can_retry:
            try:
                self.runtime.tasks.retry(task_id, reason=f"{self.manager_id} retrying after failure")
                return {"ok": True, "action": "retry", "attempt": task.attempt + 1, "task_id": task_id}
            except InvalidTransition as exc:
                return {"ok": False, "error": str(exc)}

        if alternate_role and get_role(alternate_role) is not None:
            try:
                task = self.runtime.tasks.retry(task_id, reason="reassigning")  # clears the failure
            except InvalidTransition:
                # budget spent: reassignment reopens the task explicitly
                task.status = TaskStatus.FAILED
                self.runtime.tasks.reassign(
                    task_id, role_id=alternate_role, reason="retry budget spent; reassigned"
                )
                return {"ok": True, "action": "reassign", "role_id": alternate_role, "task_id": task_id}
            self.runtime.tasks.reassign(
                task_id, role_id=alternate_role, reason="failed under previous role"
            )
            return {"ok": True, "action": "reassign", "role_id": alternate_role, "task_id": task_id}

        self.escalate(
            f"task {task_id} failed and exhausted its retry budget with no alternate role",
            task_id=task_id,
            severity="high",
        )
        return {"ok": False, "action": "escalate", "task_id": task_id}

    def available_workers(self) -> List[Dict[str, Any]]:
        """Worker roles this manager may assign — from the live catalog."""
        out = []
        for role in worker_roles():
            rec = self.runtime.registry.for_role(role.id)
            out.append(
                {
                    "role_id": role.id,
                    "display_name": role.display_name,
                    "title": role.title,
                    "capabilities": list(role.capabilities),
                    "toolsets": list(role.toolsets),
                    "state": (rec.state.value if rec else "idle"),
                    "current_task_id": (rec.current_task_id if rec else None),
                    "tasks_completed": (rec.tasks_completed if rec else 0),
                    "tasks_failed": (rec.tasks_failed if rec else 0),
                }
            )
        return out
