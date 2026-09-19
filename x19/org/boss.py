"""X19 — the Boss / executive orchestrator.

X19 owns the user's objective.  It decomposes, delegates, monitors, resolves
blockers, reassigns, reviews and synthesises.  It does not do the work itself.

The intelligence (what the plan *is*) comes from the model driving X19; this
module owns the **mechanism**: turning a declared plan into real tasks in the
runtime graph, and turning real runtime state into the answers X19 gives the
user.  Nothing here invents a plan, a result or a progress figure.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Sequence

from .audit import build_audit, render_audit
from .events import EventType
from .roles import BOSS_ROLE_ID, MANAGER_ROLE_ID, RoleKind, get_role, role_catalog, worker_roles
from .status import build_status, render_status
from .tasks import InvalidTransition, Task, TaskPriority, TaskStatus

__all__ = ["Boss"]


class Boss:
    """Executive orchestration over an :class:`x19.org.runtime.OrganizationRuntime`."""

    role_id = BOSS_ROLE_ID

    def __init__(self, runtime) -> None:
        self.runtime = runtime

    # ------------------------------------------------------------------
    # objective intake and decomposition
    # ------------------------------------------------------------------
    def accept_objective(
        self,
        objective: str,
        *,
        description: str = "",
        priority: TaskPriority = TaskPriority.NORMAL,
        tags: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Take a user objective, open a run, and hand it to X22 as a project."""
        root = self.runtime.accept_objective(
            objective, description=description, priority=priority, tags=tags
        )
        project = self.runtime.open_project(
            objective,
            parent_id=root.id,
            description=description,
            priority=priority,
        )
        return {
            "objective_task_id": root.id,
            "project_task_id": project.id,
            "manager": MANAGER_ROLE_ID,
            "state": self.runtime.run.to_dict(),
        }

    def decompose(
        self,
        steps: Sequence[Dict[str, Any]],
        *,
        project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Materialise a declared plan as real tasks with real dependencies.

        Each step is ``{objective, role_id, depends_on?, description?,
        priority?, requires_approval?, tags?}``.  ``depends_on`` may reference
        either a real task id or a step's own ``key`` — keys are resolved to ids
        so a plan can be declared in one pass.

        Unknown roles are rejected rather than silently re-routed: a plan that
        names a capability the organization does not have is a plan that cannot
        be executed, and pretending otherwise is how fake progress starts.
        """
        project = project_id or self.runtime.run.project_task_id
        if not project:
            raise ValueError("no project to decompose into — call accept_objective first")

        known = {r.id for r in role_catalog()}
        errors: List[str] = []
        for i, step in enumerate(steps):
            role_id = (step or {}).get("role_id")
            if role_id not in known:
                errors.append(f"step {i}: unknown role {role_id!r} (registered: {sorted(known)})")
            elif get_role(role_id).kind is RoleKind.BOSS:  # type: ignore[union-attr]
                errors.append(f"step {i}: the boss role cannot be assigned a worker task")
            if not (step or {}).get("objective", "").strip():
                errors.append(f"step {i}: objective is required")
        if errors:
            return {"ok": False, "errors": errors, "created": []}

        key_to_id: Dict[str, str] = {}
        created: List[Task] = []
        for i, step in enumerate(steps):
            deps: List[str] = []
            for dep in step.get("depends_on") or []:
                if dep in key_to_id:
                    deps.append(key_to_id[dep])
                elif self.runtime.tasks.get(dep) is not None:
                    deps.append(dep)
                else:
                    errors.append(f"step {i}: unknown dependency {dep!r}")
            if errors:
                return {"ok": False, "errors": errors, "created": [t.id for t in created]}
            task = self.runtime.add_worker_task(
                step["objective"].strip(),
                role_id=step["role_id"],
                parent_id=project,
                description=step.get("description", "") or "",
                depends_on=deps,
                priority=TaskPriority(step.get("priority", "normal")),
                requires_approval=bool(step.get("requires_approval", False)),
                tags=list(step.get("tags") or []),
            )
            key = step.get("key")
            if key:
                key_to_id[str(key)] = task.id
            created.append(task)

        self.runtime.bus.publish(
            EventType.TASK_PLANNED,
            f"X19 decomposed the objective into {len(created)} worker task(s)",
            task_id=project,
            objective_id=self.runtime.run.objective_task_id,
            role_id=BOSS_ROLE_ID,
            manager_id=MANAGER_ROLE_ID,
            task_ids=[t.id for t in created],
        )
        return {
            "ok": True,
            "created": [t.id for t in created],
            "keys": key_to_id,
            "tasks": [t.to_dict() for t in created],
        }

    def delegate_to_manager(self, objective: str, *, description: str = "") -> Dict[str, Any]:
        """Open an additional X22 project under the current objective (multi-team)."""
        project = self.runtime.open_project(objective, description=description)
        return {"ok": True, "project_task_id": project.id, "manager": MANAGER_ROLE_ID}

    # ------------------------------------------------------------------
    # monitoring — always real state
    # ------------------------------------------------------------------
    def status(self, *, event_limit: int = 12) -> Dict[str, Any]:
        return build_status(self.runtime, event_limit=event_limit)

    def status_text(self, *, width: int = 78) -> str:
        return render_status(self.status(), width=width)

    def audit(self, *, include_outputs: bool = True) -> Dict[str, Any]:
        report = build_audit(self.runtime, include_outputs=include_outputs)
        self.runtime.bus.publish(
            EventType.BOSS_AUDIT,
            f"executive audit: {report['overall_state']}, phase {report['phase'].get('label')}",
            task_id=self.runtime.run.objective_task_id,
            objective_id=self.runtime.run.objective_task_id,
            role_id=BOSS_ROLE_ID,
            overall_state=report["overall_state"],
            phase=report["phase"].get("label"),
            counts=report["counts"],
        )
        return report

    def audit_text(self, *, width: int = 92) -> str:
        return render_audit(self.audit())

    def answer(self, question: str) -> Dict[str, Any]:
        """Answer an operator's status question from real runtime state.

        The question selects *which* slice of state to report; it never selects
        a fabricated answer.  Anything the runtime has not observed is reported
        as not observed.
        """
        q = (question or "").lower()
        status = self.status()

        def _payload(kind: str, **extra: Any) -> Dict[str, Any]:
            return {"kind": kind, "question": question, "generated_at": time.time(), **extra}

        if any(w in q for w in ("blocked", "blocker", "stuck", "why is", "kyon", "kyu")):
            return _payload(
                "blocked",
                blocked=status["blocked"],
                pending_approvals=status["pending_approvals"],
                summary=(
                    f"{len(status['blocked'])} task(s) blocked; "
                    f"{len(status['pending_approvals'])} awaiting your decision"
                ),
            )
        if any(w in q for w in ("fail", "error", "crash")):
            return _payload("failures", failed=status["failed"], counts=status["counts"])
        if any(w in q for w in ("who", "which agent", "kaun", "worker", "x22", "manager")):
            return _payload(
                "agents",
                active_agents=status["active_agents"],
                live_subagents=status["live_subagents"],
                manager=status["manager"],
            )
        if any(w in q for w in ("done", "complete", "finish", "ho gaya", "hua")):
            return _payload("completed", completed=status["completed"], counts=status["counts"])
        if any(w in q for w in ("remain", "left", "pending", "next", "baaki")):
            return _payload("remaining", ready=status["ready"], next_actions=status["next_actions"],
                            counts=status["counts"])
        if any(w in q for w in ("audit", "report", "full", "overview", "poora")):
            return _payload("audit", audit=self.audit())
        return _payload(
            "status",
            phase=status["phase"],
            overall_state=status["overall_state"],
            counts=status["counts"],
            manager=status["manager"],
            active_agents=status["active_agents"],
            blocked=status["blocked"],
            failed=status["failed"],
            ready=status["ready"],
            next_actions=status["next_actions"],
            recent_events=status["recent_events"],
        )

    # ------------------------------------------------------------------
    # intervention
    # ------------------------------------------------------------------
    def resolve_blocker(self, task_id: str, *, resolution: str = "") -> Dict[str, Any]:
        task = self.runtime.tasks.get(task_id)
        if task is None:
            return {"ok": False, "error": f"unknown task {task_id!r}"}
        if task.requires_approval and task.review_state.value != "approved":
            return {
                "ok": False,
                "error": "this blocker needs an operator decision, not a boss override",
                "pending_approvals": self.runtime.pending_approvals(),
            }
        try:
            self.runtime.tasks.unblock(task_id, resolution=resolution or "boss resolved the blocker")
        except InvalidTransition as exc:
            return {"ok": False, "error": str(exc)}
        self.runtime.bus.publish(
            EventType.ESCALATION,
            f"X19 resolved a blocker on {task_id}",
            task_id=task_id,
            role_id=BOSS_ROLE_ID,
        )
        return {"ok": True, "task": self.runtime.tasks.get(task_id).to_dict()}  # type: ignore[union-attr]

    def reassign(self, task_id: str, role_id: str, *, reason: str = "") -> Dict[str, Any]:
        if get_role(role_id) is None:
            return {"ok": False, "error": f"unknown role {role_id!r}"}
        try:
            task = self.runtime.tasks.reassign(task_id, role_id=role_id, reason=reason)
        except (InvalidTransition, KeyError) as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "task": task.to_dict()}

    def retry(self, task_id: str, *, reason: str = "") -> Dict[str, Any]:
        try:
            task = self.runtime.tasks.retry(task_id, reason=reason)
        except (InvalidTransition, KeyError) as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "task": task.to_dict(), "attempt": task.attempt}

    def cancel(self, task_id: str, *, reason: str = "") -> Dict[str, Any]:
        try:
            task = self.runtime.tasks.cancel(task_id, reason or "cancelled by X19")
        except (InvalidTransition, KeyError) as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "task": task.to_dict()}

    def review(self, task_id: str, *, approved: bool, note: str = "") -> Dict[str, Any]:
        try:
            task = self.runtime.tasks.review(task_id, approved=approved, reviewer=BOSS_ROLE_ID, note=note)
        except (InvalidTransition, KeyError) as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "task": task.to_dict()}

    # ------------------------------------------------------------------
    # operator controls (real enforcement, not decoration)
    # ------------------------------------------------------------------
    def pause(self, reason: str = "operator pause") -> Dict[str, Any]:
        enforced = self.runtime.pause(reason=reason)
        return {"ok": True, "paused": True, "spawn_gate_enforced": enforced}

    def resume(self, reason: str = "operator resume") -> Dict[str, Any]:
        enforced = self.runtime.resume(reason=reason)
        return {"ok": True, "paused": False, "spawn_gate_enforced": enforced}

    def stop(self, reason: str = "operator stop") -> Dict[str, Any]:
        cancelled = self.runtime.stop(reason=reason)
        return {"ok": True, "cancelled": cancelled, "count": len(cancelled)}

    # ------------------------------------------------------------------
    # synthesis
    # ------------------------------------------------------------------
    def synthesise(self, summary: str, *, task_id: Optional[str] = None) -> Dict[str, Any]:
        """Record X19's synthesis of the real outputs as the objective result."""
        root_id = task_id or self.runtime.run.objective_task_id
        if not root_id:
            return {"ok": False, "error": "no objective to synthesise"}
        task = self.runtime.tasks.get(root_id)
        if task is None:
            return {"ok": False, "error": f"unknown task {root_id!r}"}
        unfinished = [t for t in self.runtime.tasks.descendants(root_id) if not t.is_terminal]
        failed = [t for t in self.runtime.tasks.descendants(root_id) if t.status is TaskStatus.FAILED]
        caveats: List[str] = []
        if unfinished:
            caveats.append(f"{len(unfinished)} subtask(s) never reached a terminal state")
        if failed:
            caveats.append(f"{len(failed)} subtask(s) failed: " + ", ".join(t.id for t in failed[:6]))
        task.outputs.append(
            {
                "kind": "boss_synthesis",
                "text": summary,
                "at": time.time(),
                "caveats": caveats,
            }
        )
        self.runtime.bus.publish(
            EventType.WORKFLOW_COMPLETED,
            "X19 synthesised the objective result" + (f" ({'; '.join(caveats)})" if caveats else ""),
            task_id=root_id,
            objective_id=root_id,
            role_id=BOSS_ROLE_ID,
            caveats=caveats,
        )
        self.runtime.tasks.progress(root_id, "X19 synthesised the result", source=BOSS_ROLE_ID)
        return {"ok": True, "task_id": root_id, "caveats": caveats}

    def org_chart(self) -> Dict[str, Any]:
        """The organization as registered — dynamic, never hardcoded."""
        roles = role_catalog()
        return {
            "boss": [r.to_dict() for r in roles if r.kind is RoleKind.BOSS],
            "managers": [r.to_dict() for r in roles if r.kind is RoleKind.MANAGER],
            "workers": [r.to_dict() for r in roles if r.kind is RoleKind.WORKER],
            "counts": {
                "boss": sum(1 for r in roles if r.kind is RoleKind.BOSS),
                "managers": sum(1 for r in roles if r.kind is RoleKind.MANAGER),
                "workers": sum(1 for r in roles if r.kind is RoleKind.WORKER),
                "total": len(roles),
            },
        }
