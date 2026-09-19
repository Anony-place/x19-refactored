"""Bridge between the X19 organization and the real delegation engine.

X19 does not re-implement agent spawning.  A worker task is translated into a
real ``delegate_task`` dispatch against the runtime's existing subagent engine,
and the engine's real per-child result entry is translated back into a task
lifecycle transition.

Two directions:

* :func:`build_dispatch` / :func:`dispatch_task` — organization -> runtime
* :func:`observe_child_started` / :func:`observe_child_result` — runtime -> organization

The ``observe_*`` functions are called from ``tools.delegate_tool_child_run``,
which is the only place that knows a child really started or really finished.
That is what makes the task graph a record of reality rather than an intention.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Sequence

from .roles import RoleSpec, get_role
from .tasks import InvalidTransition, Task, TaskStatus

__all__ = [
    "build_dispatch",
    "dispatch_task",
    "dispatch_ready_tasks",
    "observe_child_started",
    "observe_child_result",
    "role_for_goal",
]


def _task_context(task: Task, role: RoleSpec) -> str:
    """Real context for the child: the task, its lineage and its constraints."""
    parts: List[str] = []
    parts.append(f"X19 task {task.id} (attempt {task.attempt + 1} of {task.max_attempts}).")
    if task.description:
        parts.append(f"Task detail: {task.description}")
    if task.depends_on:
        parts.append(f"Depends on completed task(s): {', '.join(task.depends_on)}.")
    if role.manager_id:
        parts.append(f"You report to {role.manager_id}.")
    parts.append(
        "Report only what you actually did and observed. If you could not complete the "
        "task, say so plainly with the reason — do not present an unfinished result as finished."
    )
    if task.blockers:
        unresolved = [b for b in task.blockers if not b.get("resolved_at")]
        if unresolved:
            parts.append(
                "Previously blocked by: "
                + "; ".join(str(b.get("reason")) for b in unresolved[-3:])
            )
    return "\n".join(parts)


def build_dispatch(
    task: Task,
    *,
    runtime=None,
    model: Optional[str] = None,
    max_iterations: Optional[int] = None,
) -> Dict[str, Any]:
    """Build the real ``delegate_task`` keyword arguments for one task."""
    role = get_role(task.role_id) or get_role("execution")
    assert role is not None
    return {
        "goal": task.objective,
        "context": _task_context(task, role),
        "role": role.delegation_role,
        "model": model or (task.extra_model if hasattr(task, "extra_model") else None),
        "max_iterations": max_iterations,
        "tasks": [
            {
                "goal": task.objective,
                "context": _task_context(task, role),
                "toolsets": list(role.toolsets) or None,
                "role": role.delegation_role,
            }
        ],
    }


def _record_dispatch_refusal(rt, task_id: str, reason: str) -> None:
    """Record that the engine refused a dispatch, without blaming the worker.

    The task never ran, so it is *blocked* (recoverable) rather than failed:
    a failed task claims the work was attempted and did not succeed, which would
    be a fabrication about a worker that was never spawned.  The refusal is
    published either way, so it is visible in the event stream and the audit.
    """
    from .events import EventType

    try:
        rt.tasks.block(task_id, reason)
    except InvalidTransition:
        pass  # already terminal or already held: the event below still records it
    rt.bus.publish(
        EventType.ESCALATION,
        f"dispatch refused for task {task_id}: {reason[:200]}",
        task_id=task_id,
        reason=reason[:500],
    )


def dispatch_task(
    task_id: str,
    *,
    parent_agent: Any,
    runtime=None,
    model: Optional[str] = None,
    background: bool = False,
    max_iterations: Optional[int] = None,
) -> Dict[str, Any]:
    """Really dispatch one task through the delegation engine.

    Returns the engine's parsed response (result entries or a dispatch handle).
    Failures are recorded on the task — never swallowed into a success shape.
    """
    import json

    from .runtime import get_runtime

    rt = runtime or get_runtime()
    task = rt.tasks.get(task_id)
    if task is None:
        return {"ok": False, "error": f"unknown task {task_id!r}"}
    if task.is_terminal:
        return {"ok": False, "error": f"task {task_id} is already {task.status.value}"}
    blocking = rt.tasks.blocking_dependencies(task_id)
    if blocking:
        rt.tasks.wait_on_dependency(task_id, blocking[0]["task_id"])
        return {
            "ok": False,
            "blocked": True,
            "task_id": task_id,
            "waiting_on": blocking,
            "error": "dependencies have not completed",
        }
    if task.requires_approval and task.review_state.value != "approved":
        rt.tasks.block(task_id, "task requires operator approval before dispatch", requires_approval=True)
        return {"ok": False, "blocked": True, "task_id": task_id, "error": "awaiting operator approval"}

    args = build_dispatch(task, runtime=rt, model=model, max_iterations=max_iterations)
    args.pop("tasks", None)  # single-goal dispatch keeps the task<->child mapping 1:1
    args["background"] = background
    args = {k: v for k, v in args.items() if v is not None}

    try:
        from tools.delegate_tool import delegate_task

        raw = delegate_task(parent_agent=parent_agent, **args)
    except Exception as exc:  # the engine refused to spawn anything
        _record_dispatch_refusal(rt, task_id, f"dispatch failed: {exc}")
        return {"ok": False, "task_id": task_id, "error": str(exc), "guard": "dispatch_error"}

    try:
        payload = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        payload = {"raw": raw}

    # A synchronous child can start — and even finish — before delegate_task
    # returns, in which case tools.delegate_tool_org has already moved this task
    # to RUNNING or beyond. Assignment is therefore best-effort and never forces
    # an illegal transition over state the observer recorded from reality.
    if task.status in (TaskStatus.QUEUED, TaskStatus.PLANNED):
        try:
            rt.tasks.assign(
                task_id, role_id=task.role_id or "execution",
                manager_id=task.manager_id, agent_id=task.role_id,
            )
        except InvalidTransition:
            pass
    if isinstance(payload, dict):
        delegation_id = payload.get("delegation_id") or payload.get("async_delegation_id")
        subagent_id = payload.get("subagent_id")
        results = payload.get("results") or []
        if results and isinstance(results, list):
            entry = results[0] if isinstance(results[0], dict) else {}
            rt.record_result(task_id=task_id, entry=entry)
        elif delegation_id or subagent_id:
            rt.record_dispatch(
                task_id,
                role_id=task.role_id or "execution",
                subagent_id=subagent_id,
                delegation_id=delegation_id,
                model=model,
                goal=task.objective,
            )
        elif payload.get("error"):
            _record_dispatch_refusal(rt, task_id, str(payload["error"]))
            return {"ok": False, "task_id": task_id, "error": str(payload["error"]),
                    "guard": "engine_error", "response": payload}
    return {"ok": True, "task_id": task_id, "response": payload}


def dispatch_ready_tasks(
    *,
    parent_agent: Any,
    runtime=None,
    limit: Optional[int] = None,
    background: bool = True,
    model: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Dispatch every task whose dependencies are satisfied.

    *limit* defaults to ``x19.execution.max_parallel`` from real config.
    """
    from .runtime import get_runtime

    rt = runtime or get_runtime()
    cap = int(limit if limit is not None else rt.settings.max_parallel_dispatch)
    out: List[Dict[str, Any]] = []
    for task in rt.tasks.ready_tasks()[:max(0, cap)]:
        if task.status is TaskStatus.WAITING_APPROVAL:
            continue
        out.append(
            dispatch_task(task.id, parent_agent=parent_agent, runtime=rt, background=background, model=model)
        )
    return out


# ---------------------------------------------------------------------------
# runtime -> organization
# ---------------------------------------------------------------------------

def observe_child_started(
    *,
    goal: str,
    subagent_id: Optional[str],
    delegation_id: Optional[str],
    model: Optional[str],
    depth: int,
    parent_subagent_id: Optional[str],
    live_transcript: Optional[str] = None,
    role_hint: Optional[str] = None,
    runtime=None,
) -> Optional[str]:
    """Record that the delegation engine really started a child.

    Called from ``tools.delegate_tool_child_run._register_child``.  Returns the
    X19 task id the child was matched to, or ``None`` when the spawn did not
    originate from the X19 task graph (a plain ad-hoc ``delegate_task`` call).
    Those spawns are still observable through the registry's live overlay — they
    simply do not own a task.
    """
    rt = runtime
    if rt is None:
        try:
            from .runtime import get_runtime

            rt = get_runtime()
        except Exception:
            return None
    task = _match_task(rt, goal=goal, subagent_id=subagent_id, delegation_id=delegation_id, role_hint=role_hint)
    if task is None:
        return None
    rt.record_dispatch(
        task.id,
        role_id=task.role_id or role_hint or "execution",
        subagent_id=subagent_id,
        delegation_id=delegation_id,
        model=model,
        goal=goal,
        live_transcript=live_transcript,
    )
    return task.id


def observe_child_result(
    *,
    subagent_id: Optional[str],
    goal: Optional[str],
    entry: Dict[str, Any],
    task_id: Optional[str] = None,
    role_hint: Optional[str] = None,
    runtime=None,
) -> Optional[str]:
    """Record the engine's real result entry against the owning task."""
    rt = runtime
    if rt is None:
        try:
            from .runtime import get_runtime

            rt = get_runtime()
        except Exception:
            return None
    task = rt.tasks.get(task_id) if task_id else None
    if task is None:
        task = _match_task(rt, goal=goal, subagent_id=subagent_id, role_hint=role_hint)
    if task is None:
        return None
    rt.record_result(task_id=task.id, subagent_id=subagent_id, entry=entry)
    return task.id


def _match_task(rt, *, goal: Optional[str], subagent_id: Optional[str], delegation_id: Optional[str] = None,
                role_hint: Optional[str] = None) -> Optional[Task]:
    """Find the task a real child belongs to.

    Matching order, all from real recorded linkage:
      1. exact subagent id,  2. exact delegation id,
      3. an ASSIGNED/PLANNED task with the same goal text.
    Never guesses by role alone — that would attribute work to the wrong task.
    """
    task = rt.tasks.find_by_subagent(subagent_id)
    if task is not None:
        return task
    if delegation_id:
        matches = rt.tasks.find_by_delegation(delegation_id)
        if len(matches) == 1:
            return matches[0]
        for m in matches:
            if not m.is_terminal:
                return m
    if goal:
        wanted = " ".join(goal.split())
        candidates = [
            t
            for t in rt.tasks.by_status(TaskStatus.ASSIGNED, TaskStatus.PLANNED, TaskStatus.QUEUED)
            if " ".join((t.objective or "").split()) == wanted
        ]
        if role_hint:
            candidates = [t for t in candidates if t.role_id == role_hint] or candidates
        if len(candidates) == 1:
            return candidates[0]
        if candidates:
            return min(candidates, key=lambda t: t.created_at)
    return None


def role_for_goal(goal: str, capabilities: Sequence[str] = ()) -> Optional[RoleSpec]:
    """Pick a worker role from real declared capabilities (no hardcoded routing)."""
    from .roles import roles_for_capabilities, worker_roles

    if capabilities:
        matches = roles_for_capabilities(capabilities)
        if matches:
            return matches[0]
    text = (goal or "").lower()
    scored: List[tuple[int, RoleSpec]] = []
    for role in worker_roles():
        score = 0
        for cap in role.capabilities:
            for word in cap.replace("_", " ").split():
                if len(word) > 3 and word in text:
                    score += 1
        for tag in role.tags:
            if tag in text:
                score += 1
        if score:
            scored.append((score, role))
    if not scored:
        return None
    scored.sort(key=lambda t: (-t[0], t[1].id))
    return scored[0][1]
