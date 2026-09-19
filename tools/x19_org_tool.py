"""``x19_org`` — the organization control surface X19 drives and reports from.

One tool, one ``action``, because the organization is one thing: a run, a task
graph, a roster and an event stream that all live in :mod:`x19.org.runtime`.

Every action is a thin mapping onto the runtime, ``Boss`` or ``Manager``.  This
module holds no organization logic of its own and no state of its own, so there
is nothing here that can disagree with what actually happened:

* read actions (``status``, ``audit``, ``answer``, ``agents``, ``tasks``,
  ``events``, ``roles``, ``approvals``, ``org``) project real recorded state;
* write actions (``objective``, ``plan``, ``dispatch``, ``approve``, ``deny``,
  ``retry``, ``cancel``, ``review``, ``escalate``, ``pause``, ``resume``,
  ``stop``) are the real transitions, guarded by :mod:`x19.org.safety`.

``dispatch`` is the only action that needs the calling agent: it hands work to
the real delegation engine, which spawns actual child agents.  Results come back
into the task graph through ``tools.delegate_tool_org``, not through this tool.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

from tools.registry import registry, tool_error, tool_result

logger = logging.getLogger(__name__)

__all__ = ["x19_org_tool", "X19_ORG_SCHEMA"]

# Bounds on how much state one call returns. The model needs the shape of the
# organization, not a dump of every event since boot; callers can page with
# ``limit``/``offset`` and the audit action for depth.
_MAX_LIST = 200


def _runtime():
    """The process-wide organization runtime (created on first use)."""
    from x19.org.runtime import get_runtime

    return get_runtime()


def _boss(rt):
    from x19.org.boss import Boss

    return Boss(rt)


def _manager(rt):
    from x19.org.manager import Manager

    return Manager(rt)


def _slice(items: List[Any], limit: Any, offset: Any) -> List[Any]:
    try:
        lim = min(int(limit or 25), _MAX_LIST)
    except (TypeError, ValueError):
        lim = 25
    try:
        off = max(0, int(offset or 0))
    except (TypeError, ValueError):
        off = 0
    return list(items)[off:off + max(0, lim)]


# ---------------------------------------------------------------------------
# read actions — projections of recorded state
# ---------------------------------------------------------------------------

def _act_status(rt, args, **_kw) -> Dict[str, Any]:
    boss = _boss(rt)
    return {
        "ok": True,
        "action": "status",
        "render": boss.status_text(),
        "status": boss.status(event_limit=int(args.get("event_limit") or 12)),
    }


def _act_audit(rt, args, **_kw) -> Dict[str, Any]:
    boss = _boss(rt)
    return {
        "ok": True,
        "action": "audit",
        "render": boss.audit_text(),
        "audit": boss.audit(include_outputs=bool(args.get("include_outputs", True))),
    }


def _act_answer(rt, args, **_kw) -> Dict[str, Any]:
    question = (args.get("question") or "").strip()
    if not question:
        return {"ok": False, "error": "answer requires a 'question'"}
    out = _boss(rt).answer(question)
    return {"ok": True, "action": "answer", **out}


def _act_org(rt, args, **_kw) -> Dict[str, Any]:
    return {"ok": True, "action": "org", **_boss(rt).org_chart()}


def _act_agents(rt, args, **_kw) -> Dict[str, Any]:
    snap = rt.snapshot()
    reg = snap.get("agents") or {}
    return {
        "ok": True,
        "action": "agents",
        "agents": reg.get("agents") or [],
        "live_subagents": reg.get("live_subagents") or [],
        "counts": reg.get("counts") or {},
    }


def _act_roles(rt, args, **_kw) -> Dict[str, Any]:
    from x19.org.roles import role_catalog

    return {
        "ok": True,
        "action": "roles",
        "roles": [r.to_dict() for r in role_catalog()],
    }


def _act_tasks(rt, args, **_kw) -> Dict[str, Any]:
    from x19.org.tasks import TaskStatus

    tasks = rt.tasks.all()
    status_filter = (args.get("status") or "").strip().lower()
    role_filter = (args.get("role_id") or "").strip().lower()
    if status_filter:
        try:
            wanted = TaskStatus(status_filter)
        except ValueError:
            return {
                "ok": False,
                "error": f"unknown status {status_filter!r}",
                "valid": [s.value for s in TaskStatus],
            }
        tasks = [t for t in tasks if t.status is wanted]
    if role_filter:
        tasks = [t for t in tasks if (t.role_id or "").lower() == role_filter]
    total = len(tasks)
    tasks.sort(key=lambda t: t.updated_at, reverse=True)
    return {
        "ok": True,
        "action": "tasks",
        "total": total,
        "tasks": [t.to_dict() for t in _slice(tasks, args.get("limit"), args.get("offset"))],
    }


def _act_events(rt, args, **_kw) -> Dict[str, Any]:
    task_id = (args.get("task_id") or "").strip()
    agent_id = (args.get("agent_id") or "").strip()
    if task_id:
        events = rt.bus.for_task(task_id, limit=int(args.get("limit") or 50))
    elif agent_id:
        events = rt.bus.for_agent(agent_id, limit=int(args.get("limit") or 50))
    else:
        events = rt.bus.recent(limit=min(int(args.get("limit") or 25), _MAX_LIST))
    return {
        "ok": True,
        "action": "events",
        "counts_by_type": rt.bus.counts_by_type(),
        "events": [e.to_dict() for e in events],
    }


def _act_approvals(rt, args, **_kw) -> Dict[str, Any]:
    return {
        "ok": True,
        "action": "approvals",
        "pending": rt.pending_approvals(),
        "all": list(rt._approvals.values()),  # noqa: SLF001 — resolved decisions are part of the record
    }


# ---------------------------------------------------------------------------
# write actions — the real transitions
# ---------------------------------------------------------------------------

def _act_objective(rt, args, **_kw) -> Dict[str, Any]:
    objective = (args.get("objective") or "").strip()
    if not objective:
        return {"ok": False, "error": "objective requires an 'objective'"}
    out = _boss(rt).accept_objective(
        objective,
        description=(args.get("description") or "").strip(),
    )
    return {"ok": True, "action": "objective", **out}


def _act_plan(rt, args, **_kw) -> Dict[str, Any]:
    steps = args.get("tasks") or args.get("steps")
    if not isinstance(steps, list) or not steps:
        return {
            "ok": False,
            "error": "plan requires 'tasks': a list of {key, objective, role_id, depends_on?}",
        }
    out = _manager(rt).plan(steps, project_id=args.get("project_id"))
    return {"ok": bool(out.get("ok")), "action": "plan", **out}


def _act_dispatch(rt, args, *, parent_agent=None, **_kw) -> Dict[str, Any]:
    from x19.org.delegation import dispatch_ready_tasks, dispatch_task
    from x19.org.safety import ExecutionGuards

    if parent_agent is None:
        return {"ok": False, "error": "dispatch requires an agent context to spawn children from"}
    if rt.run.paused:
        return {"ok": False, "error": "the run is paused; resume it before dispatching"}
    if rt.run.stopped:
        return {"ok": False, "error": "the run is stopped; accept a new objective to continue"}

    guards = ExecutionGuards(rt)
    task_id = (args.get("task_id") or "").strip()
    if task_id:
        task = rt.tasks.get(task_id)
        if task is None:
            return {"ok": False, "error": f"unknown task {task_id!r}"}
        decision = guards.can_dispatch(task)
        if not decision.allowed:
            return {
                "ok": False,
                "error": f"refused to dispatch: {decision.reason}",
                "guard": decision.guard,
                "detail": decision.detail,
                "task_id": task_id,
            }
        out = dispatch_task(
            task_id,
            parent_agent=parent_agent,
            runtime=rt,
            background=bool(args.get("background", True)),
        )
        return {"ok": bool(out.get("ok")), "action": "dispatch", **out}

    ready = rt.tasks.ready_tasks()
    refused = []
    allowed = []
    for t in ready:
        d = guards.can_dispatch(t)
        (allowed if d.allowed else refused).append(
            {"task_id": t.id, "role_id": t.role_id} if d.allowed
            else {"task_id": t.id, "role_id": t.role_id, "guard": d.guard, "reason": d.reason}
        )
    results = dispatch_ready_tasks(
        parent_agent=parent_agent,
        runtime=rt,
        limit=args.get("limit"),
        background=bool(args.get("background", True)),
    )
    return {
        "ok": True,
        "action": "dispatch",
        "ready": len(ready),
        "dispatched": len(results),
        "refused": refused,
        "results": results,
    }


def _act_approval_decision(rt, args, *, approved: bool, **_kw) -> Dict[str, Any]:
    approval_id = (args.get("approval_id") or "").strip()
    if not approval_id:
        return {"ok": False, "error": f"{'approve' if approved else 'deny'} requires an 'approval_id'"}
    record = rt.resolve_approval(
        approval_id,
        approved=approved,
        decided_by=(args.get("decided_by") or "operator").strip() or "operator",
        note=(args.get("note") or "").strip(),
    )
    if record is None:
        return {"ok": False, "error": f"unknown approval {approval_id!r}"}
    return {"ok": True, "action": "approve" if approved else "deny", "approval": record}


def _act_retry(rt, args, **_kw) -> Dict[str, Any]:
    task_id = (args.get("task_id") or "").strip()
    if not task_id:
        return {"ok": False, "error": "retry requires a 'task_id'"}
    return {"ok": True, "action": "retry", **_boss(rt).retry(task_id, reason=(args.get("reason") or "").strip())}


def _act_cancel(rt, args, **_kw) -> Dict[str, Any]:
    task_id = (args.get("task_id") or "").strip()
    if not task_id:
        return {"ok": False, "error": "cancel requires a 'task_id'"}
    out = _boss(rt).cancel(task_id, reason=(args.get("reason") or "").strip())
    return {"ok": bool(out.get("ok", True)), "action": "cancel", **out}


def _act_review(rt, args, **_kw) -> Dict[str, Any]:
    task_id = (args.get("task_id") or "").strip()
    if not task_id:
        return {"ok": False, "error": "review requires a 'task_id'"}
    if "approved" not in args:
        return {"ok": False, "error": "review requires 'approved': true or false"}
    out = _boss(rt).review(
        task_id, approved=bool(args.get("approved")), note=(args.get("note") or "").strip()
    )
    return {"ok": bool(out.get("ok", True)), "action": "review", **out}


def _act_resolve_blocker(rt, args, **_kw) -> Dict[str, Any]:
    task_id = (args.get("task_id") or "").strip()
    if not task_id:
        return {"ok": False, "error": "resolve_blocker requires a 'task_id'"}
    out = _boss(rt).resolve_blocker(task_id, resolution=(args.get("resolution") or "").strip())
    return {"ok": bool(out.get("ok", True)), "action": "resolve_blocker", **out}


def _act_escalate(rt, args, **_kw) -> Dict[str, Any]:
    issue = (args.get("issue") or "").strip()
    if not issue:
        return {"ok": False, "error": "escalate requires an 'issue'"}
    out = _manager(rt).escalate(
        issue, task_id=(args.get("task_id") or "").strip() or None,
        severity=(args.get("severity") or "medium").strip(),
    )
    return {"ok": bool(out.get("ok", True)), "action": "escalate", **out}


def _act_operator(rt, args, *, verb: str, **_kw) -> Dict[str, Any]:
    reason = (args.get("reason") or "").strip() or f"operator {verb}"
    out = getattr(_boss(rt), verb)(reason)
    return {"ok": True, "action": verb, **out}


_ACTIONS: Dict[str, Callable[..., Dict[str, Any]]] = {
    # read
    "status": _act_status,
    "audit": _act_audit,
    "answer": _act_answer,
    "org": _act_org,
    "agents": _act_agents,
    "roles": _act_roles,
    "tasks": _act_tasks,
    "events": _act_events,
    "approvals": _act_approvals,
    # write
    "objective": _act_objective,
    "plan": _act_plan,
    "dispatch": _act_dispatch,
    "approve": lambda rt, args, **kw: _act_approval_decision(rt, args, approved=True, **kw),
    "deny": lambda rt, args, **kw: _act_approval_decision(rt, args, approved=False, **kw),
    "retry": _act_retry,
    "cancel": _act_cancel,
    "review": _act_review,
    "resolve_blocker": _act_resolve_blocker,
    "escalate": _act_escalate,
    "pause": lambda rt, args, **kw: _act_operator(rt, args, verb="pause", **kw),
    "resume": lambda rt, args, **kw: _act_operator(rt, args, verb="resume", **kw),
    "stop": lambda rt, args, **kw: _act_operator(rt, args, verb="stop", **kw),
}


def x19_org_tool(args: Dict[str, Any], *, parent_agent: Any = None) -> str:
    """Run one ``x19_org`` action and return its JSON result."""
    if not isinstance(args, dict):
        return tool_error("x19_org requires an arguments object")
    action = (args.get("action") or "status").strip().lower()
    handler = _ACTIONS.get(action)
    if handler is None:
        return tool_error(
            f"unknown action {action!r}",
            valid_actions=sorted(_ACTIONS),
        )
    try:
        rt = _runtime()
    except Exception as exc:
        logger.exception("x19_org: organization runtime unavailable")
        return tool_error(f"organization runtime unavailable: {exc}")
    try:
        out = handler(rt, args, parent_agent=parent_agent)
    except Exception as exc:
        logger.exception("x19_org: action %s failed", action)
        return tool_error(f"{action} failed: {type(exc).__name__}: {exc}", action=action)
    if not isinstance(out, dict):  # pragma: no cover — every handler returns a dict
        return tool_error(f"{action} produced no result", action=action)
    return tool_result(out)


_TASK_STEP_SCHEMA = {
    "type": "object",
    "properties": {
        "key": {"type": "string", "description": "Local name other steps can depend on."},
        "objective": {"type": "string", "description": "What the worker must actually produce."},
        "role_id": {
            "type": "string",
            "description": "Worker role that owns the task. Use action=roles to list the registered roles.",
        },
        "description": {"type": "string", "description": "Detail, constraints, acceptance criteria."},
        "depends_on": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Keys (or task ids) that must complete first. The task really waits.",
        },
        "priority": {"type": "string", "enum": ["low", "normal", "high", "critical"]},
        "requires_approval": {
            "type": "boolean",
            "description": "True to gate dispatch on an explicit operator decision.",
        },
    },
    "required": ["objective", "role_id"],
}

X19_ORG_SCHEMA = {
    "name": "x19_org",
    "description": (
        "Run the X19 organization: take an objective, plan it into worker tasks, dispatch them "
        "through the real delegation engine, and report what actually happened. Read actions "
        "(status, audit, answer, agents, tasks, events, roles, approvals, org) project real "
        "recorded runtime state — use them for ANY question about progress, who is working, what "
        "failed or what is blocked, and never answer such a question from memory or assumption. "
        "Write actions (objective, plan, dispatch, approve, deny, retry, cancel, review, "
        "resolve_blocker, escalate, pause, resume, stop) are the real transitions and are refused "
        "by the execution guards when they are not safe."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": sorted(_ACTIONS),
                "description": "What to do. Defaults to 'status'.",
            },
            "objective": {
                "type": "string",
                "description": "objective: the user's goal, verbatim. X19 decomposes and delegates it.",
            },
            "tasks": {
                "type": "array",
                "items": _TASK_STEP_SCHEMA,
                "description": "plan: the worker steps to create, with dependencies between them.",
            },
            "task_id": {
                "type": "string",
                "description": "dispatch/retry/cancel/review/resolve_blocker/events: which task.",
            },
            "question": {
                "type": "string",
                "description": "answer: the operator's status question, in their words.",
            },
            "status": {
                "type": "string",
                "description": "tasks: filter by task status (e.g. running, blocked, failed, completed).",
            },
            "role_id": {"type": "string", "description": "tasks: filter by owning role."},
            "approval_id": {"type": "string", "description": "approve/deny: which pending approval."},
            "approved": {"type": "boolean", "description": "review: accept or reject the delivered output."},
            "issue": {"type": "string", "description": "escalate: what X22 is raising to X19."},
            "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
            "reason": {
                "type": "string",
                "description": "retry/cancel/pause/resume/stop: why, recorded on the task and event stream.",
            },
            "resolution": {"type": "string", "description": "resolve_blocker: how it was cleared."},
            "note": {"type": "string", "description": "approve/deny/review: the operator's note."},
            "decided_by": {"type": "string", "description": "approve/deny: who decided. Defaults to 'operator'."},
            "background": {
                "type": "boolean",
                "description": "dispatch: run children in the background (default true).",
            },
            "limit": {"type": "integer", "description": "Maximum entries to return or dispatch."},
            "offset": {"type": "integer", "description": "Paging offset for list actions."},
            "include_outputs": {"type": "boolean", "description": "audit: include worker output text."},
            "event_limit": {"type": "integer", "description": "status: how many recent events to include."},
        },
        "required": [],
    },
}


registry.register(
    name="x19_org",
    toolset="x19-org",
    schema=X19_ORG_SCHEMA,
    handler=lambda args, **kw: x19_org_tool(args, parent_agent=kw.get("parent_agent")),
    emoji="🏛",
    max_result_size_chars=48_000,
)
