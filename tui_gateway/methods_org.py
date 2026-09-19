"""X19 organization JSON-RPC handlers — the TUI's only window into org state.

Every method projects :mod:`x19.org.runtime` state.  There is no caching layer,
no synthetic filler and no "last known good" fallback: when the organization has
done nothing, the panels show nothing, which is the truth.

Bodies are rebound onto server.py's globals at install time (method_ctx.py), so
they use server helpers (``_ok``, ``_err``, ``_str_param``) bare.

Scope: the organization runtime is process-wide — one X19 installation, one run,
one task graph — so these methods are not session-scoped.  A profile switch
rebuilds the runtime (``x19.org.reset_runtime``) against the new X19_HOME.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .method_ctx import HandlerRegistry, bind_module

_registry = HandlerRegistry()
method = _registry.method

# Bounds on what one poll returns. The TUI polls; it does not need the whole
# event history every time, and an unbounded response would stall the render loop.
_MAX_EVENTS = 500
_MAX_TASKS = 500


def _org_runtime():
    """The process-wide organization runtime, or None when it cannot load."""
    try:
        from x19.org.runtime import get_runtime

        return get_runtime()
    except Exception:
        return None


def _org_int_param(params: dict, key: str, default: int, *, low: int, high: int) -> int:
    try:
        value = int(params.get(key, default))
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))


def _org_unavailable(rid) -> Optional[dict]:
    return _err(rid, 5030, "x19 organization runtime is unavailable")


# ── read: projections of recorded state ─────────────────────────────
@method("org.status")
def _(rid, params: dict) -> dict:
    """Run, phase, counts, roster, blocked/failed/ready tasks and next actions.

    This is what the status panels render. ``render`` carries the same content as
    dense text for surfaces that cannot lay out the structured form.
    """
    rt = _org_runtime()
    if rt is None:
        return _org_unavailable(rid)
    from x19.org.boss import Boss

    boss = Boss(rt)
    status = boss.status(event_limit=_org_int_param(params, "event_limit", 12, low=0, high=100))
    return _ok(rid, {"status": status, "render": boss.status_text()})


@method("org.audit")
def _(rid, params: dict) -> dict:
    """Boss Audit Mode: the full executive report over graph, queue and spend."""
    rt = _org_runtime()
    if rt is None:
        return _org_unavailable(rid)
    from x19.org.boss import Boss

    boss = Boss(rt)
    return _ok(rid, {
        "audit": boss.audit(include_outputs=bool(params.get("include_outputs", True))),
        "render": boss.audit_text(),
    })


@method("org.agents")
def _(rid, params: dict) -> dict:
    """The roster overlaid with the delegation engine's live subagents."""
    rt = _org_runtime()
    if rt is None:
        return _org_unavailable(rid)
    reg = rt.snapshot().get("agents") or {}
    return _ok(rid, {
        "agents": reg.get("agents") or [],
        "live_subagents": reg.get("live_subagents") or [],
        "counts": reg.get("counts") or {},
    })


@method("org.roles")
def _(rid, params: dict) -> dict:
    """The registered role catalog — dynamic, never a frontend-side list."""
    from x19.org.roles import role_catalog

    return _ok(rid, {"roles": [r.to_dict() for r in role_catalog()]})


@method("org.tasks")
def _(rid, params: dict) -> dict:
    """The task graph: tree plus the slices the panels show."""
    rt = _org_runtime()
    if rt is None:
        return _org_unavailable(rid)
    from x19.org.tasks import TaskStatus

    snap = rt.snapshot()
    tasks = snap.get("tasks") or {}
    status_filter = str(params.get("status") or "").strip().lower()
    payload: Dict[str, Any] = {
        "stats": tasks.get("stats") or {},
        "tree": tasks.get("tree") or [],
        "ready": tasks.get("ready") or [],
        "blocked": tasks.get("blocked") or [],
        "failed": tasks.get("failed") or [],
        "in_review": tasks.get("in_review") or [],
        "run": snap.get("run") or {},
    }
    if status_filter:
        try:
            wanted = TaskStatus(status_filter)
        except ValueError:
            return _err(rid, 4002, f"unknown status {status_filter!r}",
                        {"valid": [s.value for s in TaskStatus]})
        limit = _org_int_param(params, "limit", 100, low=1, high=_MAX_TASKS)
        payload["filtered"] = [
            t.to_dict() for t in rt.tasks.by_status(wanted)[:limit]
        ]
        payload["filter"] = status_filter
    return _ok(rid, payload)


@method("org.events")
def _(rid, params: dict) -> dict:
    """Recent organization events.

    ``since_seq`` lets the TUI poll incrementally instead of re-fetching history:
    pass the highest ``seq`` it has already rendered.
    """
    rt = _org_runtime()
    if rt is None:
        return _org_unavailable(rid)
    limit = _org_int_param(params, "limit", 50, low=1, high=_MAX_EVENTS)
    since_seq = _org_int_param(params, "since_seq", 0, low=0, high=10**12)
    task_id = str(params.get("task_id") or "").strip()
    agent_id = str(params.get("agent_id") or "").strip()
    if task_id:
        events = rt.bus.for_task(task_id, limit=limit)
    elif agent_id:
        events = rt.bus.for_agent(agent_id, limit=limit)
    else:
        events = rt.bus.recent(limit=limit)
    items = [e.to_dict() for e in events]
    if since_seq:
        items = [e for e in items if int(e.get("seq") or 0) > since_seq]
    return _ok(rid, {
        "events": items,
        "last_seq": rt.bus.last_seq,
        "counts_by_type": rt.bus.counts_by_type(),
    })


@method("org.approvals")
def _(rid, params: dict) -> dict:
    """Decisions waiting on the operator, and the ones already made."""
    rt = _org_runtime()
    if rt is None:
        return _org_unavailable(rid)
    return _ok(rid, {"pending": rt.pending_approvals()})


# ── write: real operator authority ──────────────────────────────────
def _resolve_approval(rid, params: dict, *, approved: bool) -> dict:
    rt = _org_runtime()
    if rt is None:
        return _org_unavailable(rid)
    approval_id = _str_param(params, "approval_id")
    if not approval_id:
        return _err(rid, 4000, "approval_id required")
    record = rt.resolve_approval(
        approval_id,
        approved=approved,
        decided_by=_str_param(params, "decided_by") or "operator",
        note=str(params.get("note") or "").strip(),
    )
    if record is None:
        return _err(rid, 4004, f"unknown approval {approval_id!r}")
    return _ok(rid, {"approval": record})


@method("org.approve")
def _(rid, params: dict) -> dict:
    """Approve a gated task or a delivered output. Never auto-resolved."""
    return _resolve_approval(rid, params, approved=True)


@method("org.deny")
def _(rid, params: dict) -> dict:
    """Deny a request; the task is failed with the operator's reason recorded."""
    return _resolve_approval(rid, params, approved=False)


@method("org.pause")
def _(rid, params: dict) -> dict:
    """Pause the run: really gates new spawns in the delegation engine."""
    rt = _org_runtime()
    if rt is None:
        return _org_unavailable(rid)
    enforced = rt.pause(reason=str(params.get("reason") or "").strip() or "operator pause")
    return _ok(rid, {"paused": True, "enforced": enforced})


@method("org.resume")
def _(rid, params: dict) -> dict:
    rt = _org_runtime()
    if rt is None:
        return _org_unavailable(rid)
    enforced = rt.resume(reason=str(params.get("reason") or "").strip() or "operator resume")
    return _ok(rid, {"paused": False, "enforced": enforced})


@method("org.stop")
def _(rid, params: dict) -> dict:
    """Stop the run and cancel everything not already terminal."""
    rt = _org_runtime()
    if rt is None:
        return _org_unavailable(rid)
    cancelled = rt.stop(reason=str(params.get("reason") or "").strip() or "operator stop")
    return _ok(rid, {"stopped": True, "cancelled": cancelled})


@method("org.task.control")
def _(rid, params: dict) -> dict:
    """Retry, cancel or review one task — the real transition, guard-checked."""
    rt = _org_runtime()
    if rt is None:
        return _org_unavailable(rid)
    from x19.org.boss import Boss

    task_id = _str_param(params, "task_id")
    if not task_id:
        return _err(rid, 4000, "task_id required")
    if rt.tasks.get(task_id) is None:
        return _err(rid, 4004, f"unknown task {task_id!r}")
    op = str(params.get("op") or "").strip().lower()
    boss = Boss(rt)
    reason = str(params.get("reason") or params.get("note") or "").strip()
    if op == "retry":
        out = boss.retry(task_id, reason=reason)
    elif op == "cancel":
        out = boss.cancel(task_id, reason=reason)
    elif op == "resolve_blocker":
        out = boss.resolve_blocker(task_id, resolution=reason)
    elif op == "review":
        if "approved" not in params:
            return _err(rid, 4002, "review requires 'approved'")
        out = boss.review(task_id, approved=bool(params.get("approved")), note=reason)
    else:
        return _err(rid, 4002, f"unknown op {op!r}",
                    {"valid": ["retry", "cancel", "resolve_blocker", "review"]})
    return _ok(rid, {"op": op, "task_id": task_id, "result": out})


def register(server) -> None:
    """Publish this module's helpers + handlers onto ``server``, rebound to its globals."""
    bind_module(globals(), server, skip=("_",))
