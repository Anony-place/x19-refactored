"""X19 executive audit.

The Boss's oversight view: one concise operational report generated entirely
from the live task graph, the agent registry overlay and the event stream.

Every field is derived.  A section with nothing to report says so explicitly —
an empty audit is an honest audit, not a placeholder.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from .roles import BOSS_ROLE_ID, MANAGER_ROLE_ID
from .status import build_status
from .tasks import TaskStatus

__all__ = ["build_audit", "render_audit"]


def _fmt_elapsed(seconds: Optional[float]) -> str:
    if seconds is None:
        return "—"
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    m, s = divmod(seconds, 60)
    if m < 60:
        return f"{m}m{s:02d}s" if s else f"{m}m"
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m"


def _short(text: Any, limit: int = 76) -> str:
    if text is None:
        return ""
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _walk_tree(nodes: List[Dict[str, Any]], depth: int = 0, out: Optional[List[str]] = None) -> List[str]:
    out = out if out is not None else []
    for n in nodes:
        marker = {
            TaskStatus.COMPLETED.value: "✓",
            TaskStatus.FAILED.value: "✗",
            TaskStatus.RUNNING.value: "▶",
            TaskStatus.ASSIGNED.value: "→",
            TaskStatus.IN_REVIEW.value: "⌕",
            TaskStatus.CANCELLED.value: "⊘",
        }.get(n.get("status", ""), "·")
        waiting = n.get("status") in (
            TaskStatus.BLOCKED.value,
            TaskStatus.WAITING_DEPENDENCY.value,
            TaskStatus.WAITING_APPROVAL.value,
        )
        if waiting:
            marker = "‖"
        role = n.get("role_id") or "unassigned"
        elapsed = _fmt_elapsed(n.get("elapsed_seconds"))
        attempt = n.get("attempt") or 0
        attempt_txt = f" a{attempt}" if attempt > 1 else ""
        out.append(
            f"{'  ' * depth}{marker} {n.get('id'):<16} {role:<14} "
            f"{n.get('status'):<18} {elapsed:>7}{attempt_txt}  {_short(n.get('objective'), 44)}"
        )
        _walk_tree(n.get("children") or [], depth + 1, out)
    return out


def build_audit(runtime, *, event_limit: int = 20, include_outputs: bool = True) -> Dict[str, Any]:
    """Structured executive audit of the live organization."""
    status = build_status(runtime, event_limit=event_limit)
    tasks = runtime.tasks
    counts = status["counts"]

    outputs: List[Dict[str, Any]] = []
    if include_outputs:
        for t in tasks.by_status(TaskStatus.COMPLETED, TaskStatus.IN_REVIEW, TaskStatus.FAILED):
            for o in t.outputs[-2:]:
                outputs.append(
                    {
                        "task_id": t.id,
                        "role_id": t.role_id,
                        "kind": o.get("kind"),
                        "text": _short(o.get("text"), 240),
                        "at": o.get("at"),
                    }
                )

    tool_activity = _tool_activity(runtime)
    spend = _spend(tasks)

    return {
        "generated_at": time.time(),
        "report": "X19 EXECUTIVE STATUS",
        "objective": status["run"].get("objective"),
        "run": status["run"],
        "phase": status["phase"],
        "overall_state": status["overall_state"],
        "manager": status["manager"],
        "boss": status["boss"],
        "roster": {
            "registered_roles": len(status.get("roles", []) or runtime.registry.agents()),
            "active_workers": len(status["active_agents"]),
            "live_subagents": len(status["live_subagents"]),
        },
        "counts": counts,
        "task_graph": tasks.tree(status["run"].get("objective_task_id")) or tasks.tree(),
        "active_agents": status["active_agents"],
        "live_subagents": status["live_subagents"],
        "completed": status["completed"],
        "blocked": status["blocked"],
        "failed": status["failed"],
        "ready": status["ready"],
        "pending_approvals": status["pending_approvals"],
        "outputs": outputs[-20:],
        "tool_activity": tool_activity,
        "spend": spend,
        "next_actions": status["next_actions"],
        "recent_events": status["recent_events"],
    }


def _tool_activity(runtime) -> Dict[str, Any]:
    """Real tool activity, taken from the live subagent registry's counters."""
    live = runtime.registry.live_subagents()
    total_tools = 0
    per_agent: List[Dict[str, Any]] = []
    for r in live:
        tc = r.get("tool_count")
        if isinstance(tc, int):
            total_tools += tc
        per_agent.append(
            {
                "subagent_id": r.get("subagent_id"),
                "goal": _short(r.get("goal"), 48),
                "tool_count": tc,
                "model": r.get("model"),
                "depth": r.get("depth"),
            }
        )
    return {
        "observed_tool_calls": total_tools,
        "source": "delegate_tool_registry" if live else "none",
        "agents": per_agent,
        "note": None if live else "no live subagents — nothing observed to report",
    }


def _spend(tasks) -> Dict[str, Any]:
    """Real cost/token totals summed from recorded child metrics."""
    cost = 0.0
    in_tok = 0
    out_tok = 0
    api_calls = 0
    observed = False
    for t in tasks.all():
        m = t.metrics
        if m is None:
            continue
        if m.cost_usd is not None:
            cost += float(m.cost_usd)
            observed = True
        if m.input_tokens is not None:
            in_tok += int(m.input_tokens)
            observed = True
        if m.output_tokens is not None:
            out_tok += int(m.output_tokens)
            observed = True
        if m.api_calls is not None:
            api_calls += int(m.api_calls)
            observed = True
    return {
        "observed": observed,
        "cost_usd": round(cost, 6) if observed else None,
        "input_tokens": in_tok if observed else None,
        "output_tokens": out_tok if observed else None,
        "api_calls": api_calls if observed else None,
    }


def render_audit(audit: Dict[str, Any], *, width: int = 92) -> str:
    """The concise operational report the Boss shows the operator."""
    L: List[str] = []
    run = audit.get("run") or {}
    phase = audit.get("phase") or {}
    counts = audit.get("counts") or {}
    manager = audit.get("manager") or {}

    L.append("X19 EXECUTIVE STATUS")
    L.append("=" * min(width, 60))
    L.append("")
    L.append(f"Objective      : {_short(audit.get('objective'), width - 18) or '(none accepted)'}")
    L.append(f"Current Phase  : {phase.get('label', 'unknown')} — {phase.get('detail', '')}")
    L.append(f"Overall State  : {audit.get('overall_state', 'unknown')}")
    if run.get("elapsed_seconds") is not None:
        L.append(f"Elapsed        : {_fmt_elapsed(run.get('elapsed_seconds'))}")
    if run.get("paused"):
        L.append("Control        : PAUSED by operator — new spawns are blocked")
    if run.get("stopped"):
        L.append("Control        : STOPPED by operator")

    L.append("")
    m_state = manager.get("state", "idle")
    m_extra = ""
    if manager.get("current_objective"):
        m_extra = f" — {_short(manager.get('current_objective'), 46)}"
    elif manager.get("tasks_completed"):
        m_extra = (
            f" — {manager.get('tasks_completed')} delivered"
            + (f", {manager.get('tasks_failed')} failed" if manager.get("tasks_failed") else "")
        )
    L.append(f"Manager        : X22 — {m_state}{m_extra}")

    active = audit.get("active_agents") or []
    live = audit.get("live_subagents") or []
    L.append(f"Active Workers : {len(active)} roster / {len(live)} live subagent(s)")
    for a in active[:10]:
        L.append(
            f"    · {a.get('display_name') or a.get('role_id'):<22} "
            f"{a.get('state'):<8} task {a.get('current_task_id') or '—':<16} "
            f"{_fmt_elapsed(a.get('running_seconds'))}"
        )
    for s in live[:10]:
        if any(a.get("subagent_id") == s.get("subagent_id") for a in active):
            continue
        L.append(
            f"    · subagent {s.get('subagent_id')} (depth {s.get('depth')}) "
            f"{_short(s.get('goal'), 40)} — {_fmt_elapsed(s.get('running_seconds'))}"
        )
    if not active and not live:
        L.append("    · none — no worker is executing right now")

    L.append("")
    L.append(
        f"Completed      : {counts.get('completed', 0)}    "
        f"Blocked        : {counts.get('waiting', 0)}    "
        f"Failures       : {counts.get('failed', 0)}"
    )
    L.append(
        f"In Review      : {counts.get('in_review', 0)}    "
        f"Running        : {counts.get('active', 0)}    "
        f"Queued         : {counts.get('queued', 0)}"
    )

    blocked = audit.get("blocked") or []
    if blocked:
        L.append("")
        L.append("Blockers")
        for b in blocked[:8]:
            deps = b.get("blocking_dependencies") or []
            dep_txt = ""
            if deps:
                dep_txt = " — waiting on " + ", ".join(
                    f"{d.get('task_id')}({d.get('status', '?')})" for d in deps[:3]
                )
            flag = " [needs approval]" if b.get("requires_approval") else ""
            L.append(f"  ‖ {b['task_id']} {b.get('role_id') or '?'}: {_short(b.get('reason'), 56)}{dep_txt}{flag}")

    failed = audit.get("failed") or []
    if failed:
        L.append("")
        L.append("Failures")
        for f in failed[:8]:
            retry = (
                f"retryable ({f.get('attempt')}/{f.get('max_attempts')})"
                if f.get("retryable")
                else f"retries exhausted ({f.get('attempt')}/{f.get('max_attempts')})"
            )
            L.append(f"  ✗ {f['task_id']} {f.get('role_id') or '?'}: {_short(f.get('error'), 52)} — {retry}")
            if f.get("dependents_blocked"):
                L.append(f"      dependents blocked: {', '.join(f['dependents_blocked'][:5])}")

    approvals = audit.get("pending_approvals") or []
    if approvals:
        L.append("")
        L.append("Awaiting Operator Decision")
        for a in approvals[:6]:
            L.append(f"  ? [{a.get('id')}] {_short(a.get('question'), 62)}")

    graph = audit.get("task_graph") or []
    if graph:
        L.append("")
        L.append("Task Graph")
        L.extend(_walk_tree(graph))

    tool = audit.get("tool_activity") or {}
    spend = audit.get("spend") or {}
    L.append("")
    if tool.get("observed_tool_calls") or tool.get("agents"):
        L.append(f"Tool Activity  : {tool.get('observed_tool_calls', 0)} call(s) observed "
                 f"across {len(tool.get('agents') or [])} live agent(s) [source: {tool.get('source')}]")
    else:
        L.append(f"Tool Activity  : {tool.get('note') or 'not observed'}")
    if spend.get("observed"):
        parts = []
        if spend.get("api_calls") is not None:
            parts.append(f"{spend['api_calls']} api call(s)")
        if spend.get("input_tokens") is not None:
            parts.append(f"{spend['input_tokens']:,} in / {spend.get('output_tokens', 0):,} out tokens")
        if spend.get("cost_usd") is not None:
            parts.append(f"${spend['cost_usd']:.4f}")
        L.append(f"Observed Spend : {' · '.join(parts)}")
    else:
        L.append("Observed Spend : not reported by the runtime yet")

    outputs = audit.get("outputs") or []
    if outputs:
        L.append("")
        L.append("Worker Outputs (latest)")
        for o in outputs[-6:]:
            L.append(f"  · {o.get('task_id')} {o.get('role_id')}: {_short(o.get('text'), 66)}")

    actions = audit.get("next_actions") or []
    L.append("")
    L.append("Next Actions")
    for n in actions[:8]:
        L.append(f"  → [{n.get('kind')}] {_short(n.get('detail'), 66)}")

    events = audit.get("recent_events") or []
    if events:
        L.append("")
        L.append("Recent Events")
        for e in events[-10:]:
            stamp = time.strftime("%H:%M:%S", time.localtime(e.get("ts", time.time())))
            who = e.get("role_id") or e.get("agent_id") or ""
            L.append(f"  {stamp}  {e.get('type', ''):<24} {who:<12} {_short(e.get('message'), 40)}")

    return "\n".join(L)
