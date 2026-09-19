"""X19 live status projection.

Answers "where are we right now?" strictly from real runtime state: the task
graph, the agent registry's live overlay, and the event stream.  When the
runtime has not observed something, the projection says *not observed* rather
than inventing a number.

Two shapes are produced:

* :func:`build_status` — a structured dict (RPC / TUI / tests)
* :func:`render_status` — the terse operator-facing text X19 answers with
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from .registry import AgentState
from .roles import BOSS_ROLE_ID, MANAGER_ROLE_ID, RoleKind
from .tasks import Task, TaskStatus

__all__ = ["build_status", "render_status", "describe_phase"]


def _fmt_elapsed(seconds: Optional[float]) -> str:
    if seconds is None:
        return "—"
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m{secs:02d}s" if secs else f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


def _short(text: Optional[str], limit: int = 72) -> str:
    if not text:
        return ""
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def describe_phase(runtime) -> Dict[str, Any]:
    """Derive the real execution phase from the task graph.

    Phase is *computed*, not stored: it is a function of what the tasks are
    actually doing.  The denominator is the number of planned execution steps
    (project + worker tasks), never an invented total.
    """
    tasks = runtime.tasks
    stats = tasks.stats()
    root_id = runtime.run.objective_task_id
    descendants = tasks.descendants(root_id) if root_id else tasks.all()
    # Structural tasks (the objective itself, X22's project wrapper) are not
    # execution steps; counting them would keep the phase "executing" forever.
    _STRUCTURAL = ("objective", "project")
    steps = [t for t in descendants if t.status is not TaskStatus.CANCELLED]
    workers = [t for t in steps if not (set(t.tags or []) & set(_STRUCTURAL))]
    done = [t for t in workers if t.status is TaskStatus.COMPLETED]
    running = [t for t in workers if t.status is TaskStatus.RUNNING]
    assigned = [t for t in workers if t.status is TaskStatus.ASSIGNED]
    waiting = [t for t in workers if t.is_waiting]
    failed = [t for t in workers if t.status is TaskStatus.FAILED]
    review = [t for t in workers if t.status is TaskStatus.IN_REVIEW]
    queued = [t for t in workers if t.status in (TaskStatus.QUEUED, TaskStatus.PLANNED)]
    # Abandoned work stays out of the denominator (otherwise a cancelled task
    # would make "completed" unreachable) but it is never hidden from the user.
    abandoned = [
        t for t in descendants
        if t.status is TaskStatus.CANCELLED and not (set(t.tags or []) & set(_STRUCTURAL))
    ]
    suffix = f"; {len(abandoned)} abandoned" if abandoned else ""

    if not workers:
        label = "planning"
        detail = "objective accepted; no worker tasks planned yet"
    elif failed and not running and not assigned and not queued and not waiting:
        label = "failed"
        detail = f"{len(failed)} of {len(workers)} task(s) failed with nothing left to run{suffix}"
    elif running or assigned:
        label = "executing"
        detail = (
            f"{len(running) + len(assigned)} of {len(workers)} task(s) in flight, "
            f"{len(done)} completed{suffix}"
        )
    # Ordered by what is actionable now: work that can start beats work that is
    # waiting, because reporting "waiting" while a task is dispatchable would
    # understate what the organization can do this moment.
    elif queued:
        label = "ready"
        detail = (
            f"{len(queued)} task(s) ready to dispatch"
            + (f"; {len(waiting)} still waiting on dependencies" if waiting else "")
            + suffix
        )
    elif review:
        label = "review"
        detail = f"{len(review)} output(s) awaiting review{suffix}"
    elif waiting:
        label = "waiting"
        detail = f"{len(waiting)} task(s) blocked or waiting; nothing running{suffix}"
    elif done and len(done) == len(workers):
        label = "completed"
        detail = f"all {len(workers)} task(s) completed{suffix}"
    else:
        label = "unknown"
        detail = "runtime has not reported a determinate phase"

    return {
        "label": label,
        "detail": detail,
        "steps_total": len(workers),
        "steps_completed": len(done),
        "steps_running": len(running) + len(assigned),
        "steps_waiting": len(waiting),
        "steps_failed": len(failed),
        "steps_in_review": len(review),
        "steps_cancelled": len(abandoned),
        "steps_queued": len(queued),
    }


def build_status(runtime, *, event_limit: int = 12) -> Dict[str, Any]:
    """Structured live status, entirely derived from real state."""
    runtime.reconcile()
    tasks = runtime.tasks
    registry = runtime.registry
    live = registry.reconcile()
    agents = registry.agents()
    phase = describe_phase(runtime)
    stats = tasks.stats()
    run = runtime.run.to_dict()

    active_agents = [
        a.to_dict()
        for a in agents
        if a.state in (AgentState.ACTIVE, AgentState.WAITING, AgentState.BLOCKED)
    ]
    manager = registry.for_role(MANAGER_ROLE_ID)
    boss = registry.for_role(BOSS_ROLE_ID)

    # The manager's state is derived from the work it actually owns: X22 is
    # active while any task under it is in flight, waiting on it, or failed and
    # awaiting its decision.  That is a fact about the graph, not a label.
    manager_state = _manager_state(runtime, manager)

    blocked = []
    for t in tasks.by_status(TaskStatus.BLOCKED, TaskStatus.WAITING_DEPENDENCY, TaskStatus.WAITING_APPROVAL):
        blocked.append(
            {
                "task_id": t.id,
                "objective": t.objective,
                "role_id": t.role_id,
                "status": t.status.value,
                "reason": (t.blockers[-1].get("reason") if t.blockers else None),
                "requires_approval": t.requires_approval,
                "blocking_dependencies": tasks.blocking_dependencies(t.id),
            }
        )

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

    completed = [
        {
            "task_id": t.id,
            "objective": t.objective,
            "role_id": t.role_id,
            "duration_seconds": (t.metrics.duration_seconds if t.metrics else None),
            "finished_at": t.finished_at,
            "review": t.review_state.value,
        }
        for t in sorted(tasks.by_status(TaskStatus.COMPLETED), key=lambda x: x.finished_at or 0)
    ]

    ready = [
        {"task_id": t.id, "objective": t.objective, "role_id": t.role_id, "priority": t.priority.value}
        for t in tasks.ready_tasks()
    ]

    next_actions = _next_actions(runtime, phase, ready, blocked, failed)

    return {
        "run": run,
        "phase": phase,
        "overall_state": _overall_state(phase, stats, failed, blocked, run),
        "counts": {
            "total": stats.get("total", 0),
            "active": stats.get("active", 0),
            "waiting": stats.get("waiting", 0),
            "completed": stats.get("completed", 0),
            "failed": stats.get("failed", 0),
            "cancelled": stats.get("cancelled", 0),
            "in_review": stats.get("in_review", 0),
            "queued": stats.get("queued", 0) + stats.get("planned", 0),
            "retryable": stats.get("retryable", 0),
        },
        "boss": {
            "role_id": BOSS_ROLE_ID,
            "state": (boss.state.value if boss else AgentState.IDLE.value),
            "run_active": bool(run.get("active")),
            "paused": bool(run.get("paused")),
        },
        "manager": {
            "role_id": MANAGER_ROLE_ID,
            "state": manager_state,
            "current_task_id": (manager.current_task_id if manager else None),
            "current_objective": (_short(manager.current_objective) if manager else None),
            "tasks_completed": (manager.tasks_completed if manager else 0),
            "tasks_failed": (manager.tasks_failed if manager else 0),
            "last_error": (manager.last_error if manager else None),
        },
        "active_agents": active_agents,
        "live_subagents": [
            {
                "subagent_id": r.get("subagent_id"),
                "goal": _short(r.get("goal")),
                "depth": r.get("depth"),
                "model": r.get("model"),
                "status": r.get("status"),
                "tool_count": r.get("tool_count"),
                "running_seconds": (
                    round(time.time() - r["started_at"], 1)
                    if isinstance(r.get("started_at"), (int, float))
                    else None
                ),
            }
            for r in live
        ],
        "blocked": blocked,
        "failed": failed,
        "completed": completed,
        "ready": ready,
        "pending_approvals": runtime.pending_approvals(),
        "next_actions": next_actions,
        "recent_events": [e.to_dict() for e in runtime.bus.recent(event_limit)],
        "generated_at": time.time(),
    }


def _manager_state(runtime, manager) -> str:
    """Derive X22's state from the tasks it owns."""
    tasks = runtime.tasks
    if manager is not None and manager.state in (AgentState.BLOCKED, AgentState.WAITING):
        return manager.state.value
    in_flight = tasks.by_status(
        TaskStatus.RUNNING, TaskStatus.ASSIGNED, TaskStatus.IN_REVIEW,
        TaskStatus.BLOCKED, TaskStatus.WAITING_DEPENDENCY, TaskStatus.WAITING_APPROVAL,
    )
    owned = [t for t in in_flight if t.manager_id == MANAGER_ROLE_ID or t.role_id == MANAGER_ROLE_ID]
    if owned:
        return AgentState.ACTIVE.value
    if tasks.by_status(TaskStatus.FAILED):
        return AgentState.ACTIVE.value  # failures are the manager's to resolve
    return (manager.state.value if manager else AgentState.IDLE.value)


def _overall_state(phase: Dict[str, Any], stats: Dict[str, int], failed, blocked, run: Dict[str, Any]) -> str:
    """One word for "what is the organization doing", derived from real state.

    Two distinctions keep this honest:

    * A task in ``waiting_dependency`` is normal pipeline ordering, not a
      blockage — only a real ``blocked`` task or a pending approval stalls the
      run.  Reporting the whole organization as blocked because a later step is
      correctly waiting on an earlier one would be noise.
    * Activity is measured over *worker* steps (``phase["steps_running"]``), not
      the global active count: the objective and X22's project are active for
      the entire run by construction, so they say nothing about progress.
    """
    if run.get("stopped"):
        return "stopped"
    if run.get("paused"):
        return "paused"

    working = int(phase.get("steps_running") or 0)
    # Nothing left to run at all: the run is over, not waiting on anyone.
    if phase["label"] == "failed":
        return "failed"
    # A decision only the operator can make outranks a recorded failure: the
    # failure is already on the task and in the event stream, while the pending
    # approval is the one thing the organization cannot work around right now.
    if any(b.get("requires_approval") or b.get("status") == "waiting_approval" for b in blocked):
        return "awaiting_operator"
    if working:
        return "running"
    if failed:
        return "failed"
    if any(b.get("status") == "blocked" for b in blocked):
        return "blocked"
    if stats.get("in_review"):
        return "in_review"
    if phase["label"] == "completed":
        return "completed"
    if phase["label"] == "executing":
        return "running"
    if phase["label"] == "planning":
        return "planning"
    if not run.get("active"):
        return "idle"
    return phase["label"]


def _next_actions(runtime, phase, ready, blocked, failed) -> List[Dict[str, Any]]:
    """What the organization should do next — derived, not scripted."""
    actions: List[Dict[str, Any]] = []
    approvals = runtime.pending_approvals()
    for a in approvals:
        actions.append(
            {
                "kind": "operator_decision",
                "task_id": a.get("task_id"),
                "detail": _short(a.get("question"), 100),
                "approval_id": a.get("id"),
            }
        )
    for f in failed:
        if f.get("retryable"):
            actions.append(
                {
                    "kind": "retry",
                    "task_id": f["task_id"],
                    "detail": f"retry {f['role_id']} (attempt {f['attempt']}/{f['max_attempts']})",
                }
            )
        else:
            actions.append(
                {
                    "kind": "reassign_or_escalate",
                    "task_id": f["task_id"],
                    "detail": f"{f['role_id']} exhausted retries — reassign or escalate",
                }
            )
    for b in blocked:
        if b.get("blocking_dependencies"):
            deps = ", ".join(d.get("task_id", "?") for d in b["blocking_dependencies"][:3])
            actions.append(
                {"kind": "wait", "task_id": b["task_id"], "detail": f"waiting on {deps}"}
            )
        elif not b.get("requires_approval"):
            actions.append(
                {"kind": "unblock", "task_id": b["task_id"], "detail": _short(b.get("reason"), 100)}
            )
    for r in ready[:6]:
        actions.append(
            {
                "kind": "dispatch",
                "task_id": r["task_id"],
                "detail": f"dispatch {r.get('role_id') or 'worker'}: {_short(r['objective'], 80)}",
            }
        )
    review = runtime.tasks.by_status(TaskStatus.IN_REVIEW)
    for t in review[:4]:
        actions.append({"kind": "review", "task_id": t.id, "detail": f"review output of {t.role_id}"})
    if not actions:
        if phase["label"] == "completed":
            actions.append({"kind": "synthesise", "detail": "all tasks completed — synthesise the result"})
        elif phase["label"] == "planning":
            actions.append({"kind": "plan", "detail": "decompose the objective into worker tasks"})
        else:
            actions.append({"kind": "monitor", "detail": "execution in flight — nothing requires action"})
    return actions


def render_status(status: Dict[str, Any], *, width: int = 78) -> str:
    """Terse operator-facing status text.  Every value comes from *status*."""
    lines: List[str] = []
    run = status.get("run") or {}
    phase = status.get("phase") or {}
    counts = status.get("counts") or {}

    objective = _short(run.get("objective"), width - 14) or "(no objective accepted yet)"
    lines.append(f"Objective : {objective}")
    lines.append(
        f"Phase     : {phase.get('label', 'unknown')} — {phase.get('detail', '')}"
    )
    lines.append(f"State     : {status.get('overall_state', 'unknown')}")
    if run.get("elapsed_seconds") is not None:
        lines.append(f"Elapsed   : {_fmt_elapsed(run.get('elapsed_seconds'))}")

    manager = status.get("manager") or {}
    m_line = f"Manager   : X22 — {manager.get('state', 'idle')}"
    if manager.get("current_objective"):
        m_line += f" — {_short(manager.get('current_objective'), 44)}"
    lines.append(m_line)

    active = status.get("active_agents") or []
    live = status.get("live_subagents") or []
    if active:
        lines.append("Active    :")
        for a in active[:8]:
            elapsed = _fmt_elapsed(a.get("running_seconds"))
            task = a.get("current_task_id") or "—"
            lines.append(
                f"  · {a.get('display_name', a.get('role_id')):<22} "
                f"{a.get('state', ''):<8} task {task:<16} {elapsed}"
            )
    elif live:
        lines.append("Active    :")
        for s in live[:8]:
            lines.append(
                f"  · subagent {s.get('subagent_id')} d{s.get('depth')} "
                f"{_short(s.get('goal'), 40)} ({_fmt_elapsed(s.get('running_seconds'))})"
            )
    else:
        lines.append("Active    : none — no worker is running right now")

    lines.append(
        "Tasks     : "
        f"{counts.get('completed', 0)} done · {counts.get('active', 0)} running · "
        f"{counts.get('waiting', 0)} waiting · {counts.get('failed', 0)} failed · "
        f"{counts.get('in_review', 0)} in review · {counts.get('queued', 0)} queued"
    )

    blocked = status.get("blocked") or []
    if blocked:
        lines.append("Blocked   :")
        for b in blocked[:6]:
            reason = _short(b.get("reason"), 60) or "no reason recorded"
            deps = b.get("blocking_dependencies") or []
            dep_txt = f" (needs {', '.join(d.get('task_id', '?') for d in deps[:2])})" if deps else ""
            flag = " [approval]" if b.get("requires_approval") else ""
            lines.append(f"  · {b['task_id']} {b.get('role_id') or '?'}: {reason}{dep_txt}{flag}")

    failed = status.get("failed") or []
    if failed:
        lines.append("Failures  :")
        for f in failed[:6]:
            retry = "retryable" if f.get("retryable") else "retries exhausted"
            lines.append(
                f"  · {f['task_id']} {f.get('role_id') or '?'}: "
                f"{_short(f.get('error'), 54)} [{retry}]"
            )

    approvals = status.get("pending_approvals") or []
    if approvals:
        lines.append("Needs you :")
        for a in approvals[:4]:
            lines.append(f"  · {_short(a.get('question'), 66)}")

    next_actions = status.get("next_actions") or []
    if next_actions:
        lines.append("Next      :")
        for n in next_actions[:6]:
            lines.append(f"  · [{n.get('kind')}] {_short(n.get('detail'), 62)}")

    events = status.get("recent_events") or []
    if events:
        lines.append("Recent    :")
        for e in events[-6:]:
            stamp = time.strftime("%H:%M:%S", time.localtime(e.get("ts", time.time())))
            lines.append(f"  {stamp}  {e.get('type', ''):<22} {_short(e.get('message'), 44)}")

    return "\n".join(lines)
