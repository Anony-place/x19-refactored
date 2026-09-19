"""Observe real delegation-engine activity into the X19 organization runtime.

The delegation engine (``tools.delegate_tool``) is the only component that knows
a child agent really started, really finished, and what it really cost.  These
hooks translate that ground truth into X19 task-lifecycle transitions, so the
organization's task graph is a record of what happened rather than a statement
of intent.

Two guarantees this module holds:

* **Never fabricate.**  Nothing here invents a status, a duration or a result.
  Every field comes from the engine's own per-child record.  When a spawn does
  not belong to an X19 task (a plain ad-hoc ``delegate_task`` call), the
  observation is dropped for the task graph and the child still shows up in the
  registry's live overlay.
* **Never break delegation.**  Observation is strictly best-effort.  Every path
  runs inside the delegation tools' ``_quiet`` idiom, so nothing here raises or
  changes the engine's control flow; a failure to observe is logged at debug.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from tools.delegate_tool_progress import _quiet

__all__ = [
    "observe_child_started",
    "observe_child_result",
    "org_runtime",
    "org_snapshot",
]


def _str_or_none(value: Any) -> Optional[str]:
    if isinstance(value, str) and value:
        return value
    return None


def org_runtime(persist: bool = True):
    """The process-wide organization runtime, or ``None`` if it cannot load.

    Resolved lazily so importing the delegation engine never requires the org
    package to be importable.
    """
    with _quiet("x19 org: runtime unavailable: %s"):
        from x19.org.runtime import get_runtime

        return get_runtime(persist=persist)
    return None


def observe_child_started(
    child: Any,
    goal: str,
    *,
    subagent_id: Optional[str] = None,
) -> Optional[str]:
    """Record that the engine really started *child* on *goal*.

    Returns the X19 task id the child was matched to, or ``None`` when the spawn
    did not originate from the task graph.

    The whole body is guarded: an organization-layer fault degrades to ``None``
    and can never propagate into the delegation engine.
    """
    with _quiet("x19 org: failed to observe child start: %s"):
        sid = subagent_id or _str_or_none(getattr(child, "_subagent_id", None))
        if sid is None:
            return None  # test double without a stable id: nothing real to record
        rt = org_runtime()
        if rt is None:
            return None
        from x19.org.delegation import observe_child_started as _observe

        raw_depth = getattr(child, "_delegate_depth", 1)
        return _observe(
            goal=goal,
            subagent_id=sid,
            delegation_id=_str_or_none(getattr(child, "_delegation_id", None)),
            model=_str_or_none(getattr(child, "model", None)),
            depth=max(0, raw_depth - 1) if isinstance(raw_depth, int) else 0,
            parent_subagent_id=_str_or_none(getattr(child, "_parent_subagent_id", None)),
            runtime=rt,
        )
    return None


def observe_child_result(
    child: Any,
    goal: Optional[str],
    entry: Optional[Dict[str, Any]],
    *,
    subagent_id: Optional[str] = None,
    task_id: Optional[str] = None,
) -> Optional[str]:
    """Record the engine's real result *entry* against the owning task.

    *entry* is exactly what ``_build_result_entry`` / ``_fabricated_entry``
    produced for the parent: status, exit_reason, summary, api_calls, duration,
    tokens, cost, tool trace, error.  Nothing is added, nothing is inferred.
    """
    with _quiet("x19 org: failed to observe child result: %s"):
        if not isinstance(entry, dict) or not entry:
            return None
        rt = org_runtime()
        if rt is None:
            return None
        from x19.org.delegation import observe_child_result as _observe

        return _observe(
            subagent_id=subagent_id or _str_or_none(getattr(child, "_subagent_id", None)),
            goal=goal,
            entry=entry,
            task_id=task_id,
            runtime=rt,
        )
    return None


def org_snapshot() -> Optional[Dict[str, Any]]:
    """The full organization snapshot for RPC/TUI consumers."""
    with _quiet("x19 org: snapshot failed: %s"):
        rt = org_runtime()
        if rt is None:
            return None
        return rt.snapshot()
    return None
