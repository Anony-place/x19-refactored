"""Contracts: the X19 organization surface (handlers in ``tui_gateway/methods_org.py``).

The nested rows — tasks, agent records, events, approvals — are declared as
:class:`OpenModel` on purpose: their closed shape is owned by ``x19/org`` (task
lifecycle metadata, registry records, the event stream), and re-declaring every
field here would create a second definition that could silently drift from the
runtime that produces it.  The typed fields below are the ones the client lays
out; anything else passes through.

Nothing in this surface is synthetic.  A method answers from recorded runtime
state, and an organization that has done nothing reports empty lists rather than
placeholder rows.
"""

from __future__ import annotations

from .base import Params, Result
from .common import OpenModel, ProfileParams
from .registry import method

# ── shared rows ───────────────────────────────────────────────────────────────────────────────


class OrgTask(OpenModel):
    """One task-graph node (``x19.org.tasks.Task.to_dict``)."""

    id: str
    objective: str = ""
    role_id: str | None = None
    status: str = ""
    parent_id: str | None = None


class OrgAgent(OpenModel):
    """One roster slot overlaid with live delegation state (``x19.org.registry``)."""

    role_id: str
    state: str = ""
    kind: str | None = None


class OrgEvent(OpenModel):
    """One event from the append-only stream (``x19.org.events.OrgEvent.to_dict``)."""

    seq: int = 0
    type: str = ""
    message: str = ""


class OrgApproval(OpenModel):
    """A decision waiting on the operator, or one already made."""

    id: str
    task_id: str | None = None
    question: str = ""
    decision: str | None = None


class OrgRole(OpenModel):
    """One registered role (``x19.org.roles.RoleSpec.to_dict``)."""

    id: str
    kind: str = ""
    manager_id: str | None = None


class OrgPhase(OpenModel):
    """Phase is computed from the graph, never stored."""

    label: str = ""
    detail: str = ""


# ── read ──────────────────────────────────────────────────────────────────────────────────────


class OrgStatusParams(ProfileParams):
    event_limit: int | None = None


class OrgStatusResult(Result):
    """``status`` is the full projection; ``render`` is the same content as dense text."""

    status: OpenModel
    render: str = ""


method("org.status", params=OrgStatusParams, result=OrgStatusResult,
       doc="Run, phase, counts, roster, blocked/failed/ready tasks and derived next actions.")


class OrgAuditParams(ProfileParams):
    include_outputs: bool | None = None


class OrgAuditResult(Result):
    audit: OpenModel
    render: str = ""


method("org.audit", params=OrgAuditParams, result=OrgAuditResult,
       doc="Boss Audit Mode: the executive report over the task graph, queue, failures and spend.")


class OrgAgentsResult(Result):
    agents: list[OrgAgent]
    live_subagents: list[OpenModel]
    counts: OpenModel


method("org.agents", params=ProfileParams, result=OrgAgentsResult,
       doc="Registered roster overlaid with the delegation engine's live subagents.")


class OrgRolesResult(Result):
    roles: list[OrgRole]


method("org.roles", params=ProfileParams, result=OrgRolesResult,
       doc="The live role catalog — dynamic, so the client never hardcodes the org chart.")


class OrgTasksParams(ProfileParams):
    status: str | None = None
    limit: int | None = None


class OrgTasksResult(Result):
    stats: OpenModel
    tree: list[OpenModel]
    ready: list[OpenModel]
    blocked: list[OpenModel]
    failed: list[OrgTask]
    in_review: list[OrgTask]
    run: OpenModel
    filtered: list[OrgTask] | None = None
    filter: str | None = None


method("org.tasks", params=OrgTasksParams, result=OrgTasksResult,
       doc="The task graph: tree, counts and the ready/blocked/failed/review slices.")


class OrgEventsParams(ProfileParams):
    limit: int | None = None
    since_seq: int | None = None
    task_id: str | None = None
    agent_id: str | None = None


class OrgEventsResult(Result):
    events: list[OrgEvent]
    last_seq: int = 0
    counts_by_type: OpenModel


method("org.events", params=OrgEventsParams, result=OrgEventsResult,
       doc="Recent organization events; pass since_seq to poll incrementally.")


class OrgApprovalsResult(Result):
    pending: list[OrgApproval]


method("org.approvals", params=ProfileParams, result=OrgApprovalsResult,
       doc="Decisions waiting on the operator.")


# ── write: operator authority ─────────────────────────────────────────────────────────────────


class OrgApprovalDecisionParams(ProfileParams):
    approval_id: str
    decided_by: str | None = None
    note: str | None = None


class OrgApprovalResult(Result):
    approval: OrgApproval


method("org.approve", params=OrgApprovalDecisionParams, result=OrgApprovalResult,
       doc="Approve a gated task or a delivered output. Never auto-resolved.")
method("org.deny", params=OrgApprovalDecisionParams, result=OrgApprovalResult,
       doc="Deny a request; the task fails with the operator's reason recorded.")


class OrgControlParams(ProfileParams):
    reason: str | None = None


class OrgPauseResult(Result):
    paused: bool
    enforced: bool = False


method("org.pause", params=OrgControlParams, result=OrgPauseResult,
       doc="Pause the run; ``enforced`` reports whether the spawn gate really closed.")
method("org.resume", params=OrgControlParams, result=OrgPauseResult,
       doc="Resume the run and reopen the spawn gate.")


class OrgStopResult(Result):
    stopped: bool
    cancelled: list[str]


method("org.stop", params=OrgControlParams, result=OrgStopResult,
       doc="Stop the run and cancel everything not already terminal; returns the cancelled ids.")


class OrgTaskControlParams(ProfileParams):
    task_id: str
    op: str
    reason: str | None = None
    note: str | None = None
    approved: bool | None = None


class OrgTaskControlResult(Result):
    op: str
    task_id: str
    result: OpenModel


method("org.task.control", params=OrgTaskControlParams, result=OrgTaskControlResult,
       doc="Retry, cancel, resolve a blocker on, or review one task — the real transition.")
