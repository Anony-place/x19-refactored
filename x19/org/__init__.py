"""X19 organization runtime.

The three-tier hierarchy, backed by real execution state::

    USER
      |
    X19   BOSS      executive orchestrator  (x19.org.boss.Boss)
      |
    X22   MANAGER   project manager         (x19.org.manager.Manager)
      |
    workers         specialized execution   (x19.org.roles.role_catalog)
      |
    tools           the real delegation engine + tool surface

Everything visible about the organization — who exists, what they are doing,
which task is in which phase, what failed, what is blocked — is read from
:mod:`x19.org.runtime`, which is fed by the real delegation engine through
:mod:`x19.org.delegation`.  No part of it fabricates state.
"""

from __future__ import annotations

from .audit import build_audit, render_audit
from .config import DEFAULT_ORG_SETTINGS, OrgSettings, load_org_settings
from .boss import Boss
from .delegation import (
    build_dispatch,
    dispatch_ready_tasks,
    dispatch_task,
    observe_child_result,
    observe_child_started,
    role_for_goal,
)
from .events import EventBus, EventType, OrgEvent, get_event_bus, reset_event_bus
from .manager import Manager
from .registry import AgentHealth, AgentRecord, AgentRegistry, AgentState, set_live_reader
from .roles import (
    BOSS_ROLE_ID,
    MANAGER_ROLE_ID,
    RoleKind,
    RoleSpec,
    capability_index,
    get_role,
    manager_roles,
    register_role,
    reset_roles,
    role_catalog,
    roles_for_capabilities,
    unregister_role,
    worker_roles,
)
from .runtime import OrganizationRuntime, RunRecord, get_runtime, reset_runtime, set_runtime
from .safety import ExecutionGuards, GuardDecision, fingerprint
from .status import build_status, describe_phase, render_status
from .tasks import (
    InvalidTransition,
    ReviewState,
    Task,
    TaskMetrics,
    TaskPhase,
    TaskPriority,
    TaskStatus,
    TaskStore,
)

__all__ = [
    "DEFAULT_ORG_SETTINGS",
    "OrgSettings",
    "load_org_settings",
    # runtime
    "OrganizationRuntime",
    "RunRecord",
    "get_runtime",
    "reset_runtime",
    "set_runtime",
    # actors
    "Boss",
    "Manager",
    # roles
    "RoleKind",
    "RoleSpec",
    "BOSS_ROLE_ID",
    "MANAGER_ROLE_ID",
    "role_catalog",
    "worker_roles",
    "manager_roles",
    "get_role",
    "register_role",
    "unregister_role",
    "reset_roles",
    "capability_index",
    "roles_for_capabilities",
    # registry
    "AgentRegistry",
    "AgentRecord",
    "AgentState",
    "AgentHealth",
    "set_live_reader",
    # tasks
    "Task",
    "TaskStore",
    "TaskStatus",
    "TaskPhase",
    "TaskPriority",
    "TaskMetrics",
    "ReviewState",
    "InvalidTransition",
    # events
    "EventBus",
    "EventType",
    "OrgEvent",
    "get_event_bus",
    "reset_event_bus",
    # delegation bridge
    "build_dispatch",
    "dispatch_task",
    "dispatch_ready_tasks",
    "observe_child_started",
    "observe_child_result",
    "role_for_goal",
    # safety
    "ExecutionGuards",
    "GuardDecision",
    "fingerprint",
    # projection
    "build_status",
    "render_status",
    "describe_phase",
    "build_audit",
    "render_audit",
]
