"""X19 agent registry — dynamic, backed by real runtime state.

Two layers, deliberately kept apart:

* **Roster** — the organizational structure, derived from the live role catalog
  (:mod:`x19.org.roles`).  Adding a worker role adds a roster entry; the UI,
  the audit report and the status projection all render whatever is registered,
  so nothing about the organization is hardcoded in a frontend.
* **Live overlay** — what is *actually happening right now*, read from the real
  subagent registry (``tools.delegate_tool_registry.list_active_subagents``) and
  from the task store.  Agent state, current task, model, elapsed time and tool
  activity all come from there.

An agent that has never run reports ``state=IDLE`` and ``current_task=None``.
It never reports invented activity.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence

from .roles import (
    BOSS_ROLE_ID,
    MANAGER_ROLE_ID,
    RoleKind,
    RoleSpec,
    get_role,
    role_catalog,
)

__all__ = [
    "AgentState",
    "AgentHealth",
    "AgentRecord",
    "AgentRegistry",
    "STALE_ACTIVE_SECONDS",
]


class AgentState(str, Enum):
    IDLE = "idle"
    ACTIVE = "active"
    WAITING = "waiting"
    BLOCKED = "blocked"
    OFFLINE = "offline"


class AgentHealth(str, Enum):
    UNKNOWN = "unknown"
    OK = "ok"
    DEGRADED = "degraded"
    FAILING = "failing"


# A live subagent that has produced no tool activity for this long is flagged
# degraded — a real signal, computed from the runtime's own timestamps.
STALE_ACTIVE_SECONDS = 900.0


@dataclass
class AgentRecord:
    """One agent in the organization."""

    agent_id: str
    role_id: str
    kind: RoleKind
    display_name: str
    title: str
    capabilities: List[str] = field(default_factory=list)
    toolsets: List[str] = field(default_factory=list)
    manager_id: Optional[str] = None
    model: Optional[str] = None
    model_tier: Optional[str] = None

    state: AgentState = AgentState.IDLE
    health: AgentHealth = AgentHealth.UNKNOWN

    current_task_id: Optional[str] = None
    current_objective: Optional[str] = None
    subagent_id: Optional[str] = None
    delegation_id: Optional[str] = None
    live_transcript: Optional[str] = None

    started_at: Optional[float] = None
    last_activity_at: Optional[float] = None
    finished_at: Optional[float] = None

    tasks_completed: int = 0
    tasks_failed: int = 0
    last_error: Optional[str] = None

    def to_dict(self, *, now: Optional[float] = None) -> Dict[str, Any]:
        now = now if now is not None else time.time()
        running = None
        if self.started_at is not None:
            end = self.finished_at if self.finished_at is not None else now
            running = round(max(0.0, end - self.started_at), 1)
        return {
            "agent_id": self.agent_id,
            "role_id": self.role_id,
            "kind": self.kind.value,
            "display_name": self.display_name,
            "title": self.title,
            "capabilities": list(self.capabilities),
            "toolsets": list(self.toolsets),
            "manager_id": self.manager_id,
            "model": self.model,
            "model_tier": self.model_tier,
            "state": self.state.value,
            "health": self.health.value,
            "current_task_id": self.current_task_id,
            "current_objective": self.current_objective,
            "subagent_id": self.subagent_id,
            "delegation_id": self.delegation_id,
            "live_transcript": self.live_transcript,
            "started_at": self.started_at,
            "last_activity_at": self.last_activity_at,
            "finished_at": self.finished_at,
            "running_seconds": running,
            "tasks_completed": self.tasks_completed,
            "tasks_failed": self.tasks_failed,
            "last_error": self.last_error,
        }


def _record_from_role(role: RoleSpec, agent_id: str) -> AgentRecord:
    return AgentRecord(
        agent_id=agent_id,
        role_id=role.id,
        kind=role.kind,
        display_name=role.display_name,
        title=role.title,
        capabilities=list(role.capabilities),
        toolsets=list(role.toolsets),
        manager_id=role.manager_id,
        model_tier=role.model_tier,
    )


class AgentRegistry:
    """Roster + live overlay.

    ``live_reader`` is injected so this module never imports the delegation
    engine at import time (that would create a cycle and slow every startup).
    The default reader is bound lazily in :func:`default_live_reader`.
    """

    def __init__(
        self,
        *,
        live_reader: Optional[Callable[[], Sequence[Dict[str, Any]]]] = None,
        stale_after_seconds: Optional[float] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._agents: Dict[str, AgentRecord] = {}
        self._live_reader = live_reader
        self._by_subagent: Dict[str, str] = {}
        # ``x19.org.stale_after_seconds`` in config; the module constant is the
        # default so the registry stays usable standalone.
        self._stale_after_seconds = float(
            stale_after_seconds if stale_after_seconds is not None else STALE_ACTIVE_SECONDS
        )
        self.refresh_roster()

    @property
    def stale_after_seconds(self) -> float:
        return self._stale_after_seconds

    # -- roster -----------------------------------------------------------
    def refresh_roster(self) -> None:
        """Rebuild roster entries from the live role catalog.

        Existing live state is preserved for agents that are still registered,
        so a catalog refresh never erases what is actually running.
        """
        with self._lock:
            wanted: Dict[str, AgentRecord] = {}
            for role in role_catalog():
                agent_id = _agent_id_for(role)
                existing = self._agents.get(agent_id)
                wanted[agent_id] = existing or _record_from_role(role, agent_id)
                if existing is not None:
                    # keep capability/toolset metadata in sync with the catalog
                    existing.capabilities = list(role.capabilities)
                    existing.toolsets = list(role.toolsets)
                    existing.title = role.title
                    existing.display_name = role.display_name
                    existing.manager_id = role.manager_id
                    existing.model_tier = role.model_tier
            self._agents = wanted

    def register_agent(self, record: AgentRecord) -> AgentRecord:
        with self._lock:
            self._agents[record.agent_id] = record
            return record

    def agents(self) -> List[AgentRecord]:
        self.refresh_roster()
        with self._lock:
            order = {RoleKind.BOSS: 0, RoleKind.MANAGER: 1, RoleKind.WORKER: 2}
            return sorted(self._agents.values(), key=lambda a: (order[a.kind], a.agent_id))

    def get(self, agent_id: Optional[str]) -> Optional[AgentRecord]:
        if not agent_id:
            return None
        with self._lock:
            return self._agents.get(agent_id)

    def for_role(self, role_id: str) -> Optional[AgentRecord]:
        return self.get(_agent_id_for_role(role_id))

    # -- live overlay -----------------------------------------------------
    def bind_subagent(
        self,
        *,
        agent_id: str,
        subagent_id: str,
        task_id: Optional[str],
        objective: Optional[str] = None,
        delegation_id: Optional[str] = None,
        model: Optional[str] = None,
        live_transcript: Optional[str] = None,
    ) -> Optional[AgentRecord]:
        """Record that a real child agent was dispatched for this roster slot."""
        with self._lock:
            rec = self._agents.get(agent_id)
            if rec is None:
                role = get_role(agent_id)
                if role is None:
                    return None
                rec = _record_from_role(role, agent_id)
                self._agents[agent_id] = rec
            rec.subagent_id = subagent_id
            rec.delegation_id = delegation_id
            rec.current_task_id = task_id
            rec.current_objective = objective
            rec.model = model
            rec.live_transcript = live_transcript
            rec.state = AgentState.ACTIVE
            rec.started_at = time.time()
            rec.last_activity_at = rec.started_at
            rec.finished_at = None
            rec.last_error = None
            self._by_subagent[subagent_id] = agent_id
            return rec

    def mark_active(
        self,
        agent_id: str,
        *,
        task_id: Optional[str] = None,
        objective: Optional[str] = None,
    ) -> Optional[AgentRecord]:
        """Mark an orchestration slot active without a spawned child.

        Used for X22 while it owns a project: the manager is genuinely working
        (planning, assigning, tracking) even when no subagent id exists yet.
        """
        with self._lock:
            rec = self._agents.get(agent_id)
            if rec is None:
                return None
            rec.state = AgentState.ACTIVE
            rec.started_at = rec.started_at or time.time()
            rec.last_activity_at = time.time()
            rec.finished_at = None
            if task_id:
                rec.current_task_id = task_id
            if objective:
                rec.current_objective = objective
            if rec.health is AgentHealth.UNKNOWN:
                rec.health = AgentHealth.OK
            return rec

    def note_activity(self, agent_id: str, *, tool_count: Optional[int] = None) -> None:
        with self._lock:
            rec = self._agents.get(agent_id)
            if rec is None:
                return
            rec.last_activity_at = time.time()

    def mark_waiting(self, agent_id: str, reason: str = "") -> None:
        with self._lock:
            rec = self._agents.get(agent_id)
            if rec is None:
                return
            rec.state = AgentState.WAITING
            rec.last_activity_at = time.time()

    def mark_blocked(self, agent_id: str, reason: str = "") -> None:
        with self._lock:
            rec = self._agents.get(agent_id)
            if rec is None:
                return
            rec.state = AgentState.BLOCKED
            rec.last_error = reason or rec.last_error
            rec.last_activity_at = time.time()

    def release(
        self,
        agent_id: str,
        *,
        succeeded: bool,
        error: Optional[str] = None,
        model: Optional[str] = None,
    ) -> Optional[AgentRecord]:
        with self._lock:
            rec = self._agents.get(agent_id)
            if rec is None:
                return None
            rec.finished_at = time.time()
            rec.last_activity_at = rec.finished_at
            rec.state = AgentState.IDLE
            if succeeded:
                rec.tasks_completed += 1
                rec.health = AgentHealth.OK
                rec.last_error = None
            else:
                rec.tasks_failed += 1
                rec.health = AgentHealth.FAILING
                rec.last_error = error
            if model:
                rec.model = model
            rec.current_task_id = None
            rec.current_objective = None
            if rec.subagent_id:
                self._by_subagent.pop(rec.subagent_id, None)
            rec.subagent_id = None
            rec.delegation_id = None
            rec.live_transcript = None
            return rec

    def release_by_subagent(self, subagent_id: str, **kwargs: Any) -> Optional[AgentRecord]:
        with self._lock:
            agent_id = self._by_subagent.get(subagent_id)
        if not agent_id:
            return None
        return self.release(agent_id, **kwargs)

    def agent_for_subagent(self, subagent_id: Optional[str]) -> Optional[AgentRecord]:
        if not subagent_id:
            return None
        with self._lock:
            agent_id = self._by_subagent.get(subagent_id)
            return self._agents.get(agent_id) if agent_id else None

    # -- live snapshot ----------------------------------------------------
    def live_subagents(self) -> List[Dict[str, Any]]:
        """Real, currently-running subagents from the delegation engine."""
        reader = self._live_reader or default_live_reader()
        try:
            return list(reader() or [])
        except Exception:
            return []

    def reconcile(self) -> List[Dict[str, Any]]:
        """Overlay the real subagent registry onto the roster.

        Returns the live subagent records.  Roster entries whose subagent has
        disappeared from the live registry are returned to IDLE — that is the
        honest reading of "the runtime no longer lists it".
        """
        live = self.live_subagents()
        live_ids = {str(r.get("subagent_id")) for r in live if r.get("subagent_id")}
        now = time.time()
        with self._lock:
            for rec in self._agents.values():
                if rec.subagent_id and rec.subagent_id not in live_ids:
                    rec.state = AgentState.IDLE
                    rec.finished_at = rec.finished_at or now
                    rec.subagent_id = None
                    rec.current_task_id = None
                    rec.current_objective = None
                elif rec.state is AgentState.ACTIVE and rec.last_activity_at:
                    if now - rec.last_activity_at > self._stale_after_seconds:
                        rec.health = AgentHealth.DEGRADED
                    elif rec.health is AgentHealth.UNKNOWN:
                        rec.health = AgentHealth.OK
        return live

    def snapshot(self) -> Dict[str, Any]:
        """Full registry snapshot for the UI / RPC / audit."""
        live = self.reconcile()
        now = time.time()
        with self._lock:
            agents = [a.to_dict(now=now) for a in self.agents()]
        by_state: Dict[str, int] = {}
        for a in agents:
            by_state[a["state"]] = by_state.get(a["state"], 0) + 1
        return {
            "agents": agents,
            "counts": {
                "total": len(agents),
                "boss": sum(1 for a in agents if a["kind"] == RoleKind.BOSS.value),
                "manager": sum(1 for a in agents if a["kind"] == RoleKind.MANAGER.value),
                "worker": sum(1 for a in agents if a["kind"] == RoleKind.WORKER.value),
                "active": sum(1 for a in agents if a["state"] == AgentState.ACTIVE.value),
                "waiting": sum(1 for a in agents if a["state"] == AgentState.WAITING.value),
                "blocked": sum(1 for a in agents if a["state"] == AgentState.BLOCKED.value),
                "idle": sum(1 for a in agents if a["state"] == AgentState.IDLE.value),
            },
            "by_state": by_state,
            "live_subagents": [
                {
                    "subagent_id": r.get("subagent_id"),
                    "parent_id": r.get("parent_id"),
                    "depth": r.get("depth"),
                    "goal": r.get("goal"),
                    "model": r.get("model"),
                    "status": r.get("status"),
                    "started_at": r.get("started_at"),
                    "tool_count": r.get("tool_count"),
                    "delegation_id": r.get("delegation_id"),
                    "running_seconds": (
                        round(now - r["started_at"], 1)
                        if isinstance(r.get("started_at"), (int, float))
                        else None
                    ),
                }
                for r in live
            ],
            "generated_at": now,
        }


def _agent_id_for(role: RoleSpec) -> str:
    """Stable agent id for a role.

    Boss and manager are singletons named after the product identity (``x19``,
    ``x22``); workers are addressed by role id so the roster stays readable and
    multiple concurrent instances of one role are distinguished by their
    ``subagent_id`` rather than by inventing names.
    """
    return role.id


def _agent_id_for_role(role_id: str) -> str:
    return role_id


_LIVE_READER: Optional[Callable[[], Sequence[Dict[str, Any]]]] = None


def default_live_reader() -> Callable[[], Sequence[Dict[str, Any]]]:
    """Bind the real delegation registry reader (lazy, import-safe)."""
    global _LIVE_READER
    if _LIVE_READER is None:
        def _read() -> Sequence[Dict[str, Any]]:
            try:
                from tools.delegate_tool_registry import list_active_subagents

                return list_active_subagents()
            except Exception:
                return []

        _LIVE_READER = _read
    return _LIVE_READER


def set_live_reader(reader: Optional[Callable[[], Sequence[Dict[str, Any]]]]) -> None:
    """Override the live reader (tests inject a deterministic source)."""
    global _LIVE_READER
    _LIVE_READER = reader
