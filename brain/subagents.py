"""Dynamic sub-agent planning for X19.

This module creates task-specialized *reasoning workers* at runtime. Workers do
not execute commands or change scope; they return structured work proposals to
the parent controller, which remains responsible for policy, authorization,
and execution.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional
from uuid import uuid4


@dataclass(frozen=True)
class SubAgentSpec:
    """Runtime role generated from a mission task."""

    agent_id: str
    role: str
    objective: str
    capabilities: tuple[str, ...] = ()
    inputs: tuple[str, ...] = ()
    expected_outputs: tuple[str, ...] = ()
    priority: float = 0.5
    parent_task_id: str = ""


@dataclass(frozen=True)
class SubAgentResult:
    """A worker's result; execution is deliberately outside this object."""

    agent_id: str
    status: str
    observations: List[Dict[str, Any]] = field(default_factory=list)
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    proposed_actions: List[Dict[str, Any]] = field(default_factory=list)
    blockers: List[str] = field(default_factory=list)


class SubAgentFactory:
    """Build the smallest useful set of specialist workers for a task.

    The factory is deliberately deterministic at the capability boundary:
    dynamic agents may be created, but they cannot grant themselves tools,
    permissions, targets, or execution authority.
    """

    ROLE_CAPABILITIES: Mapping[str, tuple[str, ...]] = {
        "recon": ("surface_mapping", "service_analysis"),
        "web": ("endpoint_analysis", "request_analysis"),
        "api": ("api_modeling", "schema_analysis"),
        "auth": ("identity_analysis", "authorization_analysis"),
        "logic": ("workflow_analysis", "state_analysis"),
        "code": ("source_analysis", "dependency_analysis"),
        "infra": ("service_analysis", "configuration_analysis"),
        "verifier": ("evidence_review", "reproducibility_review"),
        "critic": ("failure_analysis", "strategy_review"),
    }

    ROLE_HINTS: Mapping[str, tuple[str, ...]] = {
        "recon": ("host", "service", "surface", "discovery", "enumeration"),
        "web": ("web", "http", "endpoint", "browser", "route"),
        "api": ("api", "graphql", "json", "rest", "schema"),
        "auth": ("auth", "identity", "session", "role", "permission", "access"),
        "logic": ("workflow", "business", "state", "logic"),
        "code": ("source", "code", "repository", "dependency"),
        "infra": ("network", "service", "tls", "cloud", "infrastructure"),
        "verifier": ("verify", "validate", "evidence", "reproduce", "finding"),
        "critic": ("failure", "stuck", "review", "replan", "contradiction"),
    }

    def spawn_for_task(
        self,
        task: Mapping[str, Any],
        *,
        max_agents: int = 4,
        existing_roles: Optional[Iterable[str]] = None,
    ) -> List[SubAgentSpec]:
        """Create role specs from task text/state without granting execution rights."""
        objective = str(task.get("objective") or task.get("description") or task.get("goal") or "").strip()
        task_id = str(task.get("task_id") or task.get("id") or "")
        text = objective.lower()
        roles: List[str] = []

        for role, hints in self.ROLE_HINTS.items():
            if any(hint in text for hint in hints):
                roles.append(role)

        # Always have a critic/verifier available for non-trivial tasks.
        if "verifier" not in roles and any(x in text for x in ("finding", "vulnerability", "test", "assess")):
            roles.append("verifier")
        if "critic" not in roles and any(x in text for x in ("replan", "blocked", "uncertain", "complex")):
            roles.append("critic")
        if not roles:
            roles = ["recon"]

        existing = {r for r in (existing_roles or ())}
        selected: List[SubAgentSpec] = []
        for index, role in enumerate(dict.fromkeys(roles)):
            if role in existing or len(selected) >= max_agents:
                continue
            selected.append(
                SubAgentSpec(
                    agent_id=f"sa-{uuid4().hex[:10]}",
                    role=role,
                    objective=objective,
                    capabilities=self.ROLE_CAPABILITIES[role],
                    inputs=("world_model", "mission_state", "prior_evidence"),
                    expected_outputs=("observations", "hypotheses", "proposed_actions"),
                    priority=max(0.1, 1.0 - index * 0.1),
                    parent_task_id=task_id,
                )
            )
        return selected

    @staticmethod
    def merge_results(results: Iterable[SubAgentResult]) -> Dict[str, List[Dict[str, Any]]]:
        """Merge worker proposals for the parent controller to validate."""
        merged: Dict[str, List[Dict[str, Any]]] = {
            "observations": [],
            "hypotheses": [],
            "proposed_actions": [],
            "blockers": [],
        }
        for result in results:
            merged["observations"].extend(result.observations)
            merged["hypotheses"].extend(result.hypotheses)
            merged["proposed_actions"].extend(result.proposed_actions)
            merged["blockers"].extend(result.blockers)
        return merged
