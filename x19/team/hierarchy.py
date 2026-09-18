"""
X19 Team Hierarchy — Boss → Managers → Specialists

Implements hierarchical security team coordination using Hermes' existing
delegation infrastructure. Does NOT create a second agent framework.

Hierarchy:
    OPERATOR (human client)
      ↓
    X19 BOSS / COMMANDER (you, orchestrator)
      ↓
    SECURITY MANAGERS (Recon, Web, API — orchestrator)
      ↓
    SPECIALIST AGENTS (9 specialists — leaf)
      ↓
    TOOLS / TERMINAL / BROWSER / DATA

Operator communicates primarily with Boss. Boss owns mission, defines scope,
splits assessment, delegates to Managers, Managers coordinate Specialists,
Specialists use real tools, results return upward.

This module provides:
- Hierarchy validation
- Delegation rules (who can delegate to whom)
- Communication protocol (evidence upward, tasks downward)
- Mission decomposition helpers
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from .roles import ALL_ROLES, ROLE_HIERARCHY, get_role, RoleDefinition


@dataclass
class DelegationRule:
    """Rule for who can delegate to whom."""

    from_role: str
    to_roles: List[str]
    max_depth: int  # Max spawn depth for this delegation
    requires_scope: bool
    requires_approval: bool
    description: str


# Delegation rules — enforce hierarchy
# Boss can delegate to any role (direct for small missions, via Managers for large)
ALL_SPECIALIST_AND_MANAGER_IDS = [
    "recon_manager", "web_manager", "api_manager",
    "web_security", "api_security", "auth", "cloud_infra",
    "vuln_research", "bugbounty_research", "verification", "evidence_reporting", "defensive_validation",
]

DELEGATION_RULES: List[DelegationRule] = [
    DelegationRule(
        from_role="boss",
        to_roles=ALL_SPECIALIST_AND_MANAGER_IDS,
        max_depth=2,
        requires_scope=True,
        requires_approval=False,
        description="Boss can delegate to any Manager or Specialist directly for small missions, or via Managers for large",
    ),
    DelegationRule(
        from_role="recon_manager",
        to_roles=["web_security", "api_security", "vuln_research", "web_manager", "api_manager", "auth", "cloud_infra"],
        max_depth=1,
        requires_scope=True,
        requires_approval=False,
        description="Recon Manager can delegate to recon specialists and feed Web/API Managers",
    ),
    DelegationRule(
        from_role="web_manager",
        to_roles=["web_security", "auth", "verification", "evidence_reporting", "defensive_validation", "vuln_research", "api_security"],
        max_depth=1,
        requires_scope=True,
        requires_approval=False,
        description="Web Manager coordinates web assessment specialists",
    ),
    DelegationRule(
        from_role="api_manager",
        to_roles=["api_security", "auth", "cloud_infra", "verification", "evidence_reporting", "defensive_validation", "vuln_research", "web_security"],
        max_depth=1,
        requires_scope=True,
        requires_approval=False,
        description="API Manager coordinates API assessment specialists",
    ),
    # Specialists are leaf — cannot delegate (enforced by Hermes delegation_role=leaf)
]


@dataclass
class CommunicationProtocol:
    """How agents communicate: evidence upward, tasks downward."""

    # Downward: Boss → Managers → Specialists
    task_assignment = {
        "format": "goal + context + scope + expected_evidence",
        "required_fields": ["objective", "scope", "constraints", "expected_evidence", "toolsets", "time_budget"],
        "example": (
            "Goal: Test https://target.com/api/users for BOLA/IDOR\n"
            "Context: Recon found /api/users endpoint, auth required, user IDs sequential\n"
            "Scope: authorized target target.com, allowed: read-only GETs + witness POSTs, prohibited: destructive, excluded: /admin\n"
            "Expected evidence: request/response, tool output, candidate finding with ID, endpoint, vuln class, repro steps"
        ),
    }

    # Upward: Specialists → Managers → Boss
    result_reporting = {
        "format": "evidence + status + next_steps",
        "required_fields": ["task_id", "status", "evidence", "findings", "tool_output_ref", "timestamps", "next_steps"],
        "status_values": ["completed", "blocked", "failed", "needs_verification", "needs_approval"],
        "evidence_required": True,
    }

    # Horizontal: Manager ↔ Manager, Specialist ↔ Specialist (via Boss)
    coordination = {
        "method": "Via Boss or shared mission state, not direct",
        "shared_state": "mission_state.json in workspace, persisted via hermes_state",
        "conflict_resolution": "Boss resolves, prevents duplicate work",
    }


@dataclass
class TeamHierarchy:
    """Full hierarchy definition."""

    # Levels
    levels = [
        {"level": 0, "name": "Operator", "role": "human", "delegation_role": "none", "description": "Human client, owns authorization"},
        {"level": 1, "name": "Boss/Commander", "role": "boss", "delegation_role": "orchestrator", "description": "Owns mission, defines scope, delegates, tracks state"},
        {"level": 2, "name": "Security Managers", "role": "recon_manager, web_manager, api_manager", "delegation_role": "orchestrator", "description": "Coordinate assessment domains"},
        {"level": 3, "name": "Specialist Agents", "role": "9 specialists", "delegation_role": "leaf", "description": "Focused testing with real tools"},
        {"level": 4, "name": "Tools", "role": "terminal, browser, web, file", "delegation_role": "none", "description": "Real execution"},
    ]

    # Delegation rules
    rules: List[DelegationRule] = field(default_factory=lambda: DELEGATION_RULES)

    # Communication protocol
    protocol: CommunicationProtocol = field(default_factory=CommunicationProtocol)

    def can_delegate(self, from_role: str, to_role: str) -> bool:
        """Check if from_role can delegate to to_role."""
        for rule in self.rules:
            if rule.from_role == from_role and to_role in rule.to_roles:
                return True
        return False

    def get_allowed_delegations(self, from_role: str) -> List[str]:
        """Get allowed delegation targets for a role."""
        for rule in self.rules:
            if rule.from_role == from_role:
                return rule.to_roles
        return []

    def validate_delegation(self, from_role: str, to_role: str, scope_defined: bool = False) -> Tuple[bool, str]:
        """Validate delegation: hierarchy, scope, approval."""
        if from_role not in ALL_ROLES:
            return False, f"Unknown from_role: {from_role}"
        if to_role not in ALL_ROLES:
            return False, f"Unknown to_role: {to_role}"

        from_def = ALL_ROLES[from_role]
        to_def = ALL_ROLES[to_role]

        # Leaf cannot delegate
        if from_def.delegation_role.value == "leaf":
            return False, f"Role {from_role} is leaf, cannot delegate"

        # Check hierarchy rule
        if not self.can_delegate(from_role, to_role):
            return False, f"Delegation {from_role} → {to_role} not allowed by hierarchy"

        # Scope required for boss/managers
        if from_def.type.value in ("boss", "manager") and not scope_defined:
            return False, f"Scope must be defined before {from_role} delegates"

        return True, "OK"

    def get_manager_for_specialist(self, specialist_id: str) -> Optional[str]:
        """Find which manager manages a specialist."""
        for manager_id, managed in ROLE_HIERARCHY.items():
            if specialist_id in managed:
                return manager_id
        return None

    def get_boss_managed(self) -> List[str]:
        """Get roles directly managed by Boss."""
        return ROLE_HIERARCHY.get("boss", [])

    def is_valid_hierarchy(self) -> Tuple[bool, List[str]]:
        """Validate entire hierarchy for consistency."""
        errors = []

        # Check all managed roles exist
        for manager, managed_list in ROLE_HIERARCHY.items():
            if manager not in ALL_ROLES:
                errors.append(f"Manager {manager} not in ALL_ROLES")
            for managed in managed_list:
                if managed not in ALL_ROLES:
                    errors.append(f"Managed role {managed} (by {manager}) not in ALL_ROLES")

        # Check delegation rules reference valid roles
        for rule in self.rules:
            if rule.from_role not in ALL_ROLES:
                errors.append(f"Delegation rule from_role {rule.from_role} not in ALL_ROLES")
            for to_role in rule.to_roles:
                if to_role not in ALL_ROLES:
                    errors.append(f"Delegation rule to_role {to_role} (from {rule.from_role}) not in ALL_ROLES")

        # Check no cycles (simple)
        # Boss → Managers → Specialists, Specialists leaf, so no cycles if leaf enforced
        for role_id, role in ALL_ROLES.items():
            if role.delegation_role.value == "leaf":
                # Leaf should not appear as from_role in delegation rules
                for rule in self.rules:
                    if rule.from_role == role_id:
                        errors.append(f"Leaf role {role_id} has delegation rule as from_role")

        return len(errors) == 0, errors


# Global hierarchy instance
TEAM_HIERARCHY = TeamHierarchy()

# For easy import
HIERARCHY = TEAM_HIERARCHY


def get_hierarchy() -> TeamHierarchy:
    """Get global team hierarchy."""
    return TEAM_HIERARCHY


def validate_team() -> Tuple[bool, List[str]]:
    """Validate team hierarchy and roles."""
    return TEAM_HIERARCHY.is_valid_hierarchy()


def get_delegation_chain(target_specialist: str) -> List[str]:
    """Get delegation chain from Boss to target specialist: Boss → Manager → Specialist."""
    manager = TEAM_HIERARCHY.get_manager_for_specialist(target_specialist)
    if manager:
        return ["boss", manager, target_specialist]
    # Direct from boss if no manager
    if target_specialist in TEAM_HIERARCHY.get_boss_managed():
        return ["boss", target_specialist]
    return ["boss", target_specialist]


def get_all_specialists_for_manager(manager_id: str) -> List[RoleDefinition]:
    """Get all specialists managed by a manager."""
    managed_ids = ROLE_HIERARCHY.get(manager_id, [])
    return [ALL_ROLES[mid] for mid in managed_ids if mid in ALL_ROLES and ALL_ROLES[mid].type.value == "specialist"]


def get_all_managers() -> List[RoleDefinition]:
    """Get all managers."""
    return [ALL_ROLES[mid] for mid in ROLE_HIERARCHY.keys() if mid in ALL_ROLES and ALL_ROLES[mid].type.value in ("boss", "manager")]
