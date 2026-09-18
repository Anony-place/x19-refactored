"""
X19 Specialist Base — distinct prompts, not 11 copies.

Each specialist has distinct expertise, methodology, evidence requirements.
Uses Hermes delegation: Boss/Managers are orchestrator, Specialists are leaf.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from x19.team.roles import RoleDefinition, get_role


@dataclass
class SpecialistConfig:
    """Configuration for spawning a specialist via delegate_task."""

    role_id: str
    goal: str
    context: str
    scope: Dict[str, Any]  # Scope definition
    toolsets: List[str]
    delegation_role: str  # orchestrator or leaf
    expected_evidence: List[str]
    time_budget_seconds: Optional[int] = None
    max_iterations: int = 100

    def to_delegate_task_args(self) -> Dict[str, Any]:
        """Convert to delegate_task tool arguments."""
        return {
            "goal": self.goal,
            "context": self.context,
            "toolsets": self.toolsets,
            "role": self.delegation_role,
            "max_iterations": self.max_iterations,
        }


def build_specialist_goal(
    role_id: str,
    objective: str,
    target: str,
    scope: Dict[str, Any],
    recon_data: Optional[str] = None,
    additional_context: Optional[str] = None,
) -> str:
    """Build goal string for specialist delegation."""
    role = get_role(role_id)
    if not role:
        raise ValueError(f"Unknown role: {role_id}")

    parts = [
        f"Role: {role.name} ({role.id})",
        f"Objective: {objective}",
        f"Target: {target}",
        "",
        f"Scope: {scope.get('target', target)}",
        f"Authorized: {scope.get('authorized_domains', [])}",
        f"Excluded: {scope.get('excluded_assets', [])}",
        f"Allowed actions: {scope.get('allowed_actions', [])}",
        f"Prohibited: {scope.get('prohibited_actions', [])}",
    ]

    if recon_data:
        parts.extend(["", f"Recon data: {recon_data}"])

    if additional_context:
        parts.extend(["", f"Additional context: {additional_context}"])

    parts.extend(
        [
            "",
            f"Responsibilities: {', '.join(role.responsibilities[:3])}",
            f"Evidence required: {', '.join(role.evidence_requirements[:2])}",
            "",
            f"Prompt: {role.prompt_fragment}",
            "",
            "Requirements:",
            "- Use real tools, never simulate output",
            "- Capture evidence: request/response, tool output, timestamps",
            "- Distinguish OBSERVATION/HYPOTHESIS/TEST/EVIDENCE/VERIFIED FINDING",
            "- Never auto-convert observation to vulnerability",
            "- Report with evidence, never fabricate",
            "- If tool unavailable: 'Tool unavailable: [tool] not installed'",
        ]
    )

    return "\n".join(parts)


def build_specialist_context(
    role_id: str,
    mission_id: str,
    task_id: str,
    attack_surface: Optional[str] = None,
    previous_findings: Optional[List[Dict[str, Any]]] = None,
    knowledge_refs: Optional[List[str]] = None,
) -> str:
    """Build context string for specialist delegation."""
    role = get_role(role_id)
    if not role:
        raise ValueError(f"Unknown role: {role_id}")

    parts = [
        f"Mission ID: {mission_id}",
        f"Task ID: {task_id}",
        f"Role: {role.name}",
        f"Reports to: {role.reports_to}",
        "",
        f"Allowed tools: {', '.join(role.allowed_tools)}",
        f"Toolsets: {', '.join(role.toolsets)}",
        f"Delegation role: {role.delegation_role.value}",
    ]

    if attack_surface:
        parts.extend(["", f"Attack surface: {attack_surface}"])

    if previous_findings:
        parts.extend(["", f"Previous findings: {len(previous_findings)} findings, check for duplicates"])

    if knowledge_refs:
        parts.extend(["", f"Knowledge refs: {', '.join(knowledge_refs)}"])

    parts.extend(
        [
            "",
            "Evidence-first protocol:",
            "- OBSERVATION: what tool saw",
            "- HYPOTHESIS: what might be vulnerable, needs testing",
            "- TEST: planned action to verify hypothesis",
            "- EVIDENCE: tool output, reproducible proof",
            "- VERIFIED FINDING: confirmed with repro steps, severity, confidence, remediation",
            "",
            "Lifecycle: CANDIDATE → UNDER_VERIFICATION → VERIFIED or REJECTED",
            "Never report rejected as confirmed.",
        ]
    )

    return "\n".join(parts)


def get_specialist_prompt(role_id: str) -> str:
    """Get distinct prompt fragment for a specialist."""
    role = get_role(role_id)
    if not role:
        raise ValueError(f"Unknown role: {role_id}")
    return role.prompt_fragment


def get_specialist_toolsets(role_id: str) -> List[str]:
    """Get toolsets for a specialist."""
    role = get_role(role_id)
    if not role:
        raise ValueError(f"Unknown role: {role_id}")
    return role.toolsets


def get_specialist_delegation_role(role_id: str) -> str:
    """Get Hermes delegation role for X19 role."""
    role = get_role(role_id)
    if not role:
        raise ValueError(f"Unknown role: {role_id}")
    return role.delegation_role.value


# Helper to create specialist config quickly
def create_specialist_config(
    role_id: str,
    objective: str,
    target: str,
    scope: Dict[str, Any],
    mission_id: str,
    task_id: str,
    recon_data: Optional[str] = None,
    attack_surface: Optional[str] = None,
    max_iterations: int = 100,
) -> SpecialistConfig:
    """Create SpecialistConfig for delegation."""
    role = get_role(role_id)
    if not role:
        raise ValueError(f"Unknown role: {role_id}")

    goal = build_specialist_goal(
        role_id=role_id,
        objective=objective,
        target=target,
        scope=scope,
        recon_data=recon_data,
    )

    context = build_specialist_context(
        role_id=role_id,
        mission_id=mission_id,
        task_id=task_id,
        attack_surface=attack_surface,
    )

    return SpecialistConfig(
        role_id=role_id,
        goal=goal,
        context=context,
        scope=scope,
        toolsets=role.toolsets,
        delegation_role=role.delegation_role.value,
        expected_evidence=role.evidence_requirements,
        max_iterations=max_iterations,
    )
