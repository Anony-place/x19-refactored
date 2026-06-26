"""Cognitive subsystem interfaces for X19.

The brain package starts with compatibility wrappers and will gradually absorb
planning, reasoning, reflection, and world-model responsibilities from agent.py.
"""

from brain.world_model import (
    CredentialRecord,
    EndpointRecord,
    EvidenceRecord,
    HostRecord,
    Observation,
    ServiceRecord,
    VulnerabilityRecord,
    WorldModel,
    WorldModelSnapshot,
)
from brain.planner import Planner, ToolIO, TOOL_IO, METHODOLOGIES, detect_target_type, generate_structured_hypotheses
from brain.context_builder import (
    cve_context_block,
    session_outcomes_context,
    tool_failure_context,
    false_claim_context,
)
from brain.decision_parser import parse_decision
from brain.reflection_engine import reflect_on_command

__all__ = [
    "CredentialRecord",
    "EndpointRecord",
    "EvidenceRecord",
    "HostRecord",
    "Observation",
    "ServiceRecord",
    "VulnerabilityRecord",
    "WorldModel",
    "WorldModelSnapshot",
    "Planner",
    "ToolIO",
    "TOOL_IO",
    "METHODOLOGIES",
    "detect_target_type",
    "generate_structured_hypotheses",
    "cve_context_block",
    "session_outcomes_context",
    "tool_failure_context",
    "false_claim_context",
    "parse_decision",
    "reflect_on_command",
]
