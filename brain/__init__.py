"""Cognitive subsystem interfaces for X19.

The brain package starts with compatibility wrappers and will gradually absorb
planning, reasoning, reflection, world-model responsibilities from agent.py.

Phase 2 (Self-Improving Autonomy) adds:
- CriticEngine: Converts reflection into state changes
- StrategistEngine: Dynamic goal synthesis from attack graph  
- StrategyLibrary: Cross-session learning and adaptation
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
from brain.critic_engine import CriticEngine, TechniquePenalty, StrategyBonus, CritiqueSummary
from brain.strategist_engine import StrategistEngine, StrategicGoal, InformationGap, StrategyRecommendation
from brain.strategy_library import StrategyLibrary, StrategyPattern, TargetSignature, MissionResult
from brain.evidence_ranking import EvidenceRankingEngine, EvidenceScore
from brain.hypothesis_engine import MultiHypothesisEngine, CompetingHypothesis
from brain.attack_graph import AttackGraph, GraphNode, GraphEdge

__all__ = [
    # World Model
    "CredentialRecord",
    "EndpointRecord",
    "EvidenceRecord",
    "HostRecord",
    "Observation",
    "ServiceRecord",
    "VulnerabilityRecord",
    "WorldModel",
    "WorldModelSnapshot",
    
    # Planner (legacy + hybrid)
    "Planner",
    "ToolIO",
    "TOOL_IO",
    "METHODOLOGIES",
    "detect_target_type",
    "generate_structured_hypotheses",
    
    # Context & Decision
    "cve_context_block",
    "session_outcomes_context",
    "tool_failure_context",
    "false_claim_context",
    "parse_decision",
    "reflect_on_command",
    
    # Phase 2: Self-Improving Autonomy
    "CriticEngine",
    "TechniquePenalty",
    "StrategyBonus",
    "CritiqueSummary",
    "StrategistEngine",
    "StrategicGoal",
    "InformationGap",
    "StrategyRecommendation",
    "StrategyLibrary",
    "StrategyPattern",
    "TargetSignature",
    "MissionResult",
    
    # Cognitive Core (Phase 1)
    "EvidenceRankingEngine",
    "EvidenceScore",
    "MultiHypothesisEngine",
    "CompetingHypothesis",
    "AttackGraph",
    "GraphNode",
    "GraphEdge",
]
