"""Strategist Engine - Dynamic goal synthesis from attack graph.

This engine replaces static goal selection with dynamic goal generation
based on the current state of the Attack Graph and World Model.

Key fixes from P0 spec:
  - Consumes actual WorldModel (not None)
  - Reads correct field names from graph schema (label, not name/version/parameters)
  - Creates typed node/evidence objects instead of arbitrary dict.get
  - Critic context receives actual engagement/target context
  - Strategic goals become candidate experiments
  - Strategist produces actionable plans, not just human-readable reasoning
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class StrategicGoal:
    """A dynamically generated goal based on attack graph analysis."""
    goal_id: str
    goal_type: str              # "gather_intel", "validate_finding", "exploit_path", "pivot", "privesc"
    description: str
    target_node_id: str         # Attack graph node this goal targets
    priority_score: float       # 0.0-1.0
    required_info: List[str]
    expected_outcome: str
    alternative_goals: List[str]
    created_at: str = field(default_factory=utc_now)
    parent_goal_id: Optional[str] = None
    confidence: float = 0.5
    # P0: goals must produce candidate experiments
    suggested_command: str = ""
    suggested_hypothesis: str = ""
    expected_evidence: str = ""
    falsification_condition: str = ""
    risk: str = "normal"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "goal_id": self.goal_id,
            "goal_type": self.goal_type,
            "description": self.description,
            "target_node_id": self.target_node_id,
            "priority_score": self.priority_score,
            "required_info": self.required_info,
            "expected_outcome": self.expected_outcome,
            "alternative_goals": self.alternative_goals,
            "parent_goal_id": self.parent_goal_id,
            "confidence": self.confidence,
            "suggested_command": self.suggested_command,
            "suggested_hypothesis": self.suggested_hypothesis,
            "expected_evidence": self.expected_evidence,
            "falsification_condition": self.falsification_condition,
            "risk": self.risk,
        }


@dataclass
class InformationGap:
    """Represents a piece of missing information needed for decision-making."""
    gap_id: str
    question: str
    why_it_matters: str
    related_nodes: List[str]
    estimated_value: float
    acquisition_methods: List[str]
    confidence_if_known: float = 0.0


@dataclass
class StrategyRecommendation:
    """Complete strategic recommendation from the Strategist."""
    primary_goal: StrategicGoal
    reasoning: str
    information_gaps: List[InformationGap]
    rejected_alternatives: List[Tuple[str, str]]
    attack_chain: List[str]
    risk_assessment: str
    estimated_iterations: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "primary_goal": self.primary_goal.to_dict(),
            "reasoning": self.reasoning,
            "information_gaps": [g.__dict__ for g in self.information_gaps],
            "rejected_alternatives": self.rejected_alternatives,
            "attack_chain": self.attack_chain,
            "risk_assessment": self.risk_assessment,
            "estimated_iterations": self.estimated_iterations,
        }


# ---------------------------------------------------------------------------
# Typed wrappers for attack graph nodes
# ---------------------------------------------------------------------------
@dataclass
class TypedNode:
    """Typed wrapper over the dict-shaped attack graph node.

    Reads only fields the schema actually provides; never invents
    name/version/parameters.
    """
    id: str
    node_type: str
    label: str
    state: str
    value_score: float
    difficulty_score: float
    priority: float
    properties: Dict[str, Any]

    @classmethod
    def from_dict(cls, node_id: str, data: Dict[str, Any]) -> "TypedNode":
        return cls(
            id=node_id,
            node_type=str(data.get("type", "unknown")),
            label=str(data.get("label", node_id)),
            state=str(data.get("state", "unknown")),
            value_score=float(data.get("value_score", 0.5)),
            difficulty_score=float(data.get("difficulty_score", 0.5)),
            priority=float(data.get("priority", 0.5)),
            properties=dict(data.get("properties", {})),
        )

    @property
    def service(self) -> str:
        return str(self.properties.get("service", ""))

    @property
    def port(self) -> int:
        v = self.properties.get("port", 0)
        return int(v) if isinstance(v, (int, float, str)) and str(v).isdigit() else 0

    @property
    def version(self) -> str:
        return str(self.properties.get("version", ""))

    @property
    def technique(self) -> str:
        return str(self.properties.get("technique", ""))


class StrategistEngine:
    """Dynamic goal synthesis engine.

    1. Analyzes the Attack Graph to identify high-value targets
    2. Computes information gaps blocking progress
    3. Generates strategic goals dynamically (not from templates)
    4. Prioritizes goals based on mission impact + feasibility
    5. Adapts goals when paths are blocked

    Key fix: consumes actual WorldModel, reads correct graph fields.
    """

    def __init__(self):
        self.active_goals: Dict[str, StrategicGoal] = {}
        self.completed_goals: Dict[str, StrategicGoal] = {}
        self.failed_goals: Dict[str, StrategicGoal] = {}
        self.information_gaps: Dict[str, InformationGap] = {}
        self._goal_counter = 0

    def _generate_goal_id(self, goal_type: str) -> str:
        self._goal_counter += 1
        return f"{goal_type}_{self._goal_counter}"

    def _generate_gap_id(self) -> str:
        return f"gap_{len(self.information_gaps) + 1}"

    def analyze_attack_graph(
        self,
        attack_graph: Any,
        world_model: Any,
        critic_engine: Any = None,
    ) -> StrategyRecommendation:
        """Analyze attack graph and generate optimal strategic goal.

        P0 fix: world_model is now the actual WorldModel, not None.
        P0 fix: reads correct field names from graph schema.
        """
        # Step 1: Identify candidate nodes using typed wrappers
        candidate_nodes = self._identify_candidate_nodes(attack_graph)

        # Step 2: Score each node
        scored_nodes = []
        for node in candidate_nodes:
            value_score = self._calculate_node_value(node, world_model)
            access_score = self._calculate_accessibility(node, attack_graph, critic_engine, world_model)
            combined_score = (value_score * 0.6) + (access_score * 0.4)
            scored_nodes.append((node, combined_score, value_score, access_score))

        scored_nodes.sort(key=lambda x: x[1], reverse=True)

        # Step 3: Generate goals for top candidates
        goal_candidates = []
        rejected_alternatives = []

        for node, score, value_score, access_score in scored_nodes[:5]:
            goal = self._create_goal_for_node(node, score, attack_graph, world_model)

            if critic_engine:
                blocker = self._check_critic_blocks(goal, critic_engine, attack_graph, world_model)
                if blocker:
                    rejected_alternatives.append((goal.goal_id, blocker))
                    continue

            goal_candidates.append(goal)

        if not goal_candidates:
            goal_candidates.append(self._create_generic_intel_goal(world_model))

        primary_goal = max(goal_candidates, key=lambda g: g.priority_score)

        # Step 4: Identify information gaps
        info_gaps = self._identify_information_gaps(primary_goal, attack_graph, world_model)

        # Step 5: Build attack chain
        attack_chain = self._build_attack_chain(primary_goal, attack_graph)

        # Step 6: Generate reasoning
        reasoning = self._generate_reasoning(primary_goal, scored_nodes, info_gaps, attack_chain, world_model)

        # Step 7: Risk assessment
        risk = self._assess_risk(primary_goal, attack_graph, world_model)

        return StrategyRecommendation(
            primary_goal=primary_goal,
            reasoning=reasoning,
            information_gaps=info_gaps,
            rejected_alternatives=rejected_alternatives,
            attack_chain=attack_chain,
            risk_assessment=risk,
            estimated_iterations=self._estimate_iterations(attack_chain),
        )

    def _identify_candidate_nodes(self, attack_graph: Any) -> List[TypedNode]:
        """Find nodes that are unexplored or have unexplored neighbors.

        P0 fix: uses TypedNode, reads state from the dict view.
        """
        candidates = []
        for node_id, node_data in attack_graph.nodes.items():
            node = TypedNode.from_dict(node_id, node_data)

            if node.state in ("unknown", "UNKNOWN", "observed", "OBSERVED", "identified", "IDENTIFIED"):
                candidates.append(node)
            elif node.state in ("confirmed", "CONFIRMED"):
                # Check if it has valuable unexplored neighbors
                has_valuable_neighbor = False
                for edge in attack_graph.edges.get(node_id, []):
                    neighbor_id = edge.get("target")
                    neighbor_data = attack_graph.nodes.get(neighbor_id, {})
                    if neighbor_data.get("value_score", 0) > 0.5 and neighbor_data.get("state") not in ("exploited", "EXPLOITED"):
                        has_valuable_neighbor = True
                        break
                if has_valuable_neighbor:
                    candidates.append(node)
        return candidates

    def _calculate_node_value(self, node: TypedNode, world_model: Any) -> float:
        """Calculate strategic value of a node. P0 fix: reads correct fields."""
        base_value = 0.3
        type_bonuses = {
            "credential": 0.8, "vulnerability": 0.8,
            "service": 0.5, "endpoint": 0.5,
            "user": 0.6, "host": 0.6,
            "technology": 0.4,
        }
        base_value = type_bonuses.get(node.node_type, 0.3)
        base_value += 0.1 if node.port in (22, 80, 443, 3306, 445, 3389) else 0
        # P0: properties have real confidence, not hardcoded
        confidence = float(node.properties.get("confidence", 0.5))
        return min(1.0, (base_value * 0.5) + (node.value_score * 0.3) + (confidence * 0.2))

    def _calculate_accessibility(
        self,
        node: TypedNode,
        attack_graph: Any,
        critic_engine: Any,
        world_model: Any,
    ) -> float:
        """Calculate how accessible this node is. P0 fix: uses actual target context."""
        paths_to_node = attack_graph.find_paths_to(node.id, max_depth=3)
        if not paths_to_node:
            return 0.2
        best_path_score = 0.0
        target = world_model.target if world_model and hasattr(world_model, 'target') else ""
        for path in paths_to_node:
            path_length = len(path)
            length_penalty = max(0.2, 1.0 - (path_length * 0.15))
            blocked = False
            if critic_engine:
                for step in path:
                    step_data = attack_graph.nodes.get(step, {})
                    technique = step_data.get("technique", "")
                    category = step_data.get("category", step_data.get("type", ""))
                    # P0: pass actual target context, not "current"
                    if technique and critic_engine.should_block_technique(technique, category, target):
                        blocked = True
                        break
            if not blocked:
                best_path_score = max(best_path_score, length_penalty)
        return best_path_score

    def _create_goal_for_node(
        self,
        node: TypedNode,
        priority_score: float,
        attack_graph: Any,
        world_model: Any,
    ) -> StrategicGoal:
        """Create a strategic goal targeting a specific node.

        P0 fix: reads correct fields, produces experiment-oriented goals.
        """
        goal_type = "gather_intel"
        description = f"Investigate {node.node_type}: {node.label}"
        expected_outcome = "Discover actionable intelligence"
        suggested_hypothesis = f"The {node.node_type} '{node.label}' has exploitable properties"
        expected_evidence = f"Confirmed properties and accessible surface for {node.label}"
        falsification_condition = f"No exploitable properties found for {node.label}"
        risk = "low"

        if node.state in ("unknown", "UNKNOWN", "observed", "OBSERVED"):
            goal_type = "gather_intel"
            description = f"Gather intelligence on {node.node_type}: {node.label}"
            expected_outcome = f"Confirm existence and properties of {node.node_type}"
        elif node.state in ("identified", "IDENTIFIED"):
            goal_type = "validate_finding"
            description = f"Validate and enumerate {node.node_type}: {node.label}"
            expected_outcome = "Obtain confirmed evidence for exploitation"
        elif node.state in ("confirmed", "CONFIRMED"):
            goal_type = "exploit_path"
            description = f"Exploit {node.node_type} to gain access: {node.label}"
            expected_outcome = "Achieve initial access or privilege escalation"
            risk = "normal"
        elif node.state in ("testable", "TESTABLE"):
            goal_type = "validate_finding"
            description = f"Test {node.node_type}: {node.label}"
            expected_outcome = "Determine if exploitable"
            suggested_hypothesis = f"{node.label} is exploitable via known techniques"

        required_info = []
        confidence = float(node.properties.get("confidence", 0.5))
        if confidence < 0.7:
            required_info.append(f"Higher confidence evidence for {node.id}")
        if node.node_type == "service" and not node.version:
            required_info.append("Service version information")
        if node.node_type == "endpoint" and not node.properties.get("params"):
            required_info.append("Endpoint parameters and input vectors")

        return StrategicGoal(
            goal_id=self._generate_goal_id(goal_type),
            goal_type=goal_type,
            description=description,
            target_node_id=node.id,
            priority_score=priority_score,
            required_info=required_info,
            expected_outcome=expected_outcome,
            alternative_goals=[],
            confidence=confidence,
            suggested_hypothesis=suggested_hypothesis,
            expected_evidence=expected_evidence,
            falsification_condition=falsification_condition,
            risk=risk,
        )

    def _create_generic_intel_goal(self, world_model: Any) -> StrategicGoal:
        target = getattr(world_model, 'target', 'unknown') if world_model else "unknown"
        return StrategicGoal(
            goal_id=self._generate_goal_id("gather_intel"),
            goal_type="gather_intel",
            description=f"Broad intelligence gathering on {target}",
            target_node_id="surface_enumeration",
            priority_score=0.4,
            required_info=["Additional services", "Hidden endpoints", "Technology stack details"],
            expected_outcome="Discover at least one high-value target for focused attack",
            alternative_goals=[],
            confidence=0.3,
            suggested_hypothesis=f"Target {target} has undiscovered attack surface",
            expected_evidence="New services, endpoints, or technologies discovered",
            falsification_condition="Full port scan and directory enumeration produce no new findings",
        )

    def _check_critic_blocks(
        self,
        goal: StrategicGoal,
        critic_engine: Any,
        attack_graph: Any,
        world_model: Any,
    ) -> Optional[str]:
        """Check if critic engine blocks this goal's approach.

        P0 fix: passes actual target context to critic.
        """
        target_node_data = attack_graph.nodes.get(goal.target_node_id, {})
        technique = target_node_data.get("technique", "")
        category = target_node_data.get("category", target_node_data.get("type", ""))
        target = getattr(world_model, 'target', '') if world_model else ''
        # P0: pass actual target, not "current"
        if technique and critic_engine.should_block_technique(technique, category, target):
            return f"Technique '{technique}' is blocked by critic due to repeated failures against '{target}'"
        return None

    def _identify_information_gaps(
        self,
        goal: StrategicGoal,
        attack_graph: Any,
        world_model: Any,
    ) -> List[InformationGap]:
        gaps = []
        target_node_data = attack_graph.nodes.get(goal.target_node_id, {})
        confidence = float(target_node_data.get("confidence", 0.5))
        if confidence < 0.7:
            label = target_node_data.get("label", goal.target_node_id)
            gaps.append(InformationGap(
                gap_id=self._generate_gap_id(),
                question=f"Is {label} actually present and accessible?",
                why_it_matters="Cannot plan exploitation without confirmed target",
                related_nodes=[goal.target_node_id],
                estimated_value=0.8,
                acquisition_methods=["Active scanning", "Service probing", "Banner grabbing"],
            ))
        node_type = target_node_data.get("type", "")
        if node_type == "service" and not target_node_data.get("properties", {}).get("version"):
            gaps.append(InformationGap(
                gap_id=self._generate_gap_id(),
                question="What is the exact version of this service?",
                why_it_matters="Version determines applicable CVEs and exploits",
                related_nodes=[goal.target_node_id],
                estimated_value=0.7,
                acquisition_methods=["Banner grabbing", "Version detection scan"],
            ))
        paths = attack_graph.find_paths_to(goal.target_node_id, max_depth=2)
        if not paths:
            gaps.append(InformationGap(
                gap_id=self._generate_gap_id(),
                question="How do we reach this target from our current position?",
                why_it_matters="No known attack path exists",
                related_nodes=[goal.target_node_id],
                estimated_value=0.9,
                acquisition_methods=["Network mapping", "Pivot discovery"],
            ))
        return gaps

    def _build_attack_chain(self, goal: StrategicGoal, attack_graph: Any) -> List[str]:
        paths = attack_graph.find_paths_to(goal.target_node_id, max_depth=5)
        if paths:
            shortest = min(paths, key=len)
            chain = []
            for node_id in shortest:
                node_data = attack_graph.nodes.get(node_id, {})
                # P0: reads label or technique, not name
                technique = node_data.get("technique", "")
                if not technique:
                    technique = node_data.get("label", "unknown")
                chain.append(technique)
            return chain if chain else ["reconnaissance"]
        return ["reconnaissance", "enumeration"]

    def _generate_reasoning(
        self,
        goal: StrategicGoal,
        scored_nodes: List[Tuple],
        info_gaps: List[InformationGap],
        attack_chain: List[str],
        world_model: Any,
    ) -> str:
        parts = []
        parts.append(f"Selected goal: {goal.description}")
        parts.append(f"Priority score: {goal.priority_score:.2f}")
        if scored_nodes:
            top_node = scored_nodes[0][0]
            parts.append(f"Target: {top_node.node_type} '{top_node.label}' "
                         f"(value={scored_nodes[0][2]:.2f}, access={scored_nodes[0][3]:.2f})")
        if info_gaps:
            parts.append(f"Critical information gaps: {len(info_gaps)}")
            for gap in info_gaps[:2]:
                parts.append(f"  - {gap.question}")
        parts.append(f"Attack chain: {' → '.join(attack_chain)}")
        return " | ".join(parts)

    def _assess_risk(self, goal: StrategicGoal, attack_graph: Any, world_model: Any) -> str:
        target_node_data = attack_graph.nodes.get(goal.target_node_id, {})
        detection_risk = target_node_data.get("properties", {}).get("detection_risk", "medium")
        stability_risk = target_node_data.get("properties", {}).get("stability_risk", "low")
        if detection_risk == "high" or stability_risk == "high":
            return "HIGH - Aggressive techniques may trigger IDS/IPS or cause service disruption"
        elif detection_risk == "medium" or stability_risk == "medium":
            return "MEDIUM - Standard offensive operations with moderate detection probability"
        return "LOW - Passive or low-profile techniques with minimal detection risk"

    def _estimate_iterations(self, attack_chain: List[str]) -> int:
        return max(1, len(attack_chain) * 2)

    def mark_goal_completed(self, goal_id: str, success: bool):
        if goal_id in self.active_goals:
            goal = self.active_goals.pop(goal_id)
            (self.completed_goals if success else self.failed_goals)[goal_id] = goal

    def get_active_goal(self) -> Optional[StrategicGoal]:
        if not self.active_goals:
            return None
        return max(self.active_goals.values(), key=lambda g: g.priority_score)

    def add_goal(self, goal: StrategicGoal):
        self.active_goals[goal.goal_id] = goal

    def clear_completed(self):
        self.completed_goals.clear()
        self.failed_goals.clear()

    def export_state(self) -> Dict[str, Any]:
        return {
            "active_goals": [g.to_dict() for g in self.active_goals.values()],
            "completed_goals": list(self.completed_goals.keys()),
            "failed_goals": list(self.failed_goals.keys()),
            "information_gaps": [g.__dict__ for g in self.information_gaps.values()],
        }

    def import_state(self, state: Dict[str, Any]):
        for goal_data in state.get("active_goals", []):
            goal = StrategicGoal(
                goal_id=goal_data["goal_id"],
                goal_type=goal_data["goal_type"],
                description=goal_data["description"],
                target_node_id=goal_data["target_node_id"],
                priority_score=goal_data["priority_score"],
                required_info=goal_data["required_info"],
                expected_outcome=goal_data["expected_outcome"],
                alternative_goals=goal_data["alternative_goals"],
                parent_goal_id=goal_data.get("parent_goal_id"),
                confidence=goal_data.get("confidence", 0.5),
                suggested_command=goal_data.get("suggested_command", ""),
                suggested_hypothesis=goal_data.get("suggested_hypothesis", ""),
                expected_evidence=goal_data.get("expected_evidence", ""),
                falsification_condition=goal_data.get("falsification_condition", ""),
                risk=goal_data.get("risk", "normal"),
            )
            self.active_goals[goal.goal_id] = goal
        for gap_data in state.get("information_gaps", []):
            gap = InformationGap(
                gap_id=gap_data["gap_id"],
                question=gap_data["question"],
                why_it_matters=gap_data["why_it_matters"],
                related_nodes=gap_data["related_nodes"],
                estimated_value=gap_data["estimated_value"],
                acquisition_methods=gap_data["acquisition_methods"],
                confidence_if_known=gap_data.get("confidence_if_known", 0.0),
            )
            self.information_gaps[gap.gap_id] = gap
