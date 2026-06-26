"""Strategist Engine - Dynamic goal synthesis from attack graph.

This engine replaces static goal selection with dynamic goal generation
based on the current state of the Attack Graph and World Model.

Instead of choosing from predefined goals like "recon_web" or "exploit_ad",
the Strategist analyzes the attack graph to identify:
- Highest value unexplored nodes
- Optimal paths to critical objectives
- Missing information that blocks progress
- Alternative routes when primary paths are blocked

True autonomy means goals emerge from evidence, not templates.
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
    priority_score: float       # 0.0-1.0, calculated from node value + path feasibility
    required_info: List[str]    # What information is missing to achieve this
    expected_outcome: str       # What success looks like
    alternative_goals: List[str]  # Fallback goal IDs if this fails
    created_at: str = field(default_factory=utc_now)
    parent_goal_id: Optional[str] = None
    confidence: float = 0.5
    
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
        }


@dataclass
class InformationGap:
    """Represents a piece of missing information needed for decision-making."""
    gap_id: str
    question: str             # What we need to know
    why_it_matters: str       # How this affects attack strategy
    related_nodes: List[str]  # Attack graph nodes affected
    estimated_value: float    # Information gain score (0.0-1.0)
    acquisition_methods: List[str]  # How to obtain this info
    confidence_if_known: float = 0.0  # Expected confidence after obtaining


@dataclass
class StrategyRecommendation:
    """Complete strategic recommendation from the Strategist."""
    primary_goal: StrategicGoal
    reasoning: str
    information_gaps: List[InformationGap]
    rejected_alternatives: List[Tuple[str, str]]  # (goal_id, rejection_reason)
    attack_chain: List[str]   # Sequence of steps to achieve goal
    risk_assessment: str      # low/medium/high + explanation
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


class StrategistEngine:
    """Dynamic goal synthesis engine.
    
    The Strategist Engine:
    1. Analyzes the Attack Graph to identify high-value targets
    2. Computes information gaps blocking progress
    3. Generates strategic goals dynamically (not from templates)
    4. Prioritizes goals based on mission impact + feasibility
    5. Maintains goal hierarchy (parent/child relationships)
    6. Adapts goals when paths are blocked
    
    This replaces the static GoalTree.select_active_node() approach.
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
    
    def analyze_attack_graph(self, attack_graph: Any, world_model: Any, critic_engine: Any = None) -> StrategyRecommendation:
        """Analyze attack graph and generate optimal strategic goal.
        
        Args:
            attack_graph: AttackGraph instance with nodes and edges
            world_model: WorldModel instance for context
            critic_engine: Optional CriticEngine for penalty-aware planning
            
        Returns:
            StrategyRecommendation with primary goal and reasoning
        """
        # Step 1: Identify all candidate nodes (unexplored or partially explored)
        candidate_nodes = self._identify_candidate_nodes(attack_graph)
        
        # Step 2: Score each node by value + accessibility
        scored_nodes = []
        for node in candidate_nodes:
            value_score = self._calculate_node_value(node, world_model)
            access_score = self._calculate_accessibility(node, attack_graph, critic_engine)
            combined_score = (value_score * 0.6) + (access_score * 0.4)
            scored_nodes.append((node, combined_score, value_score, access_score))
        
        # Sort by combined score descending
        scored_nodes.sort(key=lambda x: x[1], reverse=True)
        
        # Step 3: Generate goals for top candidates
        goal_candidates = []
        rejected_alternatives = []
        
        for node, score, value_score, access_score in scored_nodes[:5]:  # Top 5
            goal = self._create_goal_for_node(node, score, attack_graph, world_model)
            
            # Check if critic engine blocks this approach
            if critic_engine:
                blocker = self._check_critic_blocks(goal, critic_engine, attack_graph)
                if blocker:
                    rejected_alternatives.append((goal.goal_id, blocker))
                    continue
            
            goal_candidates.append(goal)
        
        if not goal_candidates:
            # Fallback: create generic intel-gathering goal
            goal_candidates.append(self._create_generic_intel_goal(world_model))
        
        # Select highest priority goal
        primary_goal = max(goal_candidates, key=lambda g: g.priority_score)
        
        # Step 4: Identify information gaps for this goal
        info_gaps = self._identify_information_gaps(primary_goal, attack_graph, world_model)
        
        # Step 5: Build attack chain
        attack_chain = self._build_attack_chain(primary_goal, attack_graph)
        
        # Step 6: Generate reasoning text
        reasoning = self._generate_reasoning(
            primary_goal, scored_nodes, info_gaps, attack_chain, world_model
        )
        
        # Step 7: Risk assessment
        risk = self._assess_risk(primary_goal, attack_graph, world_model)
        
        return StrategyRecommendation(
            primary_goal=primary_goal,
            reasoning=reasoning,
            information_gaps=info_gaps,
            rejected_alternatives=rejected_alternatives,
            attack_chain=attack_chain,
            risk_assessment=risk,
            estimated_iterations=self._estimate_iterations(attack_chain)
        )
    
    def _identify_candidate_nodes(self, attack_graph: Any) -> List[Any]:
        """Find nodes that are unexplored or have unexplored neighbors."""
        candidates = []
        
        for node_id, node in attack_graph.nodes.items():
            node_state = node.get("state", "unknown")
            
            # Consider nodes that are:
            # 1. Unknown/unconfirmed
            # 2. Confirmed but not yet exploited
            # 3. Have high-value unexplored neighbors
            if node_state in ["unknown", "unconfirmed", "identified"]:
                candidates.append(node)
            elif node_state == "confirmed":
                # Check if it has unexplored edges leading to valuable nodes
                has_valuable_neighbor = False
                for edge in attack_graph.edges.get(node_id, []):
                    neighbor_id = edge.get("target")
                    neighbor = attack_graph.nodes.get(neighbor_id, {})
                    if neighbor.get("value_score", 0) > 0.5 and neighbor.get("state") != "exploited":
                        has_valuable_neighbor = True
                        break
                if has_valuable_neighbor:
                    candidates.append(node)
        
        return candidates
    
    def _calculate_node_value(self, node: Dict[str, Any], world_model: Any) -> float:
        """Calculate strategic value of a node (0.0-1.0)."""
        base_value = 0.3
        
        # Node type bonuses
        node_type = node.get("type", "")
        if node_type in ["credential", "vulnerability"]:
            base_value = 0.8
        elif node_type in ["service", "endpoint"]:
            base_value = 0.5
        elif node_type in ["user", "host"]:
            base_value = 0.6
        elif node_type in ["technology"]:
            base_value = 0.4
        
        # Value score from node itself
        value_score = node.get("value_score", 0.0)
        
        # Critical service bonuses
        service = node.get("service", "")
        port = node.get("port", 0)
        if port in [22, 80, 443, 3306, 445, 3389]:
            base_value += 0.1
        
        # Evidence quality factor
        confidence = node.get("confidence", 0.5)
        
        return min(1.0, (base_value * 0.5) + (value_score * 0.3) + (confidence * 0.2))
    
    def _calculate_accessibility(
        self, 
        node: Dict[str, Any], 
        attack_graph: Any, 
        critic_engine: Any = None
    ) -> float:
        """Calculate how accessible this node is (0.0-1.0)."""
        node_id = node.get("id", "")
        
        # Check direct paths from known nodes
        paths_to_node = attack_graph.find_paths_to(node_id, max_depth=3)
        
        if not paths_to_node:
            return 0.2  # Hard to reach
        
        # Score paths by length and blocker presence
        best_path_score = 0.0
        for path in paths_to_node:
            path_length = len(path)
            length_penalty = max(0.2, 1.0 - (path_length * 0.15))
            
            # Check if critic engine blocks any step in path
            blocked = False
            if critic_engine:
                for step in path:
                    step_node = attack_graph.nodes.get(step, {})
                    technique = step_node.get("technique", "")
                    if technique and critic_engine.should_block_technique(
                        technique, step_node.get("category", ""), "current_target"
                    ):
                        blocked = True
                        break
            
            if not blocked:
                path_score = length_penalty
                best_path_score = max(best_path_score, path_score)
        
        return best_path_score
    
    def _create_goal_for_node(
        self, 
        node: Dict[str, Any], 
        priority_score: float,
        attack_graph: Any,
        world_model: Any
    ) -> StrategicGoal:
        """Create a strategic goal targeting a specific node."""
        node_id = node.get("id", "unknown")
        node_type = node.get("type", "unknown")
        
        # Determine goal type based on node type and state
        node_state = node.get("state", "unknown")
        
        if node_state in ["unknown", "unconfirmed"]:
            goal_type = "gather_intel"
            description = f"Gather intelligence on {node_type}: {node.get('name', node_id)}"
            expected_outcome = f"Confirm existence and properties of {node_type}"
        elif node_state == "identified":
            goal_type = "validate_finding"
            description = f"Validate and enumerate {node_type}: {node.get('name', node_id)}"
            expected_outcome = f"Obtain confirmed evidence for exploitation"
        elif node_state == "confirmed":
            goal_type = "exploit_path"
            description = f"Exploit {node_type} to gain access: {node.get('name', node_id)}"
            expected_outcome = f"Achieve initial access or privilege escalation"
        else:
            goal_type = "gather_intel"
            description = f"Investigate {node_type}: {node.get('name', node_id)}"
            expected_outcome = f"Discover actionable intelligence"
        
        # Identify required information
        required_info = []
        if not node.get("confidence", 0) > 0.7:
            required_info.append(f"Higher confidence evidence for {node_id}")
        if node_type == "service" and not node.get("version"):
            required_info.append("Service version information")
        if node_type == "endpoint" and not node.get("parameters"):
            required_info.append("Endpoint parameters and input vectors")
        
        # Generate alternatives (sibling nodes in graph)
        alternative_ids = []
        # Could find siblings here if needed
        
        return StrategicGoal(
            goal_id=self._generate_goal_id(goal_type),
            goal_type=goal_type,
            description=description,
            target_node_id=node_id,
            priority_score=priority_score,
            required_info=required_info,
            expected_outcome=expected_outcome,
            alternative_goals=alternative_ids,
            confidence=node.get("confidence", 0.5)
        )
    
    def _create_generic_intel_goal(self, world_model: Any) -> StrategicGoal:
        """Fallback goal when no specific targets identified."""
        return StrategicGoal(
            goal_id=self._generate_goal_id("gather_intel"),
            goal_type="gather_intel",
            description="Broad intelligence gathering to identify new attack vectors",
            target_node_id="surface_enumeration",
            priority_score=0.4,
            required_info=["Additional services", "Hidden endpoints", "Technology stack details"],
            expected_outcome="Discover at least one high-value target for focused attack",
            alternative_goals=[],
            confidence=0.3
        )
    
    def _check_critic_blocks(
        self, 
        goal: StrategicGoal, 
        critic_engine: Any, 
        attack_graph: Any
    ) -> Optional[str]:
        """Check if critic engine blocks this goal's approach."""
        # Get the path to this goal's target
        target_node = attack_graph.nodes.get(goal.target_node_id, {})
        
        # Check if required techniques are blocked
        technique = target_node.get("technique", "")
        category = target_node.get("category", "")
        
        if technique and critic_engine.should_block_technique(technique, category, "current"):
            return f"Technique '{technique}' is blocked by critic due to repeated failures"
        
        return None
    
    def _identify_information_gaps(
        self, 
        goal: StrategicGoal, 
        attack_graph: Any, 
        world_model: Any
    ) -> List[InformationGap]:
        """Identify missing information needed to achieve the goal."""
        gaps = []
        
        # Gap 1: Target confirmation
        target_node = attack_graph.nodes.get(goal.target_node_id, {})
        if target_node.get("confidence", 0.5) < 0.7:
            gaps.append(InformationGap(
                gap_id=self._generate_gap_id(),
                question=f"Is {target_node.get('name', goal.target_node_id)} actually present and accessible?",
                why_it_matters="Cannot plan exploitation without confirmed target",
                related_nodes=[goal.target_node_id],
                estimated_value=0.8,
                acquisition_methods=["Active scanning", "Service probing", "Banner grabbing"]
            ))
        
        # Gap 2: Version/technology details
        if target_node.get("type") == "service" and not target_node.get("version"):
            gaps.append(InformationGap(
                gap_id=self._generate_gap_id(),
                question="What is the exact version of this service?",
                why_it_matters="Version determines applicable CVEs and exploits",
                related_nodes=[goal.target_node_id],
                estimated_value=0.7,
                acquisition_methods=["Banner grabbing", "Version detection scan"]
            ))
        
        # Gap 3: Path accessibility
        paths = attack_graph.find_paths_to(goal.target_node_id, max_depth=2)
        if not paths or len(paths) == 0:
            gaps.append(InformationGap(
                gap_id=self._generate_gap_id(),
                question="How do we reach this target from our current position?",
                why_it_matters="No known attack path exists",
                related_nodes=[goal.target_node_id],
                estimated_value=0.9,
                acquisition_methods=["Network mapping", "Pivot discovery", "Lateral movement analysis"]
            ))
        
        return gaps
    
    def _build_attack_chain(self, goal: StrategicGoal, attack_graph: Any) -> List[str]:
        """Build sequence of steps to achieve the goal."""
        # Find shortest path to target node
        target_id = goal.target_node_id
        paths = attack_graph.find_paths_to(target_id, max_depth=5)
        
        if paths:
            # Return the shortest path as technique names
            shortest = min(paths, key=len)
            chain = []
            for node_id in shortest:
                node = attack_graph.nodes.get(node_id, {})
                technique = node.get("technique", "unknown")
                if technique and technique != "unknown":
                    chain.append(technique)
            return chain if chain else ["reconnaissance"]
        
        return ["reconnaissance", "enumeration"]
    
    def _generate_reasoning(
        self,
        goal: StrategicGoal,
        scored_nodes: List[Tuple],
        info_gaps: List[InformationGap],
        attack_chain: List[str],
        world_model: Any
    ) -> str:
        """Generate human-readable reasoning for the selected goal."""
        parts = []
        
        parts.append(f"Selected goal: {goal.description}")
        parts.append(f"Priority score: {goal.priority_score:.2f}")
        
        if scored_nodes:
            top_node = scored_nodes[0][0]
            parts.append(f"Target node type: {top_node.get('type', 'unknown')}")
            parts.append(f"Target value: {scored_nodes[0][2]:.2f}, Accessibility: {scored_nodes[0][3]:.2f}")
        
        if info_gaps:
            parts.append(f"Critical information gaps: {len(info_gaps)}")
            for gap in info_gaps[:2]:
                parts.append(f"  - {gap.question}")
        
        parts.append(f"Attack chain: {' → '.join(attack_chain)}")
        
        return " | ".join(parts)
    
    def _assess_risk(self, goal: StrategicGoal, attack_graph: Any, world_model: Any) -> str:
        """Assess risk level of pursuing this goal."""
        target_node = attack_graph.nodes.get(goal.target_node_id, {})
        
        # Factors affecting risk
        detection_risk = target_node.get("detection_risk", "medium")
        stability_risk = target_node.get("stability_risk", "low")
        
        if detection_risk == "high" or stability_risk == "high":
            return "HIGH - Aggressive techniques may trigger IDS/IPS or cause service disruption"
        elif detection_risk == "medium" or stability_risk == "medium":
            return "MEDIUM - Standard offensive operations with moderate detection probability"
        else:
            return "LOW - Passive or low-profile techniques with minimal detection risk"
    
    def _estimate_iterations(self, attack_chain: List[str]) -> int:
        """Estimate iterations needed to complete the attack chain."""
        # Rough estimate: 1-2 iterations per technique
        return max(1, len(attack_chain) * 2)
    
    def mark_goal_completed(self, goal_id: str, success: bool):
        """Mark a goal as completed (success or failure)."""
        if goal_id in self.active_goals:
            goal = self.active_goals.pop(goal_id)
            if success:
                self.completed_goals[goal_id] = goal
            else:
                self.failed_goals[goal_id] = goal
    
    def get_active_goal(self) -> Optional[StrategicGoal]:
        """Get the highest priority active goal."""
        if not self.active_goals:
            return None
        return max(self.active_goals.values(), key=lambda g: g.priority_score)
    
    def add_goal(self, goal: StrategicGoal):
        """Add a goal to the active pool."""
        self.active_goals[goal.goal_id] = goal
    
    def clear_completed(self):
        """Clear completed/failed goals to free memory."""
        self.completed_goals.clear()
        self.failed_goals.clear()
    
    def export_state(self) -> Dict[str, Any]:
        """Export strategist state for persistence."""
        return {
            "active_goals": [g.to_dict() for g in self.active_goals.values()],
            "completed_goals": list(self.completed_goals.keys()),
            "failed_goals": list(self.failed_goals.keys()),
            "information_gaps": [g.__dict__ for g in self.information_gaps.values()],
        }
    
    def import_state(self, state: Dict[str, Any]):
        """Import strategist state from persistence."""
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
                confidence=goal_data.get("confidence", 0.5)
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
                confidence_if_known=gap_data.get("confidence_if_known", 0.0)
            )
            self.information_gaps[gap.gap_id] = gap
