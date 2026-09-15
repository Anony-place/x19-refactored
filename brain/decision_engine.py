"""Decision Engine — the single canonical next-action selector.

This is the ONE component responsible for choosing the next experiment.

Input: ranked evidence, competing hypotheses, strategic goals, attack graph,
       world model, critic engine.
Output: exactly ONE CandidateExperiment to execute.

The decision cycle:
  Observation → Evidence Ranking → Competing Hypotheses → Strategic Goal →
  Candidate Experiments → Decision (single selection) → Execution Gateway

No other component may override the DecisionEngine's selection. The task
queue, agents, and legacy planner are all subordinate to this output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class CandidateExperiment:
    """An experiment that can be executed to test a hypothesis.

    Every executed action MUST be a CandidateExperiment carrying:
    hypothesis_id, hypothesis, expected_evidence, falsification_condition,
    target, risk, reason, evidence_dependencies.
    """
    experiment_id: str
    hypothesis_id: str
    hypothesis: str
    expected_evidence: str
    falsification_condition: str
    target: str
    risk: str  # "low", "normal", "high", "critical"
    reason: str
    evidence_dependencies: List[str]  # IDs of evidence this depends on
    command: str = ""
    tool: str = ""
    timeout: int = 120
    alternative_commands: List[str] = field(default_factory=list)
    information_gain: float = 0.5
    impact: float = 0.5
    cost: float = 0.5
    confidence: float = 0.5
    priority_score: float = 0.5
    source_goal_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'experiment_id': self.experiment_id,
            'hypothesis_id': self.hypothesis_id,
            'hypothesis': self.hypothesis,
            'expected_evidence': self.expected_evidence,
            'falsification_condition': self.falsification_condition,
            'target': self.target,
            'risk': self.risk,
            'reason': self.reason,
            'evidence_dependencies': self.evidence_dependencies,
            'command': self.command,
            'tool': self.tool,
            'timeout': self.timeout,
            'information_gain': self.information_gain,
            'impact': self.impact,
            'cost': self.cost,
            'confidence': self.confidence,
            'priority_score': self.priority_score,
            'source_goal_id': self.source_goal_id,
        }


@dataclass
class DecisionRecord:
    """A record of a decision and its justification."""
    decision_id: str
    selected_experiment: CandidateExperiment
    rejected_experiments: List[Dict[str, Any]]  # experiment_id + rejection reason
    reasoning: str
    timestamp: str = field(default_factory=utc_now)
    hypothesis_state: Dict[str, Any] = field(default_factory=dict)
    evidence_state: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'decision_id': self.decision_id,
            'selected': self.selected_experiment.to_dict(),
            'rejected': self.rejected_experiments,
            'reasoning': self.reasoning,
            'timestamp': self.timestamp,
            'hypothesis_state': self.hypothesis_state,
            'evidence_state': self.evidence_state,
        }

    def explain(self) -> str:
        """Generate the explanation: 'I selected experiment X because...'"""
        exp = self.selected_experiment
        parts = [
            f"I selected experiment '{exp.experiment_id}' because hypothesis '{exp.hypothesis_id}' "
            f"currently has evidence [{', '.join(exp.evidence_dependencies) or 'none'}], "
            f"expected information gain {exp.information_gain:.2f}, "
            f"expected impact {exp.impact:.2f}, "
            f"cost {exp.cost:.2f} and risk {exp.risk}."
        ]
        if self.rejected_experiments:
            for rej in self.rejected_experiments[:3]:
                parts.append(f"I rejected '{rej.get('experiment_id', '?')}': {rej.get('reason', 'no reason')}.")
        parts.append(f"I expected evidence: {exp.expected_evidence}.")
        return " ".join(parts)


class DecisionEngine:
    """The single canonical next-action selector.

    Combines:
    - Ranked evidence (from EvidenceRankingEngine)
    - Competing hypotheses (from MultiHypothesisEngine)
    - Strategic goals (from StrategistEngine)
    - Attack graph state
    - World model state
    - Critic penalties/bonuses

    Produces exactly ONE CandidateExperiment per decision cycle.
    """

    def __init__(self):
        self._decisions: List[DecisionRecord] = []
        self._decision_counter = 0

    def _next_decision_id(self) -> str:
        self._decision_counter += 1
        return f"decision_{self._decision_counter}"

    def _next_experiment_id(self) -> str:
        return f"exp_{self._decision_counter}_{len(self._decisions)}"

    def decide(
        self,
        *,
        hypothesis_engine: Any,  # MultiHypothesisEngine
        evidence_engine: Any,    # EvidenceRankingEngine
        strategist: Any,         # StrategistEngine
        attack_graph: Any,       # AttackGraph
        world_model: Any,        # WorldModel
        critic_engine: Any = None,  # CriticEngine
        target: str = "",
    ) -> Optional[DecisionRecord]:
        """Run the full decision cycle and produce exactly one experiment.

        Returns None if no viable experiment can be generated (mission complete
        or all hypotheses exhausted).
        """

        # Step 1: Get ranked evidence
        ranked_evidence = evidence_engine.get_ranked_evidence(limit=10) if evidence_engine else []
        evidence_summary = {
            'total': len(ranked_evidence) if ranked_evidence else 0,
            'top_kind': ranked_evidence[0].kind if ranked_evidence else 'none',
        }

        # Step 2: Get competing hypotheses
        active_hypotheses = hypothesis_engine.get_competing_hypotheses(limit=5, active_only=True) if hypothesis_engine else []
        hypothesis_summary = {
            'total_active': len(active_hypotheses),
            'confirmed': len(hypothesis_engine.get_confirmed_hypotheses()) if hypothesis_engine else 0,
            'rejected': len(hypothesis_engine.get_rejected_hypotheses()) if hypothesis_engine else 0,
        }

        # Step 3: Generate candidate experiments from multiple sources
        all_candidates: List[CandidateExperiment] = []

        # Source A: Experiments from active hypotheses
        for hyp in active_hypotheses:
            exp = self._hypothesis_to_experiment(hyp, target, attack_graph)
            if exp:
                all_candidates.append(exp)

        # Source B: Experiments from strategic goals
        recommendation = None
        if strategist and attack_graph:
            try:
                recommendation = strategist.analyze_attack_graph(attack_graph, world_model, critic_engine)
            except Exception:
                pass

        if recommendation and recommendation.primary_goal:
            goal_exps = self._goal_to_experiments(recommendation, target, hypothesis_engine, attack_graph)
            all_candidates.extend(goal_exps)

        # Source C: Experiments from evidence gaps
        if evidence_engine and world_model:
            gap_exps = self._evidence_gaps_to_experiments(evidence_engine, world_model, target, hypothesis_engine)
            all_candidates.extend(gap_exps)

        if not all_candidates:
            return None

        # Step 4: Score candidates with critic awareness
        for exp in all_candidates:
            exp.priority_score = self._score_experiment(exp, critic_engine, attack_graph)

        # Step 5: Select the single best experiment
        all_candidates.sort(key=lambda e: e.priority_score, reverse=True)
        selected = all_candidates[0]
        rejected = [
            {'experiment_id': c.experiment_id, 'reason': self._rejection_reason(c, selected)}
            for c in all_candidates[1:4]
        ]

        # Step 6: Build reasoning
        reasoning = self._build_reasoning(selected, rejected, ranked_evidence, active_hypotheses, recommendation)

        # Step 7: Record and return
        record = DecisionRecord(
            decision_id=self._next_decision_id(),
            selected_experiment=selected,
            rejected_experiments=rejected,
            reasoning=reasoning,
            hypothesis_state=hypothesis_summary,
            evidence_state=evidence_summary,
        )
        self._decisions.append(record)
        return record

    def _hypothesis_to_experiment(
        self,
        hyp: Any,  # CompetingHypothesis
        target: str,
        attack_graph: Any,
    ) -> Optional[CandidateExperiment]:
        """Convert a hypothesis into an executable experiment."""
        if not hyp.command:
            return None

        # Determine evidence dependencies from attack graph
        evidence_deps = []
        if attack_graph:
            for node_id, node in attack_graph.nodes.items():
                if node.get('type') in ('service', 'endpoint', 'technology'):
                    evidence_deps.append(node_id)

        risk_level = "low" if hyp.risk < 0.3 else ("normal" if hyp.risk < 0.6 else "high")

        return CandidateExperiment(
            experiment_id=self._next_experiment_id(),
            hypothesis_id=hyp.id,
            hypothesis=hyp.statement,
            expected_evidence=", ".join(hyp.expected_evidence[:3]) if hyp.expected_evidence else "observations from command output",
            falsification_condition=hyp.falsification_condition or "No supporting evidence found",
            target=target,
            risk=risk_level,
            reason=f"Testing hypothesis: {hyp.statement[:100]}",
            evidence_dependencies=evidence_deps[:5],
            command=hyp.command,
            tool=hyp.command.split()[0] if hyp.command else "",
            alternative_commands=hyp.command_alternatives[:2],
            information_gain=hyp.expected_information_gain,
            impact=hyp.expected_impact,
            cost=hyp.execution_cost,
            confidence=hyp.confidence,
        )

    def _goal_to_experiments(
        self,
        recommendation: Any,  # StrategyRecommendation
        target: str,
        hypothesis_engine: Any,
        attack_graph: Any,
    ) -> List[CandidateExperiment]:
        """Convert strategic goals into candidate experiments."""
        experiments = []
        goal = recommendation.primary_goal
        if not goal:
            return experiments

        # Create experiment for each step in attack chain
        for i, step in enumerate(recommendation.attack_chain[:3]):
            hyp_id = f"goal_{goal.goal_id}_{i}"
            # Check if a hypothesis already covers this
            if hypothesis_engine and not hypothesis_engine.is_duplicate_or_rejected(
                f"Strategic goal: {goal.description} - step {step}"
            ):
                hyp = hypothesis_engine.add_hypothesis(
                    statement=f"Strategic goal: {goal.description} - executing {step}",
                    title=f"Strategic: {step}",
                    command="",  # Will be filled by coordinator
                    confidence=goal.confidence,
                    information_gain=0.7,
                    impact=goal.priority_score,
                    tags=["strategic", step],
                    generation_reason=f"Strategic goal {goal.goal_id}",
                    falsification_condition=f"Step {step} produces no new evidence",
                )
                if hyp:
                    exp = CandidateExperiment(
                        experiment_id=self._next_experiment_id(),
                        hypothesis_id=hyp.id,
                        hypothesis=hyp.statement,
                        expected_evidence=goal.expected_outcome,
                        falsification_condition=f"Expected outcome not achieved for step {step}",
                        target=target,
                        risk=recommendation.risk_assessment.split()[0].lower() if recommendation.risk_assessment else "normal",
                        reason=f"Strategic goal: {goal.description}",
                        evidence_dependencies=[goal.target_node_id],
                        information_gain=0.7,
                        impact=goal.priority_score,
                        cost=0.5,
                        confidence=goal.confidence,
                        source_goal_id=goal.goal_id,
                        metadata={'step': step, 'attack_chain': recommendation.attack_chain},
                    )
                    experiments.append(exp)
        return experiments

    def _evidence_gaps_to_experiments(
        self,
        evidence_engine: Any,
        world_model: Any,
        target: str,
        hypothesis_engine: Any,
    ) -> List[CandidateExperiment]:
        """Convert evidence gaps into candidate experiments."""
        experiments = []
        model_state = {
            'ports': [], 'endpoints': [], 'credentials': [],
        }
        if world_model and hasattr(world_model, 'hosts'):
            for host in world_model.hosts.values():
                model_state['ports'].extend(
                    {'port': s.port, 'service': s.service, 'version': s.version}
                    for s in host.services.values()
                )
                model_state['endpoints'].extend(
                    {'url': e.url, 'method': e.method, 'status': e.status}
                    for e in host.endpoints.values()
                )
                model_state['credentials'].extend(
                    {'username': c.username, 'service': c.service}
                    for c in host.credentials
                )

        gaps = evidence_engine.get_knowledge_gaps(model_state)
        for gap in gaps[:2]:
            statement = gap.get('suggestion', 'Fill knowledge gap')
            if hypothesis_engine and not hypothesis_engine.is_duplicate_or_rejected(statement):
                hyp = hypothesis_engine.add_hypothesis(
                    statement=statement,
                    title=f"Gap: {gap.get('type', 'unknown')}",
                    confidence=0.4,
                    information_gain=gap.get('priority', 0.5),
                    tags=["gap-filling"],
                    generation_reason=f"Knowledge gap: {gap.get('type')}",
                    falsification_condition="No new information gained from this exploration",
                )
                if hyp:
                    exp = CandidateExperiment(
                        experiment_id=self._next_experiment_id(),
                        hypothesis_id=hyp.id,
                        hypothesis=hyp.statement,
                        expected_evidence=f"Information to fill: {gap.get('type')}",
                        falsification_condition="No new information gained",
                        target=gap.get('target', target),
                        risk="low",
                        reason=f"Filling knowledge gap: {gap.get('type')}",
                        evidence_dependencies=[],
                        information_gain=gap.get('priority', 0.5),
                        impact=0.5,
                        cost=0.3,
                        confidence=0.4,
                    )
                    experiments.append(exp)
        return experiments

    def _score_experiment(
        self,
        exp: CandidateExperiment,
        critic_engine: Any,
        attack_graph: Any,
    ) -> float:
        """Score a candidate experiment for priority ranking."""
        # Base score from hypothesis properties
        base = (
            exp.information_gain * 0.35 +
            exp.impact * 0.25 +
            exp.confidence * 0.20 +
            (1.0 - exp.cost) * 0.10 +
            (1.0 - {"low": 0.1, "normal": 0.3, "high": 0.6, "critical": 0.9}.get(exp.risk, 0.5)) * 0.10
        )

        # Critic penalty/bonus adjustment
        if critic_engine and exp.tool:
            try:
                multiplier = critic_engine.calculate_priority_multiplier(
                    exp.tool, exp.metadata.get('step', ''), exp.target
                )
                base *= multiplier
            except Exception:
                pass

        # Graph-based boost: experiments targeting high-value nodes get priority
        if attack_graph and exp.evidence_dependencies:
            for dep_id in exp.evidence_dependencies:
                node = attack_graph.get_node(dep_id)
                if node and node.value_score > 0.7:
                    base *= 1.2
                    break

        return max(0.0, min(1.0, base))

    def _rejection_reason(self, candidate: CandidateExperiment, winner: CandidateExperiment) -> str:
        if candidate.information_gain < winner.information_gain:
            return f"Lower information gain ({candidate.information_gain:.2f} < {winner.information_gain:.2f})"
        if candidate.confidence < winner.confidence:
            return f"Lower confidence ({candidate.confidence:.2f} < {winner.confidence:.2f})"
        if candidate.cost > winner.cost:
            return f"Higher cost ({candidate.cost:.2f} > {winner.cost:.2f})"
        if candidate.risk in ("high", "critical") and winner.risk not in ("high", "critical"):
            return f"Higher risk ({candidate.risk} > {winner.risk})"
        return "Lower combined priority score"

    def _build_reasoning(
        self,
        selected: CandidateExperiment,
        rejected: List[Dict[str, Any]],
        ranked_evidence: List[Any],
        hypotheses: List[Any],
        recommendation: Any,
    ) -> str:
        parts = [
            f"Selected experiment {selected.experiment_id} for hypothesis '{selected.hypothesis_id}': {selected.hypothesis[:120]}.",
            f"Expected information gain={selected.information_gain:.2f}, impact={selected.impact:.2f}, "
            f"cost={selected.cost:.2f}, risk={selected.risk}.",
            f"Expected evidence: {selected.expected_evidence}.",
        ]
        if rejected:
            parts.append(f"Rejected {len(rejected)} alternatives: " +
                         "; ".join(f"{r['experiment_id']} ({r['reason']})" for r in rejected[:2]))
        if recommendation and hasattr(recommendation, 'reasoning'):
            parts.append(f"Strategic context: {recommendation.reasoning[:200]}.")
        return " ".join(parts)

    @property
    def last_decision(self) -> Optional[DecisionRecord]:
        return self._decisions[-1] if self._decisions else None

    @property
    def all_decisions(self) -> List[DecisionRecord]:
        return list(self._decisions)

    def get_decision_count(self) -> int:
        return len(self._decisions)
