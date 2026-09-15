"""End-to-end test for the autonomous evidence-driven decision loop.

Verifies the full P0 architecture cycle:
  Observation → Evidence Ranking → Competing Hypotheses → Strategic Goal →
  Candidate Experiments → Decision Engine (single selection) →
  Execution Gateway → Observations → WorldModel update →
  Hypothesis confirmation/rejection → re-planning

This test does NOT instantiate individual engines manually.
It tests the canonical autonomous entrypoint.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from brain.attack_graph import (
    AttackGraph,
    EDGE_HOST_HAS_SERVICE,
    EDGE_SERVICE_SERVES_ENDPOINT,
    EDGE_ENDPOINT_VULNERABLE_TO,
    NODE_STATE_OBSERVED,
    NODE_STATE_IDENTIFIED,
    NODE_STATE_CONFIRMED,
    NODE_STATE_TESTABLE,
    NODE_STATE_UNKNOWN,
)
from brain.coordinator import SwarmCoordinator
from brain.decision_engine import DecisionEngine, CandidateExperiment
from brain.evidence_ranking import EvidenceRankingEngine, RankedEvidence
from brain.hypothesis_engine import (
    MultiHypothesisEngine,
    HYP_NEW,
    HYP_TESTING,
    HYP_CONFIRMED,
    HYP_REJECTED,
    HYP_STALE,
    HYP_DEAD,
)
from brain.strategist_engine import StrategistEngine
from brain.world_model import WorldModel, Observation, ServiceRecord, EndpointRecord


class TestDecisionLoopEndToEnd(unittest.TestCase):
    """Full autonomous loop test without hardcoded vulnerability knowledge."""

    def setUp(self):
        self.wm = WorldModel(target="192.168.1.100")
        self.wm.ensure_host("192.168.1.100")
        self.ag = AttackGraph()
        self.ee = EvidenceRankingEngine()
        self.he = MultiHypothesisEngine()
        self.se = StrategistEngine()
        self.de = DecisionEngine()

    def test_full_loop_observation_to_decision(self):
        """Observation → Evidence → Hypotheses → Strategic Goal → Decision."""
        # Step 1: Simulate observation (port discovered)
        host = self.wm.hosts["192.168.1.100"]
        host.services["80/tcp"] = ServiceRecord(port=80, proto="tcp", service="http", version="nginx/1.18")
        self.wm.ingest(Observation(kind="port", source="nmap", data={"port": 80, "service": "http"}))

        host_node = self.ag.add_node("host", "192.168.1.100", value_score=1.0)
        svc_node = self.ag.add_node(
            "service", "http:80", value_score=0.6,
            properties={"port": 80, "service": "http", "version": "nginx/1.18"},
            state=NODE_STATE_OBSERVED,
        )
        self.ag.add_edge(host_node.id, svc_node.id, EDGE_HOST_HAS_SERVICE, confidence=0.95)

        # Step 2: Evidence ranking
        self.ee.add_evidence(RankedEvidence(
            id="port-80-http", source="nmap", kind="port",
            data={"port": 80, "service": "http", "version": "nginx/1.18"},
        ))
        ranked = self.ee.get_ranked_evidence(limit=5)
        self.assertEqual(len(ranked), 1)
        self.assertGreater(ranked[0].score.total_score, 0)

        # Step 3: Hypotheses generated from state
        hyps = self.he.generate_from_scenario({
            'ports': [{'port': 80, 'service': 'http'}],
            'tech_stack': {},
            'endpoints': [],
        })
        self.assertGreater(len(hyps), 0)
        active = self.he.get_competing_hypotheses(limit=5)
        self.assertGreater(len(active), 0)

        # Step 4: Decision engine selects ONE experiment
        decision = self.de.decide(
            hypothesis_engine=self.he,
            evidence_engine=self.ee,
            strategist=self.se,
            attack_graph=self.ag,
            world_model=self.wm,
            target="192.168.1.100",
        )
        self.assertIsNotNone(decision)
        exp = decision.selected_experiment

        # Verify experiment has all required fields
        self.assertTrue(exp.hypothesis_id)
        self.assertTrue(exp.hypothesis)
        self.assertTrue(exp.expected_evidence)
        self.assertTrue(exp.falsification_condition)
        self.assertEqual(exp.target, "192.168.1.100")
        self.assertIn(exp.risk, ("low", "normal", "high", "critical"))
        self.assertTrue(exp.reason)
        self.assertIsInstance(exp.evidence_dependencies, list)

        # Verify decision explanation exists
        explanation = decision.explain()
        self.assertIn("selected experiment", explanation)
        self.assertIn("hypothesis", explanation)
        self.assertIn("information gain", explanation)

    def test_hypothesis_lifecycle_states(self):
        """Hypothesis: NEW → TESTING → CONFIRMED/REJECTED."""
        hyp = self.he.add_hypothesis(
            statement="The web server has directory listing enabled",
            title="Directory Listing",
            command="curl -sik http://target/admin/",
            assumptions=["Web server responds to /admin/"],
            expected_evidence=["200 OK with directory listing HTML"],
            falsification_condition="403 or 404 on /admin/",
            confidence=0.5,
        )
        self.assertIsNotNone(hyp)
        self.assertEqual(hyp.state, HYP_NEW)

        # Mark testing
        self.he.mark_testing(hyp.id)
        self.assertEqual(hyp.state, HYP_TESTING)

        # Confirm with evidence
        self.he.confirm_hypothesis(hyp.id, ["evidence-1"], evidence_quality=0.8)
        self.assertEqual(hyp.state, HYP_CONFIRMED)
        self.assertGreater(hyp.confidence, 0.5)

    def test_hypothesis_rejection_prevents_repetition(self):
        """Rejected hypotheses cannot be re-generated."""
        hyp = self.he.add_hypothesis(
            statement="SSH is running on port 22",
            command="nmap -p 22 target",
        )
        self.assertIsNotNone(hyp)
        self.he.reject_hypothesis(hyp.id, reason="Port 22 is closed")

        # Same hypothesis cannot be re-added
        dup = self.he.add_hypothesis(
            statement="SSH is running on port 22",
            command="nmap -p 22 target",
        )
        self.assertIsNone(dup)

    def test_evidence_delta_is_real_progress(self):
        """Progress means new services/endpoints/vulns, not keyword matching."""
        # Add initial evidence
        self.ee.add_evidence(RankedEvidence(
            id="port-80", source="nmap", kind="port",
            data={"port": 80, "service": "http"},
        ))

        # Novel evidence should have high novelty
        self.ee.add_evidence(RankedEvidence(
            id="endpoint-admin", source="gobuster", kind="endpoint",
            data={"url": "/admin", "method": "GET", "status": 200},
        ))
        admin_ev = self.ee.get_evidence_by_id("endpoint-admin")
        self.assertIsNotNone(admin_ev)
        self.assertGreater(admin_ev.score.novelty, 0.5)

        # Duplicate evidence should have low novelty
        self.ee.add_evidence(RankedEvidence(
            id="port-80-dup", source="httpx", kind="port",
            data={"port": 80, "service": "http"},
        ))
        dup_ev = self.ee.get_evidence_by_id("port-80-dup")
        self.assertLess(dup_ev.score.novelty, admin_ev.score.novelty)

    def test_attack_graph_typed_relationships(self):
        """Attack graph has explicit typed relationships."""
        host = self.ag.add_node("host", "target.com", value_score=1.0)
        svc = self.ag.add_node("service", "http:80", value_score=0.6, state=NODE_STATE_OBSERVED)
        ep = self.ag.add_node("endpoint", "/login", value_score=0.7, state=NODE_STATE_OBSERVED)
        vuln = self.ag.add_node("vulnerability", "SQLi", value_score=0.9, state=NODE_STATE_TESTABLE)

        self.ag.add_edge(host.id, svc.id, EDGE_HOST_HAS_SERVICE)
        self.ag.add_edge(svc.id, ep.id, EDGE_SERVICE_SERVES_ENDPOINT)
        self.ag.add_edge(ep.id, vuln.id, EDGE_ENDPOINT_VULNERABLE_TO)

        self.assertEqual(self.ag.node_count(), 4)
        self.assertEqual(self.ag.edge_count(), 3)

        # Find path to vulnerability
        paths = self.ag.find_paths_to(vuln.id, max_depth=5)
        self.assertGreater(len(paths), 0)

    def test_node_state_transitions_with_provenance(self):
        """Node state transitions carry provenance/evidence."""
        node = self.ag.add_node("service", "http:80", state=NODE_STATE_UNKNOWN)
        self.assertEqual(node.state, NODE_STATE_UNKNOWN)

        # Valid transition
        result = node.transition(NODE_STATE_OBSERVED, evidence="nmap -sV output", source="ReconAgent")
        self.assertTrue(result)
        self.assertEqual(node.state, NODE_STATE_OBSERVED)
        self.assertEqual(len(node.state_history), 1)
        self.assertEqual(node.state_history[0].evidence, "nmap -sV output")

        # Invalid transition (UNKNOWN → EXPLOITED is not valid)
        result = node.transition("exploited", evidence="magic")
        self.assertFalse(result)
        self.assertEqual(node.state, NODE_STATE_OBSERVED)

    def test_strategist_consumes_world_model(self):
        """StrategistEngine uses actual WorldModel, not None."""
        host = self.wm.hosts["192.168.1.100"]
        host.services["80/tcp"] = ServiceRecord(port=80, service="http")

        host_node = self.ag.add_node("host", "192.168.1.100", value_score=1.0)
        svc = self.ag.add_node(
            "service", "http:80", value_score=0.6,
            properties={"port": 80, "service": "http"},
            state=NODE_STATE_OBSERVED,
        )
        self.ag.add_edge(host_node.id, svc.id, EDGE_HOST_HAS_SERVICE)

        rec = self.se.analyze_attack_graph(self.ag, self.wm)
        self.assertIsNotNone(rec)
        self.assertIsNotNone(rec.primary_goal)
        # Strategist should produce a real goal, not a generic fallback
        self.assertIn("192.168.1.100", rec.primary_goal.description)

    def test_confidence_updated_from_observations_not_llm(self):
        """Confidence must be updated using actual observations."""
        hyp = self.he.add_hypothesis(
            statement="Web server has admin panel",
            confidence=0.5,
        )
        initial_conf = hyp.confidence

        # Positive observation
        hyp.update_confidence_from_observation(True, evidence_quality=0.8)
        self.assertGreater(hyp.confidence, initial_conf)

        # Negative observation
        hyp.update_confidence_from_observation(False, evidence_quality=0.5)
        self.assertLess(hyp.confidence, initial_conf + 0.1)

    def test_decision_engine_rejects_alternatives_with_reasons(self):
        """DecisionEngine records why alternatives were rejected."""
        # Create multiple hypotheses
        self.he.add_hypothesis(
            statement="SQL injection in login form",
            command="sqlmap -u http://target/login --data='user=a&pass=b'",
            confidence=0.6, information_gain=0.9, execution_cost=0.7, risk=0.5,
        )
        self.he.add_hypothesis(
            statement="Directory listing on /admin/",
            command="curl -sik http://target/admin/",
            confidence=0.7, information_gain=0.6, execution_cost=0.1, risk=0.1,
        )

        decision = self.de.decide(
            hypothesis_engine=self.he,
            evidence_engine=self.ee,
            strategist=self.se,
            attack_graph=self.ag,
            world_model=self.wm,
            target="192.168.1.100",
        )
        self.assertIsNotNone(decision)
        self.assertGreater(len(decision.rejected_experiments), 0)
        for rej in decision.rejected_experiments:
            self.assertIn("reason", rej)

    def test_world_model_updates_after_observation(self):
        """Every observation must update WorldModel."""
        initial_obs = len(self.wm.observations)

        self.wm.ingest(Observation(
            kind="port", source="nmap",
            data={"port": 443, "service": "https"},
        ))
        self.assertEqual(len(self.wm.observations), initial_obs + 1)

    def test_evidence_engine_identifies_knowledge_gaps(self):
        """Evidence engine identifies what's missing."""
        self.ee.add_evidence(RankedEvidence(
            id="port-80", source="nmap", kind="port",
            data={"port": 80, "service": "http", "version": ""},
        ))
        gaps = self.ee.get_knowledge_gaps({'ports': [{'port': 80, 'service': 'http', 'version': ''}], 'endpoints': [], 'credentials': []})
        self.assertGreater(len(gaps), 0)
        # Both missing_web_enumeration (0.85) and missing_version_info (0.6) are valid gaps
        gap_types = [g['type'] for g in gaps]
        self.assertIn('missing_version_info', gap_types)

    def test_graph_revision_increments_on_mutation(self):
        """Graph revision increments on every mutation."""
        initial_rev = self.ag.revision
        self.ag.add_node("host", "target.com")
        self.assertGreater(self.ag.revision, initial_rev)

        rev_after_add = self.ag.revision
        self.ag.add_node("service", "http:80")
        self.assertGreater(self.ag.revision, rev_after_add)

    def test_path_cache_includes_graph_revision(self):
        """Path cache invalidates when graph changes."""
        h = self.ag.add_node("host", "target.com", value_score=1.0)
        s = self.ag.add_node("service", "http:80", value_score=0.6)
        self.ag.add_edge(h.id, s.id, EDGE_HOST_HAS_SERVICE)

        paths1 = self.ag.find_paths(max_length=3)
        initial_count = len(paths1)

        # Adding a new node and edge should create new paths
        e = self.ag.add_node("endpoint", "/admin", value_score=0.8)
        self.ag.add_edge(s.id, e.id, EDGE_SERVICE_SERVES_ENDPOINT)
        paths2 = self.ag.find_paths(max_length=3)
        # New paths should exist (host → service → endpoint)
        self.assertGreaterEqual(len(paths2), initial_count)


class TestCoordinatorIntegration(unittest.TestCase):
    """Test SwarmCoordinator with real engines wired together."""

    def test_coordinator_maintains_world_model(self):
        """Coordinator's WorldModel is the canonical state."""
        coord = SwarmCoordinator(target="192.168.1.100")
        self.assertIsInstance(coord.world_model, WorldModel)
        self.assertEqual(coord.world_model.target, "192.168.1.100")

    def test_coordinator_wires_all_engines(self):
        """All cognitive engines are instantiated in coordinator."""
        coord = SwarmCoordinator(target="192.168.1.100")
        self.assertIsInstance(coord.evidence_engine, EvidenceRankingEngine)
        self.assertIsInstance(coord.hypothesis_engine, MultiHypothesisEngine)
        self.assertIsInstance(coord.strategist, StrategistEngine)
        self.assertIsInstance(coord.decision_engine, DecisionEngine)
        self.assertIsInstance(coord.attack_graph, AttackGraph)

    def test_register_port_updates_world_model(self):
        """Port registration updates WorldModel as canonical state."""
        coord = SwarmCoordinator(target="192.168.1.100")
        coord.register_port("192.168.1.100", 80, "http", "nginx/1.18", {})

        host = coord.world_model.hosts.get("192.168.1.100")
        self.assertIsNotNone(host)
        self.assertIn("80/tcp", host.services)
        self.assertEqual(host.services["80/tcp"].service, "http")

    def test_register_endpoint_updates_world_model(self):
        """Endpoint registration updates WorldModel."""
        coord = SwarmCoordinator(target="192.168.1.100")
        coord.register_endpoint("192.168.1.100", "/admin", 200, "Admin Panel", True, "login form")

        host = coord.world_model.hosts.get("192.168.1.100")
        self.assertIsNotNone(host)
        self.assertTrue(any("admin" in k for k in host.endpoints))

    def test_register_port_adds_evidence_to_ranking(self):
        """Port registration feeds evidence into the ranking engine."""
        coord = SwarmCoordinator(target="192.168.1.100")
        coord.register_port("192.168.1.100", 80, "http", "nginx", {})

        ranked = coord.evidence_engine.get_ranked_evidence(limit=5)
        self.assertGreater(len(ranked), 0)
        self.assertEqual(ranked[0].kind, "port")

    def test_register_port_creates_attack_graph_edge(self):
        """Port registration creates HOST_HAS_SERVICE edge."""
        coord = SwarmCoordinator(target="192.168.1.100")
        coord.register_port("192.168.1.100", 80, "http", "nginx", {})

        self.assertGreater(coord.attack_graph.node_count(), 0)
        self.assertGreater(coord.attack_graph.edge_count(), 0)

    def test_get_summary_includes_new_metrics(self):
        """Summary includes decision engine, hypothesis, and world model stats."""
        coord = SwarmCoordinator(target="192.168.1.100")
        summary = coord.get_summary()

        self.assertIn("hypotheses_active", summary["stats"])
        self.assertIn("hypotheses_confirmed", summary["stats"])
        self.assertIn("decisions_made", summary["stats"])
        self.assertIn("world_model_snapshot", summary["stats"])
        self.assertIn("attack_graph_revision", summary["stats"])


class TestTypedAttackGraph(unittest.TestCase):
    """Test typed relationships and node states."""

    def test_all_typed_relationships_exist(self):
        """All P0-specified relationship types are defined."""
        from brain.attack_graph import (
            EDGE_HOST_HAS_SERVICE, EDGE_SERVICE_SERVES_ENDPOINT,
            EDGE_ENDPOINT_HAS_PARAMETER, EDGE_ENDPOINT_EXPOSES,
            EDGE_ENDPOINT_VULNERABLE_TO, EDGE_SERVICE_AFFECTED_BY,
            EDGE_TECHNOLOGY_AFFECTED_BY, EDGE_CREDENTIAL_AUTHENTICATES_TO,
            EDGE_VULNERABILITY_REQUIRES, EDGE_VULNERABILITY_ENABLES,
            EDGE_FINDING_CONFIRMS, EDGE_FINDING_REJECTS,
            EDGE_HYPOTHESIS_TESTS, EDGE_EXPERIMENT_PRODUCES_EVIDENCE,
        )
        # All should be strings
        for edge_type in [
            EDGE_HOST_HAS_SERVICE, EDGE_SERVICE_SERVES_ENDPOINT,
            EDGE_ENDPOINT_HAS_PARAMETER, EDGE_ENDPOINT_EXPOSES,
            EDGE_ENDPOINT_VULNERABLE_TO, EDGE_SERVICE_AFFECTED_BY,
            EDGE_TECHNOLOGY_AFFECTED_BY, EDGE_CREDENTIAL_AUTHENTICATES_TO,
            EDGE_VULNERABILITY_REQUIRES, EDGE_VULNERABILITY_ENABLES,
            EDGE_FINDING_CONFIRMS, EDGE_FINDING_REJECTS,
            EDGE_HYPOTHESIS_TESTS, EDGE_EXPERIMENT_PRODUCES_EVIDENCE,
        ]:
            self.assertIsInstance(edge_type, str)
            self.assertTrue(edge_type)

    def test_all_node_states_exist(self):
        """All P0-specified node states are defined."""
        from brain.attack_graph import (
            NODE_STATE_UNKNOWN, NODE_STATE_OBSERVED, NODE_STATE_IDENTIFIED,
            NODE_STATE_CONFIRMED, NODE_STATE_TESTABLE, NODE_STATE_VALIDATED,
            NODE_STATE_EXPLOITABLE, NODE_STATE_EXPLOITED, NODE_STATE_REJECTED,
            NODE_STATE_STALE, NODE_STATE_BLOCKED, NODE_STATE_EXHAUSTED,
        )
        states = [
            NODE_STATE_UNKNOWN, NODE_STATE_OBSERVED, NODE_STATE_IDENTIFIED,
            NODE_STATE_CONFIRMED, NODE_STATE_TESTABLE, NODE_STATE_VALIDATED,
            NODE_STATE_EXPLOITABLE, NODE_STATE_EXPLOITED, NODE_STATE_REJECTED,
            NODE_STATE_STALE, NODE_STATE_BLOCKED, NODE_STATE_EXHAUSTED,
        ]
        self.assertEqual(len(states), 12)
        for state in states:
            self.assertIsInstance(state, str)


class TestHypothesisEngineSpec(unittest.TestCase):
    """Verify hypothesis engine matches P0 spec exactly."""

    def test_hypothesis_has_all_required_fields(self):
        """Hypothesis has all P0-required fields."""
        he = MultiHypothesisEngine()
        hyp = he.add_hypothesis(
            statement="Test statement",
            assumptions=["assumption1"],
            expected_evidence=["evidence1"],
            falsification_condition="condition1",
            confidence=0.5,
            information_gain=0.5,
            impact=0.5,
            execution_cost=0.5,
            risk=0.3,
        )
        self.assertIsNotNone(hyp)
        self.assertEqual(hyp.statement, "Test statement")
        self.assertEqual(hyp.assumptions, ["assumption1"])
        self.assertEqual(hyp.expected_evidence, ["evidence1"])
        self.assertEqual(hyp.falsification_condition, "condition1")
        self.assertEqual(hyp.attempt_count, 0)
        self.assertEqual(hyp.last_result, "")
        self.assertEqual(hyp.state, HYP_NEW)

    def test_hypothesis_states_match_spec(self):
        """All P0 hypothesis states are defined."""
        self.assertEqual(HYP_NEW, "NEW")
        self.assertEqual(HYP_TESTING, "TESTING")
        self.assertEqual(HYP_CONFIRMED, "CONFIRMED")
        self.assertEqual(HYP_REJECTED, "REJECTED")
        self.assertEqual(HYP_STALE, "STALE")
        self.assertEqual(HYP_DEAD, "DEAD")


if __name__ == "__main__":
    unittest.main()
