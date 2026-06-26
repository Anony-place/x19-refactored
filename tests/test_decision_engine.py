"""Unit tests for Decision Engine - Sprint 2 Phase 1."""

import unittest
from dataclasses import dataclass
from typing import List, Dict, Any

import sys
sys.path.insert(0, '/workspace')

from brain.decision_engine import (
    DecisionEngine,
    ScoreBreakdown,
    DecisionTrace,
    ScoredAction,
)


@dataclass
class MockCandidate:
    """Mock candidate action for testing."""
    tool: str
    category: str = "general"
    phase: str = "recon"
    rationale: str = ""
    description: str = ""
    prerequisites: List[str] = None
    unlocks: List[str] = None
    
    def __post_init__(self):
        if self.prerequisites is None:
            self.prerequisites = []
        if self.unlocks is None:
            self.unlocks = []


@dataclass
class MockWorldModel:
    """Mock world model for testing."""
    ports: List[Dict] = None
    tech_stack: Dict[str, str] = None
    endpoints: List[Dict] = None
    findings: List[Dict] = None
    hostname: str = "test.local"
    
    def __post_init__(self):
        if self.ports is None:
            self.ports = []
        if self.tech_stack is None:
            self.tech_stack = {}
        if self.endpoints is None:
            self.endpoints = []
        if self.findings is None:
            self.findings = []


class TestScoreBreakdown(unittest.TestCase):
    """Test ScoreBreakdown calculations."""
    
    def test_final_score_calculation(self):
        """Test weighted final score calculation."""
        breakdown = ScoreBreakdown(
            goal_relevance=1.0,
            information_gain=1.0,
            estimated_cost=1.0,
            estimated_risk=1.0,
            failure_penalty=1.0,
        )
        # Expected: 1.0*0.30 + 1.0*0.25 + 1.0*0.20 + 1.0*0.15 + 1.0*0.10 = 1.0
        self.assertAlmostEqual(breakdown.final_score, 1.0, places=2)
    
    def test_weighted_scores(self):
        """Test that weights are applied correctly."""
        breakdown = ScoreBreakdown(
            goal_relevance=0.8,
            information_gain=0.6,
            estimated_cost=0.9,
            estimated_risk=0.7,
            failure_penalty=0.5,
        )
        expected = (
            0.8 * 0.30 +  # 0.24
            0.6 * 0.25 +  # 0.15
            0.9 * 0.20 +  # 0.18
            0.7 * 0.15 +  # 0.105
            0.5 * 0.10    # 0.05
        )  # Total: 0.725
        self.assertAlmostEqual(breakdown.final_score, 0.725, places=2)
    
    def test_score_clamping(self):
        """Test that scores are clamped to 0.0-1.0."""
        # Edge case: all zeros
        breakdown = ScoreBreakdown(
            goal_relevance=0.0,
            information_gain=0.0,
            estimated_cost=0.0,
            estimated_risk=0.0,
            failure_penalty=0.0,
        )
        self.assertGreaterEqual(breakdown.final_score, 0.0)
        self.assertLessEqual(breakdown.final_score, 1.0)
    
    def test_to_dict(self):
        """Test dictionary conversion."""
        breakdown = ScoreBreakdown(
            goal_relevance=0.8,
            information_gain=0.6,
            estimated_cost=0.9,
            estimated_risk=0.7,
            failure_penalty=0.5,
        )
        result = breakdown.to_dict()
        self.assertIn("goal_relevance", result)
        self.assertIn("information_gain", result)
        self.assertIn("estimated_cost", result)
        self.assertIn("estimated_risk", result)
        self.assertIn("failure_penalty", result)
        self.assertIn("final_score", result)
        self.assertEqual(result["goal_relevance"], 0.8)


class TestDecisionEngine(unittest.TestCase):
    """Test DecisionEngine functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.engine = DecisionEngine()
        self.mock_model = MockWorldModel()
    
    def test_initialization(self):
        """Test engine initializes with empty state."""
        self.assertEqual(len(self.engine._failure_counts), 0)
        self.assertEqual(len(self.engine._decision_traces), 0)
    
    def test_record_failure(self):
        """Test recording failures increases count."""
        self.engine.record_failure("nmap")
        self.assertEqual(self.engine.get_failure_count("nmap"), 1)
        
        self.engine.record_failure("nmap")
        self.assertEqual(self.engine.get_failure_count("nmap"), 2)
    
    def test_record_success_resets_failure(self):
        """Test recording success resets failure count."""
        self.engine.record_failure("nmap")
        self.engine.record_failure("nmap")
        self.assertEqual(self.engine.get_failure_count("nmap"), 2)
        
        self.engine.record_success("nmap")
        self.assertEqual(self.engine.get_failure_count("nmap"), 0)
    
    def test_failure_penalty_calculation(self):
        """Test failure penalty decreases with more failures."""
        # No failures
        self.assertEqual(self.engine._calculate_failure_penalty("nmap"), 1.0)
        
        # 1 failure
        self.engine.record_failure("nmap")
        self.assertAlmostEqual(self.engine._calculate_failure_penalty("nmap"), 0.8, places=1)
        
        # 2 failures
        self.engine.record_failure("nmap")
        self.assertAlmostEqual(self.engine._calculate_failure_penalty("nmap"), 0.5, places=1)
        
        # 3 failures
        self.engine.record_failure("nmap")
        self.assertAlmostEqual(self.engine._calculate_failure_penalty("nmap"), 0.2, places=1)
        
        # 4+ failures (blocked)
        self.engine.record_failure("nmap")
        self.assertEqual(self.engine._calculate_failure_penalty("nmap"), 0.0)
    
    def test_score_candidates(self):
        """Test scoring multiple candidates."""
        candidates = [
            MockCandidate(tool="nmap", category="port_scan", phase="recon", unlocks=["whatweb", "gobuster"]),
            MockCandidate(tool="gobuster", category="dirbust", phase="web_enum", unlocks=["nuclei"]),
            MockCandidate(tool="sqlmap", category="web_exploit", phase="vuln_scan", unlocks=[]),
        ]
        
        scored = self.engine.score(candidates, self.mock_model, "Scan target for vulnerabilities")
        
        self.assertEqual(len(scored), 3)
        self.assertTrue(all(isinstance(s, ScoredAction) for s in scored))
        # Should be sorted by final_score descending
        for i in range(len(scored) - 1):
            self.assertGreaterEqual(scored[i].final_score, scored[i+1].final_score)
    
    def test_select_best_returns_trace(self):
        """Test select_best returns both action and trace."""
        candidates = [
            MockCandidate(tool="nmap", category="port_scan", phase="recon", unlocks=["whatweb"]),
        ]
        
        best, trace = self.engine.select_best(candidates, self.mock_model, "Discover open ports")
        
        self.assertIsNotNone(best)
        self.assertIsInstance(trace, DecisionTrace)
        self.assertEqual(trace.action_name, "nmap")
        self.assertEqual(trace.rank_among_candidates, 1)
        self.assertEqual(trace.total_candidates, 1)
    
    def test_select_best_no_candidates(self):
        """Test select_best handles empty candidate list."""
        best, trace = self.engine.select_best([], self.mock_model, "Test goal")
        
        self.assertIsNone(best)
        self.assertIsInstance(trace, DecisionTrace)
        self.assertIn("No valid candidates", trace.why_selected)
    
    def test_decision_trace_contains_rationale(self):
        """Test decision trace includes complete rationale."""
        candidates = [
            MockCandidate(tool="nmap", category="port_scan", phase="recon", 
                         rationale="Discover ports", unlocks=["whatweb", "gobuster"]),
            MockCandidate(tool="masscan", category="port_scan", phase="recon",
                         rationale="Fast scan", unlocks=["nmap"]),
        ]
        
        best, trace = self.engine.select_best(candidates, self.mock_model, "Find open ports")
        
        self.assertTrue(len(trace.why_selected) > 0)
        self.assertIsInstance(trace.why_alternatives_rejected, list)
        self.assertIsInstance(trace.expected_evidence, list)
        self.assertIsNotNone(trace.score_breakdown)
    
    def test_goal_relevance_phase_alignment(self):
        """Test that actions in current phase get higher relevance."""
        # Model with no ports yet -> recon phase
        model = MockWorldModel(ports=[], tech_stack={})
        
        recon_action = MockCandidate(tool="nmap", category="port_scan", phase="recon")
        exploit_action = MockCandidate(tool="msfconsole", category="exploit_framework", phase="exploit")
        
        scored = self.engine.score([recon_action, exploit_action], model, "Scan target")
        
        # Recon action should score higher when in recon phase
        self.assertGreater(scored[0].score_breakdown.goal_relevance, 
                          scored[1].score_breakdown.goal_relevance)
    
    def test_information_gain_from_unlocks(self):
        """Test that tools unlocking more have higher information gain."""
        model = MockWorldModel()
        
        high_gain = MockCandidate(tool="nmap", category="port_scan", 
                                 unlocks=["a", "b", "c", "d", "e"])
        low_gain = MockCandidate(tool="testssl", category="crypto", 
                                unlocks=[])
        
        scored = self.engine.score([high_gain, low_gain], model, "Test")
        
        nmap_score = next(s for s in scored if s.action_name == "nmap")
        testssl_score = next(s for s in scored if s.action_name == "testssl")
        
        self.assertGreater(nmap_score.score_breakdown.information_gain,
                          testssl_score.score_breakdown.information_gain)
    
    def test_cost_estimation_by_category(self):
        """Test cost estimates vary by category."""
        model = MockWorldModel()
        
        fast_action = MockCandidate(tool="searchsploit", category="exploit_search")
        slow_action = MockCandidate(tool="hydra", category="auth")
        
        scored = self.engine.score([fast_action, slow_action], model, "Test")
        
        searchsploit = next(s for s in scored if s.action_name == "searchsploit")
        hydra = next(s for s in scored if s.action_name == "hydra")
        
        # searchsploit should have higher cost score (meaning cheaper)
        self.assertGreater(searchsploit.score_breakdown.estimated_cost,
                          hydra.score_breakdown.estimated_cost)
    
    def test_risk_estimation_by_category(self):
        """Test risk estimates vary by category."""
        model = MockWorldModel()
        
        safe_action = MockCandidate(tool="subfinder", category="subdomain")
        risky_action = MockCandidate(tool="hydra", category="auth")
        
        scored = self.engine.score([safe_action, risky_action], model, "Test")
        
        subfinder = next(s for s in scored if s.action_name == "subfinder")
        hydra = next(s for s in scored if s.action_name == "hydra")
        
        # subfinder should have higher risk score (meaning safer)
        self.assertGreater(subfinder.score_breakdown.estimated_risk,
                          hydra.score_breakdown.estimated_risk)
    
    def test_decision_history_tracking(self):
        """Test that decisions are tracked in history."""
        candidates = [MockCandidate(tool="nmap", category="port_scan")]
        
        self.engine.select_best(candidates, self.mock_model, "Goal 1")
        self.engine.select_best(candidates, self.mock_model, "Goal 2")
        
        history = self.engine.get_decision_history()
        self.assertEqual(len(history), 2)
    
    def test_reset_for_new_target(self):
        """Test reset clears state."""
        self.engine.record_failure("nmap")
        self.engine.select_best([MockCandidate(tool="nmap")], self.mock_model, "Test")
        
        self.engine.reset_for_new_target()
        
        self.assertEqual(len(self.engine._failure_counts), 0)
        self.assertEqual(len(self.engine._decision_traces), 0)
    
    def test_export_import_state(self):
        """Test state export and import."""
        self.engine.record_failure("nmap")
        self.engine.record_failure("gobuster")
        
        exported = self.engine.export_state()
        
        self.assertIn("failure_counts", exported)
        self.assertEqual(exported["failure_counts"]["nmap"], 1)
        self.assertEqual(exported["failure_counts"]["gobuster"], 1)
        
        # Import into new engine
        new_engine = DecisionEngine()
        new_engine.import_state(exported)
        
        self.assertEqual(new_engine.get_failure_count("nmap"), 1)
        self.assertEqual(new_engine.get_failure_count("gobuster"), 1)


class TestDecisionTrace(unittest.TestCase):
    """Test DecisionTrace structure."""
    
    def test_trace_creation(self):
        """Test creating a decision trace."""
        breakdown = ScoreBreakdown(goal_relevance=0.8)
        trace = DecisionTrace(
            action_name="nmap",
            action_category="port_scan",
            why_selected="Best score",
            why_alternatives_rejected=["Other had lower score"],
            expected_evidence=["Ports", "Services"],
            confidence=0.85,
            score_breakdown=breakdown,
            rank_among_candidates=1,
            total_candidates=3,
            mission_goal="Scan target",
            world_model_state_summary="ports=0, tech=0",
        )
        
        self.assertEqual(trace.action_name, "nmap")
        self.assertEqual(trace.rank_among_candidates, 1)
        self.assertEqual(trace.total_candidates, 3)
    
    def test_trace_to_dict(self):
        """Test trace dictionary conversion."""
        breakdown = ScoreBreakdown(goal_relevance=0.8)
        trace = DecisionTrace(
            action_name="nmap",
            action_category="port_scan",
            why_selected="Test",
            score_breakdown=breakdown,
        )
        
        result = trace.to_dict()
        
        self.assertIn("action_name", result)
        self.assertIn("why_selected", result)
        self.assertIn("score_breakdown", result)
        self.assertIn("timestamp", result)


class TestIntegrationWithPlanner(unittest.TestCase):
    """Test integration patterns with existing Planner."""
    
    def setUp(self):
        self.engine = DecisionEngine()
    
    def test_scoring_planner_chainstep(self):
        """Test scoring objects similar to Planner's ChainStep."""
        from brain.planner import ChainStep
        
        step = ChainStep(
            tool="nmap",
            rationale="Discover open ports and services",
            phase="recon",
            prerequisites=[],
        )
        
        # Manually add unlocks for this test (ChainStep doesn't have it by default)
        step.unlocks = ["whatweb", "gobuster"]
        
        model = MockWorldModel()
        scored = self.engine.score([step], model, "Reconnaissance")
        
        self.assertEqual(len(scored), 1)
        self.assertEqual(scored[0].action_name, "nmap")
        self.assertIsNotNone(scored[0].score_breakdown)


if __name__ == "__main__":
    unittest.main()
