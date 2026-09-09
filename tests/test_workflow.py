"""Tests for the hybrid orchestration layer: gate, guardrails, budget, plan.

These lock down the behaviour that replaced the hardcoded 5-stage pipeline —
confidence gating, loop detection, budget ceilings, plan checkpoints, per-mission
agent retirement, and the default-deny validation gate.
"""
from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from brain.workflow import (
    ACTION_EXPLOIT,
    ACTION_PIVOT,
    ACTION_SWARM,
    ACTION_TEST,
    EXACT_FAILURE,
    IDEMPOTENT_NO_PROGRESS,
    LEVEL_STOP,
    LEVEL_WARN,
    SAME_TOOL_FAILURE,
    STAGE_GOAL,
    STAGE_ORDER,
    AgentFactory,
    BudgetState,
    ConfidenceGate,
    LoopGuard,
    MissionPlan,
    WorkflowRun,
    WorkflowStage,
    call_signature,
    result_signature,
    stage_after,
)


# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------
class StageTests(unittest.TestCase):
    def test_stage_order_is_the_xbow_loop(self):
        self.assertEqual(
            [s.value for s in STAGE_ORDER],
            ["learn", "map", "coordinate", "attack", "validate", "debrief"],
        )

    def test_every_stage_has_a_goal(self):
        for stage in STAGE_ORDER:
            self.assertTrue(STAGE_GOAL[stage].strip(), stage)

    def test_stage_after_walks_the_order(self):
        self.assertEqual(stage_after(WorkflowStage.LEARN), WorkflowStage.MAP)
        self.assertEqual(stage_after(WorkflowStage.VALIDATE), WorkflowStage.DEBRIEF)

    def test_last_stage_has_no_successor(self):
        self.assertIsNone(stage_after(WorkflowStage.DEBRIEF))


# ---------------------------------------------------------------------------
# Confidence gate (Cyber-AutoAgent thresholds)
# ---------------------------------------------------------------------------
class ConfidenceGateTests(unittest.TestCase):
    def setUp(self):
        self.gate = ConfidenceGate()

    def test_high_confidence_exploits(self):
        decision = self.gate.decide(0.9)
        self.assertEqual(decision.action, ACTION_EXPLOIT)
        self.assertEqual(decision.confidence, 0.9)

    def test_boundary_value_exploits(self):
        self.assertEqual(self.gate.decide(0.8).action, ACTION_EXPLOIT)

    def test_mid_confidence_tests_a_hypothesis(self):
        self.assertEqual(self.gate.decide(0.5).action, ACTION_TEST)
        self.assertEqual(self.gate.decide(0.79).action, ACTION_TEST)

    def test_low_confidence_deploys_a_swarm(self):
        self.assertEqual(self.gate.decide(0.1).action, ACTION_SWARM)
        self.assertEqual(self.gate.decide(0.0).action, ACTION_SWARM)

    def test_in_between_confidence_pivots(self):
        self.assertEqual(self.gate.decide(0.3).action, ACTION_PIVOT)
        self.assertEqual(self.gate.decide(0.49).action, ACTION_PIVOT)

    def test_every_decision_explains_itself(self):
        for value in (0.0, 0.3, 0.6, 0.95):
            decision = self.gate.decide(value)
            self.assertTrue(decision.reason.strip())
            self.assertEqual(decision.to_dict()["action"], decision.action)

    def test_out_of_range_confidence_is_clamped(self):
        self.assertEqual(self.gate.decide(-5).action, ACTION_SWARM)
        self.assertEqual(self.gate.decide(99).action, ACTION_EXPLOIT)

    def test_inverted_thresholds_are_refused(self):
        with self.assertRaises(ValueError):
            ConfidenceGate(exploit_above=0.4, test_above=0.9)
        with self.assertRaises(ValueError):
            ConfidenceGate(swarm_below=0.6, test_above=0.5)
        with self.assertRaises(ValueError):
            ConfidenceGate(exploit_above=1.5)

    def test_custom_thresholds_take_effect(self):
        gate = ConfidenceGate(exploit_above=0.95, test_above=0.6, swarm_below=0.1)
        self.assertEqual(gate.decide(0.9).action, ACTION_TEST)
        self.assertEqual(gate.decide(0.95).action, ACTION_EXPLOIT)
        self.assertEqual(gate.decide(0.2).action, ACTION_PIVOT)
        self.assertEqual(gate.decide(0.05).action, ACTION_SWARM)


# ---------------------------------------------------------------------------
# Loop guard (Hermes tool-loop guardrails)
# ---------------------------------------------------------------------------
class LoopGuardTests(unittest.TestCase):
    def test_first_failure_is_quiet(self):
        guard = LoopGuard()
        verdict = guard.record("nmap", {"target": "x"}, succeeded=False)
        self.assertEqual(verdict.level, "ok")
        self.assertTrue(verdict.allowed)

    def test_repeated_identical_failure_warns_then_stops(self):
        guard = LoopGuard()
        levels = []
        for _ in range(5):
            verdict = guard.record("sqlmap", {"target": "x"}, succeeded=False)
            levels.append(verdict.level)
        self.assertEqual(levels[0], "ok")
        self.assertIn(LEVEL_WARN, levels)
        self.assertEqual(levels[-1], LEVEL_STOP)

    def test_hard_stop_denies_the_call(self):
        guard = LoopGuard()
        for _ in range(5):
            verdict = guard.record("sqlmap", {"target": "x"}, succeeded=False)
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.fired, EXACT_FAILURE)
        self.assertIn("hard stop", verdict.reason)

    def test_warn_still_allows_the_call(self):
        guard = LoopGuard()
        guard.record("sqlmap", {"target": "x"}, succeeded=False)
        verdict = guard.record("sqlmap", {"target": "x"}, succeeded=False)
        self.assertEqual(verdict.level, LEVEL_WARN)
        self.assertTrue(verdict.allowed)

    def test_a_success_clears_the_exact_failure_streak(self):
        guard = LoopGuard()
        guard.record("sqlmap", {"target": "x"}, succeeded=False)
        guard.record("sqlmap", {"target": "x"}, succeeded=True, progressed=True)
        verdict = guard.record("sqlmap", {"target": "x"}, succeeded=False)
        self.assertEqual(verdict.level, "ok", "a success must reset the failure streak")

    def test_different_arguments_do_not_share_an_exact_failure_streak(self):
        guard = LoopGuard()
        for _ in range(4):
            guard.record("sqlmap", {"target": "x"}, succeeded=False)
        verdict = guard.record("sqlmap", {"target": "y"}, succeeded=False)
        self.assertNotEqual(verdict.fired, EXACT_FAILURE)

    def test_same_tool_with_different_args_counts_toward_the_tool_streak(self):
        guard = LoopGuard()
        verdict = None
        for index in range(3):
            verdict = guard.record("nmap", {"target": f"host{index}"}, succeeded=False)
        self.assertEqual(verdict.fired, SAME_TOOL_FAILURE)
        self.assertEqual(verdict.level, LEVEL_WARN)

    def test_idempotent_no_progress_fires_on_repeated_identical_success(self):
        guard = LoopGuard()
        levels = []
        for _ in range(2):
            verdict = guard.record(
                "curl", {"url": "u"}, succeeded=True, result="same body", progressed=False
            )
            levels.append(verdict.level)
        self.assertEqual(levels[-1], LEVEL_WARN)
        self.assertEqual(verdict.fired, IDEMPOTENT_NO_PROGRESS)

    def test_progressing_success_never_trips_the_guard(self):
        guard = LoopGuard()
        for index in range(20):
            verdict = guard.record("crawl", {"i": index}, succeeded=True, result=index, progressed=True)
        self.assertEqual(verdict.level, "ok")

    def test_hard_stop_can_be_disabled_for_interactive_use(self):
        guard = LoopGuard(hard_stop_enabled=False)
        verdict = None
        for _ in range(9):
            verdict = guard.record("sqlmap", {"target": "x"}, succeeded=False)
        self.assertTrue(verdict.allowed, "warn-only mode must never deny")

    def test_events_are_recorded_only_for_non_ok_verdicts(self):
        guard = LoopGuard()
        guard.record("nmap", {"target": "x"}, succeeded=False)
        self.assertEqual(guard.events, [])
        guard.record("nmap", {"target": "x"}, succeeded=False)
        self.assertEqual(len(guard.events), 1)
        self.assertEqual(guard.events[0]["tool"], "nmap")
        self.assertIn("guardrail", guard.events[0])

    def test_reset_cycle_clears_identical_result_streaks(self):
        guard = LoopGuard()
        guard.record("curl", {"url": "u"}, succeeded=True, result="b", progressed=False)
        guard.reset_cycle()
        verdict = guard.record("curl", {"url": "u"}, succeeded=True, result="b", progressed=False)
        self.assertEqual(verdict.level, "ok")

    def test_would_allow_queries_without_mutating(self):
        guard = LoopGuard()
        guard.record("sqlmap", {"t": "x"}, succeeded=False)
        verdict = guard.would_allow("sqlmap", {"t": "x"})
        self.assertEqual(verdict.level, LEVEL_WARN)
        # Repeated queries must not escalate on their own.
        self.assertEqual(guard.would_allow("sqlmap", {"t": "x"}).level, LEVEL_WARN)
        self.assertEqual(guard.would_allow("sqlmap", {"t": "x"}).level, LEVEL_WARN)
        self.assertEqual(guard.events, [], "a query must not be recorded as an event")

    def test_would_allow_is_quiet_for_a_fresh_call(self):
        self.assertEqual(LoopGuard().would_allow("nmap", {"t": "x"}).level, "ok")

    def test_recording_a_phantom_success_does_not_clear_a_pending_failure(self):
        guard = LoopGuard()
        guard.record("sqlmap", {"t": "x"}, succeeded=False)
        # The attack stage used to record succeeded=True as a pre-flight check,
        # which wiped the streak the guard existed to catch.
        self.assertEqual(guard.would_allow("sqlmap", {"t": "x"}).level, LEVEL_WARN)
        guard.record("sqlmap", {"t": "x"}, succeeded=True, progressed=True)
        self.assertEqual(guard.would_allow("sqlmap", {"t": "x"}).level, "ok")

    def test_signatures_are_stable_and_order_independent(self):
        self.assertEqual(call_signature("t", {"a": 1, "b": 2}), call_signature("t", {"b": 2, "a": 1}))
        self.assertNotEqual(call_signature("t", {"a": 1}), call_signature("t2", {"a": 1}))
        self.assertEqual(result_signature({"a": 1}), result_signature({"a": 1}))

    def test_guard_is_thread_safe(self):
        import threading

        guard = LoopGuard()
        errors = []

        def hammer():
            try:
                for _ in range(50):
                    guard.record("tool", {"x": 1}, succeeded=False)
            except Exception as exc:  # pragma: no cover - failure is the assertion
                errors.append(exc)

        threads = [threading.Thread(target=hammer) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(guard.events[-1]["level"], LEVEL_STOP)


# ---------------------------------------------------------------------------
# Budget
# ---------------------------------------------------------------------------
class BudgetStateTests(unittest.TestCase):
    def test_percentage_is_the_worst_case_ceiling(self):
        state = BudgetState(max_seconds=100, max_commands=100, max_llm_calls=100)
        state.spend(commands=50)
        self.assertAlmostEqual(state.pct_used(), 50.0, delta=0.5)

    def test_llm_calls_can_be_the_binding_constraint(self):
        state = BudgetState(max_seconds=10_000, max_commands=10_000, max_llm_calls=10)
        state.spend(llm_calls=8)
        self.assertAlmostEqual(state.pct_used(), 80.0, delta=0.5)

    def test_percentage_is_capped_at_100(self):
        state = BudgetState(max_seconds=100, max_commands=100, max_llm_calls=100)
        state.spend(commands=500)
        self.assertEqual(state.pct_used(), 100.0)

    def test_elapsed_time_counts_against_the_budget(self):
        state = BudgetState(max_seconds=10, max_commands=0, max_llm_calls=0)
        state.started_at = time.time() - 5
        self.assertAlmostEqual(state.pct_used(), 50.0, delta=5.0)

    def test_exhausted_reports_which_ceiling_hit(self):
        state = BudgetState(max_seconds=0, max_commands=5, max_llm_calls=0)
        self.assertEqual(state.exhausted(), (False, ""))
        state.spend(commands=5)
        hit, reason = state.exhausted()
        self.assertTrue(hit)
        self.assertIn("command budget", reason)

    def test_time_budget_exhaustion(self):
        state = BudgetState(max_seconds=1, max_commands=0, max_llm_calls=0)
        state.started_at = time.time() - 5
        hit, reason = state.exhausted()
        self.assertTrue(hit)
        self.assertIn("time budget", reason)

    def test_zero_means_unlimited(self):
        state = BudgetState(max_seconds=0, max_commands=0, max_llm_calls=0)
        state.spend(commands=10_000, llm_calls=10_000)
        self.assertEqual(state.exhausted(), (False, ""))
        self.assertEqual(state.pct_used(), 0.0)

    def test_cycles_are_tracked(self):
        state = BudgetState()
        state.spend(cycles=3)
        self.assertEqual(state.cycles, 3)
        self.assertEqual(state.to_dict()["cycles"], 3)


# ---------------------------------------------------------------------------
# Mission plan (external working memory)
# ---------------------------------------------------------------------------
class MissionPlanTests(unittest.TestCase):
    def setUp(self):
        self.plan = MissionPlan(target="127.0.0.1", objective="assess")

    def test_starts_with_every_stage_pending(self):
        for stage in STAGE_ORDER:
            self.assertEqual(self.plan.phase(stage).status, "pending")

    def test_mark_updates_status_and_note(self):
        self.plan.mark(WorkflowStage.LEARN, "done", "scope applied")
        phase = self.plan.phase(WorkflowStage.LEARN)
        self.assertEqual(phase.status, "done")
        self.assertIn("scope applied", phase.notes)
        self.assertGreater(phase.updated_at, 0)

    def test_completion_percentage_tracks_finished_stages(self):
        self.assertEqual(self.plan.pct_complete(), 0.0)
        self.plan.mark(WorkflowStage.LEARN, "done")
        self.assertAlmostEqual(self.plan.pct_complete(), 100 / len(STAGE_ORDER), delta=0.1)
        for stage in STAGE_ORDER:
            self.plan.mark(stage, "done")
        self.assertEqual(self.plan.pct_complete(), 100.0)

    def test_active_and_next_stage(self):
        self.assertIsNone(self.plan.active_stage())
        self.plan.mark(WorkflowStage.LEARN, "done")
        self.plan.mark(WorkflowStage.MAP, "active")
        self.assertEqual(self.plan.active_stage(), WorkflowStage.MAP)
        self.assertEqual(self.plan.next_stage(), WorkflowStage.COORDINATE)

    def test_skipped_stages_count_as_finished(self):
        for stage in STAGE_ORDER:
            self.plan.mark(stage, "skipped")
        self.assertEqual(self.plan.pct_complete(), 100.0)

    def test_checkpoint_review_lists_phase_status(self):
        self.plan.mark(WorkflowStage.LEARN, "done", "4 endpoints")
        self.plan.mark(WorkflowStage.MAP, "active")
        review = self.plan.checkpoint_review(40.0)
        self.assertIn("learn", review)
        self.assertIn("map", review)
        self.assertEqual(len(self.plan.checkpoint_reviews), 1)

    def test_to_dict_is_serialisable(self):
        import json

        self.plan.mark(WorkflowStage.LEARN, "done")
        payload = json.loads(__import__("json").dumps(self.plan.to_dict()))
        self.assertEqual(payload["target"], "127.0.0.1")
        self.assertEqual(len(payload["phases"]), len(STAGE_ORDER))


# ---------------------------------------------------------------------------
# Agent factory (fresh agent per mission)
# ---------------------------------------------------------------------------
class AgentFactoryTests(unittest.TestCase):
    def test_registry_covers_the_fleet(self):
        self.assertEqual(
            sorted(AgentFactory.REGISTRY), ["critic", "recon", "verify", "vuln", "web"]
        )

    def test_registry_entries_resolve_to_real_classes(self):
        import importlib

        for kind, (module_name, class_name) in AgentFactory.REGISTRY.items():
            module = importlib.import_module(module_name)
            self.assertTrue(hasattr(module, class_name), f"{kind} -> {class_name}")

    def test_unknown_kind_is_rejected(self):
        factory = AgentFactory()
        with self.assertRaises(KeyError):
            factory.spawn("quantum")

    def test_parallel_cap_is_enforced(self):
        factory = AgentFactory(max_parallel=1)
        with mock.patch.dict(AgentFactory.REGISTRY, {"recon": ("__main__", "object")}, clear=False):
            with mock.patch("importlib.import_module") as importer:
                importer.return_value = mock.Mock(object=lambda **kwargs: object())
                first = factory.spawn("recon")
                self.assertTrue(first is not None)
                self.assertEqual(factory.active_count, 1)
                self.assertFalse(factory.can_spawn())
                with self.assertRaises(RuntimeError):
                    factory.spawn("recon")

    def test_retire_frees_a_slot_and_records_the_agent(self):
        class Worker:
            def __init__(self, **kwargs):
                self.name = "WorkerAgent"
                self.stops = 0

            def stop(self):
                self.stops += 1

        factory = AgentFactory(max_parallel=1)
        with mock.patch("importlib.import_module") as importer:
            importer.return_value = mock.Mock(Worker=Worker)
            with mock.patch.dict(AgentFactory.REGISTRY, {"recon": ("__main__", "Worker")}):
                spawned = factory.spawn("recon")
        self.assertEqual(factory.active_count, 1)
        factory.retire(spawned)
        self.assertEqual(factory.active_count, 0)
        self.assertEqual(factory.retired, ["WorkerAgent"])
        self.assertEqual(spawned.stops, 1)
        self.assertTrue(factory.can_spawn())

    def test_retire_all_clears_the_fleet(self):
        class Worker:
            counter = 0

            def __init__(self, **kwargs):
                Worker.counter += 1
                self.name = f"a{Worker.counter}"

            def stop(self):
                pass

        factory = AgentFactory(max_parallel=4)
        with mock.patch("importlib.import_module") as importer:
            importer.return_value = mock.Mock(Worker=Worker)
            with mock.patch.dict(AgentFactory.REGISTRY, {"recon": ("__main__", "Worker")}):
                for _ in range(3):
                    factory.spawn("recon")
        self.assertEqual(factory.retire_all(), 3)
        self.assertEqual(factory.active_count, 0)

    def test_retiring_a_stopped_agent_does_not_raise(self):
        class Boom:
            name = "boom"

            def stop(self):
                raise RuntimeError("already stopped")

        factory = AgentFactory()
        factory.retire(Boom())  # must swallow
        self.assertEqual(factory.retired, ["boom"])

    def test_scope_guard_is_withheld_from_the_critic(self):
        guard = object()
        factory = AgentFactory(scope_guard=guard, max_parallel=2)
        seen = {}

        class Fake:
            def __init__(self, **kwargs):
                seen.update(kwargs)

        with mock.patch("importlib.import_module") as importer:
            importer.return_value = mock.Mock(Fake=Fake)
            with mock.patch.dict(AgentFactory.REGISTRY, {"critic": ("__main__", "Fake")}):
                factory.spawn("critic")
        self.assertNotIn("scope_guard", seen)

    def test_scope_guard_is_passed_to_attack_agents(self):
        guard = object()
        factory = AgentFactory(scope_guard=guard, max_parallel=2)
        seen = {}

        class Fake:
            def __init__(self, **kwargs):
                seen.update(kwargs)

        with mock.patch("importlib.import_module") as importer:
            importer.return_value = mock.Mock(Fake=Fake)
            with mock.patch.dict(AgentFactory.REGISTRY, {"vuln": ("__main__", "Fake")}):
                factory.spawn("vuln")
        self.assertIs(seen.get("scope_guard"), guard)


# ---------------------------------------------------------------------------
# Attack graph views the strategist needs
# ---------------------------------------------------------------------------
class AttackGraphViewTests(unittest.TestCase):
    def setUp(self):
        from brain.attack_graph import AttackGraph

        self.graph = AttackGraph()
        self.host = self.graph.add_node("host", "Target: 127.0.0.1", value_score=1.0)
        self.web = self.graph.add_node("service", "http/80", value_score=0.8, difficulty_score=0.2)
        self.db = self.graph.add_node("service", "mysql/3306", value_score=0.9, difficulty_score=0.6)
        self.graph.add_edge(self.host.id, self.web.id, "runs")
        self.graph.add_edge(self.web.id, self.db.id, "access")

    def test_nodes_expose_the_keys_the_strategist_reads(self):
        view = self.graph.nodes
        self.assertEqual(len(view), 3)
        node = view[self.web.id]
        for key in ("id", "type", "state", "value_score", "confidence",
                    "category", "technique", "service", "port"):
            self.assertIn(key, node)
        self.assertEqual(node["type"], "service")
        self.assertEqual(node["state"], "unknown")

    def test_edges_are_grouped_by_source(self):
        edges = self.graph.edges
        self.assertEqual(len(edges[self.host.id]), 1)
        self.assertEqual(edges[self.host.id][0]["target"], self.web.id)
        self.assertEqual(len(edges[self.web.id]), 1)

    def test_node_and_edge_counts(self):
        self.assertEqual(self.graph.node_count(), 3)
        self.assertEqual(self.graph.edge_count(), 2)

    def test_find_paths_to_returns_node_id_chains(self):
        paths = self.graph.find_paths_to(self.db.id, max_depth=4)
        self.assertTrue(paths, "web -> db must be discoverable")
        self.assertEqual(paths[0][-1], self.db.id)
        self.assertIn(self.web.id, paths[0])
        self.assertGreaterEqual(len(paths[0]), 2, "a lone node is not a path")

    def test_find_paths_to_is_shortest_first(self):
        far = self.graph.add_node("service", "internal/9000")
        self.graph.add_edge(self.db.id, far.id, "access")
        paths = self.graph.find_paths_to(far.id, max_depth=6)
        lengths = [len(path) for path in paths]
        self.assertEqual(lengths, sorted(lengths))

    def test_find_paths_to_unknown_node_is_empty(self):
        self.assertEqual(self.graph.find_paths_to("nope"), [])
        self.assertEqual(self.graph.find_paths_to(""), [])

    def test_find_paths_to_respects_max_depth(self):
        # max_depth counts nodes, so 2 admits only the single-hop web -> db.
        self.assertEqual(len(self.graph.find_paths_to(self.db.id, max_depth=2)[0]), 2)
        self.assertEqual(self.graph.find_paths_to(self.db.id, max_depth=1), [])

    def test_find_paths_to_never_returns_the_node_alone(self):
        for node_id in (self.host.id, self.web.id, self.db.id):
            for path in self.graph.find_paths_to(node_id, max_depth=5):
                self.assertGreaterEqual(len(path), 2)

    def test_views_are_read_only_snapshots(self):
        self.graph.nodes["injected"] = {}
        self.assertEqual(self.graph.node_count(), 3, "mutating the view must not touch the graph")


class StrategistIntegrationTests(unittest.TestCase):
    """Regression: the strategist used to raise 'AttackGraph has no nodes'."""

    def _coordinator_with_surface(self):
        from brain.coordinator import SwarmCoordinator

        coordinator = SwarmCoordinator()
        coordinator.set_target("127.0.0.1")
        coordinator.register_port("127.0.0.1", 80, "http", "Apache/2.4", {})
        coordinator.register_port("127.0.0.1", 3306, "mysql", "MySQL 8.0", {})
        coordinator.register_endpoint("127.0.0.1", "/api/v1/login", 200, "Login", True, "POST")
        return coordinator

    def test_strategist_accepts_a_real_coordinator_graph(self):
        from brain.strategist_engine import StrategistEngine

        coordinator = self._coordinator_with_surface()
        rec = StrategistEngine().analyze_attack_graph(
            coordinator.attack_graph, None, coordinator.critic_agent.critic_engine
        )
        self.assertIsNotNone(rec.primary_goal)
        self.assertTrue(rec.primary_goal.goal_type)
        self.assertTrue(rec.primary_goal.target_node_id)
        self.assertGreaterEqual(rec.primary_goal.confidence, 0.0)
        self.assertLessEqual(rec.primary_goal.confidence, 1.0)
        self.assertTrue(rec.attack_chain)

    def test_strategist_surfaces_information_gaps(self):
        from brain.strategist_engine import StrategistEngine

        coordinator = self._coordinator_with_surface()
        rec = StrategistEngine().analyze_attack_graph(coordinator.attack_graph, None, None)
        self.assertTrue(rec.information_gaps)
        for gap in rec.information_gaps:
            self.assertTrue(gap.question)

    def test_strategist_on_empty_graph_does_not_raise(self):
        from brain.attack_graph import AttackGraph
        from brain.strategist_engine import StrategistEngine

        StrategistEngine().analyze_attack_graph(AttackGraph(), None, None)


# ---------------------------------------------------------------------------
# Validation gate: default deny
# ---------------------------------------------------------------------------
def _finding(title, **overrides):
    from execution.native_vuln import VulnerabilityFinding

    base = dict(
        title=title, severity="high", target="http://127.0.0.1:8080",
        endpoint="/api/v1/login", description="d", evidence="root:toor",
        remediation="fix",
    )
    base.update(overrides)
    return VulnerabilityFinding(**base)


class _Response:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class VerifierGateTests(unittest.TestCase):
    def setUp(self):
        from brain.agents.verifier_agent import VerifierAgent

        self.agent = VerifierAgent()

    def test_unsupported_finding_class_is_rejected_by_default(self):
        with mock.patch("brain.agents.verifier_agent.requests.get",
                        return_value=_Response(text="nothing here")):
            confirmed, reason = self.agent._verify_finding(_finding("Reflected XSS"), [])
        self.assertFalse(confirmed)
        self.assertTrue(reason)

    def test_finding_without_a_replayable_target_is_rejected(self):
        confirmed, reason = self.agent._verify_finding(_finding("Exposed .env", target="", endpoint=""), [])
        self.assertFalse(confirmed)
        self.assertIn("no target", reason)

    def test_canary_proof_confirms(self):
        with mock.patch("brain.agents.verifier_agent.requests.get",
                        return_value=_Response(text="welcome CANARY-abc123 ok")):
            confirmed, reason = self.agent._verify_finding(_finding("SQL Injection"), ["CANARY-abc123"])
        self.assertTrue(confirmed)
        self.assertIn("canary", reason.lower())

    def test_canary_in_a_header_also_confirms(self):
        with mock.patch("brain.agents.verifier_agent.requests.get",
                        return_value=_Response(headers={"X-Debug": "CANARY-abc123"})):
            confirmed, _ = self.agent._verify_finding(_finding("LFI"), ["CANARY-abc123"])
        self.assertTrue(confirmed)

    def test_missing_canary_rejects_even_with_a_200(self):
        with mock.patch("brain.agents.verifier_agent.requests.get",
                        return_value=_Response(text="/etc/passwd contents")):
            confirmed, reason = self.agent._verify_finding(_finding("SQL Injection"), ["CANARY-abc123"])
        self.assertFalse(confirmed)
        self.assertIn("canary", reason.lower())

    def test_exposed_file_must_reproduce_its_evidence(self):
        with mock.patch("brain.agents.verifier_agent.requests.get",
                        return_value=_Response(text="DB_HOST=x\nroot:toor\n")):
            confirmed, _ = self.agent._verify_finding(_finding("Exposed .env file"), [])
        self.assertTrue(confirmed)

        with mock.patch("brain.agents.verifier_agent.requests.get",
                        return_value=_Response(text="404 not found")):
            confirmed, reason = self.agent._verify_finding(_finding("Exposed .env file"), [])
        self.assertFalse(confirmed)
        self.assertIn("not present", reason)

    def test_exposed_file_needs_evidence_to_match_against(self):
        with mock.patch("brain.agents.verifier_agent.requests.get",
                        return_value=_Response(text="secrets galore")):
            confirmed, reason = self.agent._verify_finding(_finding("Exposed .env file", evidence=""), [])
        self.assertFalse(confirmed)
        self.assertIn("no evidence snippet", reason)

    def test_cors_requires_the_attacker_origin_to_be_reflected(self):
        responses = [
            _Response(text=""),
            _Response(headers={"Access-Control-Allow-Origin": "https://evil-attacker.example"}),
        ]
        with mock.patch("brain.agents.verifier_agent.requests.get", side_effect=responses):
            confirmed, _ = self.agent._verify_finding(_finding("CORS misconfiguration"), [])
        self.assertTrue(confirmed)

        responses = [_Response(text=""), _Response(headers={"Access-Control-Allow-Origin": "https://app"})]
        with mock.patch("brain.agents.verifier_agent.requests.get", side_effect=responses):
            confirmed, reason = self.agent._verify_finding(_finding("CORS misconfiguration"), [])
        self.assertFalse(confirmed)
        self.assertIn("not reflected", reason)

    def test_missing_header_finding_is_confirmed_when_absent(self):
        with mock.patch("brain.agents.verifier_agent.requests.get",
                        return_value=_Response(headers={"Server": "nginx"})):
            confirmed, reason = self.agent._verify_finding(
                _finding("Missing security header: X-Content-Type-Options"), []
            )
        self.assertTrue(confirmed)
        self.assertIn("absent", reason)

    def test_missing_header_finding_is_rejected_when_present(self):
        with mock.patch("brain.agents.verifier_agent.requests.get",
                        return_value=_Response(headers={"X-Content-Type-Options": "nosniff"})):
            confirmed, _ = self.agent._verify_finding(
                _finding("Missing security header: X-Content-Type-Options"), []
            )
        self.assertFalse(confirmed)

    def test_unreachable_target_is_a_rejection_not_a_crash(self):
        with mock.patch("brain.agents.verifier_agent.requests.get",
                        side_effect=ConnectionError("refused")):
            confirmed, reason = self.agent._verify_finding(_finding("Exposed .env file"), [])
        self.assertFalse(confirmed)
        self.assertIn("replay request failed", reason)

    def test_out_of_scope_replay_is_blocked_before_any_request(self):
        from brain.agents.verifier_agent import VerifierAgent
        from execution.scope_guard import ScopeGuard

        agent = VerifierAgent(scope_guard=ScopeGuard(allowed_targets={"example.com"}, enforce=True))
        with mock.patch("brain.agents.verifier_agent.requests.get") as getter:
            confirmed, reason = agent._verify_finding(
                _finding("Exposed .env file", target="http://10.0.0.9/"), []
            )
        self.assertFalse(confirmed)
        self.assertIn("scope guard", reason)
        getter.assert_not_called()

    def test_run_records_rejections_and_verifies_survivors(self):
        findings = [
            _finding("Exposed .env file"),
            _finding("Reflected XSS"),
        ]
        with mock.patch("brain.agents.verifier_agent.requests.get",
                        return_value=_Response(text="root:toor\n")):
            self.agent.run("127.0.0.1", findings=findings)
        self.assertEqual(len(self.agent.verified_findings), 1)
        self.assertEqual(self.agent.verified_findings[0].title, "Exposed .env file")
        self.assertEqual(len(self.agent.rejections), 1)
        self.assertEqual(self.agent.rejections[0]["title"], "Reflected XSS")


# ---------------------------------------------------------------------------
# Workflow run record
# ---------------------------------------------------------------------------
class WorkflowRunTests(unittest.TestCase):
    def test_duration_is_non_negative(self):
        run = WorkflowRun(target="x")
        run.ended_at = run.started_at + 12.5
        self.assertAlmostEqual(run.duration, 12.5, delta=0.01)

    def test_duration_of_a_running_mission_uses_now(self):
        run = WorkflowRun(target="x")
        self.assertGreaterEqual(run.duration, 0.0)

    def test_to_dict_reports_the_things_worth_reporting(self):
        run = WorkflowRun(target="127.0.0.1", profile="lab", stopped_reason="budget")
        run.decisions.append({"cycle": 1, "action": ACTION_TEST})
        payload = run.to_dict()
        self.assertEqual(payload["profile"], "lab")
        self.assertEqual(payload["stopped_reason"], "budget")
        self.assertEqual(len(payload["decisions"]), 1)
        self.assertIn("duration_seconds", payload)


# ---------------------------------------------------------------------------
# Coordinator loop, offline
# ---------------------------------------------------------------------------
class _StubAgent:
    """Stands in for a fleet agent so the loop can be exercised without a network."""

    def __init__(self, findings=None, discovered=1):
        self.name = "StubAgent"
        self.state = "idle"
        self.findings = list(findings or [])
        self.discovered_count = discovered
        self.ran_with = []
        self.stopped = False

    def run(self, target, **kwargs):
        self.ran_with.append((target, kwargs))

    def stop(self):
        self.stopped = True


class _StubFactory:
    def __init__(self, findings=None):
        self.spawned = []
        self._findings = findings

    def can_spawn(self):
        return True

    def spawn(self, kind):
        agent = _StubAgent(findings=self._findings.get(kind) if self._findings else None)
        self.spawned.append((kind, agent))
        return agent

    def retire(self, agent):
        agent.stop()

    def retire_all(self):
        return 0

    def to_dict(self):
        return {"active": 0, "max_parallel": 4, "retired": []}


def _coordinator(profile, tasks=()):
    from brain.coordinator import SwarmCoordinator

    coordinator = SwarmCoordinator()
    coordinator.apply_profile(profile)

    # Offline: no recon network calls, but the plan still has to close the stage
    # or run_workflow would report MAP as unfinished.
    def _stub_map():
        coordinator.plan.mark(WorkflowStage.MAP, "done", "stubbed (offline)")

    coordinator._stage_map = _stub_map
    for task in tasks:
        coordinator.task_queue.push(task)
    return coordinator


def _with_stub_fleet(findings=None):
    """Patch the factory run_workflow builds so no real agent is spawned."""
    return mock.patch("brain.coordinator.AgentFactory", lambda **kwargs: _StubFactory(findings))


class CoordinatorWorkflowTests(unittest.TestCase):
    def _profile(self, **overrides):
        import engagement as eng

        base = dict(
            name="lab", target="127.0.0.1", targets=["127.0.0.1"], target_type="lab",
            budget=eng.MissionBudget(max_seconds=60, max_commands=50, max_llm_calls=50),
            validation=eng.Validation(canaries=[{"label": "c1", "value": "CANARY-1"}],
                                      require_poc=True, min_severity="low"),
        )
        base.update(overrides)
        return eng.EngagementProfile(**base)

    def test_workflow_runs_every_stage_and_records_a_run(self):
        coordinator = _coordinator(self._profile())
        with _with_stub_fleet():
            run = coordinator.run_workflow(coordinator.profile, target="127.0.0.1", max_cycles=1)

        self.assertEqual(run.target, "127.0.0.1")
        self.assertEqual(run.profile, "lab")
        self.assertTrue(run.stopped_reason)
        for stage in ("learn", "map", "coordinate", "attack", "validate", "debrief"):
            self.assertIn(stage, run.stages_completed, run.stages_completed)
        self.assertEqual(run.cycles, 1)
        self.assertGreater(run.duration, 0.0)
        self.assertFalse(coordinator.is_running, "mission must be released when the loop ends")

    def test_summary_is_available_after_the_run(self):
        coordinator = _coordinator(self._profile())
        with _with_stub_fleet():
            coordinator.run_workflow(coordinator.profile, target="127.0.0.1", max_cycles=1)
        summary = coordinator.get_workflow_summary()
        self.assertTrue(summary["active"])
        self.assertIn("plan", summary)
        self.assertIn("run", summary)
        self.assertEqual(summary["profile"], "lab")

    def test_learn_applies_the_profile_to_the_scope_guard(self):
        coordinator = _coordinator(self._profile())
        with _with_stub_fleet():
            coordinator.run_workflow(coordinator.profile, target="127.0.0.1", max_cycles=1)
        self.assertTrue(coordinator.scope_guard.enforce)
        self.assertTrue(coordinator.scope_guard.is_allowed_host("127.0.0.1"))
        self.assertFalse(coordinator.scope_guard.is_allowed_host("8.8.8.8"))

    def test_declared_endpoints_seed_the_attack_graph(self):
        import engagement as eng

        profile = self._profile(
            attack_surface=eng.AttackSurface(endpoints=["/api/v1/login", "/admin"]),
        )
        coordinator = _coordinator(profile)
        with _with_stub_fleet():
            coordinator.run_workflow(profile, target="127.0.0.1", max_cycles=1)
        labels = [node.label for node in coordinator.attack_graph._nodes.values()]
        self.assertTrue(any("/api/v1/login" in label for label in labels), labels)

    def test_attack_drains_the_task_queue_and_retires_its_agents(self):
        from brain.task_queue import AgentTask

        tasks = [
            AgentTask(priority=1, task_id="t1", task_type="vuln_audit", target="127.0.0.1"),
            AgentTask(priority=2, task_id="t2", task_type="web_fuzz", target="127.0.0.1"),
        ]
        coordinator = _coordinator(self._profile(), tasks=tasks)
        factory = _StubFactory()
        with mock.patch("brain.coordinator.AgentFactory", lambda **kwargs: factory):
            coordinator.run_workflow(coordinator.profile, target="127.0.0.1", max_cycles=1)

        self.assertEqual(coordinator.task_queue.pending_count(), 0)
        self.assertTrue(factory.spawned)
        self.assertTrue(all(agent.stopped for _, agent in factory.spawned),
                        "every spawned agent must be retired after its mission")

    def test_guardrail_blocks_a_repeated_identical_task(self):
        from brain.task_queue import AgentTask
        from brain.workflow import LoopGuard

        coordinator = _coordinator(self._profile())
        coordinator.agent_factory = _StubFactory()
        coordinator.loop_guard = LoopGuard(
            warn_after={EXACT_FAILURE: 1, SAME_TOOL_FAILURE: 1, IDEMPOTENT_NO_PROGRESS: 1},
            hard_stop_after={EXACT_FAILURE: 1, SAME_TOOL_FAILURE: 99, IDEMPOTENT_NO_PROGRESS: 99},
            hard_stop_enabled=True,
        )
        # The identical task has already failed once, so the pre-flight query
        # must refuse to run it again.
        coordinator.loop_guard.record("vuln_audit", {"target": "127.0.0.1", "params": {}},
                                      succeeded=False)
        coordinator.task_queue.push(
            AgentTask(priority=1, task_id="t1", task_type="vuln_audit", target="127.0.0.1")
        )
        coordinator.plan = __import__("brain.workflow", fromlist=["MissionPlan"]).MissionPlan(
            target="127.0.0.1"
        )
        coordinator._current_decision = None
        coordinator._stage_attack(1)

        # Nothing ran, and the task was recorded as a failure. It stays queued
        # for retry because mark_failed re-pushes below max_retries.
        self.assertEqual(coordinator.agent_factory.spawned, [], "no agent may run a blocked task")
        task = coordinator.task_queue._tasks["t1"]
        self.assertEqual(task.retries, 1)
        self.assertIn("hard stop", task.error)
        messages = " | ".join(entry["message"] for entry in coordinator.logs)
        self.assertIn("guardrail", messages.lower(),
                      "the block must be reported in the coordinator log")

    def test_budget_exhaustion_stops_the_loop_immediately(self):
        import engagement as eng

        profile = self._profile(budget=eng.MissionBudget(max_seconds=1, max_commands=1, max_llm_calls=1))
        coordinator = _coordinator(profile)

        def already_spent(**kwargs):
            state = BudgetState(**kwargs)
            state.started_at = time.time() - 10_000  # clock already past the ceiling
            return state

        with _with_stub_fleet(), mock.patch("brain.coordinator.BudgetState", already_spent):
            run = coordinator.run_workflow(profile, target="127.0.0.1", max_cycles=10)
        self.assertIn("budget", run.stopped_reason.lower())
        self.assertLess(run.cycles, 10)

    def test_stalled_progress_triggers_early_stop(self):
        import engagement as eng

        profile = self._profile(
            budget=eng.MissionBudget(
                max_seconds=600, max_commands=500, max_llm_calls=500, early_stop_stalls=1
            ),
        )
        coordinator = _coordinator(profile, tasks=[])
        # Nothing ever progresses: no ports, no endpoints, no findings.
        with _with_stub_fleet():
            run = coordinator.run_workflow(profile, target="127.0.0.1", max_cycles=10)
        self.assertLess(run.cycles, 10, "an unproductive loop must stop before max_cycles")
        self.assertIn("early stop", run.stopped_reason.lower())
        self.assertEqual(run.stalls, 1)

    def test_validate_passes_profile_canaries_to_the_verifier(self):
        from execution.native_vuln import VulnerabilityFinding

        finding = VulnerabilityFinding(
            title="Exposed .env file", severity="high", target="http://127.0.0.1",
            endpoint="/.env", description="d", evidence="root:toor", remediation="fix",
            confirmed=False,
        )
        coordinator = _coordinator(self._profile())
        coordinator.agent_factory = _StubFactory()
        coordinator.raw_findings.append(finding)
        coordinator._stage_validate(1)

        verify_calls = [agent for kind, agent in coordinator.agent_factory.spawned if kind == "verify"]
        self.assertEqual(len(verify_calls), 1)
        self.assertEqual(verify_calls[0].ran_with[0][1]["canaries"], ["CANARY-1"])

    def test_validate_is_skipped_with_no_candidate_findings(self):
        coordinator = _coordinator(self._profile())
        coordinator.agent_factory = _StubFactory()
        coordinator.plan = MissionPlan(target="127.0.0.1")
        coordinator._stage_validate(1)
        self.assertEqual(coordinator.plan.phase(WorkflowStage.VALIDATE).status, "skipped")
        self.assertEqual(coordinator.agent_factory.spawned, [])

    def test_debrief_penalises_unverified_and_rewards_verified(self):
        from execution.native_vuln import VulnerabilityFinding

        coordinator = _coordinator(self._profile())
        coordinator.agent_factory = _StubFactory()
        coordinator.plan = MissionPlan(target="127.0.0.1")
        unverified = VulnerabilityFinding(
            title="SQLi", severity="high", target="127.0.0.1", endpoint="/x",
            description="d", evidence="e", remediation="r", confirmed=False,
        )
        coordinator.raw_findings.append(unverified)
        coordinator._stage_debrief()
        self.assertEqual(coordinator.plan.phase(WorkflowStage.DEBRIEF).status, "done")

    def test_workflow_event_is_published(self):
        coordinator = _coordinator(self._profile())
        coordinator.agent_factory = _StubFactory()
        coordinator.run_workflow(coordinator.profile, target="127.0.0.1", max_cycles=1)
        types = {event.event_type for event in coordinator.events}
        self.assertIn("workflow_completed", types)
        payload = [e.data for e in coordinator.events if e.event_type == "workflow_completed"][0]
        self.assertEqual(payload["target"], "127.0.0.1")

    def test_exploit_decision_restricts_the_drain_to_exploitation_tasks(self):
        from brain.task_queue import AgentTask
        from brain.workflow import ConfidenceDecision

        coordinator = _coordinator(self._profile(), tasks=[
            AgentTask(priority=3, task_id="fuzz", task_type="web_fuzz", target="127.0.0.1"),
            AgentTask(priority=1, task_id="audit", task_type="vuln_audit", target="127.0.0.1"),
        ])
        coordinator.agent_factory = _StubFactory()
        coordinator.plan = MissionPlan(target="127.0.0.1")
        coordinator._current_decision = ConfidenceDecision(ACTION_EXPLOIT, 0.9, "high confidence")
        coordinator._stage_attack(1)

        kinds = [kind for kind, _ in coordinator.agent_factory.spawned]
        self.assertIn("vuln", kinds)
        self.assertNotIn("web", kinds, "at exploit confidence discovery must be skipped")
        self.assertEqual(coordinator.task_queue.pending_count(), 1, "the fuzz task stays queued")

    def test_checkpoint_fires_once_per_budget_threshold(self):
        import engagement as eng

        profile = self._profile(
            budget=eng.MissionBudget(max_seconds=10, max_commands=10, max_llm_calls=10,
                                     checkpoints=[20, 40]),
        )
        coordinator = _coordinator(profile)
        coordinator.agent_factory = _StubFactory()
        coordinator.plan = MissionPlan(target="127.0.0.1")
        coordinator.budget_state = BudgetState(max_seconds=10, max_commands=10, max_llm_calls=10)
        coordinator.budget_state.spend(commands=5)  # 50 % — past both checkpoints

        # One review per cycle: at 50 % both thresholds are crossed, but they are
        # consumed one cycle at a time so the reviews stay spread out.
        coordinator._stage_coordinate(1)
        self.assertEqual(sorted(coordinator._consumed_checkpoints), [20])
        self.assertEqual(len(coordinator.plan.checkpoint_reviews), 1)

        coordinator._stage_coordinate(2)
        self.assertEqual(sorted(coordinator._consumed_checkpoints), [20, 40])
        self.assertEqual(len(coordinator.plan.checkpoint_reviews), 2)

        # Nothing left to consume — a third cycle must not re-fire anything.
        coordinator._stage_coordinate(3)
        self.assertEqual(len(coordinator.plan.checkpoint_reviews), 2)


if __name__ == "__main__":
    unittest.main()
