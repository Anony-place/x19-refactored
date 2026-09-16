"""Parallel research trajectories: pre-registered hypotheses auto-dispatched
to team workers (Naptime sampling strategy on the ledger).

Verifies dispatch (pre-registration required, dedupe, budget interplay,
disable knobs), evaluation (pre-registered evidence auto-confirms; misses
surface to the boss model; short evidence needs word-boundary match), and
loop wiring.
"""

from __future__ import annotations

import time
import unittest
from unittest import mock

import brain.team as team_mod
from agent import X19
from brain.hypothesis_engine import HYP_CONFIRMED, HYP_NEW, HYP_TESTING
from brain.team import MissionDirector
from brain.team import trajectories_per_iter


class _R:
    def __init__(self, text=""):
        self.returncode = 0
        self.text = text


class FakeSession:
    def __init__(self):
        self.published = []

    def emit_event(self, kind, text="", **detail):
        self.published.append((kind, text, detail))


def _trajectory_agent(executor_text="rendered: 49"):
    """Bare agent wired for trajectory dispatch/evaluation."""
    agent = X19.__new__(X19)
    agent.hyp_engine = __import__("brain.hypothesis_engine", fromlist=["MultiHypothesisEngine"]).MultiHypothesisEngine()
    agent.team = MissionDirector(executor=lambda c, t: _R(executor_text),
                                 ai=None, chain_engine=None)
    agent._trajectory_dispatched = set()
    agent._trajectory_map = {}
    agent.session = FakeSession()
    return agent


def _ssti_hyp(agent, command="curl 'http://t/?q={{7*7}}'",
              evidence=("49",)):
    agent.hyp_engine.apply_actions([{
        "action": "add", "statement": "SSTI in search param",
        "command": command, "expected_evidence": list(evidence),
        "impact": 0.9,
    }])
    return agent.hyp_engine.find_hypothesis("SSTI")


class DispatchTests(unittest.TestCase):
    def tearDown(self):
        for agent_mock in ():
            pass
        import os
        for var in ("X19_TEAM_TRAJECTORIES", "X19_TEAM_DISABLE"):
            os.environ.pop(var, None)

    def test_preregistered_hypothesis_dispatched_and_marked_testing(self):
        agent = _trajectory_agent()
        hyp = _ssti_hyp(agent)
        self.assertEqual(hyp.state, HYP_NEW)
        agent._dispatch_parallel_trajectories()
        self.assertIn(hyp.id, agent._trajectory_map.values())
        self.assertEqual(hyp.state, HYP_TESTING)
        agent.team.shutdown()

    def test_missing_preregistration_skipped(self):
        agent = _trajectory_agent()
        agent.hyp_engine.apply_actions([
            {"action": "add", "statement": "no probe registered", "command": "curl x"},
            {"action": "add", "statement": "no evidence registered",
             "command": "curl y", "expected_evidence": ["sig"]},
        ])
        # first has no expected_evidence, second HAS both — wait: both have commands,
        # first lacks evidence, second has evidence -> only second dispatches.
        no_ev = agent.hyp_engine.find_hypothesis("no probe registered")
        with_ev = agent.hyp_engine.find_hypothesis("no evidence registered")
        agent._dispatch_parallel_trajectories()
        self.assertNotIn(no_ev.id, agent._trajectory_map.values())
        self.assertIn(with_ev.id, agent._trajectory_map.values())
        agent.team.shutdown()

    def test_dedupe_across_iterations(self):
        agent = _trajectory_agent()
        hyp = _ssti_hyp(agent)
        agent._dispatch_parallel_trajectories()
        n1 = len(agent._trajectory_dispatched)
        agent._dispatch_parallel_trajectories()
        self.assertEqual(len(agent._trajectory_dispatched), n1)
        agent.team.shutdown()

    def test_budget_deferral_stops_dispatch(self):
        agent = _trajectory_agent()
        agent.team.spawn("web", "m", 1)
        agent.team.probes_per_iter = 1
        agent.team.new_iteration()
        # burn the budget with a direct boss assign
        agent.team.assign("web", "boss-probe")
        hyp = _ssti_hyp(agent)
        agent._dispatch_parallel_trajectories()
        self.assertEqual(len(agent._trajectory_dispatched), 0,
                         "shared budget must gate trajectories too")
        agent.team.shutdown()

    def test_env_zero_disables(self):
        import os
        os.environ["X19_TEAM_TRAJECTORIES"] = "0"
        try:
            self.assertEqual(trajectories_per_iter(), 0)
            agent = _trajectory_agent()
            _ssti_hyp(agent)
            agent._dispatch_parallel_trajectories()
            self.assertEqual(agent._trajectory_dispatched, set())
            agent.team.shutdown()
        finally:
            os.environ.pop("X19_TEAM_TRAJECTORIES", None)

    def test_team_disabled_stops_dispatch(self):
        import os
        os.environ["X19_TEAM_DISABLE"] = "1"
        try:
            agent = _trajectory_agent()
            _ssti_hyp(agent)
            agent._dispatch_parallel_trajectories()
            self.assertEqual(agent.team.lanes, {})
            agent.team.shutdown()
        finally:
            os.environ.pop("X19_TEAM_DISABLE", None)


class EvaluationTests(unittest.TestCase):
    def test_expected_evidence_autoconfirms(self):
        agent = _trajectory_agent(executor_text="page renders: 49 ok")
        hyp = _ssti_hyp(agent)
        agent._dispatch_parallel_trajectories()
        time.sleep(1.0)
        agent.team.harvest_all()
        agent._evaluate_trajectories(agent.team.pending_reports())
        self.assertEqual(hyp.state, HYP_CONFIRMED)
        agent.team.shutdown()

    def test_miss_leaves_testing_and_notes_boss(self):
        agent = _trajectory_agent(executor_text="404 not found")
        hyp = _ssti_hyp(agent)
        agent._dispatch_parallel_trajectories()
        time.sleep(1.0)
        agent.team.harvest_all()
        agent._evaluate_trajectories(agent.team.pending_reports())
        self.assertEqual(hyp.state, HYP_TESTING)
        self.assertTrue(any("expected evidence not observed" in n
                            for n in agent.team.notes))
        agent.team.shutdown()

    def test_short_evidence_requires_word_boundary(self):
        # evidence "49" must NOT match "1492" but must match "sum: 49"
        agent = _trajectory_agent(executor_text="total is 1492 bytes")
        hyp = _ssti_hyp(agent, evidence=("49",))
        agent._dispatch_parallel_trajectories()
        time.sleep(1.0)
        agent.team.harvest_all()
        agent._evaluate_trajectories(agent.team.pending_reports())
        self.assertEqual(hyp.state, HYP_TESTING,
                         "substring of a larger number must not confirm")
        agent.team.shutdown()
        agent2 = _trajectory_agent(executor_text="rendered sum: 49 done")
        hyp2 = _ssti_hyp(agent2, evidence=("49",))
        agent2._dispatch_parallel_trajectories()
        time.sleep(1.0)
        agent2.team.harvest_all()
        agent2._evaluate_trajectories(agent2.team.pending_reports())
        self.assertEqual(hyp2.state, HYP_CONFIRMED)
        agent2.team.shutdown()

    def test_unknown_report_cmds_ignored(self):
        agent = _trajectory_agent()
        agent.team.spawn("other", "m", 1)
        agent.team.assign("other", "unrelated-probe")
        time.sleep(0.8)
        agent.team.harvest_all()
        agent._evaluate_trajectories(agent.team.pending_reports())
        self.assertFalse(any("trajectory for" in n for n in agent.team.notes),
                         "unrelated reports must not create trajectory notes")
        agent.team.shutdown()


class WiringTests(unittest.TestCase):
    def _src(self):
        with open("agent.py") as fh:
            return fh.read()

    def test_tick_calls_dispatch_and_evaluate(self):
        src = self._src()
        self.assertIn("self._dispatch_parallel_trajectories()", src)
        self.assertIn("self._evaluate_trajectories(self.team.pending_reports())", src)
        # init (annotated) + per-target reset both re-create trajectory state
        self.assertIn("self._trajectory_dispatched: set = set()", src)
        self.assertIn("self._trajectory_dispatched = set()", src)
        self.assertIn("self._trajectory_map: dict = {}", src)   # init form
        self.assertIn("self._trajectory_map = {}", src)          # reset form

    def test_prompt_documents_trajectory_contract(self):
        from constants import LEAN_SYSTEM_PROMPT
        self.assertIn("PARALLEL TRAJECTORIES", LEAN_SYSTEM_PROMPT)
        self.assertIn("auto-confirms", LEAN_SYSTEM_PROMPT)

    def test_pending_reports_does_not_drain(self):
        md = MissionDirector(executor=lambda c, t: _R("out"), ai=None, chain_engine=None)
        md.spawn("l", "m", 1)
        md.assign("l", "probe")
        time.sleep(0.8)
        md.harvest_all()
        self.assertEqual(len(md.pending_reports()), 1)
        self.assertEqual(len(md.pending_reports()), 1, "peek must not drain")
        md.shutdown()


if __name__ == "__main__":
    unittest.main()
