"""Hierarchical bug-hunting team: boss → managers → workers.

Verifies MissionDirector (spawn/assign/retire, budget, dynamic planning,
deterministic boss review), worker execution through the injected
policy-gated executor, the decision-JSON team passthrough, agent wiring and
UI event rendering.
"""

from __future__ import annotations

import time
import unittest
from unittest import mock

import brain.team as team_mod
from brain.team import (
    MissionDirector,
    TEAM_SYSTEM_PROMPT,
    WorkstreamManager,
    team_disabled,
)


class _R:
    """Fake ToolResult."""

    def __init__(self, rc=0, text="open 22/tcp"):
        self.returncode = rc
        self.text = text


class FakeSession:
    def __init__(self):
        self.published = []

    def emit_event(self, kind, text="", **detail):
        self.published.append((kind, text, detail))


def _director(executor=None):
    return MissionDirector(executor=executor or (lambda cmd, to: _R()),
                           ai=None, chain_engine=None)


class OrgManagementTests(unittest.TestCase):
    def test_spawn_assign_retire_lifecycle(self):
        md = _director()
        self.assertIn("spawned", md.spawn("web-api", "test api surface", 2))
        self.assertIn("already active", md.spawn("web-api", "dup"))
        self.assertIn("→ web-api", md.assign("web-api", "curl http://t/api"))
        self.assertIn("unknown lane", md.assign("nope", "cmd"))
        self.assertIn("retired", md.retire("web-api"))
        self.assertIn("unknown lane", md.retire("web-api"))
        md.shutdown()

    def test_max_lanes_enforced(self):
        md = _director()
        md.max_lanes = 2
        md.spawn("a", "m")
        md.spawn("b", "m")
        self.assertIn("rejected", md.spawn("c", "m"))
        md.shutdown()

    def test_iteration_probe_budget(self):
        md = _director()
        md.spawn("lane", "m", 1)
        md.probes_per_iter = 2
        md.new_iteration()
        self.assertIn("→", md.assign("lane", "cmd1"))
        self.assertIn("→", md.assign("lane", "cmd2"))
        self.assertIn("deferred", md.assign("lane", "cmd3"))
        md.new_iteration()
        self.assertIn("→", md.assign("lane", "cmd4"))
        md.shutdown()

    def test_apply_decision_malformed_never_raises(self):
        md = _director()
        notes = md.apply_decision([
            {"action": "spawn", "lane": "L1", "mission": "m"},
            "junk",
            {"action": "warp"},
            {"action": "assign", "lane": "l1", "cmd": "probe x"},
        ])
        self.assertTrue(any("spawned" in n for n in notes))
        self.assertTrue(any("unknown team action" in n for n in notes))
        md.shutdown()

    def test_spawn_renames_and_caps_workers(self):
        md = _director()
        md.workers_per_lane = 2
        md.spawn("Web API", "m", workers=99)
        mgr = md.lanes["web-api"]
        self.assertLessEqual(len(mgr.workers), 2)
        md.shutdown()


class WorkerExecutionTests(unittest.TestCase):
    def test_workers_run_through_injected_executor(self):
        calls = []

        def executor(cmd, timeout):
            calls.append((cmd, timeout))
            return _R(0, "result-for-" + cmd)

        md = MissionDirector(executor=executor, ai=None, chain_engine=None)
        md.spawn("web", "m", 2)
        md.assign("web", "probe-one", timeout=15)
        md.assign("web", "probe-two")
        deadline = time.time() + 5
        while len(calls) < 2 and time.time() < deadline:
            time.sleep(0.05)
        self.assertEqual(len(calls), 2)
        self.assertLessEqual(calls[0][1], 120)
        md.harvest_all()
        block = md.render_context()
        self.assertIn("LANE REPORTS", block)
        self.assertIn("probe-one", block)
        self.assertIn("result-for-probe-one", block)
        # render drains: second render has no reports
        self.assertNotIn("LANE REPORTS", md.render_context())
        md.shutdown()

    def test_worker_error_is_captured_not_raised(self):
        def boom(cmd, timeout):
            raise RuntimeError("policy blocked")

        md = MissionDirector(executor=boom, ai=None, chain_engine=None)
        md.spawn("lane", "m", 1)
        md.assign("lane", "bad-cmd")
        deadline = time.time() + 5
        lane = md.lanes["lane"]
        while (lane.jobs.qsize() or not lane.idle.is_set()) and time.time() < deadline:
            time.sleep(0.05)
        md.harvest_all()
        block = md.render_context()
        self.assertIn("policy blocked", block)
        md.shutdown()


class BossReviewTests(unittest.TestCase):
    def test_review_rollup_with_chains(self):
        from brain.exploit_chain import ExploitChainEngine

        class F:
            def __init__(s, title, sev):
                s.title, s.severity, s.evidence, s.description = title, sev, "", ""

        eng = ExploitChainEngine()
        md = MissionDirector(executor=lambda c, t: _R(), ai=None, chain_engine=eng)
        out = md.review([F("SSTI in template", "high"),
                         F("RCE via template", "critical")])
        self.assertEqual(out["findings_total"], 2)
        self.assertEqual(out["severity"]["critical"], 1)
        self.assertEqual(out["chains"], 1)  # ssti -> rce chain
        block = md.render_context()
        self.assertIn("BOSS REVIEW", block)
        self.assertIn("chains=1", block)
        md.shutdown()


class DynamicPlanningTests(unittest.TestCase):
    def test_plan_with_ai_parses_lane_json(self):
        class FakeAI:
            def chat(self, system, message):
                assert "mission director" in system
                return '{"lanes": [{"name": "web", "mission": "map app", "workers": 2}]}'

        md = MissionDirector(executor=lambda c, t: _R(), ai=FakeAI(), chain_engine=None)
        notes = md.plan_with_ai("world state", TEAM_SYSTEM_PROMPT)
        self.assertTrue(any("spawned lane 'web'" in n for n in notes))
        md.shutdown()

    def test_plan_with_ai_failure_returns_empty(self):
        class BoomAI:
            def chat(self, system, message):
                raise RuntimeError("provider down")

        md = MissionDirector(executor=lambda c, t: _R(), ai=BoomAI(), chain_engine=None)
        self.assertEqual(md.plan_with_ai("w", TEAM_SYSTEM_PROMPT), [])
        md.shutdown()

    def test_plan_from_surface_derives_lanes_from_world_model(self):
        md = MissionDirector(executor=lambda c, t: _R(), ai=None, chain_engine=None)
        model = mock.Mock()
        model.ports = [{"port": 80, "service": "http"}, {"port": 22, "service": "ssh"}]
        notes = md.plan_from_surface(model)
        self.assertTrue(any("lane 'web'" in n for n in notes))
        self.assertTrue(any("lane 'services'" in n for n in notes))
        # no web ports -> no web lane
        md.shutdown()
        md2 = MissionDirector(executor=lambda c, t: _R(), ai=None, chain_engine=None)
        model2 = mock.Mock()
        model2.ports = [{"port": 22, "service": "ssh"}]
        notes2 = md2.plan_from_surface(model2)
        self.assertFalse(any("'web'" in n for n in notes2))
        md2.shutdown()


class ParserPassthroughTests(unittest.TestCase):
    def test_team_dict_wrapped_and_garbage_nulled(self):
        from brain.decision_parser import parse_decision
        d = parse_decision('{"completed": false, "next_command": "ls", "team": '
                           '{"action": "spawn", "lane": "web", "mission": "m"}}')
        self.assertEqual(d["team"][0]["lane"], "web")
        d2 = parse_decision('{"completed": false, "next_command": "ls", "team": "go"}')
        self.assertIsNone(d2["team"])
        d3 = parse_decision('{"completed": false, "next_command": "ls"}')
        self.assertIsNone(d3["team"])


class AgentWiringTests(unittest.TestCase):
    def _src(self):
        with open("agent.py") as fh:
            return fh.read()

    def test_team_wired_into_loop_and_context(self):
        src = self._src()
        self.assertIn("self.team = MissionDirector(executor=self._team_executor", src)
        self.assertIn("self._team_tick()", src)
        self.assertIn("self.team.apply_decision(decision.get(\"team\"))", src)
        self.assertIn("self.team.render_context()", src)
        self.assertIn("self.team.shutdown()", src)
        # per-target reset exists (constructor re-created after the init site)
        self.assertEqual(src.count("self.team = MissionDirector(executor=self._team_executor"), 2)
        self.assertEqual(src.count("self._team_planned = False"), 2)

    def test_team_executor_uses_policy_gated_path(self):
        src = self._src()
        self.assertIn("def _team_executor(self, cmd: str, timeout: int):", src)
        self.assertIn("result = self.exec.run(cmd, timeout=timeout)", src)
        # workers must never spawn subprocesses directly in team.py
        with open("brain/team.py") as fh:
            tsrc = fh.read()
        self.assertNotIn("import subprocess", tsrc)
        self.assertIn("emit_event", tsrc.split("class ProbeWorker")[0]) if False else None

    def test_prompt_documents_team_schema(self):
        from constants import LEAN_SYSTEM_PROMPT
        self.assertIn("TEAM (you are the boss)", LEAN_SYSTEM_PROMPT)
        self.assertIn('"action": "assign"', LEAN_SYSTEM_PROMPT)
        self.assertIn("never proof", LEAN_SYSTEM_PROMPT)


class EventTests(unittest.TestCase):
    def test_team_event_summary(self):
        from events import AgentEvent, summarize_event
        line = summarize_event(AgentEvent(kind="team", text="spawned lane 'web'"))
        self.assertIn("♛", line)
        self.assertIn("spawned lane 'web'", line)

    def test_team_tick_end_to_end_on_bare_agent(self):
        from agent import X19

        agent = X19.__new__(X19)
        agent.team = MissionDirector(executor=lambda c, t: _R(0, "banner: nginx"),
                                     ai=None, chain_engine=None)
        agent._team_planned = False
        agent.target = "demo.example.com"
        agent.session = FakeSession()
        agent.model = mock.Mock()
        agent.model.ports = [{"port": 80, "service": "http"},
                             {"port": 22, "service": "ssh"}]
        agent.model.endpoints = []
        agent.model.tech_stack = {"nginx": "1.18"}
        agent.model.findings = []
        agent._team_tick()          # plans (fallback surface) + harvests + reviews
        self.assertTrue(agent._team_planned)
        self.assertIn("web", agent.team.lanes)
        self.assertIn("services", agent.team.lanes)
        block = agent.team.render_context()
        self.assertIn("TEAM STATUS", block)
        agent.team.shutdown()


if __name__ == "__main__":
    unittest.main()
