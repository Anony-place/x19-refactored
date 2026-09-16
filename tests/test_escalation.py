"""Frontier escalation + usage accounting.

Verifies: chain parsing, hard-step detection from live state, gate-respecting
escalation (critical-tier model blocked on unauthorized exploitation),
cooldown, providers.build_backend delegation, session usage accounting, and
ribbon wiring.
"""

from __future__ import annotations

import os
import unittest
from types import SimpleNamespace
from unittest import mock

import brain.escalation as esc
from brain.escalation import Escalator, escalation_chain, hard_reasons
from brain.hypothesis_engine import MultiHypothesisEngine
from providers import build_backend


class ChainParsingTests(unittest.TestCase):
    def tearDown(self):
        os.environ.pop("X19_ESCALATE", None)

    def test_empty_env_disabled(self):
        os.environ.pop("X19_ESCALATE", None)
        self.assertEqual(escalation_chain(), [])

    def test_parse_pairs_and_skip_garbage(self):
        os.environ["X19_ESCALATE"] = " openai/gpt-5.6 , groq , anthropic/claude-x ,,"
        chain = escalation_chain()
        self.assertEqual(chain, [("openai", "gpt-5.6"),
                                 ("anthropic", "claude-x")])


def _agent(**kw):
    """Bare agent with every signal hard_reasons/pick may read."""
    a = SimpleNamespace()
    a.ai = SimpleNamespace(name=lambda: "fake/mini", model="mini")
    a.target_type = kw.get("target_type", "public_real_world")
    a._current_focus_finding = kw.get("focus", None)
    a._exploit_depth = kw.get("depth", 0)
    a._ai_empty_streak = kw.get("flail", 0)
    a._no_progress_streak = kw.get("stuck", 0)
    a.hyp_engine = kw.get("hyp_engine", MultiHypothesisEngine())
    return a


class HardReasonsTests(unittest.TestCase):
    def test_silent_when_no_signals(self):
        self.assertEqual(hard_reasons(_agent()), [])

    def test_deep_dive_focus_finding(self):
        out = hard_reasons(_agent(focus="RCE via template", depth=3))
        self.assertTrue(any("deep-dive" in r for r in out))

    def test_depth_below_threshold_not_hard(self):
        self.assertEqual(hard_reasons(_agent(focus="RCE", depth=1)), [])

    def test_flail_and_stuck_streaks(self):
        self.assertTrue(any("flailing" in r for r in hard_reasons(_agent(flail=3))))
        self.assertTrue(any("no progress" in r for r in hard_reasons(_agent(stuck=4))))

    def test_high_impact_hypothesis(self):
        eng = MultiHypothesisEngine()
        eng.apply_actions([{"action": "add", "statement": "unauth admin via jwt confusion",
                            "impact": 0.9}])
        out = hard_reasons(_agent(hyp_engine=eng))
        self.assertTrue(any("high-impact hypothesis" in r for r in out))


class PickTests(unittest.TestCase):
    def tearDown(self):
        for var in ("X19_ESCALATE", "X19_ESCALATE_EVERY"):
            os.environ.pop(var, None)
        esc.escalation_chain.__globals__  # no-op; env read fresh per instance

    def test_no_chain_falls_back(self):
        os.environ.pop("X19_ESCALATE", None)
        agent = _agent(focus="RCE", depth=9)
        escator = Escalator()
        ai, reason = escator.pick(agent)
        self.assertIs(ai, agent.ai)
        self.assertEqual(reason, "")

    def test_escalates_on_hard_step_within_cooldown_window(self):
        os.environ["X19_ESCALATE"] = "fake/big-model"
        os.environ["X19_ESCALATE_EVERY"] = "1"
        agent = _agent(focus="RCE", depth=3, target_type="lab")
        escator = Escalator()
        big = SimpleNamespace(name=lambda: "fake/big-model", model="big-model")
        with mock.patch.object(escator, "_backend_for", return_value=big) as mb:
            ai, reason = escator.pick(agent)
        self.assertIs(ai, big)
        self.assertIn("deep-dive", reason)
        self.assertEqual(mb.call_args[0], ("fake", "big-model"))
        self.assertEqual(escator.escalations, 1)

    def test_cooldown_blocks_before_window(self):
        os.environ["X19_ESCALATE"] = "fake/big-model"
        os.environ["X19_ESCALATE_EVERY"] = "4"
        agent = _agent(focus="RCE", depth=9, target_type="lab")
        escator = Escalator()
        with mock.patch.object(escator, "_backend_for") as mb:
            ai, reason = escator.pick(agent)
        self.assertIs(ai, agent.ai)   # first cycle only warms the counter
        self.assertEqual(reason, "")
        mb.assert_not_called()

    def test_gate_blocks_critical_tier_on_unauthorized_exploitation(self):
        os.environ["X19_ESCALATE"] = "openai/gpt-6-astra"
        os.environ["X19_ESCALATE_EVERY"] = "1"
        # focus finding active -> phase "exploitation"; public_real_world is
        # NOT an authorized classification -> gate must refuse.
        agent = _agent(focus="RCE", depth=3, target_type="public_real_world")
        escator = Escalator()
        with mock.patch("providers.build_backend") as bb:
            ai, reason = escator.pick(agent)
        self.assertIs(ai, agent.ai)
        self.assertEqual(reason, "")
        bb.assert_not_called()

    def test_standard_tier_not_gated(self):
        os.environ["X19_ESCALATE"] = "openai/gpt-5.6"
        os.environ["X19_ESCALATE_EVERY"] = "1"
        agent = _agent(focus="RCE", depth=3, target_type="public_real_world")
        escator = Escalator()
        big = SimpleNamespace(name=lambda: "x", model="gpt-5.6")
        with mock.patch.object(escator, "_backend_for", return_value=big):
            ai, reason = escator.pick(agent)
        self.assertIs(ai, big)


class BuildBackendTests(unittest.TestCase):
    def test_unknown_provider_records_error(self):
        errors = {}
        self.assertIsNone(build_backend("nope", "m", errors))
        self.assertIn(("nope", "m"), errors)

    def test_needs_key_without_key_records_error(self):
        with mock.patch("providers._get_key_for", return_value=""):
            errors = {}
            self.assertIsNone(build_backend("openrouter", "m", errors))
            self.assertEqual(errors[("openrouter", "m")], "no API key")


class UsageAndWiringTests(unittest.TestCase):
    def test_usage_tick_accumulates(self):
        from agent import X19
        agent = X19.__new__(X19)
        agent.session = SimpleNamespace(data={})
        agent._usage_tick(1000, 200, 1.5)
        agent._usage_tick(500, 100, 0.5, escalated=True)
        u = agent.session.data["usage"]
        self.assertEqual(u["calls"], 2)
        self.assertEqual(u["chars_in"], 1500)
        self.assertEqual(u["chars_out"], 300)
        self.assertAlmostEqual(u["secs"], 2.0)
        self.assertEqual(u["escalations"], 1)

    def test_agent_decision_call_uses_wrapper(self):
        with open("agent.py") as fh:
            src = fh.read()
        self.assertIn("response = self._decision_chat(ctx)", src)
        self.assertIn("self._escalator = Escalator()", src)
        self.assertIn("def _decision_chat(self, ctx: str) -> str:", src)

    def test_ribbon_shows_usage(self):
        with open("ui/app.py") as fh:
            src = fh.read()
        self.assertIn("X19_PRICE_PER_MTOK", src)
        self.assertIn("escalated", src)
        self.assertIn("~{toks // 1000}k tok", src)


if __name__ == "__main__":
    unittest.main()


class DecisionChatFailureTests(unittest.TestCase):
    """A raising provider must keep its real error and still get accounted."""

    def test_chat_exception_preserved_and_counted(self):
        from agent import X19

        class BoomAI:
            def name(self):
                return "fake/boom"

            def chat(self, prompt, ctx):
                raise RuntimeError("provider exploded")

        agent = X19.__new__(X19)
        agent.ai = BoomAI()
        agent.session = SimpleNamespace(data={})
        agent._escalator = Escalator()   # no chain -> falls back to agent.ai
        agent._escalator.chain = []
        with self.assertRaises(RuntimeError) as ctx:
            agent._decision_chat("ctx")
        self.assertEqual(str(ctx.exception), "provider exploded",
                         "the real provider error must not be masked")
        usage = agent.session.data["usage"]
        self.assertEqual(usage["calls"], 1, "failed calls count as attempts")
        self.assertEqual(usage["chars_out"], 0)
