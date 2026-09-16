"""Dynamic-reasoning layer: model-owned hypotheses, dynamic prose parsing,
adversarial finding review.

Covers the Naptime-style research ledger (brain/hypothesis_engine), the
hypotheses field in the decision schema (brain/decision_parser), the
tool-agnostic prose extractor, and the XBOW-style hostile second reviewer
(brain/finding_review) — plus agent.py wiring so regressions get caught.
"""

from __future__ import annotations

import unittest

from brain.decision_parser import (
    _extract_prose_command,
    _looks_like_shell_command,
    parse_decision,
)
from brain.finding_review import adversarial_review, parse_review
from brain.hypothesis_engine import (
    HYP_CONFIRMED,
    HYP_NEW,
    HYP_REJECTED,
    HYP_TESTING,
    MultiHypothesisEngine,
)


class HypothesisLedgerTests(unittest.TestCase):
    def setUp(self):
        self.eng = MultiHypothesisEngine()

    def test_add_and_dedupe(self):
        notes = self.eng.apply_actions([
            {"action": "add", "statement": "SSTI in search param",
             "command": "curl 'http://t/?q={{7*7}}'", "expected_evidence": ["49"]},
            {"action": "add", "statement": "SSTI in search param"},  # dup
            "junk",                                                   # skipped
            {"action": "add"},                                        # no statement
        ])
        self.assertEqual(len([n for n in notes if n.startswith("new")]), 1)
        self.assertTrue(any("duplicate" in n for n in notes))

    def test_lifecycle_confirm_and_reject(self):
        self.eng.apply_actions([{"action": "add", "statement": "redis unauth"}])
        self.eng.apply_actions([{"action": "test", "statement": "redis unauth"}])
        hyp = self.eng.find_hypothesis("redis unauth")
        self.assertEqual(hyp.state, HYP_TESTING)
        self.eng.apply_actions([{"action": "confirm", "statement": "redis",
                                 "evidence": ["INFO output"]}])
        self.assertEqual(hyp.state, HYP_CONFIRMED)

    def test_rejected_blocks_same_probe_but_allows_new(self):
        self.eng.apply_actions([{"action": "add", "statement": "ssti",
                                 "command": "curl x"}])
        self.eng.apply_actions([{"action": "reject", "statement": "ssti",
                                 "reason": "no reflection"}])
        blocked = self.eng.apply_actions([{"action": "add", "statement": "ssti",
                                           "command": "curl x"}])
        self.assertTrue(any("blocked" in n for n in blocked))
        reopened = self.eng.apply_actions([{"action": "add", "statement": "ssti",
                                            "command": "python3 tpl_poc.py"}])
        self.assertTrue(any("reopening" in n for n in reopened))

    def test_unknown_and_bad_actions_do_not_raise(self):
        notes = self.eng.apply_actions([
            {"action": "confirm", "statement": "does not exist"},
            {"action": "warp", "statement": "x"},
            {"action": 42},
        ])
        self.assertTrue(any("unknown hypothesis" in n for n in notes))
        self.assertTrue(any("unknown action" in n for n in notes))

    def test_render_context_sections(self):
        self.eng.apply_actions([
            {"action": "add", "statement": "open thread", "command": "probe1",
             "expected_evidence": ["sig"]},
            {"action": "add", "statement": "will confirm"},
        ])
        self.eng.apply_actions([{"action": "confirm", "statement": "will confirm"}])
        self.eng.apply_actions([{"action": "add", "statement": "dead idea",
                                 "command": "p"},])
        self.eng.apply_actions([{"action": "reject", "statement": "dead idea"}])
        ctx = self.eng.render_context()
        self.assertIn("RESEARCH LEDGER", ctx)
        self.assertIn("open thread", ctx)
        self.assertIn("probe1", ctx)
        self.assertIn("CONFIRMED", ctx)
        self.assertIn("REJECTED", ctx)

    def test_render_context_empty_when_nothing_open(self):
        eng = MultiHypothesisEngine()
        self.assertEqual(eng.render_context(), "")

    def test_find_hypothesis_matches_id_title_substring(self):
        self.eng.apply_actions([{"action": "add",
                                 "statement": "unique ssti statement here"}])
        hyp = self.eng.find_hypothesis("unique ssti")
        self.assertIsNotNone(hyp)
        self.assertIsNotNone(self.eng.find_hypothesis(hyp.id))
        self.assertIsNone(self.eng.find_hypothesis("zzz-not-there"))
        self.assertIsNone(self.eng.find_hypothesis(""))


class ParserHypothesesTests(unittest.TestCase):
    def test_list_passthrough(self):
        d = parse_decision('{"completed": false, "next_command": "ls", '
                           '"hypotheses": [{"action": "add", "statement": "s"}]}')
        self.assertEqual(d["hypotheses"], [{"action": "add", "statement": "s"}])

    def test_dict_wrapped_into_list(self):
        d = parse_decision('{"completed": false, "next_command": "ls", '
                           '"hypotheses": {"action": "confirm", "statement": "s"}}')
        self.assertEqual(d["hypotheses"][0]["action"], "confirm")

    def test_missing_or_garbage_becomes_none(self):
        d = parse_decision('{"completed": false, "next_command": "ls"}')
        self.assertIsNone(d["hypotheses"])
        d2 = parse_decision('{"completed": false, "next_command": "ls", '
                            '"hypotheses": "audit everything"}')
        self.assertIsNone(d2["hypotheses"])


class ProseExtractionTests(unittest.TestCase):
    """The extractor must not gate on a hardcoded tool allowlist."""

    def test_any_plausible_binary_is_accepted(self):
        # katana / fresh custom script were NOT in the old hardcoded regex
        self.assertEqual(_extract_prose_command("try `katana -u http://x -d 3`"),
                         "katana -u http://x -d 3")
        self.assertEqual(
            _extract_prose_command("run `python3 /tmp/poc_owners.py` now"),
            "python3 /tmp/poc_owners.py")

    def test_prose_sentences_are_rejected(self):
        self.assertEqual(_extract_prose_command("The target looks vulnerable."), "")
        self.assertEqual(_extract_prose_command("`deploy the payload!`"), "")

    def test_exec_directive_and_fence_still_work(self):
        self.assertEqual(_extract_prose_command("EXEC: nuclei -u http://t"),
                         "nuclei -u http://t")
        self.assertIn("curl", _extract_prose_command(
            "```bash\ncurl -s http://t/.env\n```"))

    def test_heuristic_shapes(self):
        self.assertTrue(_looks_like_shell_command("nmap -sV host"))
        self.assertTrue(_looks_like_shell_command("/usr/bin/custom --flag"))
        self.assertFalse(_looks_like_shell_command("word"))
        self.assertFalse(_looks_like_shell_command("ends with period."))
        self.assertFalse(_looks_like_shell_command("multi\nline\ncommand"))


class _FakeAI:
    def __init__(self, reply):
        self.reply = reply
        self.calls = []

    def chat(self, system, message):
        self.calls.append((system, message))
        return self.reply


class _BoomAI:
    def chat(self, system, message):
        raise RuntimeError("provider down")


class AdversarialReviewTests(unittest.TestCase):
    def _finding(self):
        return {"title": "RCE via template injection", "severity": "critical",
                "detail": "rendered {{7*7}}", "evidence": "49"}

    def test_real_verdict_passes_through(self):
        ai = _FakeAI('{"verdict": "real", "reason": "49 present in output"}')
        out = adversarial_review(ai, self._finding(), "rendered: 49")
        self.assertEqual(out["verdict"], "real")
        # the reviewer must actually see claim + output
        system, message = ai.calls[0]
        self.assertIn("hostile", system)
        self.assertIn("49", message)

    def test_false_positive_verdict(self):
        ai = _FakeAI('{"verdict": "false_positive", "reason": "evidence absent"}')
        out = adversarial_review(ai, self._finding(), "404 Not Found")
        self.assertEqual(out["verdict"], "false_positive")

    def test_reviewer_outage_fails_open(self):
        out = adversarial_review(_BoomAI(), self._finding(), "out")
        self.assertEqual(out["verdict"], "unsure")

    def test_garbage_reply_is_unsure(self):
        out = adversarial_review(_FakeAI("looks fine to me"), self._finding(), "out")
        self.assertEqual(out["verdict"], "unsure")
        out2 = adversarial_review(_FakeAI(""), self._finding(), "out")
        self.assertEqual(out2["verdict"], "unsure")

    def test_no_ai_or_no_finding_is_unsure(self):
        self.assertEqual(adversarial_review(None, self._finding(), "o")["verdict"],
                         "unsure")
        self.assertEqual(
            adversarial_review(_FakeAI("x"), {"severity": "high"}, "o")["verdict"],
            "unsure")

    def test_parse_review_variants(self):
        self.assertEqual(parse_review('{"verdict": "real"}')["verdict"], "real")
        self.assertEqual(parse_review('{"verdict": "false-positive"}')["verdict"],
                         "false_positive")
        self.assertEqual(parse_review("verdict: false_positive because x")["verdict"],
                         "false_positive")
        self.assertEqual(parse_review("no json at all")["verdict"], "unsure")


class AgentWiringTests(unittest.TestCase):
    """Source-level guards: the ledger and reviewer must stay wired in the loop."""

    def _src(self):
        with open("agent.py") as fh:
            return fh.read()

    def test_ledger_is_instantiated_reset_applied_and_rendered(self):
        src = self._src()
        self.assertIn("self.hyp_engine = MultiHypothesisEngine()", src)
        self.assertIn('self.hyp_engine.apply_actions(decision.get("hypotheses"))', src)
        self.assertIn("self.hyp_engine.render_context()", src)

    def test_adversarial_gate_guards_critical_and_high(self):
        src = self._src()
        self.assertIn('_adversarial_review(self.ai, verified, evidence_context)', src)
        self.assertIn('("critical", "high")', src)

    def test_prose_extractor_delegates_to_shared_parser(self):
        src = self._src()
        self.assertIn("from brain.decision_parser import _extract_prose_command", src)
        # the hardcoded tool regex must be gone from the agent monolith
        self.assertNotIn("sqlmap|nuclei|ffuf|gobuster|feroxbuster", src)


if __name__ == "__main__":
    unittest.main()
