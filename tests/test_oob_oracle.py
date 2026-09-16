"""OOB oracle: interactsh callbacks as binary evidence for blind vulns.

Verifies the redesigned poll path (_poll_oob_oracle): durable evidence,
live event emission, info-severity lead (never an unverified high),
deterministic hypothesis correlation via canary-in-probe, gate integration
([OOB INTERACTION] counts as an exploit indicator), and the decision-context
status block.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace

import attacks
from agent import X19
from brain.hypothesis_engine import HYP_CONFIRMED, HYP_TESTING, MultiHypothesisEngine
from events import AgentEvent, summarize_event


class FakeSession:
    def __init__(self):
        self.events_published = []

    def emit_event(self, kind, text="", **detail):
        self.events_published.append((kind, text, detail))


class FakeModel:
    def __init__(self):
        self.findings = []

    def add_finding(self, f):
        self.findings.append(f)


class FakeOOB:
    def __init__(self, hits, available=True, canary="abc123def456.oast.pro"):
        self._hits = hits
        self.available = available
        self.canary = canary
        self._mode = "binary"
        self.polled = 0

    def poll(self, timeout=2.0):
        self.polled += 1
        return list(self._hits)

    def oast_url(self, proto="http"):
        return f"{proto}://{self.canary}"


def _bare_agent(findings_model=None):
    """X19 without __init__ — only the attributes _poll_oob_oracle touches."""
    agent = X19.__new__(X19)
    agent._oob_evidence = []
    agent.session = FakeSession()
    agent.hyp_engine = MultiHypothesisEngine()
    agent.model = findings_model or FakeModel()
    return agent


HIT = {"protocol": "dns", "full-id": "abc123def456.abc123def456.oast.pro",
       "raw": {"remote-address": "203.0.113.7"}}


class OOBOraclePollTests(unittest.TestCase):
    def _run(self, agent, fake):
        with unittest.mock.patch.object(attacks, "get_oob", lambda: fake):
            return agent._poll_oob_oracle("prev")

    def test_callback_becomes_evidence_event_and_info_lead(self):
        import unittest.mock
        agent = _bare_agent()
        note = self._run(agent, FakeOOB([HIT]))
        self.assertIn("OOB interaction", note)
        self.assertIn("binary out-of-band proof", note)
        self.assertEqual(len(agent._oob_evidence), 1)
        self.assertIn("[OOB INTERACTION] dns", agent._oob_evidence[0])
        kinds = [k for k, _, _ in agent.session.events_published]
        self.assertEqual(kinds, ["oob"])
        self.assertEqual(len(agent.model.findings), 1)
        self.assertEqual(agent.model.findings[0].severity, "info",
                         "callback alone must never be an unverified high finding")

    def test_lead_not_duplicated_across_polls(self):
        import unittest.mock
        agent = _bare_agent()
        fake = FakeOOB([HIT])
        self._run(agent, fake)
        self._run(agent, fake)
        self.assertEqual(len(agent.model.findings), 1, "same lead must dedupe")

    def test_testing_hypothesis_with_canary_gets_confirmed(self):
        import unittest.mock
        agent = _bare_agent()
        agent.hyp_engine.apply_actions([
            {"action": "add",
             "statement": "target fetches attacker URL (blind SSRF)",
             "command": "curl 'http://t/fetch?url=http://abc123def456.oast.pro/probe'"},
        ])
        agent.hyp_engine.apply_actions([{"action": "test",
                                         "statement": "blind SSRF"}])
        note = self._run(agent, FakeOOB([HIT]))
        hyp = agent.hyp_engine.find_hypothesis("blind SSRF")
        self.assertEqual(hyp.state, HYP_CONFIRMED)
        self.assertIn("Confirmed hypothesis", note)

    def test_unavailable_or_missing_client_is_noop(self):
        import unittest.mock
        agent = _bare_agent()
        self.assertEqual(self._run(agent, FakeOOB([], available=False)), "prev")
        with unittest.mock.patch.object(attacks, "get_oob", lambda: None):
            self.assertEqual(agent._poll_oob_oracle("prev"), "prev")

    def test_client_error_is_swallowed(self):
        import unittest.mock

        def boom():
            raise RuntimeError("no interactsh")

        agent = _bare_agent()
        with unittest.mock.patch.object(attacks, "get_oob", boom):
            self.assertEqual(agent._poll_oob_oracle("prev"), "prev")
        self.assertEqual(agent._oob_evidence, [])

    def test_evidence_ring_is_capped(self):
        import unittest.mock
        agent = _bare_agent()
        hits = [{"protocol": p, "full-id": f"id{i}", "raw": {}}
                for i, p in enumerate(["dns"] * 12)]
        self._run(agent, FakeOOB(hits))
        self.assertLessEqual(len(agent._oob_evidence), 8)


class OOBGateAndContextTests(unittest.TestCase):
    def _gate_agent(self):
        agent = X19.__new__(X19)
        agent._fp_records = {}
        return agent

    def test_oob_line_counts_as_exploit_indicator(self):
        agent = self._gate_agent()
        finding = {"title": "blind SSRF in fetcher", "severity": "critical",
                   "detail": "server makes outbound request", "evidence": ""}
        output = ("some noisy scan output\n"
                  "[OOB INTERACTION] dns: abc123 from 203.0.113.7")
        gate = agent._gate_security_impact(finding, output)
        self.assertTrue(gate.passed, gate.reason)

    def test_context_block_source_wiring(self):
        with open("agent.py") as fh:
            src = fh.read()
        self.assertIn("OOB ORACLE ACTIVE", src)
        self.assertIn("RECENT OOB EVIDENCE", src)
        self.assertIn("do not report blind-vuln", src)  # honest fallback mode
        self.assertIn('_oob_tail = [l for l in self._oob_evidence[-3:]',
                      src)  # evidence joins verification context
        self.assertIn("_poll_oob_oracle(previous_output)", src)

    def test_prompt_documents_the_oracle(self):
        from constants import LEAN_SYSTEM_PROMPT
        self.assertIn("OOB ORACLE (blind classes)", LEAN_SYSTEM_PROMPT)
        self.assertIn("[OOB INTERACTION]", LEAN_SYSTEM_PROMPT)


class EventAndSessionTests(unittest.TestCase):
    def test_summarize_event_oob(self):
        ev = AgentEvent(kind="oob", text="dns callback from 1.2.3.4",
                        detail={"protocol": "dns"})
        line = summarize_event(ev)
        self.assertIn("◉ oob callback [dns]", line)

    def test_session_emit_event_publishes(self):
        from events import AgentEventBus
        from storage import Session
        bus = AgentEventBus()
        token, q = bus.subscribe()
        session = Session(events=bus)
        session.data["target"] = "t"
        session.emit_event("oob", "dns callback", protocol="dns")
        ev = q.get(timeout=1)
        self.assertEqual(ev.kind, "oob")
        self.assertEqual(ev.detail.get("protocol"), "dns")


if __name__ == "__main__":
    unittest.main()
