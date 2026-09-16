"""Full-loop integration: one real `_autonomous_loop_impl` run, everything on.

The unit suites verify each subsystem in isolation; this one runs the actual
loop with a scripted fake AI and harmless `echo` probes through the real
policy gateway, asserting that the dynamic-reasoning stack is *composed*
correctly in vivo:

- team tick runs every iteration (budget reset, harvest, review);
- a pre-registered hypothesis is auto-dispatched as a parallel trajectory,
  executed by a team worker through the policy gateway, and auto-confirmed
  against its own expected evidence;
- the decision context carries the research ledger, OOB-oracle status, and
  lane reports in the right iterations;
- usage accounting accumulates one tick per decision call;
- the loop terminates cleanly at MAX_ITERATIONS with status "completed".
"""

from __future__ import annotations

import json
import os
import threading
import unittest
from unittest import mock

from config import CONFIG
from events import AgentEventBus


class FakeAI:
    """Scripted decision engine: safe echo probes + JSON decisions."""

    name_string = "fake/integration"

    def __init__(self):
        self.contexts = []
        self.n = 0
        self.lock = threading.Lock()

    def name(self):
        return self.name_string

    def chat(self, system, message):
        with self.lock:
            self.n += 1
            n = self.n
        self.contexts.append(message)
        time.sleep(0.15)   # give async trajectory workers time to finish
        if n == 1:
            return json.dumps({
                "thinking": "register a hypothesis and let a trajectory run it",
                "next_command": "echo base-probe",
                "hypotheses": [{
                    "action": "add",
                    "statement": "integration hypothesis: echo round-trips",
                    "command": "echo hyp-evidence-42",
                    "expected_evidence": ["42"],
                    "impact": 0.9,
                }],
                "completed": False,
            })
        return json.dumps({
            "thinking": "continue routine probes",
            "next_command": f"echo iter-{n}",
            "hypotheses": [],
            "completed": False,
        })


import time  # after the class body uses it at runtime only


def _run_loop():
    from agent import X19

    ai = FakeAI()
    agent = X19(target="x19-integration-test.invalid", ai=ai)
    bus = AgentEventBus()
    token, q = bus.subscribe()
    agent.session.events = bus

    with mock.patch.object(CONFIG, "MAX_ITERATIONS", 4):
        agent.autonomous_loop("x19-integration-test.invalid")
    return agent, ai, q


class FullLoopIntegrationTests(unittest.TestCase):
    def test_loop_completes_with_team_trajectories_and_usage(self):
        # keep the run offline, but scoped so the env never leaks into other
        # tests (knowledge-layer tests assert on live-source behaviour)
        with mock.patch.dict(os.environ, {"X19_INTEL_DISABLE": "1"}):
            agent, ai, q = _run_loop()

        # 1) the loop ran to its configured end, cleanly
        self.assertEqual(agent.session.data.get("status"), "completed")
        self.assertFalse(agent.running)

        # 2) usage accounting: one tick per decision call (4 iterations)
        usage = agent.session.data.get("usage") or {}
        self.assertEqual(usage.get("calls"), 4)
        self.assertGreater(int(usage.get("chars_in", 0)), 0)
        self.assertGreater(float(usage.get("secs", 0.0)), 0.0)

        # 3) the hypothesis went through the full parallel trajectory:
        #    registered -> dispatched to a worker -> executed via the
        #    policy gateway -> auto-confirmed by pre-registered evidence.
        hyp = agent.hyp_engine.find_hypothesis("integration hypothesis")
        self.assertIsNotNone(hyp)
        self.assertEqual(hyp.state, "CONFIRMED", hyp.last_result)
        self.assertIn("42", (hyp.confirmation_evidence or [""])[0])
        self.assertTrue(agent._trajectory_map, "trajectory must have been dispatched")

        # 4) context blocks appear in the right iterations: OOB oracle status
        #    is always present; the ledger only exists AFTER the iteration-1
        #    decision registered the hypothesis (so from context #2 on); lane
        #    reports appear once the worker has executed the probe.
        self.assertIn("OOB ORACLE", ai.contexts[0])
        self.assertNotIn("RESEARCH LEDGER", ai.contexts[0])   # empty before registration
        second = "\n".join(ai.contexts[1:2])
        self.assertIn("RESEARCH LEDGER", second)
        self.assertIn("integration hypothesis", second)
        later = "\n".join(ai.contexts[2:])
        self.assertIn("LANE REPORTS", later)
        self.assertIn("hyp-evidence-42", later)   # worker evidence echoed back

        # 5) live events flowed: team events (trajectory dispatch) and the
        #    command stream from the session emitter.
        events = []
        while True:
            try:
                events.append(q.get_nowait())
            except Exception:
                break
        kinds = [e.kind for e in events]
        self.assertIn("command", kinds)
        self.assertIn("team", kinds)


if __name__ == "__main__":
    unittest.main()
