"""Chain-hunting guidance + variant-analysis wiring.

Covers ExploitChainEngine.hunting_guidance (near-miss chain suggestions for
the live loop) and the agent wiring that injects chain opportunities into the
decision context and a variant-analysis advisory when a finding is confirmed.
"""

from __future__ import annotations

import unittest

from brain.exploit_chain import ExploitChainEngine
from reporting.compliance import VULN_CLASS, classify_finding


class _F:
    """Minimal finding stub: classify_finding reads title + evidence."""

    def __init__(self, title, evidence=""):
        self.title = title
        self.evidence = evidence
        self.severity = "high"
        self.description = ""


class HuntingGuidanceTests(unittest.TestCase):
    def setUp(self):
        self.eng = ExploitChainEngine()

    def test_empty_findings_no_guidance(self):
        self.assertEqual(self.eng.hunting_guidance([]), [])
        self.assertEqual(self.eng.hunting_guidance(None), [])

    def test_near_miss_single_hop_impact(self):
        # SSTI enables RCE directly; RCE alone is missing.
        out = self.eng.hunting_guidance([_F("SSTI in template name param")])
        self.assertEqual(len(out), 1)
        self.assertIn(VULN_CLASS.SSTI, out[0])
        self.assertIn(VULN_CLASS.RCE, out[0])

    def test_near_miss_two_hop_impact(self):
        # credential_leak -> jwt_weak (not itself an impact) -> broken_access.
        out = self.eng.hunting_guidance(
            [_F("aws keys leaked in public .env", "AKIA...")])
        self.assertTrue(out)
        self.assertTrue(any(VULN_CLASS.JWT_WEAK in line for line in out))

    def test_no_guidance_when_successor_already_confirmed(self):
        both = [_F("SSTI in template"), _F("remote code execution via template")]
        self.assertEqual(self.eng.hunting_guidance(both), [])

    def test_info_findings_ignored(self):
        self.assertEqual(self.eng.hunting_guidance([_F("server banner visible")]), [])

    def test_limit_caps_output(self):
        findings = [_F("aws keys leaked in .env"), _F("open redirect on /login"),
                    _F("host header injection poisons cache")]
        out = self.eng.hunting_guidance(findings, limit=2)
        self.assertLessEqual(len(out), 2)

    def test_classification_matches_compliance(self):
        # the guidance must consume the same classifier the reports use
        self.assertEqual(classify_finding(_F("SQL injection in id param")),
                         VULN_CLASS.SQLI)


class AgentChainWiringTests(unittest.TestCase):
    """Source-level guards: chain guidance + variant advisory stay wired."""

    def _src(self):
        with open("agent.py") as fh:
            return fh.read()

    def test_chain_engine_instantiated_and_rendered(self):
        src = self._src()
        self.assertIn("self.chain_engine = ExploitChainEngine()", src)
        self.assertIn("self.chain_engine.hunting_guidance(self.model.findings)", src)
        self.assertIn("CHAIN OPPORTUNITIES", src)

    def test_variant_advisory_on_confirmation(self):
        src = self._src()
        self.assertIn("VARIANT CHECK:", src)
        # the advisory must be appended to the soft-gate queue, not printed as a gate
        self.assertLess(
            src.index("VARIANT CHECK:"), src.index("def _drain_advisories"),
            "variant advisory should be defined before the drain that consumes it")
        self.assertIn("self._advisories.append(", src[src.index("VARIANT CHECK:") - 200:])


if __name__ == "__main__":
    unittest.main()
