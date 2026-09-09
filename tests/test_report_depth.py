"""Tests for the offensive/reporting depth pass.

Pins the report contract end to end: chains and compliance appear in Markdown and
JSON, each finding carries a fix in the language it is actually written in, and
the frontier-model gate is visible in `doctor` and the workspace rather than only
firing mid-run.
"""
from __future__ import annotations

import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from execution.native_vuln import VulnerabilityFinding
from reporting.compliance import VULN_CLASS
from reporting.report_generator import SecurityReportGenerator


def _finding(title: str, severity: str = "high", endpoint: str = "/",
             cvss: float = 7.0, poc: str = "") -> VulnerabilityFinding:
    return VulnerabilityFinding(
        title=title, severity=severity, target="http://example.com", endpoint=endpoint,
        description="Detected during assessment.", evidence="evidence",
        remediation="See the code fix below.", poc_command=poc, cvss_score=cvss,
    )


def _chainable_set():
    return [
        _finding("Exposed Environment Configuration File (.env)", "critical", "/.env", 9.1,
                 "curl -sik http://example.com/.env"),
        _finding("IDOR / BOLA Authorization Bypass", "high", "/api/v1/users/1337", 8.1),
        _finding("Exposed OpenAI / AI Provider Secret Key", "critical", "/js/app.js", 9.1),
        _finding("Missing HTTP Security Headers", "low", "/", 3.1),
    ]


class MarkdownStructureTests(unittest.TestCase):
    def setUp(self):
        self.md = SecurityReportGenerator("example.com", _chainable_set()).generate_markdown()

    def test_all_six_sections_present_and_ordered(self):
        expected = [
            "## 1. Executive Summary",
            "## 2. Attack Chains",
            "## 3. Detailed Technical Findings & Remediations",
            "## 4. Compliance Exposure",
            "## 5. Remediation Work List",
            "## 6. General Defensive Recommendations",
        ]
        positions = []
        for heading in expected:
            self.assertIn(heading, self.md, heading)
            positions.append(self.md.index(heading))
        self.assertEqual(positions, sorted(positions), "sections are out of order")

    def test_old_nginx_only_heading_is_gone(self):
        self.assertNotIn("Defensive Configuration Patch Guidance", self.md)

    def test_chains_are_rendered_with_their_steps(self):
        self.assertIn("### Chain 1", self.md)
        self.assertIn("Composite score", self.md)
        for role in ("entry", "impact"):
            self.assertIn(f"| {role} |", self.md)

    def test_no_chains_message_when_findings_do_not_combine(self):
        md = SecurityReportGenerator(
            "example.com", [_finding("Missing HTTP Security Headers", "low")]).generate_markdown()
        self.assertIn("## 2. Attack Chains", md)
        self.assertIn("No findings combined into a multi-step path", md)


class PerFindingTests(unittest.TestCase):
    def setUp(self):
        self.md = SecurityReportGenerator("example.com", _chainable_set()).generate_markdown()

    def test_each_finding_carries_classification_and_standards(self):
        self.assertIn("**Classification:** `exposed_file`", self.md)
        self.assertIn("**CWE:** `CWE-538`", self.md)
        self.assertIn("**OWASP Top 10 2021:** A01:2021 Broken Access Control", self.md)
        self.assertIn("**SOC 2 TSC:** CC6.1", self.md)

    def test_fix_heading_names_the_real_language(self):
        """The regression: every fix used to be labelled nginx."""
        self.assertIn("**Fix (Python):**", self.md)
        self.assertIn("**Fix (nginx):**", self.md)

    def test_python_fix_is_a_python_snippet(self):
        self.assertIn("```python", self.md)

    def test_verification_step_is_included(self):
        self.assertIn("**How to verify the fix:**", self.md)

    def test_poc_is_still_rendered(self):
        self.assertIn("curl -sik http://example.com/.env", self.md)


class ComplianceSectionTests(unittest.TestCase):
    def setUp(self):
        self.generator = SecurityReportGenerator("example.com", _chainable_set())
        self.md = self.generator.generate_markdown()

    def test_each_standard_gets_a_table(self):
        for label in ("OWASP Top 10 2021", "OWASP API Top 10 2023",
                      "PCI-DSS 4.0", "SOC 2 TSC", "CWE"):
            self.assertIn(f"**{label}**", self.md)

    def test_it_says_this_is_not_a_compliance_determination(self):
        self.assertIn("not a compliance determination", self.md)

    def test_work_list_groups_by_root_cause(self):
        self.assertIn("| `exposed_file` |", self.md)
        self.assertIn("| `broken_access_control` |", self.md)

    def test_informational_is_excluded_from_the_work_list(self):
        generator = SecurityReportGenerator(
            "example.com", [_finding("Robots.txt Information Disclosure", "info")])
        self.assertNotIn("| `informational` |", generator.generate_markdown())

    def test_gaps_helper_exposes_counts(self):
        gaps = self.generator.compliance_gaps("soc2")
        self.assertTrue(any(gap.startswith("CC6.1") for gap in gaps))

    def test_attack_chains_helper_returns_data(self):
        chains = self.generator.attack_chains(limit=2)
        self.assertLessEqual(len(chains), 2)
        for chain in chains:
            self.assertIn("impact_class", chain)
            self.assertIn("steps", chain)


class JsonReportTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(
            SecurityReportGenerator("example.com", _chainable_set()).generate_json())

    def test_new_top_level_keys(self):
        for key in ("attack_chains", "compliance", "compliance_gaps", "remediation"):
            self.assertIn(key, self.data, key)

    def test_existing_keys_are_preserved(self):
        for key in ("target", "generated_at", "risk_score", "stats", "findings", "metadata"):
            self.assertIn(key, self.data, key)

    def test_findings_carry_their_standards_and_fix(self):
        finding = self.data["findings"][0]
        self.assertEqual(finding["vuln_class"], VULN_CLASS.EXPOSED_FILE)
        self.assertEqual(finding["standards"]["cwe"], "CWE-538")
        self.assertEqual(finding["fix"]["vuln_class"], VULN_CLASS.EXPOSED_FILE)

    def test_gaps_cover_the_audit_standards(self):
        self.assertIn("soc2", self.data["compliance_gaps"])
        self.assertIn("pci_dss", self.data["compliance_gaps"])

    def test_json_is_valid_and_fully_serialisable(self):
        """Findings can hold non-JSON-native values; default=str must cover it."""
        reencoded = json.dumps(self.data)
        self.assertTrue(reencoded)

    def test_chains_reference_only_reported_findings(self):
        reported = {f["title"] for f in self.data["findings"]}
        for chain in self.data["attack_chains"]:
            for step in chain["steps"]:
                self.assertIn(step["title"], reported)


class LegacyHelperTests(unittest.TestCase):
    def test_old_snippet_helper_delegates(self):
        finding = _finding("SQL Injection Anomaly")
        generator = SecurityReportGenerator("example.com", [finding])
        self.assertEqual(
            generator._get_remediation_snippet(finding),
            generator._get_remediation_snippet(finding),
        )
        from reporting.remediation import remediation_for
        self.assertEqual(
            generator._get_remediation_snippet(finding), remediation_for(finding).snippet)

    def test_legacy_helper_is_still_available(self):
        finding = _finding("Exposed Environment Configuration File (.env)")
        generator = SecurityReportGenerator("example.com", [finding])
        self.assertIn("deny all", generator._legacy_remediation_snippet(finding))


class HtmlReportTests(unittest.TestCase):
    def test_html_still_generates(self):
        html = SecurityReportGenerator("example.com", _chainable_set()).generate_html()
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("Exposed Environment Configuration File (.env)", html)


class EmptyReportTests(unittest.TestCase):
    def test_no_findings_still_renders_every_section(self):
        md = SecurityReportGenerator("example.com", []).generate_markdown()
        for heading in ("## 1. Executive Summary", "## 2. Attack Chains",
                        "## 3. Detailed Technical Findings & Remediations",
                        "## 4. Compliance Exposure", "## 5. Remediation Work List",
                        "## 6. General Defensive Recommendations"):
            self.assertIn(heading, md)

    def test_empty_json(self):
        data = json.loads(SecurityReportGenerator("example.com", []).generate_json())
        self.assertEqual(data["attack_chains"], [])
        self.assertEqual(data["compliance"]["total"], 0)


class DoctorGateTests(unittest.TestCase):
    def test_gate_is_a_reported_diagnostic(self):
        import cli_support
        result = cli_support.run_diagnostics(check_network=False)
        gates = [c for c in result["checks"] if c["name"] == "frontier model gate"]
        self.assertEqual(len(gates), 1)
        self.assertIn(gates[0]["status"], ("pass", "warn"))
        self.assertTrue(gates[0]["detail"].strip())

    def test_gate_warns_for_an_unauthorised_critical_model(self):
        """The visible part: the operator can see the block before running."""
        import cli_support
        # run_diagnostics imports load_config inside the function, so patching it
        # on the config module is what the check actually reads.
        with mock.patch("config.load_config",
                        return_value={"AI_PROVIDER": "openai", "AI_MODEL": "gpt-6-astra"}):
            result = cli_support.run_diagnostics(check_network=False)
        gate = next(c for c in result["checks"] if c["name"] == "frontier model gate")
        self.assertEqual(gate["status"], "warn")
        self.assertIn("blocked", gate["detail"])
        self.assertIn("gpt-6-astra", gate["detail"])

    def test_new_modules_are_registered_as_critical(self):
        import cli_support
        for module in ("reporting.compliance", "reporting.remediation",
                       "brain.exploit_chain", "brain.frontier_gate"):
            self.assertIn(module, cli_support.CRITICAL_MODULES, module)


class WorkspaceGateTests(unittest.TestCase):
    def test_snapshot_includes_the_gate(self):
        import cli
        snapshot = cli.workspace_snapshot()
        self.assertIn("frontier", snapshot)
        self.assertIn("exploitation_allowed", snapshot["frontier"])

    def test_gate_survives_a_gate_failure(self):
        """A broken gate must degrade visibly, not disappear."""
        import cli
        with mock.patch("brain.frontier_gate.gate_status", side_effect=RuntimeError("boom")):
            snapshot = cli.workspace_snapshot()
        self.assertFalse(snapshot["frontier"]["gated"])
        self.assertIn("boom", snapshot["frontier"]["label"])

    def test_screen_renders_the_gate_row(self):
        from rich.console import Console
        from ui.screens import workspace_screen
        from ui.theme import X19_THEME

        for frontier, expected in (
            ({"gated": True, "exploitation_allowed": False, "target_type": "auto"},
             "blocked"),
            ({"gated": True, "exploitation_allowed": True, "target_type": "ctf"},
             "open (ctf)"),
            ({"gated": False}, "unrestricted"),
        ):
            buffer = io.StringIO()
            Console(file=buffer, theme=X19_THEME, width=110, no_color=True).print(
                workspace_screen(frontier=frontier))
            self.assertIn("exploit gate", buffer.getvalue())
            self.assertIn(expected, buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
