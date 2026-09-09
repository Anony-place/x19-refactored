"""Tests for reporting.compliance — the CWE / OWASP / PCI / SOC 2 mapping layer.

The classifier is keyword based and ordered first-match-wins, so the test that
matters most is the regression over the titles X19 *actually emits*. Two real
misclassifications were found that way (a wildcard-CORS finding claimed by the
credential rule, and an exposed-JWT finding claimed by the weak-signing rule),
so the title inventory is read out of the scanner source rather than copied by
hand — a new ``check_*`` method then fails here until it is mapped.
"""
from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from execution.native_vuln import VulnerabilityFinding
from reporting.compliance import (
    MAPPINGS,
    STANDARDS,
    STANDARD_LABELS,
    VULN_CLASS,
    classify_finding,
    compliance_summary,
    control_gaps,
    map_finding,
)


def _finding(title: str, evidence: str = "evidence", endpoint: str = "/") -> VulnerabilityFinding:
    return VulnerabilityFinding(
        title=title, severity="high", target="http://example.com", endpoint=endpoint,
        description="desc", evidence=evidence, remediation="fix",
    )


#: The two data-driven tables in the scanner whose 2nd tuple element is a
#: finding title. ``takeover_fingerprints`` also matches this shape but holds
#: response signatures rather than titles, so it is excluded by name.
_TITLE_TABLES = ("checks", "patterns")


def emitted_titles() -> list[str]:
    """Every title string the native scanner can put on a finding.

    Parsed out of ``execution/native_vuln.py`` so the list cannot drift from the
    scanner: literal ``title=`` values, f-string titles, and the two data-driven
    title tables. An f-string placeholder is substituted with ``example``.
    """
    tree = ast.parse((ROOT / "execution" / "native_vuln.py").read_text())
    titles: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "title":
            if isinstance(node.value, ast.Constant):
                titles.append(str(node.value.value))
            elif isinstance(node.value, ast.JoinedStr):
                titles.append("".join(
                    part.value if isinstance(part, ast.Constant) else "example"
                    for part in node.value.values
                ))

    for node in ast.walk(tree):
        if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.List)):
            continue
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if not any(name in _TITLE_TABLES for name in names):
            continue
        for row in node.value.elts:
            if isinstance(row, ast.Tuple) and len(row.elts) >= 2:
                title = row.elts[1]
                if isinstance(title, ast.Constant) and isinstance(title.value, str):
                    titles.append(title.value)

    return sorted(set(titles))


EXPECTED = {
    "IDOR / BOLA Authorization Bypass": VULN_CLASS.BROKEN_ACCESS,
    "SQL Injection Anomaly": VULN_CLASS.SQLI,
    "Host Header Injection": VULN_CLASS.HOST_HEADER,
    "Insecure CORS Policy (Wildcard with Credentials)": VULN_CLASS.CORS,
    "Insecure CORS Policy (Origin Reflection)": VULN_CLASS.CORS,
    "Missing HTTP Security Headers": VULN_CLASS.MISSING_HEADERS,
    "Server-Side Request Forgery (SSRF) Metadata Leak": VULN_CLASS.SSRF,
    "Server-Side Template Injection (SSTI)": VULN_CLASS.SSTI,
    "Insecure Cookie Attributes": VULN_CLASS.COOKIE,
    "Directory Listing Enabled": VULN_CLASS.DIR_LISTING,
    "GraphQL Introspection Enabled": VULN_CLASS.GRAPHQL_INTROSPECTION,
    "HTTP Request Smuggling Potential (CL.TE / TE.CL Anomaly)": VULN_CLASS.REQUEST_SMUGGLING,
    "Security.txt Policy Discovered": VULN_CLASS.INFO,
    "Unvalidated Open Redirect": VULN_CLASS.OPEN_REDIRECT,
    "JWT Unsigned Token (alg: none)": VULN_CLASS.JWT_WEAK,
    "Exposed JWT Token in Client Response": VULN_CLASS.JWT_EXPOSED,
    # f-string placeholder is substituted with "example" by emitted_titles()
    "Potential Subdomain Takeover (example)": VULN_CLASS.SUBDOMAIN_TAKEOVER,
    "Exposed Environment Configuration File (.env)": VULN_CLASS.EXPOSED_FILE,
    "Exposed Git Repository Configuration": VULN_CLASS.EXPOSED_FILE,
    "Exposed Git Repository HEAD": VULN_CLASS.EXPOSED_FILE,
    "Robots.txt Information Disclosure": VULN_CLASS.INFO,
    "PHP Info Page Information Disclosure": VULN_CLASS.EXPOSED_FILE,
    "Exposed macOS Metadata File (.DS_Store)": VULN_CLASS.EXPOSED_FILE,
    "Exposed Google API Key": VULN_CLASS.CREDENTIAL_LEAK,
    "Exposed OpenAI / AI Provider Secret Key": VULN_CLASS.CREDENTIAL_LEAK,
    "Exposed GitHub Personal Access Token": VULN_CLASS.CREDENTIAL_LEAK,
    "Exposed AWS Access Key ID": VULN_CLASS.CREDENTIAL_LEAK,
}


class ClassifierRegressionTests(unittest.TestCase):
    """Every title the scanner emits must land on the intended class."""

    def test_all_emitted_titles_are_covered(self):
        titles = emitted_titles()
        self.assertGreaterEqual(len(titles), 20, f"expected a full inventory, got {len(titles)}")
        unmapped = [t for t in titles if t not in EXPECTED]
        self.assertEqual(
            unmapped, [],
            f"scanner emits titles this test does not assert on — map them: {unmapped}",
        )

    def test_every_emitted_title_classifies_as_expected(self):
        wrong = {}
        for title, expected in EXPECTED.items():
            got = classify_finding(_finding(title))
            if got != expected:
                wrong[title] = (got, expected)
        self.assertEqual(wrong, {}, f"misclassified: {wrong}")

    def test_stale_expectations_are_removed(self):
        """Guard the other direction: EXPECTED must not keep dead titles."""
        titles = set(emitted_titles())
        dead = [t for t in EXPECTED if t not in titles]
        self.assertEqual(dead, [], f"EXPECTED holds titles the scanner no longer emits: {dead}")


class MappingTableTests(unittest.TestCase):
    def test_every_class_has_a_mapping(self):
        classes = {v for k, v in vars(VULN_CLASS).items() if not k.startswith("_")}
        self.assertEqual(set(MAPPINGS), classes)
        self.assertEqual(len(classes), 20)

    def test_every_mapping_carries_a_cwe_and_a_note(self):
        for vuln_class, mapping in MAPPINGS.items():
            if vuln_class != VULN_CLASS.INFO:  # informational has no CWE by design
                self.assertTrue(mapping.cwe.startswith("CWE-"), vuln_class)
            self.assertTrue(mapping.note.strip(), vuln_class)
            self.assertEqual(mapping.vuln_class, vuln_class)

    def test_standard_labels_cover_every_standard(self):
        self.assertEqual(set(STANDARD_LABELS), set(STANDARDS))

    def test_pci_and_soc2_controls_are_lists(self):
        for vuln_class, mapping in MAPPINGS.items():
            self.assertIsInstance(mapping.pci_dss, list, vuln_class)
            self.assertIsInstance(mapping.soc2, list, vuln_class)

    def test_controls_flattens_per_standard(self):
        controls = MAPPINGS[VULN_CLASS.CORS].controls()
        self.assertEqual(controls["cwe"], "CWE-942")
        self.assertIn("CC6.6", controls["soc2"])
        self.assertEqual(set(controls), set(STANDARDS))


class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.findings = [
            _finding("Exposed Environment Configuration File (.env)"),
            _finding("IDOR / BOLA Authorization Bypass"),
            _finding("Missing HTTP Security Headers"),
        ]

    def test_summary_counts_by_class(self):
        summary = compliance_summary(self.findings)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["by_class"][VULN_CLASS.EXPOSED_FILE], 1)
        self.assertEqual(summary["by_class"][VULN_CLASS.BROKEN_ACCESS], 1)
        self.assertEqual(summary["unmapped"], 0)

    def test_summary_tallies_each_standard(self):
        summary = compliance_summary(self.findings)
        self.assertIn("A01:2021 Broken Access Control", summary["owasp_web"])
        self.assertIn("CC6.1", summary["soc2"])
        self.assertIn("CWE-538", summary["cwe"])

    def test_control_gaps_reports_counts(self):
        gaps = control_gaps(self.findings, "soc2")
        self.assertIn("CC6.1 (2 findings)", gaps)

    def test_control_gaps_rejects_unknown_standard(self):
        with self.assertRaises(ValueError):
            control_gaps(self.findings, "iso27001")

    def test_empty_findings(self):
        summary = compliance_summary([])
        self.assertEqual(summary["total"], 0)
        self.assertEqual(summary["by_class"], {})


class ClassificationInputTests(unittest.TestCase):
    def test_accepts_a_bare_class_name(self):
        """map_finding is called with a class string by the chain engine."""
        self.assertEqual(map_finding(VULN_CLASS.SSRF).vuln_class, VULN_CLASS.SSRF)

    def test_accepts_a_title_string(self):
        self.assertEqual(
            map_finding("SQL Injection Anomaly").vuln_class, VULN_CLASS.SQLI)

    def test_unknown_text_falls_back_to_informational(self):
        self.assertEqual(
            classify_finding(_finding("Something Entirely Unrelated")),
            VULN_CLASS.INFO,
        )

    def test_evidence_can_carry_the_signal(self):
        finding = _finding("Suspicious Response", evidence="access-control-allow-origin: *")
        self.assertEqual(classify_finding(finding), VULN_CLASS.CORS)

    def test_none_is_handled(self):
        self.assertEqual(classify_finding(None), VULN_CLASS.INFO)


if __name__ == "__main__":
    unittest.main()
