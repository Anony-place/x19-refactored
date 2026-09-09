"""Tests for reporting.remediation — code-level fixes per vulnerability class.

The old report emitted a single nginx snippet for every finding, which mislabelled
JavaScript and Python fixes as nginx. These tests pin the contract that each
class carries a real fix, in a real language, with a way to verify it.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from execution.native_vuln import VulnerabilityFinding
from reporting.compliance import VULN_CLASS
from reporting.remediation import (
    LANGUAGE_LABELS,
    _FIXES,
    _GENERIC,
    remediation_for,
    remediation_summary,
)


def _finding(title: str, severity: str = "high", endpoint: str = "/") -> VulnerabilityFinding:
    return VulnerabilityFinding(
        title=title, severity=severity, target="http://example.com", endpoint=endpoint,
        description="desc", evidence="evidence", remediation="fix",
    )


class CoverageTests(unittest.TestCase):
    def test_every_actionable_class_has_a_fix(self):
        classes = {v for k, v in vars(VULN_CLASS).items() if not k.startswith("_")}
        missing = sorted(classes - set(_FIXES) - {VULN_CLASS.INFO})
        self.assertEqual(missing, [], f"classes with no code-level fix: {missing}")

    def test_informational_falls_back_to_the_generic_fix(self):
        fix = remediation_for(VULN_CLASS.INFO)
        self.assertEqual(fix.language, _GENERIC.language)

    def test_every_fix_names_a_known_language(self):
        for vuln_class, fix in _FIXES.items():
            self.assertIn(fix.language, LANGUAGE_LABELS, vuln_class)

    def test_every_language_has_a_human_label(self):
        for language, label in LANGUAGE_LABELS.items():
            self.assertTrue(label.strip(), language)

    def test_no_fix_is_mislabelled_as_nginx(self):
        """The regression this module exists to fix."""
        non_nginx = [
            vuln_class for vuln_class, fix in _FIXES.items()
            if fix.language != "nginx"
        ]
        self.assertTrue(non_nginx, "every fix is nginx — the module is not doing its job")
        for vuln_class in non_nginx:
            self.assertNotEqual(remediation_for(vuln_class).language, "nginx", vuln_class)


class FixContentTests(unittest.TestCase):
    def test_every_fix_has_a_snippet_explanation_and_verification(self):
        for vuln_class, fix in _FIXES.items():
            self.assertTrue(fix.snippet.strip(), vuln_class)
            self.assertTrue(fix.explanation.strip(), vuln_class)
            self.assertTrue(fix.verify.strip(), vuln_class)

    def test_every_fix_carries_a_reference(self):
        for vuln_class, fix in _FIXES.items():
            self.assertTrue(fix.references, vuln_class)
            self.assertTrue(
                any(ref.startswith("CWE-") or ref.startswith("OWASP") for ref in fix.references),
                vuln_class,
            )

    def test_snippets_are_valid_python_or_nginx_shape(self):
        """Snippets must be parseable where the language claims to be Python."""
        import ast
        for vuln_class, fix in _FIXES.items():
            if fix.language != "python":
                continue
            body = "\n".join(
                line for line in fix.snippet.splitlines()
                if not line.lstrip().startswith("#")
            ).strip()
            try:
                ast.parse(body)
            except SyntaxError as exc:
                self.fail(f"{vuln_class} python snippet does not parse: {exc}")

    def test_language_label_matches_language(self):
        for vuln_class, fix in _FIXES.items():
            self.assertEqual(fix.language_label, LANGUAGE_LABELS[fix.language], vuln_class)

    def test_to_dict_shape(self):
        fix = remediation_for(VULN_CLASS.SQLI)
        data = fix.to_dict()
        self.assertEqual(
            {"vuln_class", "language", "language_label", "snippet", "explanation",
             "verify", "references", "cwe", "owasp_web"},
            set(data),
        )
        self.assertEqual(data["language_label"], fix.language_label)


class LookupTests(unittest.TestCase):
    def test_accepts_a_finding_object(self):
        self.assertEqual(
            remediation_for(_finding("SQL Injection Anomaly")).vuln_class,
            VULN_CLASS.SQLI,
        )

    def test_accepts_a_bare_class_name(self):
        self.assertEqual(remediation_for(VULN_CLASS.CORS).vuln_class, VULN_CLASS.CORS)

    def test_accepts_a_title_string(self):
        self.assertEqual(
            remediation_for("Server-Side Request Forgery (SSRF) Metadata Leak").vuln_class,
            VULN_CLASS.SSRF,
        )

    def test_unknown_text_gets_the_generic_fix(self):
        self.assertEqual(
            remediation_for("Something Entirely Unrelated").vuln_class, VULN_CLASS.INFO)

    def test_none_is_handled(self):
        self.assertEqual(remediation_for(None).vuln_class, VULN_CLASS.INFO)

    def test_every_real_scanner_title_gets_its_own_fix(self):
        """Titles the scanner actually emits must not fall through to the fallback.

        A class may legitimately be written in a language-agnostic form (an
        exposed JWT is fixed by not shipping the token, in any stack), so this
        asserts the class is recognised rather than the language used.
        """
        from tests.test_compliance import EXPECTED
        for title, vuln_class in EXPECTED.items():
            if vuln_class == VULN_CLASS.INFO:
                continue
            fix = remediation_for(_finding(title))
            self.assertEqual(
                fix.vuln_class, vuln_class,
                f"{title!r} fell through to the fallback fix",
            )


class SummaryTests(unittest.TestCase):
    def test_groups_by_class(self):
        findings = [
            _finding("Exposed Environment Configuration File (.env)"),
            _finding("Exposed Git Repository Configuration"),
            _finding("SQL Injection Anomaly"),
        ]
        summary = remediation_summary(findings)
        self.assertEqual(summary["findings_total"], 3)
        by_class = {entry["vuln_class"]: entry["findings"] for entry in summary["fixes"]}
        self.assertEqual(by_class[VULN_CLASS.EXPOSED_FILE], 2)
        self.assertEqual(by_class[VULN_CLASS.SQLI], 1)

    def test_distinct_fixes_counts_classes_not_findings(self):
        findings = [_finding("Exposed Git Repository HEAD"),
                    _finding("Exposed Git Repository Configuration")]
        summary = remediation_summary(findings)
        self.assertEqual(summary["distinct_fixes"], 1)
        self.assertEqual(summary["findings_total"], 2)

    def test_fix_entries_carry_the_fields_the_report_prints(self):
        summary = remediation_summary([_finding("SQL Injection Anomaly")])
        for entry in summary["fixes"]:
            self.assertEqual(
                {"vuln_class", "language_label", "findings", "explanation"}, set(entry))

    def test_empty_input(self):
        summary = remediation_summary([])
        self.assertEqual(summary["findings_total"], 0)
        self.assertEqual(summary["fixes"], [])


if __name__ == "__main__":
    unittest.main()
