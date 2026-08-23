"""
Unit tests for X19 Security Assessment & Remediation Report Generator.
"""

import unittest
import json
from execution.native_vuln import VulnerabilityFinding
from reporting.report_generator import SecurityReportGenerator


class SecurityReportGeneratorTests(unittest.TestCase):
    def setUp(self):
        self.findings = [
            VulnerabilityFinding(
                title="Exposed Environment File (.env)",
                severity="critical",
                target="http://example.com",
                endpoint="/.env",
                description="Exposed database credentials",
                evidence="DB_PASSWORD=secret",
                remediation="Restrict access to .env",
                cvss_score=9.1,
                cwe_id="CWE-200",
                poc_command="curl -sik http://example.com/.env"
            ),
            VulnerabilityFinding(
                title="Insecure CORS Policy",
                severity="high",
                target="http://example.com",
                endpoint="/",
                description="Wildcard origin with credentials",
                evidence="ACAO: *",
                remediation="Configure explicit allowed origins",
                cvss_score=7.4,
                cwe_id="CWE-942",
                poc_command="curl -sik -H 'Origin: https://evil.com' http://example.com"
            ),
            VulnerabilityFinding(
                title="Missing HTTP Security Headers",
                severity="low",
                target="http://example.com",
                endpoint="/",
                description="Missing CSP and HSTS headers",
                evidence="Headers missing",
                remediation="Add security headers in Nginx",
                cvss_score=3.5,
                cwe_id="CWE-693",
                poc_command="curl -sI http://example.com"
            )
        ]
        self.generator = SecurityReportGenerator(target="http://example.com", findings=self.findings)

    def test_stats_and_risk_score_calculation(self):
        stats = self.generator.get_stats()
        self.assertEqual(stats["critical"], 1)
        self.assertEqual(stats["high"], 1)
        self.assertEqual(stats["low"], 1)
        self.assertEqual(stats["medium"], 0)
        self.assertTrue(self.generator.calculate_risk_score() > 50.0)

    def test_markdown_generation(self):
        md = self.generator.generate_markdown()
        self.assertIn("# 🛡️ X19 Security Assessment & Remediation Report", md)
        self.assertIn("Exposed Environment File (.env)", md)
        self.assertIn("curl -sik http://example.com/.env", md)
        self.assertIn("Defensive Configuration Patch Guidance", md)

    def test_html_generation(self):
        html = self.generator.generate_html()
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("Exposed Environment File (.env)", html)
        self.assertIn("CWE-200", html)

    def test_json_generation(self):
        json_str = self.generator.generate_json()
        parsed = json.loads(json_str)
        self.assertEqual(parsed["target"], "http://example.com")
        self.assertEqual(len(parsed["findings"]), 3)


if __name__ == "__main__":
    unittest.main()
