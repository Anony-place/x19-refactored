import unittest

from brain.context_builder import (
    cve_context_block,
    session_outcomes_context,
    tool_failure_context,
    false_claim_context,
)


class FakeModel:
    ports = [{"service": "nginx", "product": "nginx"}, {"service": "OpenSSH"}]
    tech_stack = {"nginx": "1.18"}


class CveContextBlockTests(unittest.TestCase):
    def test_returns_empty_for_unknown_services(self):
        class EmptyModel:
            ports = []
            tech_stack = {}
        self.assertEqual(cve_context_block(EmptyModel()), "")

    def test_returns_cves_for_nginx(self):
        model = FakeModel()
        result = cve_context_block(model)
        self.assertIn("nginx", result)
        self.assertIn("CVE-2023-44487", result)


class SessionOutcomesTests(unittest.TestCase):
    def test_empty_when_no_outcomes(self):
        self.assertEqual(session_outcomes_context([]), "")

    def test_formats_outcomes(self):
        outcomes = [{"status": "ok", "technique": "nmap", "service": "web", "target": "10.0.0.1", "note": "found 3 ports"}]
        result = session_outcomes_context(outcomes)
        self.assertIn("[ok]", result)
        self.assertIn("nmap", result)
        self.assertIn("10.0.0.1", result)


class ToolFailureContextTests(unittest.TestCase):
    def test_empty_when_no_broken_tools(self):
        self.assertEqual(tool_failure_context([], {}), "")

    def test_lists_broken_tools_with_counts(self):
        broken = ["nmap"]
        counts = {"nmap:timeout": 5, "nmap:permission denied": 2}
        result = tool_failure_context(broken, counts)
        self.assertIn("nmap", result)
        self.assertIn("timeout(5x)", result)


class FalseClaimContextTests(unittest.TestCase):
    def test_empty_when_no_false_claims(self):
        self.assertEqual(false_claim_context([]), "")

    def test_lists_urls_with_404_warning(self):
        urls = ["http://evil.com/shell.jsp", "http://evil.com/admin.php"]
        result = false_claim_context(urls)
        self.assertIn("404/410", result)
        self.assertIn("/shell.jsp", result)


if __name__ == "__main__":
    unittest.main()
