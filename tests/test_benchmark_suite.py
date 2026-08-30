"""
X19 Controlled Benchmark Test Suite.
Tests autonomous reasoning, stateful web security discovery, multi-step authorization verification,
differential response analysis, hypothesis evaluation, and scope safety.
"""

import unittest
import json
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

from execution.scope_guard import ScopeGuard, ScopeViolationError
from execution.policy_engine import PolicyEngine, ExecutionPolicy, CommandRequest
from execution.native_fuzzer import NativeWebFuzzer
from execution.native_vuln import NativeVulnEngine, VulnerabilityFinding
from brain.hypothesis_engine import MultiHypothesisEngine, CompetingHypothesis
from brain.world_model import WorldModel
from brain.critic_engine import CriticEngine


class MockVulnerableAppHandler(BaseHTTPRequestHandler):
    """Mock target application representing multi-step auth, IDOR, differential behavior, and scope checks."""

    def log_message(self, format, *args):
        pass  # Suppress stderr logs during testing

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # Endpoint 1: Public info
        if path == "/" or path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><head><title>Welcome to TestApp</title></head><body><h1>TestApp Home</h1></body></html>")
            return

        # Endpoint 2: Hidden API endpoint (Discovered via fuzzing)
        if path == "/api/v1/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "version": "1.4.2"}).encode())
            return

        # Endpoint 3: BOLA / IDOR vulnerability on user profiles
        if path.startswith("/api/v1/users/"):
            user_id = path.split("/")[-1]
            auth_header = self.headers.get("Authorization", "")

            # User 101 belongs to User A (token: token-user-a)
            # User 102 belongs to User B (token: token-user-b)
            # Vulnerability: Requesting user 102 with token-user-a still returns user 102 details (IDOR)
            if user_id == "102" and "token-user-a" in auth_header:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "id": 102,
                    "username": "user_b_admin",
                    "email": "user_b@internal.local",
                    "role": "administrator",
                    "ssn": "999-00-1234",
                    "flag": "FLAG{IDOR_BOLA_VERIFIED_SUCCESS}"
                }).encode())
                return
            elif user_id == "101":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"id": 101, "username": "user_a", "email": "user_a@test.local"}).encode())
                return
            elif user_id == "102":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"id": 102, "username": "user_b_admin"}).encode())
                return

        # Endpoint 4: Response Differential / SQL Injection anomaly
        if path == "/search":
            q = query.get("q", [""])[0]
            if "' or '1'='1" in q.lower() or "1 union select" in q.lower():
                self.send_response(500)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"Syntax error in SQL statement: SELECT * FROM items WHERE name = '' or '1'='1'")
                return
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"Search completed. 0 results found.")
                return

        # Endpoint 5: SSRF / Scope redirect attempt
        if path == "/redirect":
            target = query.get("target", [""])[0]
            if target:
                self.send_response(302)
                self.send_header("Location", target)
                self.end_headers()
                return

        # Default 404
        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"404 Not Found")


class BenchmarkSuiteTests(unittest.TestCase):
    """Execution benchmark testing suite for X19."""

    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), MockVulnerableAppHandler)
        cls.port = cls.server.server_port
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_scope_guard_strict_boundary(self):
        """Verify ScopeGuard prevents out-of-scope targets and external redirects."""
        guard = ScopeGuard(allowed_targets={"127.0.0.1", "localhost"}, enforce=True)

        # In-scope targets
        self.assertTrue(guard.is_allowed_host("127.0.0.1"))
        self.assertTrue(guard.is_allowed_url(self.base_url))

        # Out-of-scope targets
        self.assertFalse(guard.is_allowed_host("evil-attacker.com"))
        self.assertFalse(guard.is_allowed_url("http://evil-attacker.com/steal"))

        # Redirect validation
        self.assertTrue(guard.validate_redirect(self.base_url, "/api/v1/health"))
        with self.assertRaises(ScopeViolationError):
            guard.validate_redirect(self.base_url, "http://evil-attacker.com/exfiltrate")

    def test_multi_hypothesis_engine_scoring(self):
        """Verify MultiHypothesisEngine prioritizes competing hypotheses correctly."""
        engine = MultiHypothesisEngine()

        h_low_gain = engine.add_hypothesis(
            title="Generic port scan",
            description="Scan common ports",
            command="nmap -F 127.0.0.1",
            confidence=0.5,
            information_gain=0.2,
            execution_cost=0.5,
            risk=0.1
        )

        h_high_gain = engine.add_hypothesis(
            title="IDOR vulnerability check on user API",
            description="Test cross-tenant object authorization",
            command=f"curl -H 'Authorization: token-user-a' {self.base_url}/api/v1/users/102",
            confidence=0.8,
            information_gain=0.9,
            execution_cost=0.1,
            risk=0.1
        )

        top_hypotheses = engine.get_competing_hypotheses(limit=2)
        self.assertEqual(len(top_hypotheses), 2)
        self.assertEqual(top_hypotheses[0].id, h_high_gain.id)
        self.assertGreater(top_hypotheses[0].priority_score, top_hypotheses[1].priority_score)

    def test_native_fuzzer_endpoint_discovery(self):
        """Test NativeWebFuzzer against local benchmark server."""
        guard = ScopeGuard(allowed_targets={"127.0.0.1"}, enforce=True)
        fuzzer = NativeWebFuzzer(scope_guard=guard)

        wordlist = ["api/v1/health", "index.html", "non_existent_path_99"]
        results = fuzzer.fuzz(self.base_url, wordlist=wordlist)

        found_paths = {r.path for r in results if r.status_code == 200}
        self.assertIn("api/v1/health", found_paths)
        self.assertIn("index.html", found_paths)
        self.assertNotIn("non_existent_path_99", found_paths)

    def test_idor_authorization_verification(self):
        """Verify BOLA / IDOR detection against mock vulnerable endpoint."""
        vuln_engine = NativeVulnEngine()
        url = f"{self.base_url}/api/v1/users/102"
        headers = {"Authorization": "Bearer token-user-a"}

        res = vuln_engine.test_idor(url, baseline_token="token-user-a", target_user_id="102", headers=headers)
        self.assertIsNotNone(res)
        if res:
            self.assertIn("IDOR", res.title.upper())
            self.assertIn("FLAG{IDOR_BOLA_VERIFIED_SUCCESS}", res.evidence)

    def test_sql_injection_differential_detection(self):
        """Verify SQL injection anomaly detection via response differential."""
        vuln_engine = NativeVulnEngine()
        target_url = f"{self.base_url}/search"

        res = vuln_engine.test_sqli(target_url, param="q")
        self.assertIsNotNone(res)
        if res:
            self.assertIn("SQL", res.title.upper())
            self.assertIn("Syntax error in SQL statement", res.evidence)


if __name__ == "__main__":
    unittest.main()
