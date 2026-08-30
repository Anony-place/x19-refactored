"""
Unit & Integration Tests for X19 Swarm Coordinator, Task Queue, Scope Guard,
Native In-Process Security Tools, Controlled Mock Lab, and Self-Adaptation Engine.
"""

import http.server
import json
import threading
import time
import unittest
from execution.scope_guard import ScopeGuard, ScopeViolationError
from execution.native_net import NativeNetScanner, PortResult
from execution.native_fuzzer import NativeWebFuzzer
from execution.native_vuln import NativeVulnEngine, VulnerabilityFinding
from brain.coordinator import SwarmCoordinator
from brain.task_queue import TaskQueue, AgentTask, TaskStatus
from learning.self_adaptation import SelfAdaptationEngine


class ScopeGuardTests(unittest.TestCase):
    def test_scope_guard_enforces_domain_and_ip(self):
        guard = ScopeGuard(allowed_targets={"example.com", "192.168.1.10", "10.0.0.0/24"}, enforce=True)
        
        # In-scope
        self.assertTrue(guard.is_allowed_host("example.com"))
        self.assertTrue(guard.is_allowed_host("sub.example.com"))
        self.assertTrue(guard.is_allowed_host("192.168.1.10"))
        self.assertTrue(guard.is_allowed_host("10.0.0.55"))
        self.assertTrue(guard.is_allowed_url("http://example.com/api/v1"))
        self.assertTrue(guard.is_allowed_url("https://10.0.0.55:8080/admin"))

        # Out-of-scope
        self.assertFalse(guard.is_allowed_host("evil.com"))
        self.assertFalse(guard.is_allowed_host("192.168.1.11"))
        self.assertFalse(guard.is_allowed_host("172.16.0.1"))
        self.assertFalse(guard.is_allowed_url("https://malicious.org/payload"))

        # Assert allowed raises ScopeViolationError on forbidden
        with self.assertRaises(ScopeViolationError):
            guard.assert_allowed("http://unauthorized.target.com")

    def test_scope_guard_redirect_validation(self):
        guard = ScopeGuard(allowed_targets={"target.local"}, enforce=True)
        
        # Relative redirects (in-scope)
        self.assertTrue(guard.validate_redirect("http://target.local/login", "/dashboard"))
        self.assertTrue(guard.validate_redirect("http://target.local/login", "settings.php"))
        
        # Absolute in-scope redirects
        self.assertTrue(guard.validate_redirect("http://target.local/login", "http://target.local/home"))

        # Out-of-scope redirect destination must be blocked
        with self.assertRaises(ScopeViolationError):
            guard.validate_redirect("http://target.local/login", "https://attacker-phishing.com/harvest")


class TaskQueueTests(unittest.TestCase):
    def test_task_queue_priority_and_deduplication(self):
        q = TaskQueue()

        task_low = AgentTask(priority=5, task_id="t_low", task_type="web_fuzz", target="127.0.0.1")
        task_high = AgentTask(priority=1, task_id="t_high", task_type="verify", target="127.0.0.1")
        task_dup = AgentTask(priority=2, task_id="t_dup", task_type="web_fuzz", target="127.0.0.1")

        self.assertTrue(q.push(task_low))
        self.assertTrue(q.push(task_high))
        
        # Duplicate task signature should be rejected
        self.assertFalse(q.push(task_dup))

        # Highest priority (1) should pop first
        popped = q.pop()
        self.assertIsNotNone(popped)
        self.assertEqual(popped.task_id, "t_high")

        # Next is low priority (5)
        popped2 = q.pop()
        self.assertIsNotNone(popped2)
        self.assertEqual(popped2.task_id, "t_low")

    def test_task_queue_retry_and_cancellation(self):
        q = TaskQueue()
        task = AgentTask(priority=3, task_id="t_retry", task_type="vuln_audit", target="127.0.0.1", max_retries=2)
        q.push(task)

        # Pop and fail once -> should requeue
        t = q.pop()
        self.assertEqual(t.task_id, "t_retry")
        res = q.mark_failed("t_retry", "Transient timeout")
        self.assertEqual(res.retries, 1)
        self.assertEqual(res.status, TaskStatus.PENDING)

        # Pop and fail second time -> exceeds max_retries -> FAILED
        t2 = q.pop()
        res2 = q.mark_failed("t_retry", "Persistent error")
        self.assertEqual(res2.retries, 2)
        self.assertEqual(res2.status, TaskStatus.FAILED)


class ControlledMockServer(http.server.BaseHTTPRequestHandler):
    """Local mock HTTP server simulating a vulnerable application."""

    def do_GET(self):
        if self.path == "/.git/config":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"[core]\nrepositoryformatversion = 0\n")
        elif self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"DB_PASSWORD=supersecret_controlled_lab\n")
        elif self.path == "/admin":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><head><title>Admin Control</title></head><body>Admin</body></html>")
        elif self.path == "/redirect_test":
            self.send_response(302)
            self.send_header("Location", "https://example.com")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Quiet logs during test execution


class ControlledLabIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 18888), ControlledMockServer)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_native_fuzzer_against_mock_lab(self):
        guard = ScopeGuard(allowed_targets={"127.0.0.1:18888"}, enforce=True)
        fuzzer = NativeWebFuzzer(scope_guard=guard, timeout=1.0)
        results = fuzzer.fuzz("http://127.0.0.1:18888", wordlist=[".git/config", ".env", "admin", "not_exist_404"])

        found_paths = {r.path for r in results}
        self.assertIn(".git/config", found_paths)
        self.assertIn(".env", found_paths)
        self.assertIn("admin", found_paths)

    def test_native_vuln_engine_against_mock_lab(self):
        guard = ScopeGuard(allowed_targets={"127.0.0.1:18888"}, enforce=True)
        engine = NativeVulnEngine(scope_guard=guard, timeout=1.0)
        findings = engine.check_exposed_files("http://127.0.0.1:18888")

        titles = [f.title for f in findings]
        self.assertTrue(any("Git" in t for t in titles))
        self.assertTrue(any("Environment" in t for t in titles))

    def test_advanced_vuln_engine_checks(self):
        guard = ScopeGuard(allowed_targets={"127.0.0.1:18888"}, enforce=False)
        engine = NativeVulnEngine(scope_guard=guard, timeout=1.0)

        # Test methods run without exceptions
        host_findings = engine.check_host_header_injection("http://127.0.0.1:18888")
        ssrf_findings = engine.check_ssrf_heuristic("http://127.0.0.1:18888")
        ssti_findings = engine.check_ssti("http://127.0.0.1:18888")
        key_findings = engine.check_api_key_leakage("http://127.0.0.1:18888")

        self.assertIsInstance(host_findings, list)
        self.assertIsInstance(ssrf_findings, list)
        self.assertIsInstance(ssti_findings, list)
        self.assertIsInstance(key_findings, list)


class SwarmCoordinatorTests(unittest.TestCase):
    def test_coordinator_initialization_and_registration(self):
        coord = SwarmCoordinator(target="127.0.0.1")
        self.assertEqual(coord.target, "127.0.0.1")
        self.assertEqual(len(coord.agents), 5)

        # Register port
        coord.register_port("127.0.0.1", 80, "http", "Apache 2.4", {})
        self.assertEqual(len(coord.discovered_ports), 1)
        self.assertTrue(len(coord.attack_graph._nodes) >= 2)

        # Register endpoint
        coord.register_endpoint("127.0.0.1", "/admin", 200, "Admin Portal", True, "snippet")
        self.assertEqual(len(coord.discovered_endpoints), 1)

        # Register and verify finding
        finding = VulnerabilityFinding(
            title="Exposed Git Config",
            severity="high",
            target="http://127.0.0.1",
            endpoint="/.git/config",
            description="Exposed repo",
            evidence="core",
            remediation="Block access",
            cvss_score=7.5
        )
        coord.register_finding(finding)
        coord.mark_finding_verified(finding)

        summary = coord.get_summary()
        self.assertEqual(summary["stats"]["open_ports"], 1)
        self.assertEqual(summary["stats"]["endpoints"], 1)
        self.assertEqual(summary["stats"]["verified_findings"], 1)

        graph_d3 = coord.get_attack_graph_d3()
        self.assertTrue(len(graph_d3["nodes"]) >= 3)
        self.assertTrue(len(graph_d3["edges"]) >= 2)


class SelfAdaptationTests(unittest.TestCase):
    def test_self_adaptation_lessons_and_diagnostics(self):
        engine = SelfAdaptationEngine(storage_path="/tmp/test_adapt_memory.json")
        engine.record_failure_lesson("gobuster", "web", "timed_out", "Use native fuzzer with smaller batches")
        lessons = engine.get_lessons_for_target("web")
        self.assertIn("Use native fuzzer with smaller batches", lessons)

        # Diagnostics check
        diag = engine.run_self_diagnostics()
        self.assertEqual(len(diag["syntax_errors"]), 0)
        self.assertTrue(diag["health_score"] >= 80)


if __name__ == "__main__":
    unittest.main()
