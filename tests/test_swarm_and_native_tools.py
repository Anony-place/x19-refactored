"""
Unit & Integration Tests for X19 Swarm Coordinator, Scope Guard,
Native In-Process Security Tools, and Self-Adaptation Engine.
"""

import unittest
from execution.scope_guard import ScopeGuard, ScopeViolationError
from execution.native_net import NativeNetScanner, PortResult
from execution.native_fuzzer import NativeWebFuzzer
from execution.native_vuln import NativeVulnEngine, VulnerabilityFinding
from brain.coordinator import SwarmCoordinator
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


class NativeToolTests(unittest.TestCase):
    def test_scanner_initialization(self):
        guard = ScopeGuard(allowed_targets={"127.0.0.1"}, enforce=True)
        scanner = NativeNetScanner(scope_guard=guard, timeout=0.2)
        self.assertEqual(scanner.scope_guard, guard)

    def test_fuzzer_initialization(self):
        guard = ScopeGuard(allowed_targets={"127.0.0.1"}, enforce=True)
        fuzzer = NativeWebFuzzer(scope_guard=guard, timeout=0.2)
        self.assertEqual(fuzzer.scope_guard, guard)

    def test_vuln_engine_initialization(self):
        guard = ScopeGuard(allowed_targets={"127.0.0.1"}, enforce=True)
        engine = NativeVulnEngine(scope_guard=guard, timeout=0.2)
        self.assertEqual(engine.scope_guard, guard)


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
