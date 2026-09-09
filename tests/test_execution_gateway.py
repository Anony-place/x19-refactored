import tempfile
import unittest

from config import CONFIG
from execution import (
    CommandGateway,
    CommandRequest,
    ExecutionPolicy,
    GatewayExecutorAdapter,
    PolicyEngine,
    policy_from_config,
)
from tools import ToolExecutor


class CommandGatewayTests(unittest.TestCase):
    def test_gateway_delegates_allowed_request_to_legacy_executor(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway = CommandGateway(ToolExecutor(tmp))
            result = gateway.run(CommandRequest.from_shell("echo gateway-ok", timeout=5))

        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.returncode, 0)
        self.assertIn("gateway-ok", result.stdout)

    def test_adapter_preserves_legacy_tool_result_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            legacy = ToolExecutor(tmp)
            adapter = GatewayExecutorAdapter(legacy, CommandGateway(legacy))
            result = adapter.run("echo adapter-ok", timeout=5)

        self.assertEqual(result.returncode, 0)
        self.assertIn("adapter-ok", result.stdout)
        self.assertTrue(hasattr(result, "text"))

    def test_gateway_blocks_empty_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway = CommandGateway(ToolExecutor(tmp))
            result = gateway.run(CommandRequest.from_shell(""))

        self.assertFalse(result.policy.allowed)
        self.assertEqual(result.error, "policy_blocked")
        self.assertEqual(result.policy.rule, "empty_command")

    def test_policy_blocks_configured_tool(self):
        policy = ExecutionPolicy(blocked_tools={"nmap"})
        verdict = PolicyEngine(policy).evaluate(CommandRequest.from_shell("nmap -sV example.com"))

        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.rule, "blocked_tool")

    def test_policy_allows_subdomain_in_scope(self):
        policy = ExecutionPolicy(allowed_targets={"example.com"})
        request = CommandRequest.from_shell("curl -I https://api.example.com/health")
        verdict = PolicyEngine(policy).evaluate(request)

        self.assertTrue(verdict.allowed)

    def test_policy_blocks_out_of_scope_url(self):
        policy = ExecutionPolicy(allowed_targets={"example.com"})
        request = CommandRequest.from_shell("curl -I https://not-example.net/")
        verdict = PolicyEngine(policy).evaluate(request)

        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.rule, "scope")
        self.assertIn("not-example.net", verdict.reason)

    def test_policy_allows_ip_inside_allowed_cidr(self):
        policy = ExecutionPolicy(allowed_targets={"10.10.10.0/24"})
        request = CommandRequest.from_shell("nmap -sV 10.10.10.20")
        verdict = PolicyEngine(policy).evaluate(request)

        self.assertTrue(verdict.allowed)

    def test_policy_blocks_ip_outside_allowed_cidr(self):
        policy = ExecutionPolicy(allowed_targets={"10.10.10.0/24"})
        request = CommandRequest.from_shell("nmap -sV 10.10.11.20")
        verdict = PolicyEngine(policy).evaluate(request)

        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.rule, "scope")

    def test_policy_from_config_always_includes_mission_target(self):
        # Regression test (AUDIT_REPORT.md Bug #1): the mission target must be
        # in scope even when scope enforcement is disabled. An empty allowlist
        # here makes the fail-closed gateway block EVERY target-bearing
        # command, so a default-config run could not execute any recon.
        old_enforce = CONFIG.ENFORCE_SCOPE
        old_allowlist = CONFIG.SCOPE_ALLOWLIST
        try:
            CONFIG.ENFORCE_SCOPE = False
            CONFIG.SCOPE_ALLOWLIST = ""
            policy = policy_from_config("target.local")
            self.assertIn("target.local", policy.allowed_targets)

            # Out-of-scope references must still be blocked.
            verdict = PolicyEngine(policy).evaluate(
                CommandRequest.from_shell("curl http://evil.example.net/steal", target="target.local")
            )
            self.assertFalse(verdict.allowed)
            self.assertEqual(verdict.rule, "scope")

            CONFIG.ENFORCE_SCOPE = True
            CONFIG.SCOPE_ALLOWLIST = "example.com,10.0.0.0/8"
            policy = policy_from_config("target.local")
            self.assertEqual(policy.allowed_targets, {"target.local", "example.com", "10.0.0.0/8"})
        finally:
            CONFIG.ENFORCE_SCOPE = old_enforce
            CONFIG.SCOPE_ALLOWLIST = old_allowlist


class ReasoningMappingPolicyTests(unittest.TestCase):
    """TODO §5: the policy layer must verify hypothesis ↔ evidence ↔ command
    before a request reaches execution, instead of only checking scope."""

    def test_evidence_claim_without_any_grounding_is_blocked(self):
        policy = ExecutionPolicy(allowed_targets={"127.0.0.1"})
        request = CommandRequest.from_shell(
            "curl -s http://127.0.0.1/.env",
            target="127.0.0.1",
            evidence_required=True,
        )
        verdict = PolicyEngine(policy).evaluate(request)

        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.rule, "evidence_claim")

    def test_expected_evidence_without_hypothesis_is_blocked(self):
        policy = ExecutionPolicy(allowed_targets={"127.0.0.1"})
        request = CommandRequest.from_shell(
            "curl -s http://127.0.0.1/.env",
            target="127.0.0.1",
            expected_evidence="AWS_ACCESS_KEY_ID present in body",
        )
        verdict = PolicyEngine(policy).evaluate(request)

        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.rule, "evidence_claim")

    def test_full_mapping_is_allowed(self):
        policy = ExecutionPolicy(allowed_targets={"127.0.0.1"})
        request = CommandRequest.from_shell(
            "curl -s http://127.0.0.1/.env",
            target="127.0.0.1",
            hypothesis_id="h-1",
            hypothesis="Dotenv file is served by the web root",
            expected_evidence="AWS_ACCESS_KEY_ID present in body",
            evidence_required=True,
        )
        verdict = PolicyEngine(policy).evaluate(request)

        self.assertTrue(verdict.allowed)

    def test_blanket_requirement_blocks_unjustified_targeted_command(self):
        policy = ExecutionPolicy(
            allowed_targets={"127.0.0.1"}, require_hypothesis_mapping=True
        )
        request = CommandRequest.from_shell(
            "nmap -sV 127.0.0.1", target="127.0.0.1"
        )
        verdict = PolicyEngine(policy).evaluate(request)

        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.rule, "hypothesis_mapping")

    def test_blanket_requirement_still_lets_local_commands_through(self):
        policy = ExecutionPolicy(
            allowed_targets={"127.0.0.1"}, require_hypothesis_mapping=True
        )
        verdict = PolicyEngine(policy).evaluate(
            CommandRequest.from_shell("echo hi", timeout=5)
        )

        self.assertTrue(verdict.allowed)

    def test_scope_failure_wins_over_missing_mapping(self):
        policy = ExecutionPolicy(
            allowed_targets={"127.0.0.1"}, require_hypothesis_mapping=True
        )
        verdict = PolicyEngine(policy).evaluate(
            CommandRequest.from_shell("nmap -sV 10.9.9.9", target="10.9.9.9")
        )

        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.rule, "scope")

    def test_gateway_forwards_hypothesis_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway = CommandGateway(ToolExecutor(tmp))
            result = gateway.run_shell(
                "echo mapped-ok",
                timeout=5,
                hypothesis_id="h-7",
                hypothesis="banner is spoofable",
                expected_evidence="string 'mapped-ok'",
                evidence_required=True,
            )

        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.request.hypothesis_id, "h-7")
        self.assertEqual(result.request.hypothesis, "banner is spoofable")
        self.assertEqual(result.request.expected_evidence, "string 'mapped-ok'")
        self.assertTrue(result.request.evidence_required)


if __name__ == "__main__":
    unittest.main()
