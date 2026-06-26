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

    def test_policy_from_config_is_permissive_until_scope_enabled(self):
        old_enforce = CONFIG.ENFORCE_SCOPE
        old_allowlist = CONFIG.SCOPE_ALLOWLIST
        try:
            CONFIG.ENFORCE_SCOPE = False
            CONFIG.SCOPE_ALLOWLIST = "example.com"
            self.assertEqual(policy_from_config("target.local").allowed_targets, set())

            CONFIG.ENFORCE_SCOPE = True
            CONFIG.SCOPE_ALLOWLIST = "example.com,10.0.0.0/8"
            policy = policy_from_config("target.local")
            self.assertEqual(policy.allowed_targets, {"target.local", "example.com", "10.0.0.0/8"})
        finally:
            CONFIG.ENFORCE_SCOPE = old_enforce
            CONFIG.SCOPE_ALLOWLIST = old_allowlist


if __name__ == "__main__":
    unittest.main()
