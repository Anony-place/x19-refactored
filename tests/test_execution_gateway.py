import contextlib
import os
import pathlib
import shlex
import tempfile
import unittest
from unittest import mock

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


class SandboxDegradationTests(unittest.TestCase):
    """A docker CLI that cannot run the image must not eat the command.

    ``docker run`` reports its *own* failures — image missing, daemon
    unreachable — with exit status 125. The gateway used to hand that back as if
    it were the exit status of the command, so on any machine with a docker CLI
    but no locally built ``x19-sandbox`` image (a fresh install, a CI runner)
    every tool call died with rc=125 and the reasoning loop could never gather
    evidence: hypotheses stayed TESTING forever.

    These tests put a real fake docker executable on PATH instead of mocking
    subprocess, because the bug lives in how a real exit status is interpreted.
    """

    IMAGE_MISSING = (
        "Unable to find image 'x19-sandbox:latest' locally\n"
        "docker: Error response from daemon: No such image: x19-sandbox:latest\n"
    )

    @staticmethod
    @contextlib.contextmanager
    def docker_cli(exit_code: int, stdout: str = "", stderr: str = ""):
        """A throwaway `docker` on PATH that exits the way the real CLI would."""
        with tempfile.TemporaryDirectory() as bin_dir:
            root = pathlib.Path(bin_dir)
            invocations = root / "invocations"
            script = root / "docker"
            body = "#!/bin/sh\n"
            body += "echo x >> %s\n" % shlex.quote(str(invocations))
            if stdout:
                body += "printf '%%s' %s\n" % shlex.quote(stdout)
            if stderr:
                body += "printf '%%s' %s >&2\n" % shlex.quote(stderr)
            body += "exit %d\n" % exit_code
            script.write_text(body)
            script.chmod(0o755)
            path = bin_dir + os.pathsep + os.environ.get("PATH", "")
            with mock.patch.dict(os.environ, {"PATH": path}):
                yield invocations

    @staticmethod
    def docker_calls(path) -> int:
        return path.read_text().count("x") if path.exists() else 0

    def test_unusable_sandbox_degrades_to_the_host_executor(self):
        with self.docker_cli(125, stderr=self.IMAGE_MISSING) as calls:
            with tempfile.TemporaryDirectory() as tmp:
                gateway = CommandGateway(ToolExecutor(tmp))
                self.assertTrue(gateway.sandbox.available)   # the CLI is there
                result = gateway.run(CommandRequest.from_shell("echo gateway-ok", timeout=5))
                used_docker = self.docker_calls(calls)

        self.assertTrue(result.policy.allowed)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("gateway-ok", result.stdout)
        self.assertEqual(used_docker, 1)

    def test_a_broken_sandbox_is_remembered_instead_of_retried_per_command(self):
        with self.docker_cli(125, stderr=self.IMAGE_MISSING) as calls:
            with tempfile.TemporaryDirectory() as tmp:
                gateway = CommandGateway(ToolExecutor(tmp))
                first = gateway.run(CommandRequest.from_shell("echo one", timeout=5))
                second = gateway.run(CommandRequest.from_shell("echo two", timeout=5))

                self.assertEqual((first.returncode, second.returncode), (0, 0))
                self.assertIn("two", second.stdout)
                self.assertFalse(gateway.sandbox.available)
                self.assertIn("125", gateway.sandbox.unavailable_reason)
                # the loop must not pay for a dead container on every command
                self.assertEqual(self.docker_calls(calls), 1)

    def test_a_working_sandbox_still_wins_over_the_host(self):
        with self.docker_cli(0, stdout="sandbox-ok") as calls:
            with tempfile.TemporaryDirectory() as tmp:
                gateway = CommandGateway(ToolExecutor(tmp))
                result = gateway.run(CommandRequest.from_shell("echo gateway-ok", timeout=5))

                self.assertEqual(result.returncode, 0)
                self.assertIn("sandbox-ok", result.stdout)
                self.assertNotIn("gateway-ok", result.stdout)   # host never ran
                self.assertTrue(gateway.sandbox.available)
                self.assertEqual(self.docker_calls(calls), 1)

    def test_a_command_failing_inside_the_sandbox_keeps_its_own_exit_code(self):
        with self.docker_cli(3, stderr="grep: nothing matched") as calls:
            with tempfile.TemporaryDirectory() as tmp:
                gateway = CommandGateway(ToolExecutor(tmp))
                result = gateway.run(CommandRequest.from_shell("echo gateway-ok", timeout=5))

                # 3 is the command's verdict, not docker's — no silent host re-run
                self.assertEqual(result.returncode, 3)
                self.assertIn("nothing matched", result.stderr)
                self.assertTrue(gateway.sandbox.available)
                self.assertEqual(self.docker_calls(calls), 1)

    def test_an_unreachable_daemon_is_also_an_unavailable_sandbox(self):
        stderr = "Cannot connect to the Docker daemon at unix:///var/run/docker.sock."
        with self.docker_cli(1, stderr=stderr):
            with tempfile.TemporaryDirectory() as tmp:
                gateway = CommandGateway(ToolExecutor(tmp))
                result = gateway.run(CommandRequest.from_shell("echo daemon-ok", timeout=5))

                self.assertEqual(result.returncode, 0)
                self.assertIn("daemon-ok", result.stdout)
                self.assertIn("Cannot connect", gateway.sandbox.unavailable_reason)
