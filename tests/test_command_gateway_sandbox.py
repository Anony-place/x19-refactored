from pathlib import Path

from execution.command_gateway import CommandGateway
from execution.command_request import CommandRequest
from execution.policy_engine import ExecutionPolicy, PolicyEngine
from execution.sandbox import SandboxExecutor
from tools import ToolResult


class FakeExecutor:
    workspace = "/tmp/x19-test"

    def __init__(self):
        self.calls = []

    def run(self, command, timeout=120):
        self.calls.append((command, timeout))
        return ToolResult("host", "", 0)

    def resolve_tool(self, *args, **kwargs):
        return None


class FakeSandbox:
    def __init__(self):
        self.calls = []

    def run(self, command, timeout=120):
        self.calls.append((command, timeout))
        return ToolResult("sandbox", "", 0)


def test_gateway_uses_sandbox_by_default():
    host = FakeExecutor()
    sandbox = FakeSandbox()
    gateway = CommandGateway(
        host,
        policy_engine=PolicyEngine(ExecutionPolicy(allowed_targets={"example.com"})),
        sandbox=sandbox,
    )

    result = gateway.run(CommandRequest.from_shell("printf ok", target="example.com"))

    assert result.stdout == "sandbox"
    assert sandbox.calls == [("printf ok", 120)]
    assert host.calls == []


def test_gateway_host_backend_is_explicit_only():
    host = FakeExecutor()
    sandbox = FakeSandbox()
    gateway = CommandGateway(
        host,
        policy_engine=PolicyEngine(ExecutionPolicy(allowed_targets={"example.com"})),
        sandbox=sandbox,
    )

    result = gateway.run(
        CommandRequest.from_shell("printf ok", target="example.com", backend="host")
    )

    assert result.stdout == "host"
    assert host.calls == [("printf ok", 120)]
    assert sandbox.calls == []


def test_docker_cli_failure_reads_as_an_unavailable_sandbox(tmp_path: Path):
    """125 is docker's own exit code, never the command's."""
    classify = SandboxExecutor._infrastructure_failure

    assert classify(125, "Unable to find image 'x19-sandbox:latest' locally").startswith(
        "sandbox_unavailable:"
    )
    assert classify(1, "Cannot connect to the Docker daemon at unix:///var/run/docker.sock").startswith(
        "sandbox_unavailable:"
    )
    # A real command failure inside a real container must pass through untouched.
    assert classify(3, "grep: nothing matched") == ""
    assert classify(0, "") == ""


def test_an_unusable_docker_is_remembered(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("execution.sandbox.shutil.which", lambda _: "/usr/bin/docker")

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)

        class Done:
            returncode = 125
            stdout = ""
            stderr = "docker: Error response from daemon: No such image"

        return Done()

    monkeypatch.setattr("execution.sandbox.subprocess.run", fake_run)
    sandbox = SandboxExecutor(tmp_path)

    first = sandbox.run("printf ok")
    second = sandbox.run("printf ok")

    assert first.error.startswith("sandbox_unavailable:")
    assert first.error == second.error
    assert sandbox.available is False
    assert len(calls) == 1          # the dead sandbox is not retried per command
