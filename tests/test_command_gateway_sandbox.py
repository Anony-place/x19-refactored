from execution.command_gateway import CommandGateway
from execution.command_request import CommandRequest
from execution.policy_engine import ExecutionPolicy, PolicyEngine
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
