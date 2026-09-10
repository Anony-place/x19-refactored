"""Typed execution boundary for X19 command execution.

New planner/brain modules should depend on this package instead of invoking
raw host subprocesses directly. The default gateway backend is sandboxed.
"""

from execution.command_gateway import CommandGateway, GatewayExecutorAdapter
from execution.command_request import CommandRequest, CommandResult, PolicyVerdict
from execution.policy_engine import ExecutionPolicy, PolicyEngine, policy_from_config
from execution.sandbox import SandboxExecutor, SandboxPolicy

__all__ = [
    "CommandGateway",
    "GatewayExecutorAdapter",
    "CommandRequest",
    "CommandResult",
    "ExecutionPolicy",
    "PolicyEngine",
    "PolicyVerdict",
    "policy_from_config",
    "SandboxExecutor",
    "SandboxPolicy",
]
