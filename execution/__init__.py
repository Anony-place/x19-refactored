"""Typed execution compatibility layer.

The execution package starts as a wrapper around the legacy ToolExecutor. New
brain/planner modules should depend on these typed interfaces instead of raw
shell strings.
"""

from execution.command_gateway import CommandGateway, GatewayExecutorAdapter
from execution.command_request import CommandRequest, CommandResult, PolicyVerdict
from execution.policy_engine import ExecutionPolicy, PolicyEngine, policy_from_config

__all__ = [
    "CommandGateway",
    "GatewayExecutorAdapter",
    "CommandRequest",
    "CommandResult",
    "ExecutionPolicy",
    "PolicyEngine",
    "PolicyVerdict",
    "policy_from_config",
]
