"""Typed execution boundary for X19 command execution."""

# The exported gateway adds observational assessment telemetry while keeping
# the original CommandGateway as the final policy/execution authority.
from execution.instrumented_gateway import CommandGateway, GatewayExecutorAdapter
from execution.command_request import CommandRequest, CommandResult, PolicyVerdict
from execution.policy_engine import ExecutionPolicy, PolicyEngine, policy_from_config
from execution.sandbox import SandboxExecutor, SandboxPolicy
from execution.memory_kernel import MemoryKernel, MemorySnapshot, MemoryItem
from execution.security_memory_v2 import SecurityMemory as LegacySecurityMemory, SecurityMemorySnapshot as LegacySecurityMemorySnapshot
from execution.security_memory_v3 import SecurityMemory, SecurityMemorySnapshot
from execution.scope_guard import ScopeGuard, ScopeViolationError
try:
    from execution.mcp_gateway import MCPGateway, ToolSpec
except Exception:
    MCPGateway = None  # type: ignore
    ToolSpec = None  # type: ignore

__all__ = [
    "CommandGateway", "GatewayExecutorAdapter", "CommandRequest", "CommandResult",
    "ExecutionPolicy", "PolicyEngine", "PolicyVerdict", "policy_from_config",
    "SandboxExecutor", "SandboxPolicy", "MemoryKernel", "MemorySnapshot", "MemoryItem",
    "SecurityMemory", "SecurityMemorySnapshot", "LegacySecurityMemory", "LegacySecurityMemorySnapshot",
    "ScopeGuard", "ScopeViolationError", "MCPGateway", "ToolSpec",
]
