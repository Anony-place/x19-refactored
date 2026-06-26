from __future__ import annotations

from typing import Optional

from execution.command_request import CommandRequest, CommandResult, utc_now
from execution.policy_engine import ExecutionPolicy, PolicyEngine
from logging_utils import log
from tools import ToolExecutor, ToolResult


class CommandGateway:
    """Mandatory execution entry point for new architecture modules.

    The gateway currently delegates to the legacy ToolExecutor after policy
    approval. That keeps behavior stable while giving planners a typed boundary.
    """

    def __init__(
        self,
        executor: ToolExecutor,
        policy_engine: Optional[PolicyEngine] = None,
    ):
        self.executor = executor
        self.policy_engine = policy_engine or PolicyEngine(ExecutionPolicy())

    def run(self, request: CommandRequest) -> CommandResult:
        verdict = self.policy_engine.evaluate(request)
        if not verdict.allowed:
            log(f"[GATEWAY_BLOCK] {request.request_id} rule={verdict.rule} reason={verdict.reason}")
            return CommandResult.blocked(request, verdict)

        started = utc_now()
        log(
            f"[GATEWAY_START] {request.request_id} tool={request.tool or '?'} "
            f"risk={request.risk} backend={request.backend} cmd={request.command[:160]}"
        )
        result = self.executor.run(request.command, timeout=request.timeout)
        finished = utc_now()
        log(f"[GATEWAY_EXIT] {request.request_id} rc={getattr(result, 'returncode', -1)}")
        return CommandResult.from_tool_result(
            request,
            result,
            policy=verdict,
            started_at=started,
            finished_at=finished,
        )

    def run_shell(
        self,
        command: str,
        *,
        target: str = "",
        timeout: int = 120,
        reason: str = "",
        risk: str = "normal",
    ) -> CommandResult:
        request = CommandRequest.from_shell(
            command,
            target=target,
            timeout=timeout,
            reason=reason,
            risk=risk,
        )
        return self.run(request)


class GatewayExecutorAdapter:
    """ToolExecutor-compatible adapter backed by CommandGateway.

    This lets legacy code keep calling .run(command, timeout) and .resolve_tool()
    while execution passes through typed policy/audit hooks.
    """

    def __init__(self, legacy_executor: ToolExecutor, gateway: CommandGateway):
        self.legacy_executor = legacy_executor
        self.gateway = gateway

    def run(self, command: str, timeout: int = 120) -> ToolResult:
        request = CommandRequest.from_shell(command, timeout=timeout)
        result = self.gateway.run(request)
        return ToolResult(result.stdout, result.stderr, result.returncode, result.error)

    def resolve_tool(self, tool_name: str, target: str, **kwargs):
        return self.legacy_executor.resolve_tool(tool_name, target, **kwargs)
