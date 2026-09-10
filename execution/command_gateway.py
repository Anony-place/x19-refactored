from __future__ import annotations

from typing import Optional

from execution.command_request import CommandRequest, CommandResult, utc_now
from execution.policy_engine import ExecutionPolicy, PolicyEngine
from execution.sandbox import SandboxExecutor
from logging_utils import log
from tools import ToolExecutor, ToolResult


class CommandGateway:
    """Mandatory execution entry point for new architecture modules.

    Policy is evaluated first, then commands are executed in the hardened
    sandbox by default. ``backend=host`` is intentionally explicit and is not
    selected by the autonomous agent automatically.
    """

    def __init__(
        self,
        executor: ToolExecutor,
        policy_engine: Optional[PolicyEngine] = None,
        sandbox: Optional[SandboxExecutor] = None,
    ):
        self.executor = executor
        self.policy_engine = policy_engine or PolicyEngine(ExecutionPolicy())
        self.sandbox = sandbox or SandboxExecutor(executor.workspace)

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

        backend = (request.backend or "auto").strip().lower()
        if backend == "host":
            # Explicit operator-only escape hatch for compatibility/debugging.
            # Autonomous paths should remain on the default sandbox backend.
            result = self.executor.run(request.command, timeout=request.timeout)
        else:
            result = self.sandbox.run(request.command, timeout=request.timeout)

        finished = utc_now()
        log(
            f"[GATEWAY_EXIT] {request.request_id} rc={getattr(result, 'returncode', -1)} "
            f"sandbox={backend != 'host'}"
        )
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
        backend: str = "auto",
        hypothesis_id: str = "",
        hypothesis: str = "",
        expected_evidence: str = "",
        evidence_required: bool = False,
    ) -> CommandResult:
        request = CommandRequest.from_shell(
            command,
            target=target,
            timeout=timeout,
            reason=reason,
            risk=risk,
            backend=backend,
            hypothesis_id=hypothesis_id,
            hypothesis=hypothesis,
            expected_evidence=expected_evidence,
            evidence_required=evidence_required,
        )
        return self.run(request)


class GatewayExecutorAdapter:
    """ToolExecutor-compatible adapter backed by CommandGateway.

    Legacy callers keep the existing ``.run(command, timeout)`` interface while
    the gateway transparently moves execution into the sandbox.
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
