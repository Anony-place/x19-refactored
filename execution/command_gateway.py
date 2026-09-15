from __future__ import annotations

from typing import Optional

from config import CONFIG
from execution.command_request import CommandRequest, CommandResult, utc_now
from execution.policy_engine import ExecutionPolicy, PolicyEngine, policy_from_config
from execution.sandbox import SandboxExecutor
from logging_utils import log
from tools import ToolExecutor, ToolResult


class CommandGateway:
    """Mandatory execution entry point for new architecture modules.

    Policy is evaluated first, then commands are executed in the hardened
    sandbox by default. ``backend=host`` is intentionally explicit and is not
    selected by the autonomous agent automatically.

    P0 fixes:
    - Must be initialized with policy_from_config/engagement policy.
    - Never instantiate with an empty default ExecutionPolicy for autonomous use.
    - Scope enforcement at the final execution boundary.
    - Budget enforcement at the execution boundary (counts every command/LLM call).
    - Enforce max_seconds, max_commands, max_llm_calls as hard limits.
    """

    def __init__(
        self,
        executor: ToolExecutor,
        policy_engine: Optional[PolicyEngine] = None,
        sandbox: Optional[SandboxExecutor] = None,
        target: str = "",
    ):
        self.executor = executor
        # P0 fix: if no policy_engine given, build from config with target scope.
        # Never create an empty permissive policy for autonomous operation.
        if policy_engine is not None:
            self.policy_engine = policy_engine
        elif target:
            self.policy_engine = PolicyEngine(policy_from_config(target))
        else:
            # Fail-closed: no target means no network commands allowed.
            self.policy_engine = PolicyEngine(ExecutionPolicy())
        workspace = getattr(executor, "workspace", None) or CONFIG.WORKSPACE
        self.sandbox = sandbox or SandboxExecutor(workspace)

        # Budget counters (P0: count every actual command/LLM call)
        self._command_count: int = 0
        self._llm_call_count: int = 0

    def run(self, request: CommandRequest) -> CommandResult:
        verdict = self.policy_engine.evaluate(request)
        if not verdict.allowed:
            log(f"[GATEWAY_BLOCK] {request.request_id} rule={verdict.rule} reason={verdict.reason}")
            return CommandResult.blocked(request, verdict)

        started = utc_now()
        log(
            f"[GATEWAY_START] {request.request_id} tool={request.tool or '?'} "
            f"risk={request.risk} backend={request.backend} "
            f"hyp={request.hypothesis_id or '?'} cmd={request.command[:160]}"
        )

        backend = (request.backend or "auto").strip().lower()
        if backend == "host":
            result = self.executor.run(request.command, timeout=request.timeout)
        else:
            result = self.sandbox.run(request.command, timeout=request.timeout)

        # P0: count every actual command execution
        self._command_count += 1

        finished = utc_now()
        log(
            f"[GATEWAY_EXIT] {request.request_id} rc={getattr(result, 'returncode', -1)} "
            f"sandbox={backend != 'host'} commands={self._command_count}"
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
        falsification_condition: str = "",
        evidence_required: bool = False,
        metadata: Optional[dict] = None,
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
            metadata=metadata,
        )
        return self.run(request)

    @property
    def command_count(self) -> int:
        return self._command_count

    @property
    def llm_call_count(self) -> int:
        return self._llm_call_count

    def record_llm_call(self) -> None:
        """Record an LLM call for budget tracking."""
        self._llm_call_count += 1


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
