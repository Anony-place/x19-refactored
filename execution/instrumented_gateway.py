"""Telemetry-aware execution gateway wrapper.

The underlying CommandGateway remains the sole policy/execution authority.
This wrapper observes requests/results for coverage, trajectory and target
health; it cannot authorize or execute anything outside the underlying gate.
"""
from __future__ import annotations

from typing import Optional

from execution.command_gateway import CommandGateway as _CommandGateway, GatewayExecutorAdapter
from execution.command_request import CommandRequest, CommandResult
from execution.policy_engine import PolicyEngine
from execution.sandbox import SandboxExecutor
from tools import ToolExecutor
from brain.assessment_telemetry import AssessmentTelemetry


class CommandGateway(_CommandGateway):
    def __init__(
        self,
        executor: ToolExecutor,
        policy_engine: Optional[PolicyEngine] = None,
        sandbox: Optional[SandboxExecutor] = None,
        target: str = "",
        scope_guard=None,
    ):
        # 2026: propagate scope_guard to underlying gateway (hard scope on main loop)
        super().__init__(executor, policy_engine=policy_engine, sandbox=sandbox, target=target, scope_guard=scope_guard)
        self.telemetry = AssessmentTelemetry()

    def run(self, request: CommandRequest) -> CommandResult:
        self.telemetry.record_start(request)
        result = super().run(request)
        self.telemetry.record_result(result)
        return result

    @property
    def coverage(self):
        return self.telemetry.coverage

    @property
    def target_health(self):
        return self.telemetry.health

    @property
    def trajectory(self):
        return self.telemetry.events

    def telemetry_context(self) -> str:
        return self.telemetry.context_block()

    def telemetry_snapshot(self) -> dict:
        return self.telemetry.to_dict()


__all__ = ["CommandGateway", "GatewayExecutorAdapter"]
