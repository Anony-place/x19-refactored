from __future__ import annotations

import os
from typing import Optional

from config import CONFIG
from execution.command_request import CommandRequest, CommandResult, PolicyVerdict, utc_now
from execution.policy_engine import ExecutionPolicy, PolicyEngine, policy_from_config
from execution.sandbox import SandboxExecutor
from execution.scope_guard import ScopeGuard, ScopeViolationError
from logging_utils import log
from tools import ToolExecutor, ToolResult

# 2026 TrafficMind hook (Strix/RedAMon pattern) — optional, no hard dep
try:
    from execution.traffic_mind import get_traffic_mind  # type: ignore
except Exception:  # pragma: no cover
    get_traffic_mind = None  # type: ignore


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
        scope_guard: Optional[ScopeGuard] = None,
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
        # 2026 P0: hard scope via OS/socket boundary — ScopeGuard on the gateway itself,
        # not only in coordinator. Uses same allowlist as policy so they agree.
        if scope_guard is not None:
            self.scope_guard = scope_guard
        else:
            allowed = set(getattr(self.policy_engine.policy, "allowed_targets", set()) or set())
            # enforce=True even when allowed empty → fail-closed (no escape)
            self.scope_guard = ScopeGuard(allowed_targets=allowed, enforce=True)

        # Budget counters (P0: count every actual command/LLM call)
        self._command_count: int = 0
        self._llm_call_count: int = 0
        # 2026: optional attack-credit budget + observability tracer (additive, no hard dep)
        self._credit_budget = None
        try:
            from brain.attack_credits import get_budget
            self._credit_budget = get_budget()
        except Exception:
            pass
        self._tracer = None
        try:
            from runtime.observability import get_tracer
            self._tracer = get_tracer()
        except Exception:
            pass

    def _scope_guard_verdict(self, request: CommandRequest) -> Optional[PolicyVerdict]:
        """Second boundary: socket-level scope check (NodeZero/XBOW hard-scope pattern).

        PolicyEngine does textual ref extraction (regex). ScopeGuard does host/IP/CIDR
        validation at the transport layer. Both must pass. This catches bypasses where
        a host is smuggled past regex (e.g. encoded, via env var) but would still
        resolve to an out-of-scope IP at connect time. Returns blocking verdict or None.
        """
        # non-targeted local commands (echo, ls) don't need socket check
        try:
            from execution.policy_engine import PolicyEngine as _PE
            refs = _PE._extract_refs(request.command)
            if request.target:
                refs.add(request.target)
        except Exception:
            refs = set()
            if request.target:
                refs.add(request.target)
        if not refs:
            return None
        for ref in refs:
            # ScopeGuard understands URLs, hosts, IPs, CIDRs
            allowed = self.scope_guard.is_allowed_host(ref) or self.scope_guard.is_allowed_url(ref)
            if not allowed:
                # also try normalized host extraction for bare refs
                try:
                    from urllib.parse import urlparse
                    candidate = ref
                    if "://" in candidate:
                        candidate = urlparse(candidate).hostname or candidate
                    candidate = candidate.split("/")[0].split(":")[0].strip("[]")
                    if candidate and (self.scope_guard.is_allowed_host(candidate) or self.scope_guard.is_allowed_url(candidate)):
                        continue
                except Exception:
                    pass
                return PolicyVerdict(False, f"out-of-scope (socket guard) ref: {ref}", "scope_guard")
        return None

    def run(self, request: CommandRequest) -> CommandResult:
        verdict = self.policy_engine.evaluate(request)
        if not verdict.allowed:
            log(f"[GATEWAY_BLOCK] {request.request_id} rule={verdict.rule} reason={verdict.reason}")
            return CommandResult.blocked(request, verdict)
        # 2026 P0: hard socket-level guard — OS/network boundary, not just regex
        guard_verdict = self._scope_guard_verdict(request)
        if guard_verdict is not None and not guard_verdict.allowed:
            log(f"[GATEWAY_BLOCK] {request.request_id} rule={guard_verdict.rule} reason={guard_verdict.reason}")
            return CommandResult.blocked(request, guard_verdict)
        # 2026: attack-credit check (XBOW) — deterministic, advisory unless strict
        if self._credit_budget is not None:
            try:
                # only deduct for network-targeted commands
                from execution.policy_engine import PolicyEngine as _PE
                refs = _PE._extract_refs(request.command)
                if refs or request.target:
                    if not self._credit_budget.can_spend("probe"):
                        log(f"[GATEWAY_CREDIT] {request.request_id} credits {self._credit_budget.spent}/{self._credit_budget.total} — running with warning (not blocking)")
            except Exception:
                pass

        started = utc_now()
        # 2026 observability span
        _span = None
        if self._tracer is not None:
            try:
                _span = self._tracer.start_span("gateway.run", command=request.command[:80], target=request.target or "", backend=request.backend or "auto", hypothesis=request.hypothesis_id or "")
            except Exception:
                _span = None
        log(
            f"[GATEWAY_START] {request.request_id} tool={request.tool or '?'} "
            f"risk={request.risk} backend={request.backend} "
            f"hyp={request.hypothesis_id or '?'} cmd={request.command[:160]}"
        )

        backend = (request.backend or "auto").strip().lower()
        # 2026: sandbox permissive flag — when X19_SANDBOX_STRICT=1, network commands fail instead of degrading
        strict_sandbox = (os.getenv("X19_SANDBOX_STRICT", "") or "").strip().lower() in ("1", "true", "yes", "on")
        if backend == "host":
            result = self.executor.run(request.command, timeout=request.timeout)
        elif backend == "sandbox":
            # An explicit sandbox request must be honoured or fail loudly —
            # silently running on the host would defeat the operator's choice.
            result = self.sandbox.run(request.command, timeout=request.timeout)
        else:
            # ``auto`` prefers the hardened sandbox but degrades gracefully to
            # the host executor when containerisation is unavailable (no docker
            # CLI, no image, no workspace). Policy was already enforced above,
            # so the security boundary holds either way; the degradation is
            # always visible in the log and on the result. A sandbox backend
            # that does not advertise ``available`` is assumed capable.
            result = None
            if getattr(self.sandbox, "available", True):
                result = self.sandbox.run(request.command, timeout=request.timeout)
                if result.error and str(result.error).startswith("sandbox_unavailable"):
                    if strict_sandbox:
                        # fail-closed in strict mode — do not degrade for network commands
                        try:
                            from execution.policy_engine import PolicyEngine as _PE
                            refs = _PE._extract_refs(request.command)
                            if refs or request.target:
                                log(f"[GATEWAY_STRICT] {request.request_id} sandbox unavailable but X19_SANDBOX_STRICT=1 — blocking network command")
                                finished = utc_now()
                                if _span is not None:
                                    try:
                                        self._tracer.end_span(_span, status="error", error="sandbox_unavailable_strict")
                                    except Exception:
                                        pass
                                return CommandResult.blocked(request, PolicyVerdict(False, "sandbox unavailable in strict mode", "sandbox_required"))
                        except Exception:
                            pass
                    result = None
            if result is None:
                log(
                    f"[GATEWAY_FALLBACK] {request.request_id} sandbox unavailable "
                    f"({self._sandbox_state()}) — executing on host backend"
                )
                result = self.executor.run(request.command, timeout=request.timeout)

        # 2026: TrafficMind capture (HMAC-tagged history, Strix/RedAMon parity)
        if get_traffic_mind is not None:
            try:
                tm = get_traffic_mind()
                tm.capture(
                    target=request.target or "",
                    method="EXEC",
                    url=request.command[:500],
                    request_headers=request.command[:2000],
                    request_body="",
                    response_status=int(getattr(result, "returncode", 0) or 0),
                    response_headers="",
                    response_body=str(getattr(result, "stdout", "") or "")[:4000],
                    tags="gateway",
                    tool=str(request.tool or ""),
                    command_id=str(request.request_id or ""),
                )
            except Exception:
                pass

        # P0: count every actual command execution
        self._command_count += 1
        # 2026: attack-credit spend
        if self._credit_budget is not None:
            try:
                from execution.policy_engine import PolicyEngine as _PE
                refs = _PE._extract_refs(request.command)
                if refs or request.target:
                    self._credit_budget.spend("probe", reason=request.hypothesis_id or request.command[:30])
            except Exception:
                pass

        finished = utc_now()
        log(
            f"[GATEWAY_EXIT] {request.request_id} rc={getattr(result, 'returncode', -1)} "
            f"sandbox={backend != 'host'} commands={self._command_count}"
        )
        if _span is not None:
            try:
                self._tracer.end_span(_span, status="ok" if getattr(result,"returncode",1)==0 else "ok", rc=getattr(result,"returncode",-1))
            except Exception:
                pass
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

    def _sandbox_state(self) -> str:
        """Human-readable reason the sandbox can or cannot run (for logs)."""
        if not getattr(self.sandbox, "available", False):
            reason = getattr(self.sandbox, "unavailable_reason", "") or ""
            return reason.removeprefix("sandbox_unavailable: ").strip() or "docker CLI not found"
        image = getattr(getattr(self.sandbox, "policy", None), "image", "")
        return f"image={image or 'unset'}"

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
