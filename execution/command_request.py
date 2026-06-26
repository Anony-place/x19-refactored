from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class CommandRequest:
    """A typed request to execute a tool command.

    This intentionally still carries a legacy shell command so the migration can
    wrap existing behavior first. Future planners should fill in tool/args and
    let the gateway render backend-specific commands.
    """

    command: str
    tool: str = ""
    target: str = ""
    timeout: int = 120
    risk: str = "normal"
    backend: str = "auto"
    reason: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    request_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: str = field(default_factory=utc_now)

    @classmethod
    def from_shell(
        cls,
        command: str,
        *,
        target: str = "",
        timeout: int = 120,
        reason: str = "",
        risk: str = "normal",
        backend: str = "auto",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "CommandRequest":
        parts = (command or "").strip().split()
        return cls(
            command=command or "",
            tool=parts[0].lower() if parts else "",
            target=target,
            timeout=timeout,
            risk=risk,
            backend=backend,
            reason=reason,
            metadata=metadata or {},
        )


@dataclass(frozen=True)
class PolicyVerdict:
    allowed: bool
    reason: str = ""
    rule: str = ""


@dataclass(frozen=True)
class CommandResult:
    request: CommandRequest
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None
    policy: PolicyVerdict = field(default_factory=lambda: PolicyVerdict(True))
    started_at: str = ""
    finished_at: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.error and self.policy.allowed

    @property
    def text(self) -> str:
        parts = []
        if self.stdout:
            parts.append(self.stdout)
        if self.stderr:
            parts.append(f"[STDERR] {self.stderr}")
        if self.error:
            parts.append(f"[ERROR] {self.error}")
        return "\n".join(parts)

    @classmethod
    def blocked(cls, request: CommandRequest, verdict: PolicyVerdict) -> "CommandResult":
        now = utc_now()
        return cls(
            request=request,
            stderr=f"Blocked by policy: {verdict.reason}",
            returncode=-1,
            error="policy_blocked",
            policy=verdict,
            started_at=now,
            finished_at=now,
        )

    @classmethod
    def from_tool_result(
        cls,
        request: CommandRequest,
        tool_result: Any,
        *,
        policy: PolicyVerdict,
        started_at: str,
        finished_at: str,
    ) -> "CommandResult":
        return cls(
            request=request,
            stdout=getattr(tool_result, "stdout", "") or "",
            stderr=getattr(tool_result, "stderr", "") or "",
            returncode=int(getattr(tool_result, "returncode", -1)),
            error=getattr(tool_result, "error", None),
            policy=policy,
            started_at=started_at,
            finished_at=finished_at,
        )
