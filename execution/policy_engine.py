from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Iterable, Set
from urllib.parse import urlparse

from config import CONFIG
from execution.command_request import CommandRequest, PolicyVerdict


@dataclass(frozen=True)
class ExecutionPolicy:
    """Policy options for the command gateway.

    Empty allowlists preserve legacy behavior. Supplying allowed_targets turns
    on scope enforcement for hosts, IPs, CIDRs, and URLs found in commands.
    """

    allowed_targets: Set[str] = field(default_factory=set)
    blocked_tools: Set[str] = field(default_factory=set)
    allow_raw_shell: bool = True
    max_timeout: int = 3600


class PolicyEngine:
    def __init__(self, policy: ExecutionPolicy | None = None):
        self.policy = policy or ExecutionPolicy()

    def evaluate(self, request: CommandRequest) -> PolicyVerdict:
        if not request.command.strip():
            return PolicyVerdict(False, "empty command", "empty_command")
        if not self.policy.allow_raw_shell:
            return PolicyVerdict(False, "raw shell execution disabled", "raw_shell_disabled")
        if request.timeout > self.policy.max_timeout:
            return PolicyVerdict(False, f"timeout exceeds max {self.policy.max_timeout}s", "timeout")
        if request.tool and request.tool.lower() in self.policy.blocked_tools:
            return PolicyVerdict(False, f"tool '{request.tool}' is blocked", "blocked_tool")

        if self.policy.allowed_targets:
            outside = sorted(self._out_of_scope_refs(request))
            if outside:
                return PolicyVerdict(False, f"out-of-scope reference(s): {', '.join(outside[:5])}", "scope")

        return PolicyVerdict(True)

    def _out_of_scope_refs(self, request: CommandRequest) -> Set[str]:
        refs = self._extract_refs(request.command)
        if request.target:
            refs.add(request.target)
        return {ref for ref in refs if not self._is_allowed(ref)}

    def _is_allowed(self, ref: str) -> bool:
        normalized = self._normalize_ref(ref)
        if not normalized:
            return True

        for allowed in self.policy.allowed_targets:
            candidate = self._normalize_ref(allowed)
            if not candidate:
                continue
            if normalized == candidate:
                return True
            if self._ip_in_network(normalized, candidate):
                return True
            if normalized.endswith("." + candidate):
                return True
        return False

    @staticmethod
    def _normalize_ref(ref: str) -> str:
        value = (ref or "").strip().strip("'\"").lower()
        if not value:
            return ""
        try:
            ipaddress.ip_network(value, strict=False)
            return value
        except ValueError:
            pass
        parsed = urlparse(value if "://" in value else f"//{value}")
        host = parsed.hostname or value.split("/", 1)[0]
        return host.strip("[]").rstrip(".")

    @staticmethod
    def _ip_in_network(ref: str, allowed: str) -> bool:
        try:
            ip = ipaddress.ip_address(ref)
        except ValueError:
            return False
        try:
            network = ipaddress.ip_network(allowed, strict=False)
        except ValueError:
            return False
        return ip in network

    @classmethod
    def _extract_refs(cls, command: str) -> Set[str]:
        refs: Set[str] = set()
        for match in re.findall(r"https?://[^\s'\"<>]+", command or "", flags=re.I):
            refs.add(match)

        for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", command or ""):
            refs.add(match)

        for token in cls._shell_tokens(command):
            if cls._looks_like_host(token):
                refs.add(token)
        return refs

    @staticmethod
    def _shell_tokens(command: str) -> Iterable[str]:
        return re.findall(r"[A-Za-z0-9][A-Za-z0-9_.:-]+\.[A-Za-z]{2,}(?::\d+)?", command or "")

    @staticmethod
    def _looks_like_host(token: str) -> bool:
        if token.startswith("-"):
            return False
        return "." in token and not token.endswith((".txt", ".json", ".xml", ".log", ".py", ".sh"))


def policy_from_config(target: str = "") -> ExecutionPolicy:
    """Build an execution policy from global config.

    Scope enforcement is opt-in for compatibility. When enabled, the mission
    target is automatically included alongside X19_SCOPE_ALLOWLIST entries.
    """

    allowed = set()
    if CONFIG.ENFORCE_SCOPE:
        if target:
            allowed.add(target)
        for item in (CONFIG.SCOPE_ALLOWLIST or "").split(","):
            item = item.strip()
            if item:
                allowed.add(item)
    return ExecutionPolicy(allowed_targets=allowed)
