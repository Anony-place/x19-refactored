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
    """Fail-closed policy for the command gateway.

    An empty target allowlist is intentionally *not* permissive. A mission must
    explicitly establish an authorized target before network-capable execution
    is allowed. This keeps the policy boundary independent of LLM decisions.
    """

    allowed_targets: Set[str] = field(default_factory=set)
    blocked_tools: Set[str] = field(default_factory=set)
    allow_raw_shell: bool = True
    max_timeout: int = 3600
    #: Every targeted command must name the hypothesis it tests and the
    #: evidence that would confirm it. Off by default so a mission started
    #: before the planner is wired keeps running; an engagement profile turns
    #: it on to make unjustified actions a hard failure instead of a log line.
    require_hypothesis_mapping: bool = False
    #: A request may not claim it produced evidence without citing what that
    #: evidence is. Cheap honesty check on the planner's own output.
    enforce_evidence_claims: bool = True


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

        # Scope is mandatory for commands that carry a target or network-like
        # reference. Do not silently fall back to legacy permissive behavior.
        refs = self._extract_refs(request.command)
        if request.target:
            refs.add(request.target)
        if not self.policy.allowed_targets:
            if refs:
                return PolicyVerdict(False, "no authorized scope configured", "scope_required")
            return PolicyVerdict(True, rule="non_targeted_command")

        outside = sorted(ref for ref in refs if not self._is_allowed(ref))
        if outside:
            return PolicyVerdict(
                False,
                f"out-of-scope reference(s): {', '.join(outside[:5])}",
                "scope",
            )

        # Hypothesis ↔ expected-evidence ↔ command mapping. The gateway is the
        # last deterministic place to refuse an action that no hypothesis
        # predicted, so an ungrounded probe never reaches the target.
        verdict = self._evaluate_reasoning(request, targeted=bool(refs or request.target))
        if verdict is not None:
            return verdict

        return PolicyVerdict(True, rule="scope")

    def _evaluate_reasoning(
        self, request: CommandRequest, *, targeted: bool
    ) -> "PolicyVerdict | None":
        """Return a blocking verdict, or None when the mapping is satisfied."""
        hypothesis = (request.hypothesis or "").strip()
        hypothesis_id = (request.hypothesis_id or "").strip()
        evidence = (request.expected_evidence or "").strip()

        if request.evidence_required and not hypothesis and not evidence:
            return PolicyVerdict(
                False,
                "request asserts evidence_required but cites no hypothesis or "
                "expected evidence",
                "evidence_claim",
            )

        if self.policy.enforce_evidence_claims and evidence and not hypothesis:
            return PolicyVerdict(
                False,
                "expected_evidence given without the hypothesis it would confirm",
                "evidence_claim",
            )

        if self.policy.require_hypothesis_mapping and targeted:
            if not hypothesis:
                return PolicyVerdict(
                    False,
                    "targeted command has no hypothesis; planner must justify "
                    "every action against current world-model state",
                    "hypothesis_mapping",
                )
            if not evidence:
                return PolicyVerdict(
                    False,
                    f"hypothesis {hypothesis_id or '(unnamed)'} declares no "
                    "expected evidence; nothing to verify the result against",
                    "hypothesis_mapping",
                )
        return None

    def _is_allowed(self, ref: str) -> bool:
        normalized = self._normalize_ref(ref)
        if not normalized:
            return False

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

    #: A dotted quad counts as a network destination only when it stands alone
    #: as an argument. The lookbehind/lookahead matter: `_execute_and_store`
    #: decorates every curl with a browser UA containing `Chrome/120.0.0.0`, the
    #: old backslash-b anchored regex matched that version as an IP, and the scope check
    #: then refused the command as out-of-scope — blocking the agent's single
    #: most common action against its own assigned target.
    #:
    #: URLs are still scanned across the whole command (including flag values),
    #: so hiding an endpoint inside `--header` or `--data` does not skip the check.
    _BARE_IP = re.compile(r"(?<![\w.\-/])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.\-])")

    @staticmethod
    def _plausible_address(candidate: str) -> bool:
        """Reject version strings and bind-any addresses that are not targets."""
        head = candidate.split("/")[0]
        try:
            octets = [int(part) for part in head.split(".")]
        except ValueError:
            return False
        if len(octets) != 4 or any(octet > 255 for octet in octets):
            return False
        return head != "0.0.0.0"

    #: Scheme prefixes are removed before the bare-IP scan so a destination
    #: smuggled into a query string (`/r?to=http://91.99.0.1/x`) is still seen as
    #: a host, while `Chrome/120.0.0.0` in a User-Agent keeps its disqualifying
    #: `/` lookbehind.
    _SCHEME = re.compile(r"https?://", re.I)

    @classmethod
    def _extract_refs(cls, command: str) -> Set[str]:
        refs: Set[str] = set()
        text = command or ""

        for match in re.findall(r"https?://[^\s'\"<>]+", text, flags=re.I):
            refs.add(match)

        for match in cls._BARE_IP.findall(cls._SCHEME.sub("", text)):
            if cls._plausible_address(match):
                refs.add(match)

        for token in cls._shell_tokens(text):
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
    """Build an execution policy from the current mission scope.

    The mission target is always in scope: the mission is explicitly started
    against it by the operator after validate_target() confirmation, so a
    fail-closed gateway must not also block the target the user asked for.
    Additional scope entries come from SCOPE_ALLOWLIST whenever configured.
    Out-of-scope references remain blocked either way.
    """

    allowed: Set[str] = set()
    if target:
        allowed.add(target)
    for item in (CONFIG.SCOPE_ALLOWLIST or "").split(","):
        item = item.strip()
        if item:
            allowed.add(item)
    return ExecutionPolicy(allowed_targets=allowed)
