"""
X19 Scope Control — explicit scope definition and enforcement.

Every mission must have explicit scope:
- target, authorized domains/IPs, excluded assets
- allowed actions, prohibited actions
- time/budget limits, concurrency limits

Boss enforces before delegating. Default to authorized program scope.
Never silently expand scope.

Uses Hermes approval system for high-impact actions.
"""

from __future__ import annotations

import re
import ipaddress
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple, Any
from datetime import datetime, timedelta
from enum import Enum


class ActionRisk(str, Enum):
    """Risk level for actions."""

    LOW = "low"  # Read-only GETs, header analysis, endpoint discovery
    MEDIUM = "medium"  # Witness payloads, auth tests with minimal proof
    HIGH = "high"  # Destructive payloads, auth bypass attempts, cloud metadata probing, production testing
    CRITICAL = "critical"  # Data deletion, DoS, accessing other users' PII beyond minimal proof


# Default allowed actions (low-risk recon)
DEFAULT_ALLOWED_ACTIONS = [
    "read_only_get",
    "header_analysis",
    "endpoint_discovery",
    "tech_fingerprint",
    "subdomain_enum",
]

# Default prohibited actions (high-risk, require approval)
DEFAULT_PROHIBITED_ACTIONS = [
    "destructive_payload",
    "data_deletion",
    "dos",
    "brute_force",
    "cloud_metadata_probing",
    "access_other_user_pii_beyond_minimal",
    "production_testing_without_approval",
    "bypass_rate_limits",
]

# High-impact actions requiring human approval
HIGH_IMPACT_ACTIONS = [
    "destructive_payload",
    "auth_bypass_attempt",
    "cloud_metadata_probing",
    "production_testing",
    "brute_force",
    "access_other_user_data",
    "cloud_api_calls",
    "open_port_scanning",
]


@dataclass
class ScopeDefinition:
    """Explicit scope for a mission."""

    # Target
    target: str  # Primary target: e.g., "https://target.com" or "target.com"
    authorized_domains: List[str] = field(default_factory=list)  # e.g., ["target.com", "*.target.com"]
    authorized_ips: List[str] = field(default_factory=list)  # e.g., ["1.2.3.4", "1.2.3.0/24"]
    authorized_ranges: List[str] = field(default_factory=list)  # CIDR ranges

    # Exclusions
    excluded_assets: List[str] = field(default_factory=list)  # e.g., ["/admin", "api.internal.com"]
    excluded_ips: List[str] = field(default_factory=list)

    # Actions
    allowed_actions: List[str] = field(default_factory=lambda: DEFAULT_ALLOWED_ACTIONS.copy())
    prohibited_actions: List[str] = field(default_factory=lambda: DEFAULT_PROHIBITED_ACTIONS.copy())

    # Limits
    time_limit_seconds: Optional[int] = None  # e.g., 3600 for 1 hour
    budget_limit_tokens: Optional[int] = None
    concurrency_limit: int = 3  # Max concurrent tasks (matches delegation.max_concurrent_children)
    rate_limit_ms: int = 200  # ms between active requests per host

    # Metadata
    program_name: Optional[str] = None  # Bug-bounty program name
    program_url: Optional[str] = None
    authorization_source: str = "operator"  # operator, program, config
    created_at: datetime = field(default_factory=datetime.utcnow)
    created_by: str = "operator"

    # Validation
    validated: bool = False
    validation_errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for persistence."""
        return {
            "target": self.target,
            "authorized_domains": self.authorized_domains,
            "authorized_ips": self.authorized_ips,
            "authorized_ranges": self.authorized_ranges,
            "excluded_assets": self.excluded_assets,
            "excluded_ips": self.excluded_ips,
            "allowed_actions": self.allowed_actions,
            "prohibited_actions": self.prohibited_actions,
            "time_limit_seconds": self.time_limit_seconds,
            "budget_limit_tokens": self.budget_limit_tokens,
            "concurrency_limit": self.concurrency_limit,
            "rate_limit_ms": self.rate_limit_ms,
            "program_name": self.program_name,
            "program_url": self.program_url,
            "authorization_source": self.authorization_source,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "validated": self.validated,
            "validation_errors": self.validation_errors,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScopeDefinition":
        """Create from dict."""
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            try:
                created_at = datetime.fromisoformat(created_at)
            except Exception:
                created_at = datetime.utcnow()
        elif not isinstance(created_at, datetime):
            created_at = datetime.utcnow()

        return cls(
            target=data.get("target", ""),
            authorized_domains=data.get("authorized_domains", []),
            authorized_ips=data.get("authorized_ips", []),
            authorized_ranges=data.get("authorized_ranges", []),
            excluded_assets=data.get("excluded_assets", []),
            excluded_ips=data.get("excluded_ips", []),
            allowed_actions=data.get("allowed_actions", DEFAULT_ALLOWED_ACTIONS.copy()),
            prohibited_actions=data.get("prohibited_actions", DEFAULT_PROHIBITED_ACTIONS.copy()),
            time_limit_seconds=data.get("time_limit_seconds"),
            budget_limit_tokens=data.get("budget_limit_tokens"),
            concurrency_limit=data.get("concurrency_limit", 3),
            rate_limit_ms=data.get("rate_limit_ms", 200),
            program_name=data.get("program_name"),
            program_url=data.get("program_url"),
            authorization_source=data.get("authorization_source", "operator"),
            created_at=created_at,
            created_by=data.get("created_by", "operator"),
            validated=data.get("validated", False),
            validation_errors=data.get("validation_errors", []),
        )


class ScopeEnforcer:
    """Enforces scope before delegation and during execution."""

    def __init__(self, scope: ScopeDefinition):
        self.scope = scope
        self._domain_patterns: List[re.Pattern] = []
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile authorized domain patterns for matching."""
        for domain in self.scope.authorized_domains:
            # Handle wildcard: *.target.com
            if domain.startswith("*."):
                base = re.escape(domain[2:])
                pattern = re.compile(rf"^(.+\.)?{base}$", re.IGNORECASE)
            else:
                pattern = re.compile(rf"^{re.escape(domain)}$", re.IGNORECASE)
            self._domain_patterns.append(pattern)

    def is_domain_authorized(self, domain: str) -> bool:
        """Check if domain is authorized."""
        # Direct match or wildcard
        for pattern in self._domain_patterns:
            if pattern.match(domain):
                return True

        # Check if target itself is authorized
        if self.scope.target and domain in self.scope.target:
            return True

        # If no authorized domains specified, default to target only
        if not self.scope.authorized_domains:
            return domain in self.scope.target or self.scope.target in domain

        return False

    def is_ip_authorized(self, ip: str) -> bool:
        """Check if IP is authorized."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Check explicit IPs
            for auth_ip in self.scope.authorized_ips:
                try:
                    if ipaddress.ip_address(auth_ip) == ip_obj:
                        return True
                except ValueError:
                    continue

            # Check ranges
            for range_str in self.scope.authorized_ranges:
                try:
                    network = ipaddress.ip_network(range_str, strict=False)
                    if ip_obj in network:
                        return True
                except ValueError:
                    continue

            return False
        except ValueError:
            return False

    def is_asset_excluded(self, asset: str) -> bool:
        """Check if asset is excluded."""
        for excluded in self.scope.excluded_assets:
            if excluded in asset or asset in excluded:
                return True
            # Wildcard handling
            if excluded.startswith("*") and asset.endswith(excluded[1:]):
                return True
            if excluded.endswith("*") and asset.startswith(excluded[:-1]):
                return True
        return False

    def is_action_allowed(self, action: str) -> bool:
        """Check if action is allowed."""
        if action in self.scope.prohibited_actions:
            return False
        if action in self.scope.allowed_actions:
            return True
        # Default deny for unknown high-impact actions
        if action in HIGH_IMPACT_ACTIONS:
            return False
        # Allow low-risk by default if not explicitly prohibited
        return True

    def requires_approval(self, action: str) -> bool:
        """Check if action requires human approval."""
        return action in HIGH_IMPACT_ACTIONS or action in self.scope.prohibited_actions

    def validate_target(self, target: str) -> Tuple[bool, str]:
        """Validate if target is within scope."""
        # Check excluded first
        if self.is_asset_excluded(target):
            return False, f"Target {target} is excluded by scope"

        # Check domain authorization
        # Extract domain from URL if present
        domain = target
        if "://" in target:
            try:
                domain = target.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
            except Exception:
                domain = target

        if self.scope.authorized_domains:
            if not self.is_domain_authorized(domain):
                # Also check IP
                try:
                    ipaddress.ip_address(domain)
                    if not self.is_ip_authorized(domain):
                        return False, f"Domain/IP {domain} not in authorized list"
                except ValueError:
                    return False, f"Domain {domain} not in authorized domains: {self.scope.authorized_domains}"

        # Check IP authorization if target is IP
        try:
            ipaddress.ip_address(domain)
            if self.scope.authorized_ips or self.scope.authorized_ranges:
                if not self.is_ip_authorized(domain):
                    return False, f"IP {domain} not in authorized IPs/ranges"
        except ValueError:
            pass  # Not an IP, skip

        return True, "OK"

    def validate_action(self, action: str, target: str) -> Tuple[bool, str]:
        """Validate action + target against scope."""
        # Validate target first
        ok, msg = self.validate_target(target)
        if not ok:
            return False, msg

        # Validate action
        if not self.is_action_allowed(action):
            if self.requires_approval(action):
                return False, f"Action {action} requires Operator approval (high-impact)"
            return False, f"Action {action} is prohibited by scope"

        return True, "OK"

    def enforce_before_delegation(self, task_target: str, task_action: str) -> Tuple[bool, str]:
        """Enforce scope before delegating task — Boss must call this."""
        return self.validate_action(task_action, task_target)

    def get_scope_summary(self) -> str:
        """Get human-readable scope summary."""
        lines = [
            f"Target: {self.scope.target}",
            f"Authorized domains: {', '.join(self.scope.authorized_domains) or 'target only'}",
            f"Authorized IPs: {', '.join(self.scope.authorized_ips) or 'none'}",
            f"Authorized ranges: {', '.join(self.scope.authorized_ranges) or 'none'}",
            f"Excluded: {', '.join(self.scope.excluded_assets) or 'none'}",
            f"Allowed: {', '.join(self.scope.allowed_actions)}",
            f"Prohibited: {', '.join(self.scope.prohibited_actions)}",
            f"Rate limit: {self.scope.rate_limit_ms}ms",
            f"Concurrency: {self.scope.concurrency_limit}",
            f"Time limit: {self.scope.time_limit_seconds or 'none'}s",
        ]
        return "\n".join(lines)


def create_scope(
    target: str,
    authorized_domains: Optional[List[str]] = None,
    authorized_ips: Optional[List[str]] = None,
    excluded_assets: Optional[List[str]] = None,
    allowed_actions: Optional[List[str]] = None,
    prohibited_actions: Optional[List[str]] = None,
    program_name: Optional[str] = None,
    **kwargs,
) -> ScopeDefinition:
    """Create scope definition with defaults."""
    # Explicit logic: if authorized_domains provided, use it; else if target is bare domain (no ://), use [target]; else []
    if authorized_domains is not None:
        auth_domains = authorized_domains
    else:
        auth_domains = [target] if "://" not in target else []

    return ScopeDefinition(
        target=target,
        authorized_domains=auth_domains,
        authorized_ips=authorized_ips or [],
        excluded_assets=excluded_assets or [],
        allowed_actions=allowed_actions or DEFAULT_ALLOWED_ACTIONS.copy(),
        prohibited_actions=prohibited_actions or DEFAULT_PROHIBITED_ACTIONS.copy(),
        program_name=program_name,
        **kwargs,
    )


def validate_scope(scope: ScopeDefinition) -> Tuple[bool, List[str]]:
    """Validate scope definition has required fields."""
    errors = []

    if not scope.target:
        errors.append("Scope must have target")

    if not scope.authorized_domains and not scope.authorized_ips and not scope.authorized_ranges:
        # If no authorized lists, target itself is authorized — OK, but warn
        pass

    if scope.concurrency_limit < 1 or scope.concurrency_limit > 10:
        errors.append(f"Concurrency limit {scope.concurrency_limit} out of range [1,10]")

    if scope.rate_limit_ms < 0:
        errors.append(f"Rate limit {scope.rate_limit_ms} must be >=0")

    if scope.time_limit_seconds is not None and scope.time_limit_seconds <= 0:
        errors.append(f"Time limit {scope.time_limit_seconds} must be >0")

    scope.validated = len(errors) == 0
    scope.validation_errors = errors

    return scope.validated, errors
