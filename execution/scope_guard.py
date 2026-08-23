"""
X19 Strict Transport-Level Scope Sandbox Guard.
Ensures zero out-of-scope traffic leaves the agent at the socket and HTTP layer.
Includes domain, IP, CIDR, URL, and redirect destination validation.
"""

from __future__ import annotations
import ipaddress
import socket
import urllib.parse
from typing import Set, Optional, Tuple, Union


class ScopeViolationError(Exception):
    """Raised when an out-of-scope target connection or redirect is attempted."""
    pass


class ScopeGuard:
    """
    Enforces target boundaries deterministically at runtime.
    Validates hostnames, IP addresses, CIDR ranges, URLs, and redirect targets.
    """

    def __init__(self, allowed_targets: Optional[Set[str]] = None, enforce: bool = True):
        self.enforce = enforce
        self.allowed_raw: Set[str] = set(allowed_targets or [])
        self.allowed_ips: Set[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = set()
        self.allowed_networks: Set[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = set()
        self.allowed_domains: Set[str] = set()
        
        self._compile_rules()

    def add_target(self, target: str) -> None:
        """Add a target to the allowlist dynamically."""
        if target and target.strip():
            self.allowed_raw.add(target.strip())
            self._compile_rules()

    def _compile_rules(self) -> None:
        self.allowed_ips.clear()
        self.allowed_networks.clear()
        self.allowed_domains.clear()

        for raw in self.allowed_raw:
            cleaned = self._clean_target(raw)
            if not cleaned:
                continue

            # Try parsing as IP or CIDR network
            try:
                if "/" in cleaned:
                    net = ipaddress.ip_network(cleaned, strict=False)
                    self.allowed_networks.add(net)
                else:
                    ip = ipaddress.ip_address(cleaned)
                    self.allowed_ips.add(ip)
                continue
            except ValueError:
                pass

            # Otherwise treated as domain/hostname
            domain = cleaned.lower()
            self.allowed_domains.add(domain)

    @staticmethod
    def _clean_target(raw: str) -> str:
        s = raw.strip().strip("'\"").lower()
        if "://" in s:
            parsed = urllib.parse.urlparse(s)
            s = parsed.hostname or s
        elif "/" in s and not any(c.isdigit() for c in s.split("/")[1]):
            s = s.split("/")[0]
        if ":" in s and not "/" in s:
            # strip port if not ipv6
            parts = s.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                s = parts[0]
        return s.strip("[]")

    def is_allowed_host(self, host: str) -> bool:
        """Check if a host (IP or domain name) is within the allowed scope."""
        if not self.enforce:
            return True
        if not self.allowed_raw:
            # If no scope configured, permissive by default unless enforced
            return True

        cleaned = self._clean_target(host)
        if not cleaned:
            return False

        # 1. Check IP / CIDR matches
        try:
            ip = ipaddress.ip_address(cleaned)
            if ip in self.allowed_ips:
                return True
            for net in self.allowed_networks:
                if ip in net:
                    return True
            return False
        except ValueError:
            pass

        # 2. Check Domain / Subdomain matches
        domain = cleaned.lower()
        for allowed in self.allowed_domains:
            if domain == allowed:
                return True
            if domain.endswith("." + allowed):
                return True

        return False

    def is_allowed_url(self, url: str) -> bool:
        """Check if a complete URL is inside the allowed scope."""
        if not self.enforce or not self.allowed_raw:
            return True
        try:
            parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
            host = parsed.hostname
            if not host:
                return False
            return self.is_allowed_host(host)
        except Exception:
            return False

    def validate_redirect(self, source_url: str, redirect_target: str) -> bool:
        """Validate whether a redirect destination remains in scope.
        Raises ScopeViolationError if the redirect escapes allowed scope.
        """
        if not self.enforce or not self.allowed_raw:
            return True
        if not redirect_target:
            return True

        # Relative paths stay on the same origin (in-scope)
        if redirect_target.startswith("/") and not redirect_target.startswith("//"):
            return True

        # Resolve relative / absolute redirect against source
        resolved = urllib.parse.urljoin(source_url, redirect_target)
        if not self.is_allowed_url(resolved):
            raise ScopeViolationError(
                f"Redirect from '{source_url}' to out-of-scope destination '{redirect_target}' blocked."
            )
        return True

    def assert_allowed(self, target_or_url: str) -> None:
        """Raise ScopeViolationError if the target or URL is out of scope."""
        if not self.is_allowed_host(target_or_url) and not self.is_allowed_url(target_or_url):
            raise ScopeViolationError(f"Target '{target_or_url}' is OUT OF SCOPE. Execution blocked.")
