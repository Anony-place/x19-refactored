"""Deterministic passive public-program scope discovery.

Authorization is resolved outside the LLM. This module only reads public
scope metadata or an explicitly configured scope URL; it never sends attack
traffic to the target.
"""
from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field
from html import unescape
from typing import Iterable, List, Optional, Sequence
from urllib.parse import urlparse

try:
    import requests
except Exception:  # pragma: no cover
    requests = None


@dataclass(frozen=True)
class ProgramSource:
    name: str
    platform: str
    scope_url: str
    program_url: str
    patterns: Sequence[str]
    notes: Sequence[str] = field(default_factory=tuple)


@dataclass
class ScopeResult:
    target: str
    normalized_target: str
    state: str  # verified_in_scope | verified_out_of_scope | unknown
    program: str = ""
    platform: str = ""
    source_url: str = ""
    program_url: str = ""
    matched_pattern: str = ""
    scope_patterns: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    reason: str = ""

    @property
    def verified(self) -> bool:
        return self.state in {"verified_in_scope", "verified_out_of_scope"}


TRUSTED_SOURCES = (
    ProgramSource(
        name="Paytm Bug Bounty",
        platform="paytm",
        scope_url="https://bugbounty.paytm.com/scope/",
        program_url="https://bugbounty.paytm.com/",
        patterns=(
            "*.paytm.com", "*.paytm.in", "*.mypaytm.com",
            "paytmfoundation.org", "*.paytmmall.com", "*.paytmmoney.com",
            "*.paytminsurance.co.in", "*.paytmpayments.com",
        ),
        notes=(
            "Only test your own accounts.",
            "Do not disrupt services, target other users, social-engineer, or DDoS.",
            "If severe system access is found, stop further exploitation.",
            "Automated scanner-generated reports are excluded.",
        ),
    ),
    ProgramSource(
        name="Xiaomi Bug Bounty",
        platform="hackerone",
        scope_url="https://hackerone.com/xiaomi",
        program_url="https://hackerone.com/xiaomi",
        patterns=(
            "*.mi.com", "*.miui.com", "*.xiaomiyoupin.com", "*.miwifi.com",
            "*.xiaomi.market", "*.xiaomi.com", "*.mi.cn", "*.mifile.cn",
            "*.migames.com", "*.mipay.com", "*.mios.cn", "*.miot-spec.org",
            "*.mijiayoupin.com", "*.duokan.com", "*.aleenote.com", "*.aleenote.cn",
            "*.baoliyun.com", "*.airstar.com", "*.airstar-finance.com",
            "*.airstarfinance.net", "*.miinsurtech.com", "*.miinsurtech.net",
            "*.miinsurtech.cn", "*.mioffice.cn", "*.hongyuanib.com",
        ),
        notes=(
            "Scope is based on Xiaomi's public HackerOne program metadata.",
            "The wildcard *.mi.com covers subdomains; the mi.com apex is not implied by that wildcard.",
            "Verify the live HackerOne program rules before active testing or submission.",
        ),
    ),
)


def normalize_target(value: str) -> str:
    """Normalize a concrete target while preserving wildcard patterns elsewhere."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    candidate = raw if "://" in raw else f"//{raw}"
    try:
        parsed = urlparse(candidate)
        host = parsed.hostname or parsed.path.split("/", 1)[0]
    except Exception:
        host = raw.split("/", 1)[0].split(":", 1)[0]
    host = host.strip().strip(".").lower()
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        return host


def normalize_pattern(value: str) -> str:
    raw = str(value or "").strip().lower().strip(".")
    wildcard = raw.startswith("*.")
    if wildcard:
        raw = raw[2:]
    host = normalize_target(raw)
    return f"*.{host}" if wildcard and host else host


def _matches(host: str, pattern: str) -> bool:
    host = normalize_target(host)
    pattern = normalize_pattern(pattern)
    if not host or not pattern:
        return False
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) and host != suffix[1:]
    return host == pattern


def _extract_patterns(html: str) -> List[str]:
    text = unescape(re.sub(r"<[^>]+>", " ", html))
    candidates = set(re.findall(
        r"(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
        text, re.I,
    ))
    return sorted({normalize_pattern(c) for c in candidates if normalize_pattern(c)})


def _source_for_target(target: str, sources: Iterable[ProgramSource]) -> Optional[ProgramSource]:
    host = normalize_target(target)
    if not host:
        return None
    source_list = list(sources)
    for source in source_list:
        if any(_matches(host, pattern) for pattern in source.patterns):
            return source
    labels = host.split(".")
    root = ".".join(labels[-2:]) if len(labels) >= 2 else host
    for source in source_list:
        for pattern in source.patterns:
            base = normalize_pattern(pattern).lstrip("*.")
            if base == root or base.endswith("." + root):
                return source
    return None


def _verify_source(target: str, source: ProgramSource) -> ScopeResult:
    host = normalize_target(target)
    patterns = [normalize_pattern(p) for p in source.patterns]
    for pattern in patterns:
        if _matches(host, pattern):
            return ScopeResult(
                target=target, normalized_target=host, state="verified_in_scope",
                program=source.name, platform=source.platform,
                source_url=source.scope_url, program_url=source.program_url,
                matched_pattern=pattern, scope_patterns=patterns,
                notes=list(source.notes), reason=f"matched declared scope {pattern}",
            )
    return ScopeResult(
        target=target, normalized_target=host, state="verified_out_of_scope",
        program=source.name, platform=source.platform,
        source_url=source.scope_url, program_url=source.program_url,
        scope_patterns=patterns, notes=list(source.notes),
        reason="public program found, but the exact target does not match a declared scope pattern",
    )


def _verify_remote_source(target: str, scope_url: str, timeout: float) -> ScopeResult:
    host = normalize_target(target)
    if requests is None:
        return ScopeResult(target=target, normalized_target=host, state="unknown", source_url=scope_url, reason="HTTP client unavailable")
    try:
        response = requests.get(scope_url, timeout=timeout, headers={"User-Agent": "X19-ScopeResolver/1.1"})
        response.raise_for_status()
        patterns = _extract_patterns(response.text)
        matched = next((p for p in patterns if _matches(host, p)), "")
        return ScopeResult(
            target=target, normalized_target=host,
            state="verified_in_scope" if matched else "verified_out_of_scope",
            source_url=scope_url, scope_patterns=patterns, matched_pattern=matched,
            reason=(f"matched declared scope {matched}" if matched else "source loaded, but target did not match any declared hostname"),
        )
    except Exception as exc:
        return ScopeResult(target=target, normalized_target=host, state="unknown", source_url=scope_url, reason=f"scope source unavailable: {type(exc).__name__}")


def resolve_scope(target: str, *, scope_url: str = "", timeout: float = 8.0) -> ScopeResult:
    """Resolve a target passively against trusted or explicitly supplied scope metadata.

    For HackerOne/Bugcrowd, supply the exact public program/scope URL. Merely
    finding that an organization uses a platform is not treated as scope proof.
    """
    host = normalize_target(target)
    if not host:
        return ScopeResult(target=target, normalized_target="", state="unknown", reason="target could not be normalized")
    configured_url = (scope_url or os.getenv("X19_SCOPE_URL", "")).strip()
    if configured_url:
        trusted = next((s for s in TRUSTED_SOURCES if configured_url.rstrip("/") == s.scope_url.rstrip("/")), None)
        if trusted:
            return _verify_source(host, trusted)
        return _verify_remote_source(host, configured_url, timeout)
    source = _source_for_target(host, TRUSTED_SOURCES)
    if source:
        return _verify_source(host, source)
    return ScopeResult(target=target, normalized_target=host, state="unknown", reason="no trusted public program matched this target")
