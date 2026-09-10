"""Deterministic, passive engagement/scope discovery for X19.

This module deliberately keeps authorization decisions out of the LLM.  It
resolves a target against trusted, public program scope metadata and returns a
structured result that the terminal router can present to the user.

It is a *scope discovery* layer, not a permission bypass: finding a public
program does not grant permission to ignore that program's rules.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
from dataclasses import dataclass, field
from html import unescape
from typing import Iterable, List, Optional, Sequence
from urllib.parse import urlparse

try:
    import requests
except Exception:  # pragma: no cover - requests is already an X19 dependency
    requests = None


@dataclass(frozen=True)
class ProgramSource:
    name: str
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
    source_url: str = ""
    program_url: str = ""
    matched_pattern: str = ""
    scope_patterns: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    reason: str = ""

    @property
    def verified(self) -> bool:
        return self.state in {"verified_in_scope", "verified_out_of_scope"}


# Trusted first-party sources.  More programs can be added without changing
# the router.  For arbitrary programs, users can provide X19_SCOPE_URL rather
# than trusting a search-engine result as authorization evidence.
TRUSTED_SOURCES = (
    ProgramSource(
        name="Paytm Bug Bounty",
        scope_url="https://bugbounty.paytm.com/scope/",
        program_url="https://bugbounty.paytm.com/",
        patterns=(
            "*.paytm.com",
            "*.paytm.in",
            "*.mypaytm.com",
            "paytmfoundation.org",
            "*.paytmmall.com",
            "*.paytmmoney.com",
            "*.paytminsurance.co.in",
            "*.paytmpayments.com",
        ),
        notes=(
            "Only test your own accounts.",
            "Do not disrupt services, target other users, social-engineer, or DDoS.",
            "If severe system access is found, stop further exploitation.",
            "Automated scanner-generated reports are excluded.",
        ),
    ),
)


def normalize_target(value: str) -> str:
    """Return a hostname/IP without scheme, path, port or trailing dot."""
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
    if host.startswith("*."):
        host = host[2:]
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        return host


def _matches(host: str, pattern: str) -> bool:
    pattern = normalize_target(pattern)
    if not host or not pattern:
        return False
    # fnmatch gives the expected wildcard semantics but does not make a
    # wildcard automatically include the apex domain.  That distinction is
    # important for bounty scopes such as *.example.com.
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) and host != suffix[1:]
    return host == pattern


def _extract_patterns(html: str) -> List[str]:
    """Extract conservative hostname patterns from a public scope page."""
    text = unescape(re.sub(r"<[^>]+>", " ", html))
    candidates = set(re.findall(r"(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", text, re.I))
    # Keep this parser intentionally narrow: only domain-like values are
    # accepted, and URLs/paths are stripped before matching.
    return sorted({c.lower().strip(".,") for c in candidates})


def _source_for_target(target: str, sources: Iterable[ProgramSource]) -> Optional[ProgramSource]:
    host = normalize_target(target)
    if not host:
        return None
    # Prefer a source whose declared scope already matches.  Then fall back to
    # registrable-domain hints so a program can still be surfaced when the
    # exact target is out of scope (e.g. paytm.com vs *.paytm.com).
    for source in sources:
        if any(_matches(host, p) for p in source.patterns):
            return source
    labels = host.split(".")
    root = ".".join(labels[-2:]) if len(labels) >= 2 else host
    for source in sources:
        if any(normalize_target(p).lstrip("*.").endswith(root) for p in source.patterns):
            return source
    return None


def _verify_source(target: str, source: ProgramSource) -> ScopeResult:
    host = normalize_target(target)
    patterns = list(source.patterns)
    for pattern in patterns:
        if _matches(host, pattern):
            return ScopeResult(
                target=target,
                normalized_target=host,
                state="verified_in_scope",
                program=source.name,
                source_url=source.scope_url,
                program_url=source.program_url,
                matched_pattern=pattern,
                scope_patterns=patterns,
                notes=list(source.notes),
                reason=f"matched declared scope {pattern}",
            )
    return ScopeResult(
        target=target,
        normalized_target=host,
        state="verified_out_of_scope",
        program=source.name,
        source_url=source.scope_url,
        program_url=source.program_url,
        scope_patterns=patterns,
        notes=list(source.notes),
        reason="public program found, but the exact target does not match a declared scope pattern",
    )


def resolve_scope(target: str, *, scope_url: str = "", timeout: float = 8.0) -> ScopeResult:
    """Resolve a target against trusted public scope metadata.

    Resolution is passive: it fetches only a public scope document and never
    sends attack payloads to the target.  If the source cannot be verified,
    the result is ``unknown`` rather than an authorization assumption.
    """
    host = normalize_target(target)
    if not host:
        return ScopeResult(target=target, normalized_target="", state="unknown", reason="target could not be normalized")

    configured_url = (scope_url or os.getenv("X19_SCOPE_URL", "")).strip()
    if configured_url:
        source = _source_for_target(host, TRUSTED_SOURCES)
        if source and configured_url.rstrip("/") == source.scope_url.rstrip("/"):
            return _verify_source(host, source)
        if requests is None:
            return ScopeResult(target=target, normalized_target=host, state="unknown", source_url=configured_url, reason="HTTP client unavailable")
        try:
            response = requests.get(configured_url, timeout=timeout, headers={"User-Agent": "X19-ScopeResolver/1.0"})
            response.raise_for_status()
            patterns = _extract_patterns(response.text)
            matched = next((p for p in patterns if _matches(host, p)), "")
            return ScopeResult(
                target=target,
                normalized_target=host,
                state="verified_in_scope" if matched else "verified_out_of_scope",
                source_url=configured_url,
                scope_patterns=patterns,
                matched_pattern=matched,
                reason=(f"matched declared scope {matched}" if matched else "source loaded, but target did not match any declared hostname"),
            )
        except Exception as exc:
            return ScopeResult(target=target, normalized_target=host, state="unknown", source_url=configured_url, reason=f"scope source unavailable: {type(exc).__name__}")

    source = _source_for_target(host, TRUSTED_SOURCES)
    if source:
        return _verify_source(host, source)
    return ScopeResult(target=target, normalized_target=host, state="unknown", reason="no trusted public program matched this target")
