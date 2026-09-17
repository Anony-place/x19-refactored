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


# ---------------------------------------------------------------------------
# Target classification — one truth for the agent loop and the CLI gate
# ---------------------------------------------------------------------------
#: Local artifacts (mobile apps, binaries) are analysed, not attacked over a network.
_LOCAL_ARTIFACT_RE = re.compile(r"\.(apk|ipa|aab|dex|jar|so|elf|exe|bin|war)$", re.I)

#: Private/lab ranges: whoever owns the network owns the authorization.
_PRIVATE_PATTERNS = (
    r"^10\.", r"^172\.(1[6-9]|2\d|3[01])\.", r"^192\.168\.",
    r"^127\.", r"^localhost$", r"^0\.",
    r"^::1$", r"^fe80:", r"^fc00:", r"^fd00:",
    r"\.local$", r"\.internal$", r"\.lan$",
)

#: Deliberately vulnerable practice platforms.
CTF_HINTS = ("ctf", "hackme", "hack.me", "capturetheflag", "challenge",
             "vulnhub", "hackthebox", "tryhackme")

_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_IPV4_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


def classify_target(target: str) -> str:
    """Classify a target as ``authorized`` / ``ctf`` / ``public_real_world``.

    This is a *posture* heuristic, not authorization proof: it decides how hard
    X19 may push by default (private lab and practice platforms are the
    operator's own, a public host is somebody else's). Whether active testing of
    a public host is authorized is a separate question answered by
    :func:`decide_active_run` from evidence.
    """
    value = str(target or "").strip().lower()
    if not value:
        return "public_real_world"
    if _LOCAL_ARTIFACT_RE.search(value):
        return "authorized"
    for pattern in _PRIVATE_PATTERNS:
        if re.match(pattern, value):
            return "authorized"
    if any(hint in value for hint in CTF_HINTS):
        return "ctf"
    if _DOMAIN_RE.match(value) and not _IPV4_RE.match(value):
        return "public_real_world"
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "authorized"  # not a network target at all (a file, a word)
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return "authorized"
    return "public_real_world"


@dataclass
class ActiveRunDecision:
    """Whether a one-shot active run may test this target, and why."""

    allowed: bool
    state: str                      # verified_in_scope | verified_out_of_scope | unknown
    target_type: str                # posture to run with ("" = leave it to classification)
    reason: str                     # one honest line for the operator
    result: Optional[ScopeResult] = None
    #: an operator who can present a scope URL could still turn this into a yes
    needs_input: bool = False

    @property
    def verified(self) -> bool:
        return self.state == "verified_in_scope"


def decide_active_run(
    target: str,
    *,
    claimed: bool = False,
    scope_url: str = "",
    engagement: bool = False,
    allow_unverified: Optional[bool] = None,
) -> ActiveRunDecision:
    """Evidence decides whether active testing of ``target`` is authorized.

    ``claimed`` is an operator *assertion* (``--bug-bounty``,
    ``X19_BUG_BOUNTY_MODE``, ``--target-type authorized``). An assertion is not
    evidence, and treating it as one is how a tool ends up attacking something
    nobody authorized: a claim is verified against the program's own scope
    metadata before it may widen the posture.

    Deliberately permissive where permission is obvious (a private range, a lab,
    a practice platform, an attached engagement profile) and deliberately
    fail-closed where it is not (an unverified public host with no evidence and
    nobody to ask).
    """
    result = resolve_scope(target, scope_url=scope_url)
    posture = classify_target(target)

    if result.state == "verified_in_scope":
        program = result.program or "the configured program"
        return ActiveRunDecision(
            allowed=True, state=result.state, target_type="authorized",
            reason=f"verified — {program} declares {result.matched_pattern or target}",
            result=result,
        )

    if result.state == "verified_out_of_scope":
        declared = ", ".join((result.scope_patterns or [])[:6]) or "its declared scope"
        return ActiveRunDecision(
            allowed=False, state=result.state, target_type="",
            reason=(f"{result.program or 'the program'} was found, but "
                    f"{result.normalized_target or target} is outside its declared scope ({declared})"),
            result=result,
        )

    # unknown: no trusted public program matched this target
    if posture in ("authorized", "ctf"):
        return ActiveRunDecision(
            allowed=True, state=result.state, target_type=posture,
            reason=f"{posture} target — no public program needed",
            result=result,
        )
    if engagement:
        return ActiveRunDecision(
            allowed=True, state=result.state, target_type="authorized",
            reason="engagement profile records the authorization",
            result=result,
        )
    if allow_unverified is None:
        allow_unverified = os.getenv("X19_ALLOW_UNVERIFIED", "").strip().lower() in ("1", "true", "yes")
    if allow_unverified:
        return ActiveRunDecision(
            allowed=True, state=result.state, target_type="authorized",
            reason="X19_ALLOW_UNVERIFIED is set — the operator asserts written authorization",
            result=result,
        )
    if claimed:
        return ActiveRunDecision(
            allowed=False, state=result.state, target_type="",
            reason=("active testing was requested, but no public program or scope source "
                    f"verifies {result.normalized_target or target}"),
            result=result, needs_input=True,
        )
    return ActiveRunDecision(
        allowed=True, state=result.state, target_type="",
        reason="no trusted public program matched — recon/enumeration posture only",
        result=result,
    )
