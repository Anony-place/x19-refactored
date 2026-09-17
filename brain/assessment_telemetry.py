"""Runtime telemetry for evidence-driven security assessments.

This module is deliberately observational: it records what X19 actually
attempted and what the execution boundary returned. It never grants scope,
selects a target, or turns a failed check into a finding.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List
import re

from brain.coverage import CoverageMatrix
from brain.decision_guard import evaluate_request
from brain.atlas import attach_atlas


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class TrajectoryEvent:
    request_id: str
    phase: str
    command: str
    target: str = ""
    hypothesis_id: str = ""
    reason: str = ""
    status: str = ""
    returncode: int = -1
    evidence: str = ""
    decision_level: str = ""
    decision_reasons: tuple[str, ...] = ()
    atlas_tags: List[Dict[str, str]] = field(default_factory=list)
    timestamp: str = field(default_factory=_now)


@dataclass
class TargetHealth:
    """Small explicit state machine derived only from observed execution."""
    state: str = "unknown"
    consecutive_failures: int = 0
    observations: int = 0
    last_error: str = ""
    updated_at: str = field(default_factory=_now)

    def observe(self, *, returncode: int, error: str = "", stdout: str = "", stderr: str = "") -> None:
        self.observations += 1
        text = f"{error} {stderr} {stdout}".lower()
        network_failure = any(x in text for x in (
            "connection refused", "connection timed out", "timed out",
            "name or service not known", "could not resolve", "no route to host",
            "network is unreachable", "connection reset",
        ))
        if not error and returncode == 0:
            self.consecutive_failures = 0
            self.state = "reachable"
        elif "policy_blocked" in text or "scope" in text:
            self.state = "blocked"
            self.last_error = error or stderr[:240]
        elif network_failure:
            self.consecutive_failures += 1
            self.last_error = error or stderr[:240]
            self.state = "offline" if self.consecutive_failures >= 3 else "degraded"
        else:
            self.consecutive_failures = 0
            self.state = "degraded" if error or returncode != 0 else "reachable"
            if error or stderr:
                self.last_error = error or stderr[:240]
        self.updated_at = _now()


_DOMAIN_PATTERNS = {
    "injection": (r"\bsqlmap\b", r"\bsql\b", r"\bxpath\b", r"\bldap\b", r"\bcommand injection\b"),
    "access-control": (r"\bauthz\b", r"\bidor\b", r"\baccess.?control\b"),
    "authentication": (r"\bauth\b", r"\blogin\b", r"\bjwt\b", r"\bpassword\b", r"\bcredential\b"),
    "session": (r"\bsession\b", r"\bcookie\b", r"\bcsrf\b", r"\btoken\b"),
    "ssrf": (r"\bssrf\b", r"\binteractsh\b", r"\boob\b", r"\bcallback\b"),
    "file-handling": (r"\bfile\b", r"\bupload\b", r"\bdownload\b", r"\bpath traversal\b", r"\blfi\b"),
    "xss": (r"\bxss\b", r"\bcross.?site scripting\b", r"\bdom xss\b"),
    "request-smuggling": (r"\bsmuggling\b", r"\bcl\.te\b", r"\bte\.cl\b", r"\bhttp.?2\b"),
    "misconfiguration": (r"\btestssl\b", r"\bmisconfig", r"\bheaders?\b", r"\btls\b", r"\bssl\b"),
    "business-logic": (r"\bbusiness.?logic\b", r"\bworkflow\b", r"\bcoupon\b", r"\bprice\b", r"\brace condition\b"),
    "api": (r"\bapi\b", r"\bgraphql\b", r"\bopenapi\b", r"\bswagger\b"),
}


def infer_domains(command: str, reason: str = "", hypothesis: str = "", metadata: Dict[str, Any] | None = None) -> List[str]:
    metadata = metadata or {}
    explicit = metadata.get("security_domains")
    if isinstance(explicit, (list, tuple)):
        return [str(x).strip().lower() for x in explicit if str(x).strip()]
    text = " ".join((command or "", reason or "", hypothesis or "")).lower()
    return [domain for domain, patterns in _DOMAIN_PATTERNS.items() if any(re.search(p, text) for p in patterns)]


class AssessmentTelemetry:
    def __init__(self) -> None:
        self.coverage = CoverageMatrix()
        self.health = TargetHealth()
        self.events: List[TrajectoryEvent] = []

    @staticmethod
    def _decision_fields(request: Any):
        guard = evaluate_request(request)
        metadata = attach_atlas(getattr(request, "metadata", None))
        return guard, metadata.get("atlas_tags", [])

    def record_start(self, request: Any) -> None:
        domains = infer_domains(request.command, request.reason, request.hypothesis, request.metadata)
        endpoint = str(request.target or "").strip()
        guard, atlas_tags = self._decision_fields(request)
        if endpoint:
            self.coverage.ensure_endpoint(endpoint)
            for domain in domains:
                self.coverage.mark(endpoint, domain, "testing", command=request.command)
        self.events.append(TrajectoryEvent(
            request_id=request.request_id, phase="execution.start", command=request.command,
            target=endpoint, hypothesis_id=request.hypothesis_id, reason=request.reason,
            decision_level=guard.level, decision_reasons=guard.reasons, atlas_tags=atlas_tags,
        ))

    def record_result(self, result: Any) -> None:
        request = result.request
        endpoint = str(request.target or "").strip()
        domains = infer_domains(request.command, request.reason, request.hypothesis, request.metadata)
        guard, atlas_tags = self._decision_fields(request)
        status = "covered" if result.policy.allowed and not result.error else "blocked" if not result.policy.allowed else "testing"
        evidence = (result.stdout or result.stderr or "")[:1200]
        if endpoint:
            for domain in domains:
                self.coverage.mark(endpoint, domain, status, command=request.command)
        self.health.observe(returncode=result.returncode, error=result.error or "", stdout=result.stdout, stderr=result.stderr)
        self.events.append(TrajectoryEvent(
            request_id=request.request_id, phase="execution.result", command=request.command,
            target=endpoint, hypothesis_id=request.hypothesis_id, reason=request.reason,
            status=status, returncode=result.returncode, evidence=evidence,
            decision_level=guard.level, decision_reasons=guard.reasons, atlas_tags=atlas_tags,
        ))

    def context_block(self) -> str:
        blocks = [self.coverage.context_block()]
        blocks.append(f"TARGET HEALTH: state={self.health.state} failures={self.health.consecutive_failures}")
        if self.events:
            weak = sum(1 for event in self.events[-50:] if event.decision_level == "weak")
            blocks.append(f"DECISION QUALITY: weak_recent={weak}/{min(50, len(self.events))}")
        return "\n".join(x for x in blocks if x)

    def to_dict(self) -> dict:
        return {
            "coverage": self.coverage.to_dict(),
            "target_health": self.health.__dict__.copy(),
            "trajectory": [event.__dict__.copy() for event in self.events[-200:]],
        }
