"""
X19 Evidence-First Findings Lifecycle.

Every finding must have:
- ID, target, endpoint/component, vuln class, severity, confidence,
  reproduction steps, observed evidence, tool output/reference,
  timestamps, affected agent, verification status, remediation.

Lifecycle: CANDIDATE → UNDER_VERIFICATION → VERIFIED or REJECTED
Never report rejected as confirmed.

Distinguish:
- OBSERVATION (what tool saw)
- HYPOTHESIS (what might be vulnerable)
- TEST (what you will do)
- EVIDENCE (tool output, reproducible proof)
- VERIFIED FINDING (confirmed with repro steps)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Optional, Any
import uuid


class FindingStatus(str, Enum):
    """Finding lifecycle status."""

    CANDIDATE = "candidate"  # Initial observation, needs verification
    UNDER_VERIFICATION = "under_verification"  # Verification specialist working
    VERIFIED = "verified"  # Confirmed with reproduction
    REJECTED = "rejected"  # False positive or not exploitable
    NEEDS_MORE_EVIDENCE = "needs_more_evidence"  # Requires additional testing


class Severity(str, Enum):
    """CVSS 3.1 inspired severity."""

    CRITICAL = "critical"  # 9.0-10.0
    HIGH = "high"  # 7.0-8.9
    MEDIUM = "medium"  # 4.0-6.9
    LOW = "low"  # 0.1-3.9
    INFO = "info"  # Informational


class Confidence(str, Enum):
    """Confidence in finding."""

    HIGH = "high"  # Reproduced, clear evidence
    MEDIUM = "medium"  # Likely, needs more verification
    LOW = "low"  # Possible, weak evidence
    CONFIRMED = "confirmed"  # Verified by specialist


class VulnClass(str, Enum):
    """Vulnerability classes (CWE-inspired)."""

    # Web
    XSS = "xss"
    SQLI = "sqli"
    SSTI = "ssti"
    SSRF = "ssrf"
    XXE = "xxe"
    OPEN_REDIRECT = "open_redirect"
    IDOR = "idor"
    BOLA = "bola"
    BFLA = "bfla"
    AUTH_BYPASS = "auth_bypass"
    PRIV_ESC = "privilege_escalation"
    SESSION_FIXATION = "session_fixation"
    CSRF = "csrf"
    CORS_MISCONFIG = "cors_misconfig"
    # API
    MASS_ASSIGNMENT = "mass_assignment"
    EXCESSIVE_DATA_EXPOSURE = "excessive_data_exposure"
    RATE_LIMIT_BYPASS = "rate_limit_bypass"
    # Cloud/Infra
    S3_EXPOSURE = "s3_exposure"
    IAM_MISCONFIG = "iam_misconfig"
    METADATA_EXPOSURE = "metadata_exposure"
    OPEN_PORT = "open_port"
    EXPOSED_CONFIG = "exposed_config"
    # Other
    INFO_DISCLOSURE = "info_disclosure"
    BUSINESS_LOGIC = "business_logic"
    OTHER = "other"


@dataclass
class Evidence:
    """Evidence for a finding — must be real tool output, never fabricated."""

    # What tool saw
    tool_name: str  # e.g., "terminal", "browser_navigate", "web_search"
    tool_output: str  # Actual output, truncated if needed
    tool_output_ref: str  # Path to full output file or log reference
    request: Optional[str] = None  # HTTP request if applicable
    response: Optional[str] = None  # HTTP response if applicable
    timestamp: datetime = field(default_factory=datetime.utcnow)
    agent_id: str = ""  # Which specialist produced this
    endpoint: str = ""  # Endpoint/component where evidence observed

    # Evidence chain
    observation: str = ""  # What was observed (factual)
    hypothesis: Optional[str] = None  # What might be vulnerable
    test_performed: Optional[str] = None  # What test was done
    observed_behavior: str = ""  # What behavior observed after test

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "tool_output": self.tool_output[:2000] if len(self.tool_output) > 2000 else self.tool_output,
            "tool_output_ref": self.tool_output_ref,
            "request": self.request,
            "response": self.response,
            "timestamp": self.timestamp.isoformat(),
            "agent_id": self.agent_id,
            "endpoint": self.endpoint,
            "observation": self.observation,
            "hypothesis": self.hypothesis,
            "test_performed": self.test_performed,
            "observed_behavior": self.observed_behavior,
        }


@dataclass
class Finding:
    """Evidence-first finding with full lifecycle."""

    # Identity
    id: str = field(default_factory=lambda: f"X19-{uuid.uuid4().hex[:8].upper()}")
    target: str = ""  # e.g., "https://target.com"
    endpoint: str = ""  # e.g., "/api/users"
    component: str = ""  # e.g., "User API"

    # Classification
    vuln_class: VulnClass = VulnClass.OTHER
    cwe_id: Optional[str] = None  # e.g., "CWE-79" for XSS
    owasp_category: Optional[str] = None  # e.g., "A03:2021-Injection"
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.LOW
    cvss_score: Optional[float] = None  # 0.0-10.0
    cvss_vector: Optional[str] = None  # e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    # Evidence and reproduction
    evidence: List[Evidence] = field(default_factory=list)
    reproduction_steps: List[str] = field(default_factory=list)
    observed_evidence: str = ""  # Summary of observed evidence
    tool_output_reference: str = ""  # Path to evidence files

    # Lifecycle
    status: FindingStatus = FindingStatus.CANDIDATE
    verification_status: str = "pending"  # pending, in_progress, verified, rejected
    verified_by: Optional[str] = None  # Agent ID that verified
    rejected_reason: Optional[str] = None
    bypasses_tried: List[str] = field(default_factory=list)  # For verification: what bypasses tried

    # Tracking
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    created_by: str = ""  # Agent ID
    affected_agent: str = ""  # Which agent found it

    # Remediation
    remediation: str = ""  # Fix guidance
    impact: str = ""  # Business impact
    references: List[str] = field(default_factory=list)  # CWE, OWASP, CVE refs

    # Metadata
    tags: List[str] = field(default_factory=list)
    false_positive_indicators: List[str] = field(default_factory=list)

    def add_evidence(self, evidence: Evidence):
        """Add evidence to finding."""
        self.evidence.append(evidence)
        self.updated_at = datetime.utcnow()
        if evidence.observed_behavior:
            self.observed_evidence = evidence.observed_behavior

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for persistence."""
        return {
            "id": self.id,
            "target": self.target,
            "endpoint": self.endpoint,
            "component": self.component,
            "vuln_class": self.vuln_class.value,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "evidence": [e.to_dict() for e in self.evidence],
            "reproduction_steps": self.reproduction_steps,
            "observed_evidence": self.observed_evidence,
            "tool_output_reference": self.tool_output_reference,
            "status": self.status.value,
            "verification_status": self.verification_status,
            "verified_by": self.verified_by,
            "rejected_reason": self.rejected_reason,
            "bypasses_tried": self.bypasses_tried,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "created_by": self.created_by,
            "affected_agent": self.affected_agent,
            "remediation": self.remediation,
            "impact": self.impact,
            "references": self.references,
            "tags": self.tags,
            "false_positive_indicators": self.false_positive_indicators,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """Create from dict."""
        # Parse enums
        try:
            vuln_class = VulnClass(data.get("vuln_class", "other"))
        except ValueError:
            vuln_class = VulnClass.OTHER

        try:
            severity = Severity(data.get("severity", "medium"))
        except ValueError:
            severity = Severity.MEDIUM

        try:
            confidence = Confidence(data.get("confidence", "low"))
        except ValueError:
            confidence = Confidence.LOW

        try:
            status = FindingStatus(data.get("status", "candidate"))
        except ValueError:
            status = FindingStatus.CANDIDATE

        # Parse datetimes
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            try:
                created_at = datetime.fromisoformat(created_at)
            except Exception:
                created_at = datetime.utcnow()
        elif not isinstance(created_at, datetime):
            created_at = datetime.utcnow()

        updated_at = data.get("updated_at")
        if isinstance(updated_at, str):
            try:
                updated_at = datetime.fromisoformat(updated_at)
            except Exception:
                updated_at = datetime.utcnow()
        elif not isinstance(updated_at, datetime):
            updated_at = datetime.utcnow()

        return cls(
            id=data.get("id", f"X19-{uuid.uuid4().hex[:8].upper()}"),
            target=data.get("target", ""),
            endpoint=data.get("endpoint", ""),
            component=data.get("component", ""),
            vuln_class=vuln_class,
            cwe_id=data.get("cwe_id"),
            owasp_category=data.get("owasp_category"),
            severity=severity,
            confidence=confidence,
            cvss_score=data.get("cvss_score"),
            cvss_vector=data.get("cvss_vector"),
            evidence=[],  # Evidence parsing omitted for brevity — add if needed
            reproduction_steps=data.get("reproduction_steps", []),
            observed_evidence=data.get("observed_evidence", ""),
            tool_output_reference=data.get("tool_output_reference", ""),
            status=status,
            verification_status=data.get("verification_status", "pending"),
            verified_by=data.get("verified_by"),
            rejected_reason=data.get("rejected_reason"),
            bypasses_tried=data.get("bypasses_tried", []),
            created_at=created_at,
            updated_at=updated_at,
            created_by=data.get("created_by", ""),
            affected_agent=data.get("affected_agent", ""),
            remediation=data.get("remediation", ""),
            impact=data.get("impact", ""),
            references=data.get("references", []),
            tags=data.get("tags", []),
            false_positive_indicators=data.get("false_positive_indicators", []),
        )

    def can_report_as_verified(self) -> bool:
        """Check if finding can be reported as verified (L3/L4)."""
        return self.status == FindingStatus.VERIFIED and self.confidence in (Confidence.HIGH, Confidence.CONFIRMED)

    def can_report_as_candidate(self) -> bool:
        """Check if finding can be reported as candidate (L1/L2 pending verification)."""
        return self.status in (FindingStatus.CANDIDATE, FindingStatus.UNDER_VERIFICATION, FindingStatus.NEEDS_MORE_EVIDENCE)

    def is_rejected(self) -> bool:
        """Check if finding is rejected."""
        return self.status == FindingStatus.REJECTED

    def requires_verification(self) -> bool:
        """Check if finding requires verification."""
        return self.status == FindingStatus.CANDIDATE

    def transition_to(self, new_status: FindingStatus, reason: str = "", verified_by: Optional[str] = None) -> bool:
        """Transition finding to new status with validation."""
        # Validate transitions
        valid_transitions = {
            FindingStatus.CANDIDATE: [FindingStatus.UNDER_VERIFICATION, FindingStatus.REJECTED, FindingStatus.NEEDS_MORE_EVIDENCE],
            FindingStatus.UNDER_VERIFICATION: [FindingStatus.VERIFIED, FindingStatus.REJECTED, FindingStatus.NEEDS_MORE_EVIDENCE],
            FindingStatus.NEEDS_MORE_EVIDENCE: [FindingStatus.UNDER_VERIFICATION, FindingStatus.CANDIDATE, FindingStatus.REJECTED],
            FindingStatus.VERIFIED: [FindingStatus.REJECTED],  # Can be re-evaluated as false positive
            FindingStatus.REJECTED: [FindingStatus.CANDIDATE, FindingStatus.UNDER_VERIFICATION],  # Can be re-opened
        }

        if new_status not in valid_transitions.get(self.status, []):
            # Allow same status (no-op)
            if new_status == self.status:
                return True
            return False

        self.status = new_status
        self.updated_at = datetime.utcnow()

        if new_status == FindingStatus.VERIFIED:
            self.verification_status = "verified"
            self.verified_by = verified_by
            self.confidence = Confidence.CONFIRMED if self.confidence != Confidence.HIGH else self.confidence
        elif new_status == FindingStatus.REJECTED:
            self.verification_status = "rejected"
            self.rejected_reason = reason
            self.verified_by = verified_by
        elif new_status == FindingStatus.UNDER_VERIFICATION:
            self.verification_status = "in_progress"

        return True


class FindingStore:
    """In-memory store for findings with lifecycle enforcement."""

    def __init__(self):
        self.findings: Dict[str, Finding] = {}

    def add(self, finding: Finding) -> str:
        """Add finding, return ID."""
        self.findings[finding.id] = finding
        return finding.id

    def get(self, finding_id: str) -> Optional[Finding]:
        """Get finding by ID."""
        return self.findings.get(finding_id)

    def update(self, finding: Finding) -> bool:
        """Update finding."""
        if finding.id not in self.findings:
            return False
        self.findings[finding.id] = finding
        return True

    def list_by_status(self, status: FindingStatus) -> List[Finding]:
        """List findings by status."""
        return [f for f in self.findings.values() if f.status == status]

    def list_verified(self) -> List[Finding]:
        """List verified findings (L3/L4 reportable)."""
        return [f for f in self.findings.values() if f.can_report_as_verified()]

    def list_candidates(self) -> List[Finding]:
        """List candidate findings (L1/L2 pending)."""
        return [f for f in self.findings.values() if f.can_report_as_candidate()]

    def list_rejected(self) -> List[Finding]:
        """List rejected findings."""
        return [f for f in self.findings.values() if f.is_rejected()]

    def get_stats(self) -> Dict[str, int]:
        """Get finding stats."""
        return {
            "total": len(self.findings),
            "candidates": len(self.list_by_status(FindingStatus.CANDIDATE)),
            "under_verification": len(self.list_by_status(FindingStatus.UNDER_VERIFICATION)),
            "verified": len(self.list_by_status(FindingStatus.VERIFIED)),
            "rejected": len(self.list_by_status(FindingStatus.REJECTED)),
            "needs_more_evidence": len(self.list_by_status(FindingStatus.NEEDS_MORE_EVIDENCE)),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert store to dict."""
        return {fid: f.to_dict() for fid, f in self.findings.items()}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FindingStore":
        """Create from dict."""
        store = cls()
        for fid, fdata in data.items():
            try:
                finding = Finding.from_dict(fdata)
                store.findings[fid] = finding
            except Exception:
                continue
        return store


def create_candidate_finding(
    target: str,
    endpoint: str,
    vuln_class: VulnClass,
    observed_evidence: str,
    tool_output: str,
    tool_name: str,
    agent_id: str,
    severity: Severity = Severity.MEDIUM,
    confidence: Confidence = Confidence.LOW,
    **kwargs,
) -> Finding:
    """Create candidate finding with evidence — evidence-first."""
    evidence = Evidence(
        tool_name=tool_name,
        tool_output=tool_output,
        tool_output_ref=kwargs.get("tool_output_ref", ""),
        request=kwargs.get("request"),
        response=kwargs.get("response"),
        agent_id=agent_id,
        endpoint=endpoint,
        observation=observed_evidence,
        hypothesis=kwargs.get("hypothesis"),
        test_performed=kwargs.get("test_performed"),
        observed_behavior=observed_evidence,
    )

    finding = Finding(
        target=target,
        endpoint=endpoint,
        component=kwargs.get("component", ""),
        vuln_class=vuln_class,
        severity=severity,
        confidence=confidence,
        observed_evidence=observed_evidence,
        evidence=[evidence],
        reproduction_steps=kwargs.get("reproduction_steps", []),
        created_by=agent_id,
        affected_agent=agent_id,
        status=FindingStatus.CANDIDATE,
        verification_status="pending",
        remediation=kwargs.get("remediation", ""),
        impact=kwargs.get("impact", ""),
        cwe_id=kwargs.get("cwe_id"),
        owasp_category=kwargs.get("owasp_category"),
    )

    return finding
