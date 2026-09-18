"""Tests for X19 evidence-first findings lifecycle."""

import sys
sys.path.insert(0, '.')

from x19.findings import (
    Finding,
    Evidence,
    FindingStore,
    FindingStatus,
    Severity,
    Confidence,
    VulnClass,
    create_candidate_finding,
)


def test_create_candidate_finding():
    """Candidate finding must have evidence, not fabricated."""
    finding = create_candidate_finding(
        target="https://target.com",
        endpoint="/api/users",
        vuln_class=VulnClass.BOLA,
        observed_evidence="User ID 123 returns other user data",
        tool_output="curl -H 'Authorization: Bearer token' https://target.com/api/users/123 -> 200 with other user data",
        tool_name="terminal",
        agent_id="api_security",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
    )

    assert finding.target == "https://target.com"
    assert finding.endpoint == "/api/users"
    assert finding.vuln_class == VulnClass.BOLA
    assert finding.status == FindingStatus.CANDIDATE
    assert len(finding.evidence) == 1
    assert finding.evidence[0].tool_name == "terminal"
    assert "other user data" in finding.evidence[0].tool_output


def test_finding_lifecycle():
    """Lifecycle: CANDIDATE → UNDER_VERIFICATION → VERIFIED or REJECTED."""
    finding = create_candidate_finding(
        target="https://target.com",
        endpoint="/search",
        vuln_class=VulnClass.XSS,
        observed_evidence="Reflected XSS via q param",
        tool_output="<script>alert(1)</script> reflected",
        tool_name="terminal",
        agent_id="web_security",
    )

    assert finding.status == FindingStatus.CANDIDATE
    assert finding.can_report_as_candidate()
    assert not finding.can_report_as_verified()

    # Transition to under verification
    assert finding.transition_to(FindingStatus.UNDER_VERIFICATION)
    assert finding.status == FindingStatus.UNDER_VERIFICATION
    assert finding.verification_status == "in_progress"

    # Transition to verified
    assert finding.transition_to(FindingStatus.VERIFIED, verified_by="verification")
    assert finding.status == FindingStatus.VERIFIED
    assert finding.can_report_as_verified()
    assert not finding.can_report_as_candidate()
    assert finding.confidence == Confidence.CONFIRMED

    # Can be re-evaluated as rejected (false positive)
    assert finding.transition_to(FindingStatus.REJECTED, reason="WAF blocks, not exploitable", verified_by="defensive_validation")
    assert finding.status == FindingStatus.REJECTED
    assert finding.is_rejected()


def test_finding_invalid_transition():
    """Invalid lifecycle transitions must be rejected."""
    finding = create_candidate_finding(
        target="https://target.com",
        endpoint="/api/users",
        vuln_class=VulnClass.BOLA,
        observed_evidence="Test",
        tool_output="Test output",
        tool_name="terminal",
        agent_id="api_security",
    )

    # Cannot go directly from CANDIDATE to VERIFIED (must go via UNDER_VERIFICATION)
    assert not finding.transition_to(FindingStatus.VERIFIED)
    assert finding.status == FindingStatus.CANDIDATE


def test_evidence_required():
    """Every finding must have evidence — never fabricate."""
    finding = create_candidate_finding(
        target="https://target.com",
        endpoint="/api/users",
        vuln_class=VulnClass.BOLA,
        observed_evidence="Test",
        tool_output="Real tool output",
        tool_name="terminal",
        agent_id="api_security",
    )

    assert len(finding.evidence) > 0
    assert finding.evidence[0].tool_output == "Real tool output"
    assert finding.evidence[0].tool_name == "terminal"

    # Evidence must have observation
    assert finding.evidence[0].observation == "Test"


def test_finding_store():
    """Finding store must track candidates, verified, rejected separately."""
    store = FindingStore()

    f1 = create_candidate_finding(
        target="https://target.com",
        endpoint="/search",
        vuln_class=VulnClass.XSS,
        observed_evidence="XSS",
        tool_output="XSS output",
        tool_name="terminal",
        agent_id="web_security",
    )

    f2 = create_candidate_finding(
        target="https://target.com",
        endpoint="/api/users",
        vuln_class=VulnClass.BOLA,
        observed_evidence="BOLA",
        tool_output="BOLA output",
        tool_name="terminal",
        agent_id="api_security",
    )

    f2.transition_to(FindingStatus.UNDER_VERIFICATION)
    f2.transition_to(FindingStatus.VERIFIED, verified_by="verification")

    f3 = create_candidate_finding(
        target="https://target.com",
        endpoint="/admin",
        vuln_class=VulnClass.INFO_DISCLOSURE,
        observed_evidence="Info disclosure",
        tool_output="Info output",
        tool_name="terminal",
        agent_id="web_security",
    )
    f3.transition_to(FindingStatus.REJECTED, reason="False positive")

    store.add(f1)
    store.add(f2)
    store.add(f3)

    assert len(store.list_candidates()) == 1
    assert len(store.list_verified()) == 1
    assert len(store.list_rejected()) == 1
    assert store.get_stats()["total"] == 3
    assert store.get_stats()["verified"] == 1
    assert store.get_stats()["candidates"] == 1
    assert store.get_stats()["rejected"] == 1


def test_never_report_rejected_as_confirmed():
    """Never report rejected findings as confirmed — critical safety check."""
    store = FindingStore()

    rejected = create_candidate_finding(
        target="https://target.com",
        endpoint="/api/users",
        vuln_class=VulnClass.BOLA,
        observed_evidence="BOLA",
        tool_output="BOLA output",
        tool_name="terminal",
        agent_id="api_security",
    )
    rejected.transition_to(FindingStatus.REJECTED, reason="False positive, WAF")

    store.add(rejected)

    # Rejected must NOT be in verified list
    assert len(store.list_verified()) == 0
    assert len(store.list_rejected()) == 1

    # Rejected must NOT be reportable as verified
    assert not rejected.can_report_as_verified()


def test_finding_must_have_repro_steps_for_verified():
    """Verified findings should have reproduction steps (evidence-first)."""
    finding = create_candidate_finding(
        target="https://target.com",
        endpoint="/search",
        vuln_class=VulnClass.XSS,
        observed_evidence="XSS",
        tool_output="XSS output",
        tool_name="terminal",
        agent_id="web_security",
        severity=Severity.HIGH,
    )

    finding.reproduction_steps = [
        "Navigate to https://target.com/search?q=<script>alert(1)</script>",
        "Observe script execution",
    ]

    finding.transition_to(FindingStatus.UNDER_VERIFICATION)
    finding.transition_to(FindingStatus.VERIFIED, verified_by="verification")

    assert len(finding.reproduction_steps) > 0
    assert finding.can_report_as_verified()
