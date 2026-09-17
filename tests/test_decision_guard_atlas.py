from brain.atlas import attach_atlas
from brain.decision_guard import evaluate_request
from execution.command_request import CommandRequest


def test_high_risk_request_without_provenance_is_flagged():
    request = CommandRequest.from_shell(
        "curl https://example.test/admin",
        target="https://example.test/admin",
        risk="high",
    )
    result = evaluate_request(request)
    assert result.ok is False
    assert "no decision reason" in result.reasons
    assert "no hypothesis" in result.reasons


def test_provenance_present_is_accepted():
    request = CommandRequest.from_shell(
        "curl https://example.test/api",
        target="https://example.test/api",
        risk="high",
        reason="validate authorization boundary",
        hypothesis_id="h-1",
        hypothesis="authorization differs by identity",
        expected_evidence="different response status/body",
    )
    result = evaluate_request(request)
    assert result.ok is True
    assert result.level == "provenance-present"


def test_atlas_tags_are_metadata_only():
    data = attach_atlas({"atlas_techniques": ["AML.T0051"]})
    assert data["atlas_tags"][0]["id"] == "AML.T0051"
    assert data["atlas_tags"][0]["name"] == "Prompt Injection"
