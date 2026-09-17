from brain.assessment_telemetry import AssessmentTelemetry, TargetHealth, infer_domains
from execution.command_request import CommandRequest, CommandResult, PolicyVerdict


def test_domain_inference_is_advisory_and_deterministic():
    domains = infer_domains(
        "curl https://example.test/api/login",
        reason="check authentication and API behavior",
    )
    assert "authentication" in domains
    assert "api" in domains


def test_telemetry_tracks_testing_then_covered():
    telemetry = AssessmentTelemetry()
    request = CommandRequest.from_shell(
        "curl https://example.test/api/login",
        target="https://example.test/api/login",
        reason="authentication check",
        metadata={"security_domains": ["authentication", "api"]},
    )
    telemetry.record_start(request)
    assert telemetry.coverage.summary()["testing"] == 2

    result = CommandResult(
        request=request,
        stdout="HTTP/1.1 200 OK",
        returncode=0,
        policy=PolicyVerdict(True),
    )
    telemetry.record_result(result)
    summary = telemetry.coverage.summary()
    assert summary["covered"] == 2
    assert telemetry.health.state == "reachable"
    assert len(telemetry.events) == 2


def test_health_enters_offline_after_repeated_network_failures():
    health = TargetHealth()
    for _ in range(3):
        health.observe(returncode=7, error="connection timed out")
    assert health.state == "offline"
    assert health.consecutive_failures == 3
