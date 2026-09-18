"""Tests for X19 anti-loop / anti-waste system."""

import sys
sys.path.insert(0, '.')

from x19.safety import AntiLoopDetector, LoopType


def test_repeated_command_detection():
    """Detect repeated identical commands/tool calls."""
    detector = AntiLoopDetector(max_repeated_commands=3)

    # First two should not trigger
    assert detector.record_command("curl https://target.com/api", "", "api_security", "T-1") is None
    assert detector.record_command("curl https://target.com/api", "", "api_security", "T-1") is None

    # Third should trigger
    detection = detector.record_command("curl https://target.com/api", "", "api_security", "T-1")
    assert detection is not None
    assert detection.type == LoopType.REPEATED_COMMAND
    assert detection.count == 3


def test_stale_task_detection():
    """Detect stale tasks (running too long without progress)."""
    detector = AntiLoopDetector(stale_task_seconds=1)

    detector.record_task_start("T-1", "web_security")

    # Immediately should not be stale
    stale = detector.check_stale_tasks()
    assert len(stale) == 0

    # Simulate stale by manipulating timestamp
    import datetime
    detector.task_history["T-1"]["last_progress"] = datetime.datetime.utcnow() - datetime.timedelta(seconds=2)

    stale = detector.check_stale_tasks()
    assert len(stale) == 1
    assert stale[0].type == LoopType.STALE_TASK
    assert stale[0].task_id == "T-1"


def test_repeated_failed_hypothesis():
    """Detect repeated failed hypotheses."""
    detector = AntiLoopDetector(max_failed_hypothesis=3)

    assert detector.record_hypothesis_failure("XSS via q param", "web_security", "T-1") is None
    assert detector.record_hypothesis_failure("XSS via q param", "web_security", "T-1") is None

    detection = detector.record_hypothesis_failure("XSS via q param", "web_security", "T-1")
    assert detection is not None
    assert detection.type == LoopType.REPEATED_FAILED_HYPOTHESIS
    assert detection.count == 3


def test_endless_recon_detection():
    """Detect endless recon (no new assets)."""
    detector = AntiLoopDetector(max_recon_iterations_without_new_assets=2)

    # First iteration: 3 assets
    assert detector.record_recon_assets({"a.target.com", "b.target.com", "c.target.com"}) is None

    # Second: same assets, no new
    assert detector.record_recon_assets({"a.target.com", "b.target.com", "c.target.com"}) is None

    # Third: still same, should trigger endless recon
    detection = detector.record_recon_assets({"a.target.com", "b.target.com", "c.target.com"})
    assert detection is not None
    assert detection.type == LoopType.ENDLESS_RECON


def test_identical_payload_detection():
    """Detect identical payloads sent repeatedly."""
    detector = AntiLoopDetector(max_repeated_commands=3)

    assert detector.record_payload("<script>alert(1)</script>", "/search", "web_security", "T-1") is None
    assert detector.record_payload("<script>alert(1)</script>", "/search", "web_security", "T-1") is None

    detection = detector.record_payload("<script>alert(1)</script>", "/search", "web_security", "T-1")
    assert detection is not None
    assert detection.type == LoopType.IDENTICAL_PAYLOAD


def test_missing_evidence_detection():
    """Detect missing evidence and hallucinated evidence."""
    detector = AntiLoopDetector()

    # Missing tool output
    detection = detector.check_evidence("F-1", has_tool_output=False, tool_output_ref="")
    assert detection is not None
    assert detection.type == LoopType.MISSING_EVIDENCE

    # Has output but no ref (could be hallucinated)
    detection = detector.check_evidence("F-2", has_tool_output=True, tool_output_ref="")
    assert detection is not None
    assert detection.type == LoopType.HALLUCINATED_EVIDENCE

    # Valid evidence should not trigger
    assert detector.check_evidence("F-3", has_tool_output=True, tool_output_ref="/tmp/evidence.log") is None


def test_should_stop_mission():
    """Check if mission should stop due to loops."""
    detector = AntiLoopDetector()

    # No detections, should continue
    should_stop, reason = detector.should_stop_mission()
    assert not should_stop

    # Add 5 high severity detections
    from x19.safety.anti_loop import LoopDetection
    import datetime

    for i in range(5):
        detector.detections.append(
            LoopDetection(
                type=LoopType.REPEATED_COMMAND,
                description=f"Repeated command {i}",
                evidence="Test",
                severity="high",
                last_seen=datetime.datetime.utcnow(),
            )
        )

    should_stop, reason = detector.should_stop_mission()
    assert should_stop
    assert "Too many high/critical" in reason


def test_strategy_change_suggestion():
    """Suggest strategy change for detected loop."""
    detector = AntiLoopDetector()

    from x19.safety.anti_loop import LoopDetection

    detection = LoopDetection(
        type=LoopType.REPEATED_COMMAND,
        description="Repeated command",
        evidence="Test",
    )

    suggestion = detector.get_strategy_change_suggestion(detection)
    assert len(suggestion) > 0
    assert "different" in suggestion.lower() or "strategy" in suggestion.lower()


def test_failure_recording():
    """Record failure for learning."""
    detector = AntiLoopDetector()

    from x19.safety.anti_loop import LoopDetection

    detection = LoopDetection(
        type=LoopType.REPEATED_COMMAND,
        description="Repeated curl",
        evidence="curl repeated 3 times",
        task_id="T-1",
        agent_id="web_security",
    )

    failure = detector.record_failure("T-1", "web_security", detection, strategy_tried=["curl", "curl with different headers"])

    assert failure.task_id == "T-1"
    assert failure.agent_id == "web_security"
    assert failure.failure_type == LoopType.REPEATED_COMMAND
    assert len(failure.strategy_tried) == 2
    assert failure.next_strategy is not None
    assert len(detector.failures) == 1
