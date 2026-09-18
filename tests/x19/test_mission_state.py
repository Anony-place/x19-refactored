"""Tests for X19 mission state — real-time, no mock, from runtime."""

import sys
sys.path.insert(0, '.')

import tempfile
import shutil
from pathlib import Path

from x19.scope import create_scope
from x19.orchestration import MissionStateManager, MissionState, MissionPhase, MissionStatus, Task, TaskStatus
from x19.findings import create_candidate_finding, VulnClass, FindingStatus
from x19.mission import get_mission_status


def test_mission_creation():
    """Mission must have explicit scope, objectives, phase."""
    tmpdir = tempfile.mkdtemp()
    try:
        scope = create_scope(target="https://target.com", authorized_domains=["target.com"])
        manager = MissionStateManager(storage_dir=tmpdir)
        mission = manager.create_mission(name="Test Mission", scope=scope, objectives=["Assess target.com"])

        assert mission.id.startswith("M-")
        assert mission.name == "Test Mission"
        assert mission.scope.target == "https://target.com"
        assert mission.phase == MissionPhase.SCOPE
        assert mission.status == MissionStatus.ACTIVE
        assert len(mission.objectives) == 1
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_mission_persistence():
    """Mission state must persist via file (uses Hermes state pattern)."""
    tmpdir = tempfile.mkdtemp()
    try:
        scope = create_scope(target="https://target.com", authorized_domains=["target.com"])
        manager = MissionStateManager(storage_dir=tmpdir)
        mission = manager.create_mission(name="Test Mission", scope=scope)

        # Save and load
        manager.save_mission(mission)
        loaded = manager.load_mission(mission.id)

        assert loaded is not None
        assert loaded.id == mission.id
        assert loaded.name == mission.name
        assert loaded.scope.target == mission.scope.target
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_mission_status_no_mock():
    """Mission status must be derived from real runtime state, no mock."""
    tmpdir = tempfile.mkdtemp()
    try:
        scope = create_scope(target="https://target.com", authorized_domains=["target.com"])
        manager = MissionStateManager(storage_dir=tmpdir)
        mission = manager.create_mission(name="Test Mission", scope=scope)

        # Add tasks
        task1 = Task(mission_id=mission.id, objective="Recon", target="https://target.com", assigned_to="recon_manager")
        task2 = Task(mission_id=mission.id, objective="Web test", target="https://target.com", assigned_to="web_security")
        mission.tasks.add(task1)
        mission.tasks.add(task2)

        task1.start()
        task1.complete()

        # Add discovery
        mission.add_discovery("subdomains", "sub.target.com")
        mission.add_discovery("endpoints", "/api/users")

        # Add finding
        finding = create_candidate_finding(
            target="https://target.com",
            endpoint="/api/users",
            vuln_class=VulnClass.BOLA,
            observed_evidence="BOLA",
            tool_output="BOLA output",
            tool_name="terminal",
            agent_id="api_security",
        )
        mission.findings.add(finding)

        status = get_mission_status(mission)

        # Must be from real state, not mock
        assert status["mission_id"] == mission.id
        assert status["tasks"]["total"] == 2
        assert status["tasks"]["completed"] == 1
        assert status["discoveries"]["subdomains"] == 1
        assert status["discoveries"]["endpoints"] == 1
        assert status["findings"]["total"] == 1
        assert status["findings"]["candidates"] == 1

        # No fake progress
        assert status["tasks"]["total"] == len(mission.tasks.tasks)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_mission_phase_transitions():
    """Mission phase must transition via explicit methods, not fabricated."""
    tmpdir = tempfile.mkdtemp()
    try:
        scope = create_scope(target="https://target.com")
        manager = MissionStateManager(storage_dir=tmpdir)
        mission = manager.create_mission(name="Test", scope=scope)

        assert mission.phase == MissionPhase.SCOPE

        mission.set_phase(MissionPhase.PLAN)
        assert mission.phase == MissionPhase.PLAN
        assert len(mission.timeline) >= 2  # Created + phase transition

        mission.set_phase(MissionPhase.RECON)
        assert mission.phase == MissionPhase.RECON
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_mission_timeline_real():
    """Timeline must be real events, not fabricated."""
    tmpdir = tempfile.mkdtemp()
    try:
        scope = create_scope(target="https://target.com")
        manager = MissionStateManager(storage_dir=tmpdir)
        mission = manager.create_mission(name="Test", scope=scope)

        initial_len = len(mission.timeline)

        mission.add_timeline_event(MissionPhase.RECON, "Recon started", "recon_manager", "Starting subdomain enum")
        assert len(mission.timeline) == initial_len + 1
        assert mission.timeline[-1]["event"] == "Recon started"
        assert mission.timeline[-1]["agent"] == "recon_manager"
        assert mission.timeline[-1]["phase"] == "recon"

        # Timeline must have timestamps
        assert "timestamp" in mission.timeline[-1]
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_mission_blockers():
    """Blockers must be tracked from real runtime."""
    tmpdir = tempfile.mkdtemp()
    try:
        scope = create_scope(target="https://target.com")
        manager = MissionStateManager(storage_dir=tmpdir)
        mission = manager.create_mission(name="Test", scope=scope)

        assert len(mission.blockers) == 0

        mission.add_blocker("auth_required", "Auth required for /api/users", task_id="T-123", agent_id="api_security")

        assert len(mission.blockers) == 1
        assert mission.blockers[0]["type"] == "auth_required"
        assert mission.blockers[0]["task_id"] == "T-123"
        assert not mission.blockers[0]["resolved"]
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_mission_lessons_provenance():
    """Lessons must have provenance: FACT, OBSERVATION, LESSON, SKILL, HYPOTHESIS."""
    tmpdir = tempfile.mkdtemp()
    try:
        scope = create_scope(target="https://target.com")
        manager = MissionStateManager(storage_dir=tmpdir)
        mission = manager.create_mission(name="Test", scope=scope)

        mission.add_lesson("FACT", "Target uses nginx", "Tool output: Server header", "high")
        mission.add_lesson("OBSERVATION", "Endpoint /api/users returns 200", "curl output", "medium")
        mission.add_lesson("LESSON", "BOLA testing requires auth", "Failed without auth", "medium")

        assert len(mission.lessons) == 3
        assert mission.lessons[0]["type"] == "FACT"
        assert mission.lessons[1]["type"] == "OBSERVATION"
        assert mission.lessons[2]["type"] == "LESSON"

        # Invalid type must raise
        try:
            mission.add_lesson("INVALID", "Test", "Test", "low")
            assert False, "Should have raised ValueError"
        except ValueError:
            pass
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
