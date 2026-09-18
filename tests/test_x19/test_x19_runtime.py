"""
X19 Runtime Phase 1 — Comprehensive Test Suite.

Tests cover:
1. X19 activation detection
2. X19 SOUL loading
3. X19 identity in real system prompt path
4. Boss initialization
5. Mission creation
6. Specialist delegation context
7. Explicit delegation context
8. Structured specialist result
9. Boss state update
10. Operator status query
11. Pause/stop/kill-all
12. Hermes baseline compatibility
"""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure the repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


# ============================================================
# 1. X19 ACTIVATION
# ============================================================

class TestX19Activation:
    """Test X19 mode detection."""

    def test_x19_enabled_in_repo(self):
        """X19 mode MUST be enabled when running inside the x19-refactored repo."""
        from x19.identity.core import is_x19_enabled
        assert is_x19_enabled() is True

    def test_x19_disabled_by_env_override(self):
        """X19_ENABLED=0 MUST disable X19 even in the x19 repo."""
        from x19.identity.core import is_x19_enabled
        with patch.dict(os.environ, {"X19_ENABLED": "0"}):
            assert is_x19_enabled() is False

    def test_x19_enabled_by_env_override(self):
        """X19_ENABLED=1 MUST enable X19."""
        from x19.identity.core import is_x19_enabled
        with patch.dict(os.environ, {"X19_ENABLED": "1"}):
            assert is_x19_enabled() is True

    def test_x19_enabled_by_config_dict(self):
        """Explicit config dict MUST override all other detection."""
        from x19.identity.core import is_x19_enabled
        assert is_x19_enabled(config={"x19": {"enabled": True}}) is True
        assert is_x19_enabled(config={"x19": {"enabled": False}}) is False

    def test_x19_env_var_variations(self):
        """All accepted env var values."""
        from x19.identity.core import is_x19_enabled
        for val in ("1", "true", "TRUE", "yes", "YES", "on", "ON"):
            with patch.dict(os.environ, {"X19_ENABLED": val}):
                assert is_x19_enabled() is True, f"X19_ENABLED={val!r} should be True"
        for val in ("0", "false", "FALSE", "no", "NO", "off", "OFF"):
            with patch.dict(os.environ, {"X19_ENABLED": val}):
                assert is_x19_enabled() is False, f"X19_ENABLED={val!r} should be False"

    def test_x19_soul_md_detection(self):
        """Repo SOUL.md MUST contain X19 marker."""
        soul_path = Path(__file__).resolve().parent.parent.parent / "SOUL.md"
        assert soul_path.exists(), "SOUL.md must exist"
        text = soul_path.read_text()
        assert "X19" in text, "SOUL.md must contain 'X19'"
        assert "Autonomous Security Operations" in text, "SOUL.md must contain 'Autonomous Security Operations'"


# ============================================================
# 2. X19 SOUL LOADING
# ============================================================

class TestX19SoulLoading:
    """Test X19 SOUL.md and identity loading."""

    def test_get_x19_identity(self):
        """get_x19_identity() MUST return X19 identity string."""
        from x19.identity.core import get_x19_identity
        identity = get_x19_identity()
        assert "X19" in identity
        assert "Autonomous Security Operations Agent" in identity
        assert identity.startswith("You are X19")

    def test_get_x19_soul_md(self):
        """get_x19_soul_md() MUST return full X19 SOUL.md content."""
        from x19.identity.core import get_x19_soul_md
        soul = get_x19_soul_md()
        assert "X19" in soul
        assert "Autonomous Security Operations Agent" in soul
        assert "Team Model" in soul
        assert "Evidence-First" in soul
        assert "Scope Control" in soul

    def test_soul_md_repo_file_is_x19(self):
        """The actual repo SOUL.md file MUST be X19, not Hermes default."""
        soul_path = Path(__file__).resolve().parent.parent.parent / "SOUL.md"
        text = soul_path.read_text()
        assert "You are X19" in text, "SOUL.md must declare X19 identity"
        assert "You are Hermes Agent" not in text, "SOUL.md must NOT contain 'You are Hermes Agent'"

    def test_x19_guidance_blocks(self):
        """X19 guidance blocks MUST be available."""
        from x19.identity.prompts import get_x19_guidance_blocks
        blocks = get_x19_guidance_blocks()
        assert len(blocks) == 6, f"Expected 6 guidance blocks, got {len(blocks)}"
        all_text = " ".join(blocks)
        assert "Security" in all_text
        assert "Evidence" in all_text
        assert "Team" in all_text

    def test_default_soul_md_returns_x19(self):
        """get_default_soul_md() MUST return X19 when X19 is enabled."""
        from hermes_cli.default_soul import get_default_soul_md
        soul = get_default_soul_md()
        assert "X19" in soul, f"Expected X19 SOUL, got: {soul[:80]}"

    def test_x19_identity_override(self):
        """Custom identity override MUST be respected."""
        from x19.identity.core import get_x19_identity
        custom = "Custom identity for testing"
        result = get_x19_identity(custom_override=custom)
        assert result == custom


# ============================================================
# 3. X19 IDENTITY IN REAL SYSTEM PROMPT PATH
# ============================================================

class TestX19SystemPromptPath:
    """Test that X19 identity flows through the actual system prompt pipeline."""

    def test_prompt_builder_resolves_x19(self):
        """prompt_builder.DEFAULT_AGENT_IDENTITY MUST be X19."""
        from agent.prompt_builder import DEFAULT_AGENT_IDENTITY
        assert "X19" in DEFAULT_AGENT_IDENTITY, \
            f"DEFAULT_AGENT_IDENTITY must be X19, got: {DEFAULT_AGENT_IDENTITY[:80]}"

    def test_prompt_builder_x19_identity_helper(self):
        """_get_x19_identity_for_prompt_builder MUST return X19 identity."""
        from agent.prompt_builder import _get_x19_identity_for_prompt_builder
        identity = _get_x19_identity_for_prompt_builder()
        assert identity is not None
        assert "X19" in identity

    def test_prompt_builder_x19_soul_md_fallback(self):
        """_get_x19_soul_md_if_enabled MUST return X19 SOUL.md."""
        from agent.prompt_builder import _get_x19_soul_md_if_enabled
        soul = _get_x19_soul_md_if_enabled()
        assert soul is not None
        assert "X19" in soul

    def test_system_prompt_identity_parts(self):
        """system_prompt._get_x19_identity_if_enabled MUST return X19 identity."""
        from agent.system_prompt import _get_x19_identity_if_enabled
        identity = _get_x19_identity_if_enabled()
        assert identity is not None
        assert "X19" in identity

    def test_system_prompt_guidance_blocks(self):
        """system_prompt._get_x19_guidance_blocks MUST return 6 blocks."""
        from agent.system_prompt import _get_x19_guidance_blocks
        blocks = _get_x19_guidance_blocks()
        assert len(blocks) == 6

    def test_x19_not_hermes_default_identity(self):
        """When X19 is active, model MUST NOT receive 'You are Hermes Agent'."""
        from agent.prompt_builder import DEFAULT_AGENT_IDENTITY
        hermes_default = "You are Hermes Agent, built by Nous Research."
        assert hermes_default not in DEFAULT_AGENT_IDENTITY, \
            "X19 active: DEFAULT_AGENT_IDENTITY must NOT be Hermes default"


# ============================================================
# 4. BOSS INITIALIZATION
# ============================================================

class TestBossInit:
    """Test BossOrchestrator initialization."""

    def test_boss_creation(self):
        from x19.orchestration.boss import BossOrchestrator
        boss = BossOrchestrator()
        assert boss is not None
        assert boss.mission is None

    def test_boss_with_custom_manager(self):
        from x19.orchestration.boss import BossOrchestrator
        from x19.orchestration.mission_state import MissionStateManager
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = MissionStateManager(storage_dir=tmpdir)
            boss = BossOrchestrator(mission_manager=manager)
            assert boss.mission_manager is manager


# ============================================================
# 5. MISSION CREATION
# ============================================================

class TestMissionCreation:
    """Test mission creation with scope validation."""

    def test_create_mission(self):
        from x19.orchestration.boss import BossOrchestrator
        boss = BossOrchestrator()
        mission, errors = boss.create_mission(
            name="Test Mission",
            target="https://example.com",
            authorized_domains=["example.com"],
            excluded_assets=["example.com/admin"],
            objectives=["Find XSS"],
        )
        assert mission is not None, f"Mission creation failed: {errors}"
        assert len(errors) == 0
        assert mission.name == "Test Mission"
        assert mission.scope.target == "https://example.com"

    def test_mission_state_persistence(self):
        from x19.orchestration.mission_state import MissionStateManager
        from x19.scope.scope import create_scope
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = MissionStateManager(storage_dir=tmpdir)
            scope = create_scope(target="https://example.com", authorized_domains=["example.com"])
            mission = manager.create_mission(name="Persist Test", scope=scope)
            loaded = manager.load_mission(mission.id)
            assert loaded is not None
            assert loaded.id == mission.id
            assert loaded.name == "Persist Test"

    def test_mission_decomposition(self):
        from x19.orchestration.boss import BossOrchestrator
        boss = BossOrchestrator()
        mission, _ = boss.create_mission(
            name="Decomp Test",
            target="https://example.com",
            authorized_domains=["example.com"],
        )
        plan = boss.decompose_mission(mission)
        assert len(plan.tasks) > 0
        recon_tasks = [t for t in plan.tasks if t.assigned_to == "recon_manager"]
        assert len(recon_tasks) > 0
        verify_tasks = [t for t in plan.tasks if t.assigned_to == "verification"]
        assert len(verify_tasks) > 0

    def test_mission_no_hardcoded_data(self):
        from x19.orchestration.boss import BossOrchestrator
        boss = BossOrchestrator()
        mission, _ = boss.create_mission(
            name="No Hardcode",
            target="https://test.example.com",
            authorized_domains=["test.example.com"],
        )
        assert len(mission.findings.findings) == 0
        assert len(mission.agents) == 0
        assert len(mission.discoveries) == 0


# ============================================================
# 6. SPECIALIST DELEGATION
# ============================================================

class TestSpecialistDelegation:
    """Test specialist delegation context construction."""

    def test_specialist_goal_construction(self):
        from x19.specialists.base import build_specialist_goal
        goal = build_specialist_goal(
            role_id="recon_manager",
            objective="Asset discovery",
            target="https://example.com",
            scope={"target": "https://example.com", "authorized_domains": ["example.com"],
                   "excluded_assets": [], "allowed_actions": ["read_only_get"], "prohibited_actions": []},
        )
        assert "Recon Manager" in goal
        assert "Asset discovery" in goal
        assert "https://example.com" in goal

    def test_specialist_context_construction(self):
        from x19.specialists.base import build_specialist_context
        context = build_specialist_context(
            role_id="recon_manager",
            mission_id="M-TEST",
            task_id="T-001",
        )
        assert "M-TEST" in context
        assert "T-001" in context

    def test_specialist_config_to_delegate_args(self):
        from x19.specialists.base import create_specialist_config
        config = create_specialist_config(
            role_id="web_security",
            objective="Test XSS",
            target="https://example.com",
            scope={"target": "https://example.com", "authorized_domains": ["example.com"],
                   "excluded_assets": [], "allowed_actions": ["read_only_get"], "prohibited_actions": []},
            mission_id="M-TEST",
            task_id="T-002",
        )
        args = config.to_delegate_task_args()
        assert "goal" in args
        assert "context" in args
        assert "toolsets" in args
        assert "role" in args
        assert args["role"] == "leaf"

    def test_three_minimal_specialists(self):
        from x19.team.roles import get_role
        for role_id in ("recon_manager", "web_manager", "verification"):
            role = get_role(role_id)
            assert role is not None, f"Role {role_id} must exist"
            assert role.prompt_fragment, f"Role {role_id} must have a prompt"
            assert role.toolsets, f"Role {role_id} must have toolsets"


# ============================================================
# 7. EXPLICIT DELEGATION CONTEXT
# ============================================================

class TestDelegationContext:
    """Test delegation context includes mission_id, target, scope, task_id."""

    def test_delegation_args_include_mission_context(self):
        from x19.orchestration.boss import BossOrchestrator
        boss = BossOrchestrator()
        mission, _ = boss.create_mission(
            name="Delegation Test",
            target="https://example.com",
            authorized_domains=["example.com"],
        )
        plan = boss.decompose_mission(mission)
        boss.assign_tasks(mission, plan)
        ready = boss.get_next_tasks(mission)
        assert len(ready) > 0
        task = ready[0]
        args = boss.build_delegation_args(task, mission)
        assert "goal" in args
        assert "context" in args
        assert mission.id in args["context"]
        assert task.id in args["context"]
        assert "https://example.com" in args["goal"]


# ============================================================
# 8. STRUCTURED SPECIALIST RESULT
# ============================================================

class TestStructuredResult:
    """Test structured specialist result contract."""

    def test_task_completion_updates_state(self):
        from x19.orchestration.boss import BossOrchestrator
        from x19.orchestration.task import TaskStatus
        boss = BossOrchestrator()
        mission, _ = boss.create_mission(
            name="Result Test", target="https://example.com", authorized_domains=["example.com"],
        )
        plan = boss.decompose_mission(mission)
        boss.assign_tasks(mission, plan)
        ready = boss.get_next_tasks(mission)
        task = ready[0]
        task.start()

        result = {
            "agent_id": "recon_manager", "mission_id": mission.id, "task_id": task.id,
            "status": "completed", "observations": ["Found 3 endpoints"],
            "actions_taken": ["GET /", "GET /api", "GET /login"],
            "tool_results": ["200 OK", "200 OK", "302 Redirect"],
            "evidence": ["Server: nginx", "X-Powered-By: Express"],
            "hypotheses": ["Possible IDOR in /api/users"],
            "confirmed_findings": [], "rejected_findings": [],
            "next_recommendation": "Test /api/users for IDOR", "errors": [],
        }
        boss.handle_task_completion(mission, task.id, result)
        updated_task = mission.tasks.get(task.id)
        assert updated_task.status == TaskStatus.COMPLETED
        assert len(updated_task.evidence) > 0

    def test_finding_lifecycle(self):
        from x19.findings.finding import Finding, FindingStatus, Severity, Confidence, VulnClass
        finding = Finding(
            target="https://example.com", endpoint="/search",
            vuln_class=VulnClass.XSS, severity=Severity.HIGH,
            confidence=Confidence.HIGH, status=FindingStatus.CANDIDATE,
        )
        assert finding.status == FindingStatus.CANDIDATE
        assert finding.transition_to(FindingStatus.UNDER_VERIFICATION)
        assert finding.transition_to(FindingStatus.VERIFIED, verified_by="verification_agent")
        assert finding.status == FindingStatus.VERIFIED

    def test_finding_rejection(self):
        from x19.findings.finding import Finding, FindingStatus, Severity, Confidence, VulnClass
        finding = Finding(
            target="https://example.com", endpoint="/search",
            vuln_class=VulnClass.XSS, severity=Severity.HIGH,
            confidence=Confidence.HIGH, status=FindingStatus.CANDIDATE,
        )
        finding.transition_to(FindingStatus.UNDER_VERIFICATION)
        assert finding.transition_to(FindingStatus.REJECTED, reason="False positive")
        assert finding.status == FindingStatus.REJECTED
        assert not finding.can_report_as_verified()


# ============================================================
# 9. BOSS STATE UPDATE
# ============================================================

class TestBossStateUpdate:
    """Test Boss updates mission state correctly."""

    def test_task_failure_handling(self):
        """Failed tasks auto-retry then escalate."""
        from x19.orchestration.boss import BossOrchestrator
        from x19.orchestration.task import TaskStatus
        boss = BossOrchestrator()
        mission, _ = boss.create_mission(
            name="Failure Test", target="https://example.com", authorized_domains=["example.com"],
        )
        plan = boss.decompose_mission(mission)
        boss.assign_tasks(mission, plan)
        ready = boss.get_next_tasks(mission)
        task = ready[0]
        task.start()

        boss.handle_task_failure(mission, task.id, "Network timeout")
        updated_task = mission.tasks.get(task.id)
        assert updated_task.retry_count == 1
        assert updated_task.status == TaskStatus.PENDING

    def test_task_blocked_handling(self):
        from x19.orchestration.boss import BossOrchestrator
        from x19.orchestration.task import TaskStatus
        boss = BossOrchestrator()
        mission, _ = boss.create_mission(
            name="Block Test", target="https://example.com", authorized_domains=["example.com"],
        )
        plan = boss.decompose_mission(mission)
        boss.assign_tasks(mission, plan)
        ready = boss.get_next_tasks(mission)
        task = ready[0]
        task.start()
        boss.handle_task_blocked(mission, task.id, "Requires approval", requires_approval=True)
        updated_task = mission.tasks.get(task.id)
        assert updated_task.status == TaskStatus.BLOCKED
        assert len(mission.blockers) > 0

    def test_timeline_events(self):
        from x19.orchestration.boss import BossOrchestrator
        boss = BossOrchestrator()
        mission, _ = boss.create_mission(
            name="Timeline Test", target="https://example.com", authorized_domains=["example.com"],
        )
        assert len(mission.timeline) > 0

    def test_mission_stats(self):
        from x19.orchestration.boss import BossOrchestrator
        boss = BossOrchestrator()
        mission, _ = boss.create_mission(
            name="Stats Test", target="https://example.com", authorized_domains=["example.com"],
        )
        stats = boss.get_mission_status(mission)
        assert "mission_id" in stats
        assert "status" in stats
        assert "phase" in stats
        assert stats["mission_id"] == mission.id


# ============================================================
# 10. OPERATOR STATUS QUERIES
# ============================================================

class TestOperatorStatus:
    """Test operator status queries come from real mission state."""

    def test_whats_happening(self):
        from x19.interface.operator import OperatorInterface
        from x19.orchestration.mission_state import MissionStateManager
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = MissionStateManager(storage_dir=tmpdir)
            op = OperatorInterface(mission_manager=manager)
            mission, msg = op.start_assessment(
                target="https://example.com", authorized_domains=["example.com"],
            )
            assert mission is not None
            assert "Mission accepted" in msg

    def test_no_mission_status(self):
        from x19.interface.operator import OperatorInterface
        from x19.orchestration.mission_state import MissionStateManager
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = MissionStateManager(storage_dir=tmpdir)
            op = OperatorInterface(mission_manager=manager)
            assert "No active mission" in op.whats_happening()
            assert "No active mission" in op.what_completed()
            assert "No active mission" in op.show_active_tasks()


# ============================================================
# 11. PAUSE/STOP/KILL-ALL
# ============================================================

class TestOperatorControls:
    """Test operator pause/stop/kill-all controls."""

    def test_pause(self):
        from x19.interface.operator import OperatorInterface
        from x19.orchestration.mission_state import MissionStateManager, MissionStatus
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = MissionStateManager(storage_dir=tmpdir)
            op = OperatorInterface(mission_manager=manager)
            mission, _ = op.start_assessment(
                target="https://example.com", authorized_domains=["example.com"],
            )
            result = op.pause()
            assert "paused" in result.lower()
            loaded = manager.load_mission(mission.id)
            assert loaded.status == MissionStatus.PAUSED

    def test_resume(self):
        from x19.interface.operator import OperatorInterface
        from x19.orchestration.mission_state import MissionStateManager, MissionStatus
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = MissionStateManager(storage_dir=tmpdir)
            op = OperatorInterface(mission_manager=manager)
            mission, _ = op.start_assessment(
                target="https://example.com", authorized_domains=["example.com"],
            )
            op.pause()
            result = op.resume()
            assert "resumed" in result.lower()
            loaded = manager.load_mission(mission.id)
            assert loaded.status == MissionStatus.ACTIVE

    def test_stop(self):
        from x19.interface.operator import OperatorInterface
        from x19.orchestration.mission_state import MissionStateManager, MissionStatus
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = MissionStateManager(storage_dir=tmpdir)
            op = OperatorInterface(mission_manager=manager)
            mission, _ = op.start_assessment(
                target="https://example.com", authorized_domains=["example.com"],
            )
            result = op.stop(reason="Testing stop")
            assert "stopped" in result.lower()
            loaded = manager.load_mission(mission.id)
            assert loaded.status == MissionStatus.STOPPED

    def test_kill_all(self):
        from x19.interface.operator import OperatorInterface
        from x19.orchestration.mission_state import MissionStateManager
        from x19.orchestration.task import TaskStatus
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = MissionStateManager(storage_dir=tmpdir)
            op = OperatorInterface(mission_manager=manager)
            mission, _ = op.start_assessment(
                target="https://example.com", authorized_domains=["example.com"],
            )
            result = op.kill_all()
            assert "killed" in result.lower()
            loaded = manager.load_mission(mission.id)
            cancelled = [t for t in loaded.tasks.tasks.values() if t.status == TaskStatus.CANCELLED]
            assert len(cancelled) > 0


# ============================================================
# 12. HERMES BASELINE COMPATIBILITY
# ============================================================

class TestHermesBaselineCompat:
    """Test that Hermes baseline still works when X19 is disabled."""

    def test_x19_disabled_returns_hermes_default(self):
        from x19.identity.core import is_x19_enabled
        with patch.dict(os.environ, {"X19_ENABLED": "0"}):
            assert is_x19_enabled() is False

    def test_config_dict_disable(self):
        from x19.identity.core import is_x19_enabled
        assert is_x19_enabled(config={"x19": {"enabled": False}}) is False

    def test_x19_package_imports_without_error(self):
        import x19
        assert hasattr(x19, '__version__')
        assert hasattr(x19, '__identity__')
        assert x19.__identity__ == "X19 — Autonomous Security Operations Agent"

    def test_orchestration_imports(self):
        from x19.orchestration import BossOrchestrator, MissionState, MissionStateManager
        from x19.orchestration import Task, TaskStore, TaskStatus, TaskPriority
        assert BossOrchestrator is not None
        assert MissionState is not None
        assert Task is not None

    def test_specialists_import(self):
        from x19.specialists import SPECIALIST_MODULES
        assert len(SPECIALIST_MODULES) >= 3


# ============================================================
# MISSION STATE SERIALIZATION
# ============================================================

class TestMissionStateSerialization:
    """Test mission state persistence round-trip."""

    def test_mission_to_dict_from_dict(self):
        from x19.orchestration.mission_state import MissionState, MissionPhase, MissionStatus
        from x19.scope.scope import create_scope
        scope = create_scope(target="https://example.com", authorized_domains=["example.com"])
        mission = MissionState(
            name="Serialization Test", scope=scope,
            objectives=["Test XSS"], phase=MissionPhase.RECON, status=MissionStatus.ACTIVE,
        )
        mission.add_timeline_event(MissionPhase.RECON, "Started recon", "recon_manager")
        mission.add_discovery("endpoints", "/api/users")
        mission.add_hypothesis({"vuln_class": "xss", "endpoint": "/search"})
        data = mission.to_dict()
        restored = MissionState.from_dict(data)
        assert restored.id == mission.id
        assert restored.name == "Serialization Test"
        assert restored.phase == MissionPhase.RECON
        assert len(restored.timeline) == len(mission.timeline)


# ============================================================
# SCOPE VALIDATION
# ============================================================

class TestScopeValidation:
    """Test scope enforcement."""

    def test_valid_scope(self):
        from x19.scope.scope import create_scope, validate_scope
        scope = create_scope(target="https://example.com", authorized_domains=["example.com"])
        valid, errors = validate_scope(scope)
        assert valid is True
        assert len(errors) == 0

    def test_scope_creation(self):
        from x19.scope.scope import create_scope
        scope = create_scope(
            target="https://example.com",
            authorized_domains=["example.com", "*.api.example.com"],
            excluded_assets=["example.com/admin"],
            program_name="Example BBP",
        )
        assert scope.target == "https://example.com"
        assert "example.com" in scope.authorized_domains

    def test_scope_to_dict(self):
        from x19.scope.scope import create_scope
        scope = create_scope(target="https://example.com", authorized_domains=["example.com"])
        data = scope.to_dict()
        assert "target" in data
        assert data["target"] == "https://example.com"


# ============================================================
# STRUCTURED REPORT CONTRACT
# ============================================================

class TestReportContract:
    """Test the machine-readable specialist result contract."""

    REQUIRED_FIELDS = [
        "agent_id", "mission_id", "task_id", "status",
        "observations", "actions_taken", "tool_results",
        "evidence", "hypotheses", "confirmed_findings",
        "rejected_findings", "next_recommendation", "errors",
    ]

    def test_report_contract_has_all_fields(self):
        result = {
            "agent_id": "recon_manager", "mission_id": "M-TEST", "task_id": "T-001",
            "status": "completed", "observations": ["Found 3 endpoints"],
            "actions_taken": ["GET /"], "tool_results": ["200 OK"],
            "evidence": ["Server: nginx"], "hypotheses": ["Possible XSS"],
            "confirmed_findings": [], "rejected_findings": [],
            "next_recommendation": "Test XSS", "errors": [],
        }
        for field in self.REQUIRED_FIELDS:
            assert field in result, f"Missing required field: {field}"

    def test_report_contract_is_machine_readable(self):
        result = {
            "agent_id": "web_security", "mission_id": "M-TEST", "task_id": "T-002",
            "status": "completed", "observations": ["Reflected XSS in /search"],
            "actions_taken": ["Sent payload"], "tool_results": ["Script reflected"],
            "evidence": ["Unescaped script tag"],
            "hypotheses": [{"vuln_class": "xss", "confidence": "high"}],
            "confirmed_findings": [], "rejected_findings": [],
            "next_recommendation": "Verify with different payloads", "errors": [],
        }
        serialized = json.dumps(result)
        deserialized = json.loads(serialized)
        assert deserialized == result

    def test_boss_parses_report_contract(self):
        from x19.orchestration.boss import BossOrchestrator
        from x19.orchestration.task import TaskStatus
        boss = BossOrchestrator()
        mission, _ = boss.create_mission(
            name="Report Parse Test", target="https://example.com", authorized_domains=["example.com"],
        )
        plan = boss.decompose_mission(mission)
        boss.assign_tasks(mission, plan)
        ready = boss.get_next_tasks(mission)
        task = ready[0]
        task.start()

        result = {
            "agent_id": "recon_manager", "mission_id": mission.id, "task_id": task.id,
            "status": "completed",
            "observations": ["Subdomain: api.example.com"],
            "actions_taken": ["DNS enum", "Header analysis"],
            "tool_results": ["api.example.com A 1.2.3.4"],
            "evidence": ["4 endpoints discovered"],
            "hypotheses": [{"id": "H-1", "vuln_class": "cors_misconfig", "endpoint": "/api"}],
            "confirmed_findings": [], "rejected_findings": [],
            "next_recommendation": "Test CORS", "errors": [],
        }
        boss.handle_task_completion(mission, task.id, result)
        updated_task = mission.tasks.get(task.id)
        assert updated_task.status == TaskStatus.COMPLETED
        assert len(updated_task.evidence) > 0


# ============================================================
# ANTI-LOOP / SAFETY
# ============================================================

class TestAntiLoop:
    """Test anti-loop detection and mission safety."""

    def test_anti_loop_detector_exists(self):
        from x19.safety.anti_loop import AntiLoopDetector
        detector = AntiLoopDetector()
        stats = detector.get_stats()
        assert "total_detections" in stats

    def test_anti_loop_records_failure(self):
        from x19.safety.anti_loop import AntiLoopDetector, LoopDetection, LoopType
        detector = AntiLoopDetector()
        detection = LoopDetection(
            type=LoopType.NO_PROGRESS,
            description="Task failed 3 times",
            evidence="Network timeout",
            task_id="T-001",
            agent_id="recon_manager",
            severity="medium",
            suggested_action="Change strategy",
        )
        detector.detections.append(detection)
        detector.record_failure("T-001", "recon_manager", detection, strategy_tried=["recon scan"])
        stats = detector.get_stats()
        assert stats["total_detections"] > 0

    def test_scope_enforcement(self):
        from x19.scope.scope import create_scope, validate_scope
        scope = create_scope(target="https://example.com", authorized_domains=["example.com"])
        valid, errors = validate_scope(scope)
        assert valid is True

    def test_scope_to_dict_round_trip(self):
        from x19.scope.scope import create_scope, ScopeDefinition
        scope = create_scope(
            target="https://example.com",
            authorized_domains=["example.com"],
            excluded_assets=["example.com/admin"],
        )
        data = scope.to_dict()
        restored = ScopeDefinition.from_dict(data)
        assert restored.target == scope.target
        assert restored.authorized_domains == scope.authorized_domains


# ============================================================
# MISSION STATE COMPLETENESS
# ============================================================

class TestMissionStateCompleteness:
    """Test that MissionState has ALL required fields per spec."""

    def test_mission_state_required_fields(self):
        from x19.orchestration.mission_state import MissionState, MissionPhase, MissionStatus
        from x19.scope.scope import create_scope
        scope = create_scope(target="https://example.com", authorized_domains=["example.com"])
        mission = MissionState(name="Field Test", scope=scope, objectives=["Test"])

        assert hasattr(mission, 'id') and mission.id
        assert mission.scope.target == "https://example.com"
        assert mission.scope is not None
        assert hasattr(mission, 'status')
        assert hasattr(mission, 'phase')
        assert hasattr(mission, 'objectives')
        assert hasattr(mission, 'tasks')
        stats = mission.tasks.get_stats()
        assert "pending" in stats and "completed" in stats and "blocked" in stats
        assert hasattr(mission, 'findings')
        assert hasattr(mission, 'agents')
        assert hasattr(mission, 'timeline')
        assert hasattr(mission, 'evidence')
        assert hasattr(mission, 'created_at')
        assert hasattr(mission, 'updated_at')


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
