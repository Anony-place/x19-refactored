"""Tests for X19 Boss orchestration — mission decomposition, delegation, state tracking."""

import sys
sys.path.insert(0, '.')

import tempfile
import shutil

from x19.scope import create_scope
from x19.orchestration import MissionStateManager, TaskStatus
from x19.orchestration.boss import BossOrchestrator
from x19.team import TEAM_HIERARCHY


def test_boss_create_mission():
    """Boss must create mission with explicit scope, enforce before delegating."""
    tmpdir = tempfile.mkdtemp()
    try:
        manager = MissionStateManager(storage_dir=tmpdir)
        boss = BossOrchestrator(manager)

        mission, errors = boss.create_mission(
            name="Test Mission",
            target="https://target.com",
            authorized_domains=["target.com"],
            excluded_assets=["/admin"],
            objectives=["Assess target.com"],
        )

        assert mission is not None, f"Failed to create mission: {errors}"
        assert mission.scope.target == "https://target.com"
        assert "target.com" in mission.scope.authorized_domains
        assert "/admin" in mission.scope.excluded_assets
        assert len(errors) == 0
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_boss_decompose_mission():
    """Boss must decompose mission into tasks for Managers/Specialists."""
    tmpdir = tempfile.mkdtemp()
    try:
        scope = create_scope(target="https://target.com", authorized_domains=["target.com"])
        manager = MissionStateManager(storage_dir=tmpdir)
        boss = BossOrchestrator(manager)
        mission, _ = boss.create_mission(name="Test", target="https://target.com", authorized_domains=["target.com"])

        plan = boss.decompose_mission(mission)

        assert len(plan.tasks) == 7  # Recon, attack surface, hypothesis, web, api, verification, reporting
        assert len(plan.parallel_groups) == 6

        # Check tasks assigned to correct roles
        assigned_roles = [t.assigned_to for t in plan.tasks]
        assert "recon_manager" in assigned_roles
        assert "vuln_research" in assigned_roles
        assert "web_manager" in assigned_roles
        assert "api_manager" in assigned_roles
        assert "verification" in assigned_roles
        assert "evidence_reporting" in assigned_roles

        # Check dependencies
        recon_task = [t for t in plan.tasks if t.assigned_to == "recon_manager"][0]
        assert len(recon_task.depends_on) == 0  # Recon has no dependencies

        attack_surface_task = [t for t in plan.tasks if "attack surface" in t.objective.lower()][0]
        assert recon_task.id in attack_surface_task.depends_on

        # Web and API should be parallel (same dependency, no dependency between them)
        web_task = [t for t in plan.tasks if t.assigned_to == "web_manager"][0]
        api_task = [t for t in plan.tasks if t.assigned_to == "api_manager"][0]
        assert web_task.depends_on == api_task.depends_on  # Same dependency, can run parallel
        assert web_task.id not in api_task.depends_on
        assert api_task.id not in web_task.depends_on
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_boss_assign_tasks_prevents_duplicates():
    """Boss must prevent duplicate work."""
    tmpdir = tempfile.mkdtemp()
    try:
        scope = create_scope(target="https://target.com", authorized_domains=["target.com"])
        manager = MissionStateManager(storage_dir=tmpdir)
        boss = BossOrchestrator(manager)
        mission, _ = boss.create_mission(name="Test", target="https://target.com", authorized_domains=["target.com"])

        plan = boss.decompose_mission(mission)
        assigned1 = boss.assign_tasks(mission, plan)
        assigned2 = boss.assign_tasks(mission, plan)

        # Second assignment should not create duplicates (same IDs returned)
        assert len(assigned1) == len(assigned2)
        assert mission.tasks.get_stats()["total"] == len(plan.tasks)  # Not double
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_boss_get_next_tasks():
    """Boss must get next tasks that are ready (dependencies completed)."""
    tmpdir = tempfile.mkdtemp()
    try:
        scope = create_scope(target="https://target.com")
        manager = MissionStateManager(storage_dir=tmpdir)
        boss = BossOrchestrator(manager)
        mission, _ = boss.create_mission(name="Test", target="https://target.com")
        plan = boss.decompose_mission(mission)
        boss.assign_tasks(mission, plan)

        # Initially, only recon should be ready (no dependencies)
        next_tasks = boss.get_next_tasks(mission)
        assert len(next_tasks) == 1
        assert next_tasks[0].assigned_to == "recon_manager"

        # Complete recon, next should be attack surface
        recon_task = next_tasks[0]
        recon_task.start()
        recon_task.complete()
        mission.tasks.tasks[recon_task.id] = recon_task

        next_tasks = boss.get_next_tasks(mission)
        assert len(next_tasks) == 1
        assert "attack surface" in next_tasks[0].objective.lower()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_boss_build_delegation_args():
    """Boss must build delegate_task args with goal, context, toolsets, role."""
    tmpdir = tempfile.mkdtemp()
    try:
        scope = create_scope(target="https://target.com", authorized_domains=["target.com"])
        manager = MissionStateManager(storage_dir=tmpdir)
        boss = BossOrchestrator(manager)
        mission, _ = boss.create_mission(name="Test", target="https://target.com", authorized_domains=["target.com"])
        plan = boss.decompose_mission(mission)
        boss.assign_tasks(mission, plan)

        task = list(mission.tasks.tasks.values())[0]
        args = boss.build_delegation_args(task, mission)

        assert "goal" in args
        assert "context" in args
        assert "toolsets" in args
        assert "role" in args
        assert len(args["goal"]) > 50
        assert len(args["context"]) > 50
        assert len(args["toolsets"]) > 0
        assert args["role"] in ("orchestrator", "leaf")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_boss_handle_task_completion():
    """Boss must handle task completion: update state, add evidence."""
    tmpdir = tempfile.mkdtemp()
    try:
        scope = create_scope(target="https://target.com")
        manager = MissionStateManager(storage_dir=tmpdir)
        boss = BossOrchestrator(manager)
        mission, _ = boss.create_mission(name="Test", target="https://target.com")
        plan = boss.decompose_mission(mission)
        boss.assign_tasks(mission, plan)

        task = list(mission.tasks.tasks.values())[0]
        task.start()

        result = {"tool_output": "Found subdomains: a.target.com", "evidence": "subdomains"}

        boss.handle_task_completion(mission, task.id, result)

        updated_task = mission.tasks.get(task.id)
        assert updated_task.status == TaskStatus.COMPLETED
        assert len(updated_task.evidence) == 1
        assert len(mission.timeline) >= 2
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_boss_controls_pause_resume_stop_kill():
    """Boss must support Operator controls: PAUSE/STOP/KILL ALL/RESET."""
    tmpdir = tempfile.mkdtemp()
    try:
        scope = create_scope(target="https://target.com")
        manager = MissionStateManager(storage_dir=tmpdir)
        boss = BossOrchestrator(manager)
        mission, _ = boss.create_mission(name="Test", target="https://target.com")
        plan = boss.decompose_mission(mission)
        boss.assign_tasks(mission, plan)

        # Pause
        boss.pause_mission(mission)
        assert mission.status.value == "paused"

        # Resume
        boss.resume_mission(mission)
        assert mission.status.value == "active"

        # Stop
        boss.stop_mission(mission, "Test stop")
        assert mission.status.value == "stopped"

        # Kill all
        # Reset to active first
        from x19.orchestration.mission_state import MissionStatus
        mission.status = MissionStatus.ACTIVE
        boss.kill_all_tasks(mission)

        for task in mission.tasks.tasks.values():
            assert task.status.value == "cancelled"
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
