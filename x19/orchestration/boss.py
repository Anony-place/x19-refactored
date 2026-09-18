"""
X19 Boss Orchestration — mission decomposition, delegation, state tracking.

Boss uses Hermes' existing delegation infrastructure (delegate_task tool),
not a second framework. Boss is orchestrator role, Managers are orchestrator,
Specialists are leaf.

Boss capabilities:
- decompose missions, assign tasks, run independent tasks in parallel,
  track task state, receive reports, detect blocked agents, retry failed work,
  prevent duplicate work, escalate important findings, request verification,
  terminate unproductive loops, update mission state, explain to operator.
"""

from __future__ import annotations

from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime

from x19.team.roles import get_role, ROLE_HIERARCHY, ALL_ROLES
from x19.team.hierarchy import TEAM_HIERARCHY
from x19.scope.scope import ScopeDefinition, ScopeEnforcer, validate_scope
from x19.orchestration.mission_state import MissionState, MissionPhase, MissionStatus, MissionStateManager
from x19.orchestration.task import Task, TaskStatus, TaskPriority
from x19.specialists.base import create_specialist_config
from x19.findings.finding import Finding, FindingStatus


@dataclass
class DelegationPlan:
    """Plan for delegation: which tasks to which roles."""

    tasks: List[Task]
    parallel_groups: List[List[str]]  # Groups of task IDs that can run in parallel
    dependencies: Dict[str, List[str]]  # task_id → depends_on task_ids


class BossOrchestrator:
    """Boss/Commander orchestration logic — uses Hermes delegation."""

    def __init__(self, mission_manager: Optional[MissionStateManager] = None):
        self.mission_manager = mission_manager or MissionStateManager()
        self.mission: Optional[MissionState] = None

    def create_mission(
        self,
        name: str,
        target: str,
        authorized_domains: Optional[List[str]] = None,
        excluded_assets: Optional[List[str]] = None,
        objectives: Optional[List[str]] = None,
        program_name: Optional[str] = None,
        **scope_kwargs,
    ) -> Tuple[MissionState, List[str]]:
        """Create mission with explicit scope — Boss enforces before delegating."""
        from x19.scope.scope import create_scope

        scope = create_scope(
            target=target,
            authorized_domains=authorized_domains,
            excluded_assets=excluded_assets,
            program_name=program_name,
            **scope_kwargs,
        )

        # Validate scope
        valid, errors = validate_scope(scope)
        if not valid:
            return None, errors

        mission = self.mission_manager.create_mission(
            name=name,
            scope=scope,
            objectives=objectives or [f"Assess {target} for vulnerabilities"],
        )

        self.mission = mission
        return mission, []

    def decompose_mission(self, mission: MissionState) -> DelegationPlan:
        """Decompose mission into tasks for Managers/Specialists."""
        tasks = []
        scope_dict = mission.scope.to_dict() if mission.scope else {}

        # Phase 1: Recon — always first
        recon_task = Task(
            mission_id=mission.id,
            objective="Asset discovery: subdomains, endpoints, tech fingerprint, auth surface (read-only)",
            target=mission.scope.target if mission.scope else "unknown",
            assigned_to="recon_manager",
            scope=scope_dict,
            allowed_actions=["read_only_get", "header_analysis", "endpoint_discovery", "tech_fingerprint", "subdomain_enum"],
            expected_evidence=["asset_inventory", "endpoint_list", "tech_fingerprint", "tool_output"],
            priority=TaskPriority.HIGH,
        )
        tasks.append(recon_task)

        # Phase 2: Attack surface modeling — depends on recon
        attack_surface_task = Task(
            mission_id=mission.id,
            objective="Build attack surface model: inputs, sinks, trust boundaries, auth flows from recon data",
            target=mission.scope.target if mission.scope else "unknown",
            assigned_to="vuln_research",
            scope=scope_dict,
            depends_on=[recon_task.id],
            expected_evidence=["attack_surface_model", "inputs", "sinks", "trust_boundaries"],
            priority=TaskPriority.HIGH,
        )
        tasks.append(attack_surface_task)

        # Phase 3: Hypothesis generation — depends on attack surface
        hypothesis_task = Task(
            mission_id=mission.id,
            objective="Generate testable hypotheses from recon and attack surface: vuln class, rationale, test method",
            target=mission.scope.target if mission.scope else "unknown",
            assigned_to="vuln_research",
            scope=scope_dict,
            depends_on=[attack_surface_task.id],
            expected_evidence=["hypotheses", "prioritized_test_plan", "methodology_refs"],
            priority=TaskPriority.HIGH,
        )
        tasks.append(hypothesis_task)

        # Phase 4: Testing — web and api in parallel, depends on hypotheses
        web_test_task = Task(
            mission_id=mission.id,
            objective="Web security testing: XSS, SQLi, SSTI, SSRF, XXE, open redirect, etc. with witness payloads",
            target=mission.scope.target if mission.scope else "unknown",
            assigned_to="web_manager",
            scope=scope_dict,
            depends_on=[hypothesis_task.id],
            allowed_actions=["read_only_get", "witness_payload", "header_analysis"],
            expected_evidence=["web_test_evidence", "candidate_findings", "tool_output"],
            priority=TaskPriority.MEDIUM,
        )
        tasks.append(web_test_task)

        api_test_task = Task(
            mission_id=mission.id,
            objective="API security testing: BOLA, BFLA, injection, mass assignment, excessive data exposure",
            target=mission.scope.target if mission.scope else "unknown",
            assigned_to="api_manager",
            scope=scope_dict,
            depends_on=[hypothesis_task.id],
            allowed_actions=["read_only_get", "witness_payload"],
            expected_evidence=["api_test_evidence", "candidate_findings", "tool_output"],
            priority=TaskPriority.MEDIUM,
        )
        tasks.append(api_test_task)

        # Phase 5: Verification — depends on testing
        verification_task = Task(
            mission_id=mission.id,
            objective="Verify candidate findings: reproduce with minimal proof, bypass exhaustion before false-positive",
            target=mission.scope.target if mission.scope else "unknown",
            assigned_to="verification",
            scope=scope_dict,
            depends_on=[web_test_task.id, api_test_task.id],
            expected_evidence=["verification_result", "verified_findings", "rejected_findings"],
            priority=TaskPriority.HIGH,
        )
        tasks.append(verification_task)

        # Phase 6: Reporting — depends on verification
        reporting_task = Task(
            mission_id=mission.id,
            objective="Evidence collection and reporting: L3/L4 only for verified, L1/L2 as candidates, never rejected as confirmed",
            target=mission.scope.target if mission.scope else "unknown",
            assigned_to="evidence_reporting",
            scope=scope_dict,
            depends_on=[verification_task.id],
            expected_evidence=["evidence_bundle", "final_report", "remediation_guidance"],
            priority=TaskPriority.HIGH,
        )
        tasks.append(reporting_task)

        # Parallel groups: recon alone, then attack surface + hypothesis sequential, then web+api parallel, then verification, then reporting
        parallel_groups = [
            [recon_task.id],
            [attack_surface_task.id],
            [hypothesis_task.id],
            [web_test_task.id, api_test_task.id],  # Parallel
            [verification_task.id],
            [reporting_task.id],
        ]

        dependencies = {t.id: t.depends_on for t in tasks}

        return DelegationPlan(tasks=tasks, parallel_groups=parallel_groups, dependencies=dependencies)

    def assign_tasks(self, mission: MissionState, plan: DelegationPlan) -> List[str]:
        """Assign tasks to mission state, preventing duplicates."""
        assigned_ids = []
        for task in plan.tasks:
            task_id = mission.tasks.add(task)
            assigned_ids.append(task_id)
            mission.add_timeline_event(
                MissionPhase.PLAN, f"Task assigned: {task.objective[:60]} → {task.assigned_to}", "boss", f"Task ID: {task_id}"
            )

        self.mission_manager.save_mission(mission)
        return assigned_ids

    def get_next_tasks(self, mission: MissionState) -> List[Task]:
        """Get next tasks that are ready to run (dependencies completed)."""
        ready = []
        for task in mission.tasks.tasks.values():
            if task.status != TaskStatus.PENDING:
                continue

            # Check dependencies
            deps_ok = True
            for dep_id in task.depends_on:
                dep = mission.tasks.get(dep_id)
                if not dep or dep.status != TaskStatus.COMPLETED:
                    deps_ok = False
                    break

            if deps_ok:
                ready.append(task)

        return ready

    def build_delegation_args(self, task: Task, mission: MissionState) -> Dict[str, Any]:
        """Build delegate_task arguments for a task."""
        role = get_role(task.assigned_to)
        if not role:
            raise ValueError(f"Unknown role: {task.assigned_to}")

        # Build goal and context via specialist base
        from x19.specialists.base import build_specialist_goal, build_specialist_context

        scope_dict = mission.scope.to_dict() if mission.scope else {}

        goal = build_specialist_goal(
            role_id=task.assigned_to,
            objective=task.objective,
            target=task.target,
            scope=scope_dict,
            recon_data=str(mission.discoveries) if mission.discoveries else None,
            additional_context=f"Mission {mission.id}, Task {task.id}, Phase {mission.phase.value}",
        )

        context = build_specialist_context(
            role_id=task.assigned_to,
            mission_id=mission.id,
            task_id=task.id,
            attack_surface=str(mission.discoveries) if mission.discoveries else None,
            previous_findings=list(mission.findings.findings.values())[:5] if mission.findings else None,
        )

        return {
            "goal": goal,
            "context": context,
            "toolsets": role.toolsets,
            "role": role.delegation_role.value,
            "max_iterations": 150,
        }

    def handle_task_completion(
        self, mission: MissionState, task_id: str, result: Dict[str, Any], findings: Optional[List[Finding]] = None
    ):
        """Handle task completion: update state, add evidence, check next tasks."""
        task = mission.tasks.get(task_id)
        if not task:
            return

        # Update task
        task.complete(evidence=[result], findings=[f.id for f in findings] if findings else [])
        mission.tasks.tasks[task_id] = task

        # Add findings
        if findings:
            for finding in findings:
                mission.findings.add(finding)

        # Add timeline event
        mission.add_timeline_event(mission.phase, f"Task completed: {task.objective[:60]}", task.assigned_to, f"Task ID: {task_id}")

        # Check if phase should transition
        self._check_phase_transition(mission)

        self.mission_manager.save_mission(mission)

    def handle_task_failure(self, mission: MissionState, task_id: str, reason: str):
        """Handle task failure: retry or escalate."""
        task = mission.tasks.get(task_id)
        if not task:
            return

        task.fail(reason)
        mission.add_timeline_event(mission.phase, f"Task failed: {task.objective[:60]} — {reason}", task.assigned_to)

        # Record failure in anti-loop
        from x19.safety.anti_loop import LoopDetection, LoopType
        detection = LoopDetection(
            type=LoopType.NO_PROGRESS,
            description=f"Task failed: {reason}",
            evidence=reason,
            task_id=task_id,
            agent_id=task.assigned_to,
            severity="medium",
            suggested_action="Retry or change strategy",
        )
        mission.anti_loop.detections.append(detection)
        mission.anti_loop.record_failure(task_id, task.assigned_to, detection, strategy_tried=[task.objective])

        # Check if can retry
        if task.can_retry():
            task.retry()
            mission.add_timeline_event(mission.phase, f"Task retrying: {task.id} (attempt {task.retry_count})", "boss")
        else:
            # Escalate: add blocker
            mission.add_blocker("task_failure", f"Task {task_id} failed after {task.retry_count} retries: {reason}", task_id, task.assigned_to)

        self.mission_manager.save_mission(mission)

    def handle_task_blocked(self, mission: MissionState, task_id: str, reason: str, requires_approval: bool = False):
        """Handle blocked task."""
        task = mission.tasks.get(task_id)
        if not task:
            return

        task.block(reason, requires_approval)
        mission.add_blocker("task_blocked", reason, task_id, task.assigned_to)
        mission.add_timeline_event(mission.phase, f"Task blocked: {task.objective[:60]} — {reason}", task.assigned_to)

        self.mission_manager.save_mission(mission)

    def _check_phase_transition(self, mission: MissionState):
        """Check if mission should transition to next phase based on task completion."""
        stats = mission.tasks.get_stats()

        # If all tasks completed, move to next phase or completed
        if stats["total"] > 0 and stats["completed"] == stats["total"]:
            if mission.phase == MissionPhase.REPORT:
                mission.set_phase(MissionPhase.COMPLETED)
                mission.status = MissionStatus.COMPLETED
            # Otherwise, phase transitions are managed by task dependencies

        # Check anti-loop should stop
        should_stop, reason = mission.anti_loop.should_stop_mission()
        if should_stop:
            mission.status = MissionStatus.STOPPED
            mission.add_blocker("anti_loop", reason)
            mission.add_timeline_event(mission.phase, f"Mission stopped by anti-loop: {reason}", "boss")

    def get_mission_status(self, mission: MissionState) -> Dict[str, Any]:
        """Get mission status — real-time, no mock, from actual runtime state."""
        return mission.get_stats()

    def pause_mission(self, mission: MissionState) -> MissionState:
        """Pause mission and prevent new runtime delegations."""
        try:
            from tools.delegate_tool_registry import set_spawn_paused
            set_spawn_paused(True)
        except Exception:
            pass
        mission.status = MissionStatus.PAUSED
        mission.set_phase(MissionPhase.PAUSED)
        mission.add_timeline_event(MissionPhase.PAUSED, "Mission paused by Operator; new delegation blocked", "operator")
        self.mission_manager.save_mission(mission)
        return mission

    def resume_mission(self, mission: MissionState) -> MissionState:
        """Resume mission and allow new runtime delegations."""
        try:
            from tools.delegate_tool_registry import set_spawn_paused
            set_spawn_paused(False)
        except Exception:
            pass
        mission.status = MissionStatus.ACTIVE
        mission.set_phase(MissionPhase.REASSESS)
        mission.add_timeline_event(MissionPhase.REASSESS, "Mission resumed by Operator", "operator")
        self.mission_manager.save_mission(mission)
        return mission

    def stop_mission(self, mission: MissionState, reason: str = "Stopped by Operator") -> MissionState:
        """Stop mission and cancel live child work owned by this runtime."""
        try:
            from tools.delegate_tool_registry import list_active_subagents, interrupt_subagent, set_spawn_paused
            set_spawn_paused(True)
            for child in list_active_subagents():
                child_id = child.get("id") if isinstance(child, dict) else getattr(child, "id", None)
                if child_id:
                    try:
                        interrupt_subagent(str(child_id), reason=reason)
                    except Exception:
                        pass
        except Exception:
            pass
        mission.status = MissionStatus.STOPPED
        mission.set_phase(MissionPhase.STOPPED)
        mission.add_timeline_event(MissionPhase.STOPPED, reason, "operator")
        self.mission_manager.save_mission(mission)
        return mission

    def kill_all_tasks(self, mission: MissionState) -> MissionState:
        """Kill all running tasks — Operator KILL ALL control."""
        for task in mission.tasks.tasks.values():
            if task.status in (TaskStatus.RUNNING, TaskStatus.ASSIGNED, TaskStatus.PENDING):
                task.status = TaskStatus.CANCELLED
                task.updated_at = datetime.utcnow()

        mission.add_timeline_event(mission.phase, "All tasks killed by Operator", "operator")
        self.mission_manager.save_mission(mission)
        return mission
