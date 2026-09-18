"""
X19 Autonomous Security Loop — evidence-driven, closed-loop.

SCOPE → PLAN → RECON → ATTACK-SURFACE MODEL → HYPOTHESIS GENERATION → TEST → OBSERVE → CORRELATE → VERIFY → CLASSIFY → REPORT → LEARN → REASSESS

- SCOPE: Define authorized target, domains/IPs, excluded assets, allowed/prohibited actions, time/budget/concurrency
- PLAN: Decompose into tasks, assign to managers/specialists, define objectives/constraints
- RECON: Asset discovery, endpoint enumeration, tech fingerprint, auth surface (read-only, low-risk)
- ATTACK-SURFACE MODEL: Map inputs, sinks, trust boundaries, auth flows
- HYPOTHESIS GENERATION: For each vuln class, generate testable hypotheses from recon observations
- TEST: Execute real tools with witness payloads (minimal proof, not destructive)
- OBSERVE: Capture tool output, response behavior, timing, errors as evidence
- CORRELATE: Map observations against known vuln classes (CWE, OWASP, CVE)
- VERIFY: Verification specialist reproduces candidate findings, bypass exhaustion before false-positive dismissal
- CLASSIFY: Severity (CVSS 3.1), confidence, impact, remediation
- REPORT: Evidence-based report, L3/L4 only (confirmed/critical), L1/L2 as candidates pending verification
- LEARN: Store successful/failed workflows, false positives, verification strategies, tool behavior, target context with provenance
- REASSESS: Check remaining scope, uncovered areas, new hypotheses from learnings
- Loop terminates when scope covered, time/budget exhausted, no productive hypotheses remain, or operator stops.
- Anti-loop: Detect repeated identical commands/tool calls, no-progress, repeated failed hypotheses, duplicate/stale tasks, conflicting conclusions, hallucinated/missing evidence, endless recon → detect → record failure → change strategy → ask another specialist → escalate to Boss → stop if no productive path.

Never auto-convert observation to vulnerability.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Any, Callable
from enum import Enum
from dataclasses import dataclass
from datetime import datetime

from x19.orchestration.mission_state import MissionState, MissionPhase, MissionStatus
from x19.orchestration.boss import BossOrchestrator
from x19.scope.scope import ScopeDefinition
from x19.findings.finding import FindingStatus


class LoopPhase(str, Enum):
    """Loop phases in order."""

    SCOPE = "scope"
    PLAN = "plan"
    RECON = "recon"
    ATTACK_SURFACE = "attack_surface"
    HYPOTHESIS = "hypothesis"
    TEST = "test"
    OBSERVE = "observe"
    CORRELATE = "correlate"
    VERIFY = "verify"
    CLASSIFY = "classify"
    REPORT = "report"
    LEARN = "learn"
    REASSESS = "reassess"


# Phase order for autonomous loop
PHASE_ORDER = [
    LoopPhase.SCOPE,
    LoopPhase.PLAN,
    LoopPhase.RECON,
    LoopPhase.ATTACK_SURFACE,
    LoopPhase.HYPOTHESIS,
    LoopPhase.TEST,
    LoopPhase.OBSERVE,
    LoopPhase.CORRELATE,
    LoopPhase.VERIFY,
    LoopPhase.CLASSIFY,
    LoopPhase.REPORT,
    LoopPhase.LEARN,
    LoopPhase.REASSESS,
]

# Map LoopPhase to MissionPhase
LOOP_TO_MISSION_PHASE = {
    LoopPhase.SCOPE: MissionPhase.SCOPE,
    LoopPhase.PLAN: MissionPhase.PLAN,
    LoopPhase.RECON: MissionPhase.RECON,
    LoopPhase.ATTACK_SURFACE: MissionPhase.ATTACK_SURFACE,
    LoopPhase.HYPOTHESIS: MissionPhase.HYPOTHESIS,
    LoopPhase.TEST: MissionPhase.TEST,
    LoopPhase.OBSERVE: MissionPhase.OBSERVE,
    LoopPhase.CORRELATE: MissionPhase.CORRELATE,
    LoopPhase.VERIFY: MissionPhase.VERIFY,
    LoopPhase.CLASSIFY: MissionPhase.CLASSIFY,
    LoopPhase.REPORT: MissionPhase.REPORT,
    LoopPhase.LEARN: MissionPhase.LEARN,
    LoopPhase.REASSESS: MissionPhase.REASSESS,
}


@dataclass
class LoopState:
    """State of autonomous loop."""

    mission_id: str
    current_phase: LoopPhase
    iteration: int = 0
    max_iterations: int = 10  # Max loop iterations
    started_at: datetime = None
    phase_started_at: datetime = None
    phase_results: Dict[str, Any] = None
    should_continue: bool = True
    stop_reason: Optional[str] = None

    def __post_init__(self):
        if self.started_at is None:
            self.started_at = datetime.utcnow()
        if self.phase_started_at is None:
            self.phase_started_at = datetime.utcnow()
        if self.phase_results is None:
            self.phase_results = {}


class AutonomousSecurityLoop:
    """Autonomous security loop — evidence-driven, closed-loop."""

    def __init__(self, boss: Optional[BossOrchestrator] = None):
        self.boss = boss or BossOrchestrator()
        self.phase_handlers: Dict[LoopPhase, Callable] = {
            LoopPhase.SCOPE: self.handle_scope,
            LoopPhase.PLAN: self.handle_plan,
            LoopPhase.RECON: self.handle_recon,
            LoopPhase.ATTACK_SURFACE: self.handle_attack_surface,
            LoopPhase.HYPOTHESIS: self.handle_hypothesis,
            LoopPhase.TEST: self.handle_test,
            LoopPhase.OBSERVE: self.handle_observe,
            LoopPhase.CORRELATE: self.handle_correlate,
            LoopPhase.VERIFY: self.handle_verify,
            LoopPhase.CLASSIFY: self.handle_classify,
            LoopPhase.REPORT: self.handle_report,
            LoopPhase.LEARN: self.handle_learn,
            LoopPhase.REASSESS: self.handle_reassess,
        }

    def run_phase(self, mission: MissionState, phase: LoopPhase) -> Dict[str, Any]:
        """Run single phase of loop."""
        handler = self.phase_handlers.get(phase)
        if not handler:
            return {"status": "unknown_phase", "phase": phase.value}

        # Set mission phase
        mission_phase = LOOP_TO_MISSION_PHASE.get(phase, MissionPhase.RECON)
        mission.set_phase(mission_phase)

        # Run handler
        result = handler(mission)

        # Record timeline
        mission.add_timeline_event(
            mission_phase, f"Phase {phase.value} completed: {result.get('status', 'unknown')}", "boss", str(result.get("summary", ""))[:200]
        )

        # Save mission
        self.boss.mission_manager.save_mission(mission)

        return result

    def handle_scope(self, mission: MissionState) -> Dict[str, Any]:
        """SCOPE: Define authorized target, domains/IPs, excluded, allowed/prohibited, time/budget/concurrency."""
        if not mission.scope:
            return {"status": "failed", "summary": "No scope defined", "requires": "scope"}

        # Validate scope
        from x19.scope.scope import validate_scope

        valid, errors = validate_scope(mission.scope)
        if not valid:
            return {"status": "failed", "summary": f"Scope invalid: {errors}", "errors": errors}

        return {
            "status": "completed",
            "summary": f"Scope defined: target={mission.scope.target}, authorized={mission.scope.authorized_domains}, excluded={mission.scope.excluded_assets}",
            "scope": mission.scope.to_dict(),
        }

    def handle_plan(self, mission: MissionState) -> Dict[str, Any]:
        """PLAN: Decompose into tasks, assign to managers/specialists."""
        plan = self.boss.decompose_mission(mission)
        assigned = self.boss.assign_tasks(mission, plan)

        return {
            "status": "completed",
            "summary": f"Decomposed into {len(plan.tasks)} tasks in {len(plan.parallel_groups)} parallel groups",
            "tasks_created": len(assigned),
            "parallel_groups": len(plan.parallel_groups),
            "plan": {
                "tasks": [t.to_dict() for t in plan.tasks],
                "parallel_groups": plan.parallel_groups,
            },
        }

    def handle_recon(self, mission: MissionState) -> Dict[str, Any]:
        """RECON: Asset discovery, endpoint enumeration, tech fingerprint, auth surface (read-only, low-risk)."""
        # Recon is performed by specialists via delegation — this phase checks if recon tasks completed
        from x19.orchestration.task import TaskStatus

        recon_tasks = [t for t in mission.tasks.tasks.values() if "recon" in t.assigned_to or "recon" in t.objective.lower()]

        if not recon_tasks:
            return {"status": "pending", "summary": "No recon tasks assigned, creating"}

        completed = [t for t in recon_tasks if t.status == TaskStatus.COMPLETED]
        running = [t for t in recon_tasks if t.status == TaskStatus.RUNNING]

        if running:
            return {"status": "running", "summary": f"Recon running: {len(running)} tasks", "running": len(running)}

        if len(completed) == len(recon_tasks) and recon_tasks:
            return {
                "status": "completed",
                "summary": f"Recon completed: {len(completed)} tasks, discoveries: {mission.discoveries}",
                "discoveries": mission.discoveries,
            }

        return {"status": "pending", "summary": f"Recon pending: {len(recon_tasks)-len(completed)} tasks remaining"}

    def handle_attack_surface(self, mission: MissionState) -> Dict[str, Any]:
        """ATTACK-SURFACE MODEL: Map inputs, sinks, trust boundaries, auth flows."""
        if not mission.discoveries:
            return {"status": "pending", "summary": "No discoveries yet, waiting for recon"}

        # Build attack surface model from discoveries
        model = {
            "inputs": mission.discoveries.get("endpoints", []) + mission.discoveries.get("parameters", []),
            "tech": mission.discoveries.get("tech", []),
            "auth_flows": mission.discoveries.get("auth", []),
            "subdomains": mission.discoveries.get("subdomains", []),
        }

        return {
            "status": "completed",
            "summary": f"Attack surface model built: {len(model['inputs'])} inputs, {len(model['tech'])} tech",
            "model": model,
        }

    def handle_hypothesis(self, mission: MissionState) -> Dict[str, Any]:
        """HYPOTHESIS GENERATION: For each vuln class, generate testable hypotheses from recon observations."""
        if not mission.discoveries:
            return {"status": "pending", "summary": "No discoveries for hypothesis generation"}

        # Hypotheses should be generated by vuln_research specialist
        # Check if hypotheses exist
        if mission.hypotheses:
            pending = [h for h in mission.hypotheses if h.get("status") == "pending"]
            return {
                "status": "completed" if not pending else "running",
                "summary": f"Hypotheses: {len(mission.hypotheses)} total, {len(pending)} pending",
                "hypotheses": mission.hypotheses,
            }

        return {"status": "pending", "summary": "No hypotheses yet, need vuln_research specialist"}

    def handle_test(self, mission: MissionState) -> Dict[str, Any]:
        """TEST: Execute real tools with witness payloads (minimal proof, not destructive)."""
        from x19.orchestration.task import TaskStatus

        test_tasks = [t for t in mission.tasks.tasks.values() if "test" in t.objective.lower() or t.assigned_to in ("web_manager", "api_manager", "web_security", "api_security")]

        if not test_tasks:
            return {"status": "pending", "summary": "No test tasks assigned"}

        completed = [t for t in test_tasks if t.status == TaskStatus.COMPLETED]
        running = [t for t in test_tasks if t.status == TaskStatus.RUNNING]

        if running:
            return {"status": "running", "summary": f"Testing running: {len(running)} tasks"}

        return {
            "status": "completed" if len(completed) == len(test_tasks) else "pending",
            "summary": f"Testing: {len(completed)}/{len(test_tasks)} completed",
            "completed": len(completed),
            "total": len(test_tasks),
        }

    def handle_observe(self, mission: MissionState) -> Dict[str, Any]:
        """OBSERVE: Capture tool output, response behavior, timing, errors as evidence."""
        # Observations are captured as evidence in tasks and findings
        evidence_count = len(mission.evidence)
        finding_evidence = sum(len(f.evidence) for f in mission.findings.findings.values())

        return {
            "status": "completed",
            "summary": f"Observations captured: {evidence_count} evidence items, {finding_evidence} finding evidence",
            "evidence_count": evidence_count,
            "finding_evidence": finding_evidence,
        }

    def handle_correlate(self, mission: MissionState) -> Dict[str, Any]:
        """CORRELATE: Map observations against known vuln classes (CWE, OWASP, CVE)."""
        # Correlation is done by vuln_research specialist
        findings_by_class = {}
        for finding in mission.findings.findings.values():
            vc = finding.vuln_class.value
            findings_by_class[vc] = findings_by_class.get(vc, 0) + 1

        return {
            "status": "completed",
            "summary": f"Correlated: {len(mission.findings.findings)} findings by class: {findings_by_class}",
            "by_class": findings_by_class,
        }

    def handle_verify(self, mission: MissionState) -> Dict[str, Any]:
        """VERIFY: Verification specialist reproduces candidate findings, bypass exhaustion before false-positive dismissal."""
        from x19.orchestration.task import TaskStatus

        verify_tasks = [t for t in mission.tasks.tasks.values() if t.assigned_to == "verification"]

        candidates = mission.findings.list_by_status(FindingStatus.CANDIDATE)
        under_verification = mission.findings.list_by_status(FindingStatus.UNDER_VERIFICATION)

        if candidates and not verify_tasks:
            return {"status": "pending", "summary": f"{len(candidates)} candidates need verification tasks"}

        completed = [t for t in verify_tasks if t.status == TaskStatus.COMPLETED]

        return {
            "status": "completed" if len(completed) == len(verify_tasks) and not candidates else "running",
            "summary": f"Verification: {len(completed)}/{len(verify_tasks)} tasks, {len(candidates)} candidates, {len(under_verification)} verifying",
            "candidates": len(candidates),
            "under_verification": len(under_verification),
        }

    def handle_classify(self, mission: MissionState) -> Dict[str, Any]:
        """CLASSIFY: Severity (CVSS 3.1), confidence, impact, remediation."""
        verified = mission.findings.list_verified()

        by_severity = {}
        for finding in verified:
            sev = finding.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1

        return {
            "status": "completed",
            "summary": f"Classified: {len(verified)} verified findings by severity: {by_severity}",
            "by_severity": by_severity,
            "verified_count": len(verified),
        }

    def handle_report(self, mission: MissionState) -> Dict[str, Any]:
        """REPORT: Evidence-based report, L3/L4 only (confirmed/critical), L1/L2 as candidates pending verification."""
        from x19.interface.operator import OperatorInterface

        operator = OperatorInterface(self.boss.mission_manager)
        operator._current_mission_id = mission.id
        report = operator.generate_report(mission.id)

        return {
            "status": "completed",
            "summary": f"Report generated: {len(report)} chars, path: {mission.report_path}",
            "report_path": mission.report_path,
            "report_length": len(report),
        }

    def handle_learn(self, mission: MissionState) -> Dict[str, Any]:
        """LEARN: Store successful/failed workflows, false positives, verification strategies, tool behavior, target context with provenance."""
        # Learning: store lessons with provenance
        lessons = mission.lessons

        # Example: if mission completed, add lessons
        if mission.status == MissionStatus.COMPLETED:
            # Add factual lessons
            mission.add_lesson("FACT", f"Mission {mission.id} completed for target {mission.scope.target if mission.scope else 'unknown'}", f"Mission {mission.id} timeline", "high")
            mission.add_lesson("OBSERVATION", f"Discoveries: {mission.discoveries}", f"Mission {mission.id} discoveries", "medium")

        return {
            "status": "completed",
            "summary": f"Learning: {len(lessons)} lessons stored with provenance",
            "lessons": len(lessons),
        }

    def handle_reassess(self, mission: MissionState) -> Dict[str, Any]:
        """REASSESS: Check remaining scope, uncovered areas, new hypotheses from learnings."""
        # Check remaining scope
        from x19.orchestration.task import TaskStatus

        pending_tasks = mission.tasks.list_by_status(TaskStatus.PENDING)
        failed_tasks = mission.tasks.list_by_status(TaskStatus.FAILED)
        blocked_tasks = mission.tasks.list_by_status(TaskStatus.BLOCKED)

        # Check if should continue loop
        should_continue = True
        stop_reason = None

        if not pending_tasks and not failed_tasks and not blocked_tasks:
            # All tasks done
            should_continue = False
            stop_reason = "All tasks completed, scope covered"

        # Check anti-loop
        should_stop, reason = mission.anti_loop.should_stop_mission()
        if should_stop:
            should_continue = False
            stop_reason = reason

        # Check time/budget
        # (Implementation would check actual time/budget limits)

        return {
            "status": "completed",
            "summary": f"Reassess: pending={len(pending_tasks)}, failed={len(failed_tasks)}, blocked={len(blocked_tasks)}, continue={should_continue}",
            "should_continue": should_continue,
            "stop_reason": stop_reason,
            "pending_tasks": len(pending_tasks),
            "failed_tasks": len(failed_tasks),
            "blocked_tasks": len(blocked_tasks),
        }

    def run_full_loop(self, mission: MissionState, max_iterations: int = 10) -> Dict[str, Any]:
        """Run full autonomous loop SCOPE → ... → REASSESS, with termination checks."""
        loop_state = LoopState(
            mission_id=mission.id,
            current_phase=LoopPhase.SCOPE,
            max_iterations=max_iterations,
        )

        results = {}
        iteration = 0

        while loop_state.should_continue and iteration < max_iterations:
            iteration += 1
            loop_state.iteration = iteration

            # Run phases in order
            for phase in PHASE_ORDER:
                if mission.status in (MissionStatus.STOPPED, MissionStatus.PAUSED, MissionStatus.COMPLETED):
                    loop_state.should_continue = False
                    loop_state.stop_reason = f"Mission status {mission.status.value}"
                    break

                result = self.run_phase(mission, phase)
                results[phase.value] = result

                # If reassess says stop, break
                if phase == LoopPhase.REASSESS:
                    if not result.get("should_continue", True):
                        loop_state.should_continue = False
                        loop_state.stop_reason = result.get("stop_reason", "Reassess says stop")
                        break

            # Check if should continue for next iteration
            if loop_state.should_continue:
                # Only continue if there are pending tasks or new hypotheses
                from x19.orchestration.task import TaskStatus

                pending = mission.tasks.list_by_status(TaskStatus.PENDING)
                if not pending:
                    loop_state.should_continue = False
                    loop_state.stop_reason = "No pending tasks, loop complete"

        return {
            "mission_id": mission.id,
            "iterations": iteration,
            "should_continue": loop_state.should_continue,
            "stop_reason": loop_state.stop_reason,
            "results": results,
            "final_phase": mission.phase.value,
            "final_status": mission.status.value,
        }
