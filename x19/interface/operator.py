"""
X19 Human ↔ Boss Interface — Operator communicates primarily with Boss.

Supports concepts:
- Start assessment → Boss establishes scope, creates mission plan, delegates
- What's happening? / What are agents doing? / Show active tasks → answer from actual mission state
- What has been completed? → completed tasks, discoveries, verified findings from real runtime
- Show findings → candidates, verified, rejected with evidence
- Why did you stop? → explain blockers, no-progress detection, strategy change
- Verify finding #3 → request verification specialist, move to UNDER_VERIFICATION
- Pause/Resume/Stop all agents/Change scope/Generate report → controls, always from real state
- Never fabricate progress. If no mission active: say so. If phase pending: say pending.

Uses gateway + CLI existing infra — this module provides the logic, not the transport.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime

from x19.orchestration.mission_state import MissionState, MissionStateManager, MissionStatus, MissionPhase
from x19.orchestration.boss import BossOrchestrator
from x19.scope.scope import ScopeDefinition, create_scope, validate_scope
from x19.findings.finding import FindingStatus
from x19.mission.status import (
    get_mission_status,
    format_status_for_operator,
    get_whats_happening,
    get_what_completed,
    get_what_agents_doing,
    get_active_tasks,
    get_findings_summary,
)


class OperatorInterface:
    """Human ↔ Boss interface — answers from real mission state, never fabricated."""

    def __init__(self, mission_manager: Optional[MissionStateManager] = None):
        self.mission_manager = mission_manager or MissionStateManager()
        self.boss = BossOrchestrator(self.mission_manager)
        self._current_mission_id: Optional[str] = None

    def start_assessment(
        self,
        target: str,
        authorized_domains: Optional[List[str]] = None,
        excluded_assets: Optional[List[str]] = None,
        program_name: Optional[str] = None,
        objectives: Optional[List[str]] = None,
        name: Optional[str] = None,
        **scope_kwargs,
    ) -> Tuple[Optional[MissionState], str]:
        """Start assessment — Boss establishes scope, creates mission plan, delegates."""

        # Create mission with explicit scope
        mission_name = name or f"Assessment of {target}"
        mission, errors = self.boss.create_mission(
            name=mission_name,
            target=target,
            authorized_domains=authorized_domains,
            excluded_assets=excluded_assets,
            objectives=objectives,
            program_name=program_name,
            **scope_kwargs,
        )

        if not mission:
            return None, f"Failed to create mission: {errors}"

        # Decompose into tasks
        plan = self.boss.decompose_mission(mission)
        assigned = self.boss.assign_tasks(mission, plan)

        self._current_mission_id = mission.id

        return mission, (
            f"Mission accepted: {mission.id}\n"
            f"Target: {target}\n"
            f"Scope: {mission.scope.target if mission.scope else target}\n"
            f"Authorized: {mission.scope.authorized_domains if mission.scope else []}\n"
            f"Excluded: {mission.scope.excluded_assets if mission.scope else []}\n"
            f"Tasks created: {len(assigned)} in {len(plan.parallel_groups)} parallel groups\n"
            f"Phase: {mission.phase.value}\n"
            f"Next: Run recon task via delegation"
        )

    def whats_happening(self, mission_id: Optional[str] = None) -> str:
        """Answer 'What's happening?' from actual mission state."""
        mission = self._get_mission(mission_id)
        if not mission:
            return "No active mission. Use 'Start assessment' to begin."

        return get_whats_happening(mission)

    def what_completed(self, mission_id: Optional[str] = None) -> str:
        """Answer 'What has been completed?' from real runtime."""
        mission = self._get_mission(mission_id)
        if not mission:
            return "No active mission."

        return get_what_completed(mission)

    def what_agents_doing(self, mission_id: Optional[str] = None) -> str:
        """Answer 'What are agents doing?' from real state."""
        mission = self._get_mission(mission_id)
        if not mission:
            return "No active mission."

        return get_what_agents_doing(mission)

    def show_active_tasks(self, mission_id: Optional[str] = None) -> str:
        """Answer 'Show active tasks' from real state."""
        mission = self._get_mission(mission_id)
        if not mission:
            return "No active mission."

        return get_active_tasks(mission)

    def show_findings(self, mission_id: Optional[str] = None) -> str:
        """Answer 'Show findings' → candidates, verified, rejected with evidence."""
        mission = self._get_mission(mission_id)
        if not mission:
            return "No active mission."

        return get_findings_summary(mission)

    def why_stopped(self, mission_id: Optional[str] = None) -> str:
        """Answer 'Why did you stop?' → explain blockers, no-progress, strategy change."""
        mission = self._get_mission(mission_id)
        if not mission:
            return "No active mission."

        lines = [f"Mission {mission.id} status: {mission.status.value}, phase: {mission.phase.value}", ""]

        if mission.status == MissionStatus.STOPPED:
            lines.append("Mission stopped.")
        elif mission.status == MissionStatus.PAUSED:
            lines.append("Mission paused.")
        elif mission.status == MissionStatus.COMPLETED:
            lines.append("Mission completed.")
        else:
            lines.append("Mission still active.")

        lines.append("")

        # Blockers
        unresolved = [b for b in mission.blockers if not b.get("resolved")]
        if unresolved:
            lines.append(f"Blockers ({len(unresolved)} unresolved):")
            for b in unresolved[-5:]:
                lines.append(f"  - {b['type']}: {b['description'][:100]} (task: {b.get('task_id')})")
            lines.append("")

        # Anti-loop
        should_stop, reason = mission.anti_loop.should_stop_mission()
        if should_stop:
            lines.append(f"Anti-loop triggered stop: {reason}")
            lines.append("")

        stats = mission.anti_loop.get_stats()
        if stats["total_detections"] > 0:
            lines.append(f"Loop detections: {stats['total_detections']}")
            for det in stats["recent_detections"][-3:]:
                lines.append(f"  - {det['type']}: {det['description'][:80]} → {det['suggested_action'][:60]}")
            lines.append("")

        # Timeline: last events
        if mission.timeline:
            lines.append("Recent timeline:")
            for event in mission.timeline[-5:]:
                lines.append(f"  - {event['timestamp']}: {event['phase']} — {event['event']}")

        return "\n".join(lines)

    def verify_finding(self, finding_id: str, mission_id: Optional[str] = None) -> str:
        """Verify finding #X → request verification specialist, move to UNDER_VERIFICATION."""
        mission = self._get_mission(mission_id)
        if not mission:
            return "No active mission."

        finding = mission.findings.get(finding_id)
        if not finding:
            return f"Finding {finding_id} not found."

        if finding.status == FindingStatus.VERIFIED:
            return f"Finding {finding_id} already verified."

        if finding.status == FindingStatus.UNDER_VERIFICATION:
            return f"Finding {finding_id} already under verification."

        # Transition to under verification
        success = finding.transition_to(FindingStatus.UNDER_VERIFICATION)
        if not success:
            return f"Cannot transition finding {finding_id} from {finding.status.value} to under_verification"

        mission.findings.update(finding)
        mission.add_timeline_event(MissionPhase.VERIFY, f"Finding {finding_id} moved to UNDER_VERIFICATION", "boss")
        self.mission_manager.save_mission(mission)

        # Create verification task
        from x19.orchestration.task import Task, TaskPriority

        verify_task = Task(
            mission_id=mission.id,
            objective=f"Verify finding {finding_id}: {finding.vuln_class.value} at {finding.endpoint}",
            target=finding.target,
            assigned_to="verification",
            scope=mission.scope.to_dict() if mission.scope else {},
            expected_evidence=["verification_result", "repro_steps", "tool_output"],
            priority=TaskPriority.HIGH,
        )

        mission.tasks.add(verify_task)
        self.mission_manager.save_mission(mission)

        return f"Finding {finding_id} moved to UNDER_VERIFICATION, verification task {verify_task.id} created for specialist"

    def pause(self, mission_id: Optional[str] = None) -> str:
        """Pause mission — Operator control."""
        mission = self._get_mission(mission_id)
        if not mission:
            return "No active mission."

        self.boss.pause_mission(mission)
        return f"Mission {mission.id} paused. Use Resume to continue."

    def resume(self, mission_id: Optional[str] = None) -> str:
        """Resume mission."""
        mission = self._get_mission(mission_id)
        if not mission:
            return "No active mission."

        self.boss.resume_mission(mission)
        return f"Mission {mission.id} resumed, phase: {mission.phase.value}"

    def stop(self, mission_id: Optional[str] = None, reason: str = "Stopped by Operator") -> str:
        """Stop mission — Operator control."""
        mission = self._get_mission(mission_id)
        if not mission:
            return "No active mission."

        self.boss.stop_mission(mission, reason)
        return f"Mission {mission.id} stopped: {reason}"

    def kill_all(self, mission_id: Optional[str] = None) -> str:
        """KILL ALL — Operator control."""
        mission = self._get_mission(mission_id)
        if not mission:
            return "No active mission."

        self.boss.kill_all_tasks(mission)
        return f"Mission {mission.id}: all tasks killed (KILL ALL)"

    def change_scope(self, mission_id: Optional[str] = None, **new_scope) -> str:
        """Change scope — Operator control."""
        mission = self._get_mission(mission_id)
        if not mission:
            return "No active mission."

        # Update scope
        if not mission.scope:
            return "Mission has no scope to change"

        for key, value in new_scope.items():
            if hasattr(mission.scope, key):
                setattr(mission.scope, key, value)

        valid, errors = validate_scope(mission.scope)
        if not valid:
            return f"New scope invalid: {errors}"

        mission.add_timeline_event(mission.phase, f"Scope changed by Operator: {new_scope}", "operator")
        self.mission_manager.save_mission(mission)

        return f"Mission {mission.id} scope updated: {new_scope}"

    def generate_report(self, mission_id: Optional[str] = None) -> str:
        """Generate report — evidence-based, never rejected as confirmed."""
        mission = self._get_mission(mission_id)
        if not mission:
            return "No active mission."

        verified = mission.findings.list_verified()
        candidates = mission.findings.list_candidates()
        rejected = mission.findings.list_rejected()

        lines = [
            f"# X19 Security Assessment Report",
            f"",
            f"Mission: {mission.name} ({mission.id})",
            f"Target: {mission.scope.target if mission.scope else 'unknown'}",
            f"Status: {mission.status.value} | Phase: {mission.phase.value}",
            f"Created: {mission.created_at.isoformat()} | Updated: {mission.updated_at.isoformat()}",
            f"",
            f"## Executive Summary",
            f"",
            f"- Total findings: {len(mission.findings.findings)}",
            f"- Verified (L3/L4): {len(verified)}",
            f"- Candidates (L1/L2): {len(candidates)}",
            f"- Rejected: {len(rejected)}",
            f"- Tasks: {mission.tasks.get_stats()}",
            f"- Discoveries: {mission.discoveries}",
            f"",
            f"## Scope",
            f"",
            f"```",
            f"{mission.scope.to_dict() if mission.scope else 'No scope'}",
            f"```",
            f"",
            f"## Verified Findings (L3/L4 — Reportable)",
            f"",
        ]

        if verified:
            for finding in verified:
                lines.extend(
                    [
                        f"### {finding.id}: {finding.vuln_class.value} at {finding.endpoint}",
                        f"",
                        f"- Target: {finding.target}",
                        f"- Endpoint: {finding.endpoint}",
                        f"- Component: {finding.component}",
                        f"- Vuln class: {finding.vuln_class.value} ({finding.cwe_id or 'no CWE'})",
                        f"- Severity: {finding.severity.value} (CVSS: {finding.cvss_score or 'N/A'})",
                        f"- Confidence: {finding.confidence.value}",
                        f"- Status: {finding.status.value}",
                        f"- Created by: {finding.created_by}",
                        f"- Verified by: {finding.verified_by or 'N/A'}",
                        f"",
                        f"**Reproduction steps:**",
                        f"",
                    ]
                )
                for i, step in enumerate(finding.reproduction_steps, 1):
                    lines.append(f"{i}. {step}")

                lines.extend(
                    [
                        f"",
                        f"**Observed evidence:**",
                        f"",
                        f"{finding.observed_evidence}",
                        f"",
                        f"**Impact:** {finding.impact or 'N/A'}",
                        f"",
                        f"**Remediation:** {finding.remediation or 'N/A'}",
                        f"",
                        f"**Evidence:** {len(finding.evidence)} items, tool refs: {finding.tool_output_reference}",
                        f"",
                        f"**References:** {', '.join(finding.references) or 'N/A'}",
                        f"",
                        f"---",
                        f"",
                    ]
                )
        else:
            lines.append("No verified findings.")
            lines.append("")

        lines.extend(
            [
                f"## Candidate Findings (L1/L2 — Pending Verification)",
                f"",
            ]
        )

        if candidates:
            for finding in candidates[:10]:
                lines.append(
                    f"- {finding.id}: {finding.vuln_class.value} at {finding.endpoint} [{finding.severity.value}/{finding.confidence.value}] — {finding.status.value}"
                )
        else:
            lines.append("No candidate findings.")

        lines.extend(
            [
                f"",
                f"## Rejected Findings",
                f"",
                f"Count: {len(rejected)} (not reported as confirmed)",
                f"",
            ]
        )

        if rejected:
            for finding in rejected[:5]:
                lines.append(f"- {finding.id}: {finding.vuln_class.value} at {finding.endpoint} — {finding.rejected_reason or 'no reason'}")

        lines.extend(
            [
                f"",
                f"## Timeline",
                f"",
            ]
        )

        for event in mission.timeline[-20:]:
            lines.append(f"- {event['timestamp']}: [{event['phase']}] {event['event']} ({event['agent']})")

        report = "\n".join(lines)

        # Save report
        try:
            from pathlib import Path

            report_dir = Path(mission.evidence_dir) if mission.evidence_dir else self.mission_manager.storage_dir
            report_dir.mkdir(parents=True, exist_ok=True)
            report_path = report_dir / f"{mission.id}_report.md"
            report_path.write_text(report, encoding="utf-8")
            mission.report_path = str(report_path)
            mission.final_report = report
            self.mission_manager.save_mission(mission)
        except Exception:
            pass

        return report

    def _get_mission(self, mission_id: Optional[str] = None) -> Optional[MissionState]:
        """Get mission by ID or current."""
        mid = mission_id or self._current_mission_id
        if not mid:
            # Try to get latest mission
            missions = self.mission_manager.list_missions()
            if missions:
                mid = missions[-1]

        if not mid:
            return None

        return self.mission_manager.load_mission(mid)

    def list_missions(self) -> str:
        """List missions."""
        missions = self.mission_manager.list_missions()
        if not missions:
            return "No missions found."

        lines = ["Missions:"]
        for mid in missions[-10:]:
            mission = self.mission_manager.load_mission(mid)
            if mission:
                lines.append(f"  - {mission.id}: {mission.name} [{mission.status.value}/{mission.phase.value}] target={mission.scope.target if mission.scope else 'unknown'}")

        return "\n".join(lines)
