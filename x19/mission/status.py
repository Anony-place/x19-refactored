"""
X19 Real-Time Mission Status — derived from actual runtime state, no mock.

Provides:
- Mission ACTIVE, Target, Phase, Boss, Managers, Specialists, Tasks
  (total/completed/running/blocked/awaiting verification),
  Findings (candidates/verified/rejected), Current activity
- Derived from runtime, no mock data, no fake progress bars
"""

from __future__ import annotations

from typing import Dict, List, Optional, Any
from datetime import datetime

from x19.orchestration.mission_state import MissionState, MissionPhase, MissionStatus
from x19.orchestration.task import TaskStatus
from x19.findings.finding import FindingStatus


def get_mission_status(mission: MissionState) -> Dict[str, Any]:
    """Get real-time mission status from actual runtime state — no mock."""
    stats = mission.get_stats()

    # Current activity: what are agents doing?
    current_activity = []
    for task in mission.tasks.tasks.values():
        if task.status in (TaskStatus.RUNNING, TaskStatus.ASSIGNED):
            current_activity.append(
                {
                    "task_id": task.id,
                    "objective": task.objective,
                    "assigned_to": task.assigned_to,
                    "status": task.status.value,
                    "progress": task.progress,
                    "progress_message": task.progress_message,
                    "started_at": task.started_at.isoformat() if task.started_at else None,
                }
            )

    # Blocked tasks
    blocked_tasks = []
    for task in mission.tasks.list_by_status(TaskStatus.BLOCKED):
        blocked_tasks.append(
            {
                "task_id": task.id,
                "objective": task.objective,
                "assigned_to": task.assigned_to,
                "blocked_reason": task.blocked_reason,
                "requires_approval": task.requires_approval,
            }
        )

    # Findings summary
    verified = mission.findings.list_verified()
    candidates = mission.findings.list_candidates()
    rejected = mission.findings.list_rejected()

    # Timeline: last 10 events
    recent_timeline = mission.timeline[-10:] if len(mission.timeline) > 10 else mission.timeline

    # Discoveries
    discoveries_summary = {k: len(v) for k, v in mission.discoveries.items()}

    return {
        "mission_id": mission.id,
        "name": mission.name,
        "status": mission.status.value,
        "phase": mission.phase.value,
        "target": mission.scope.target if mission.scope else "unknown",
        "created_at": mission.created_at.isoformat(),
        "updated_at": mission.updated_at.isoformat(),
        "objectives": mission.objectives,
        "agents": {
            "total": len(mission.agents),
            "by_role": stats["agents"]["by_role"],
            "active": stats["agents"]["active"],
            "details": mission.agents,
        },
        "tasks": {
            "total": stats["tasks"]["total"],
            "pending": stats["tasks"]["pending"],
            "assigned": stats["tasks"]["assigned"],
            "running": stats["tasks"]["running"],
            "completed": stats["tasks"]["completed"],
            "failed": stats["tasks"]["failed"],
            "blocked": stats["tasks"]["blocked"],
            "cancelled": stats["tasks"]["cancelled"],
        },
        "current_activity": current_activity,
        "blocked_tasks": blocked_tasks,
        "findings": {
            "total": stats["findings"]["total"],
            "candidates": len(candidates),
            "verified": len(verified),
            "rejected": len(rejected),
            "under_verification": stats["findings"]["under_verification"],
            "needs_more_evidence": stats["findings"]["needs_more_evidence"],
            "verified_list": [
                {
                    "id": f.id,
                    "target": f.target,
                    "endpoint": f.endpoint,
                    "vuln_class": f.vuln_class.value,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "status": f.status.value,
                }
                for f in verified[:10]
            ],
            "candidate_list": [
                {
                    "id": f.id,
                    "target": f.target,
                    "endpoint": f.endpoint,
                    "vuln_class": f.vuln_class.value,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "status": f.status.value,
                }
                for f in candidates[:10]
            ],
        },
        "discoveries": discoveries_summary,
        "hypotheses": stats["hypotheses"],
        "blockers": len([b for b in mission.blockers if not b.get("resolved")]),
        "timeline_recent": recent_timeline,
        "anti_loop": stats["anti_loop"],
        "evidence_dir": mission.evidence_dir,
        "report_path": mission.report_path,
    }


def format_status_for_operator(status: Dict[str, Any]) -> str:
    """Format mission status as concise text for Operator — from real state, never fabricated."""
    lines = [
        f"Mission: {status['name']} ({status['mission_id']})",
        f"Status: {status['status']} | Phase: {status['phase']} | Target: {status['target']}",
        f"Updated: {status['updated_at']}",
        "",
        f"Agents: {status['agents']['total']} total, {status['agents']['active']} active",
        f"  By role: {status['agents']['by_role']}",
        "",
        f"Tasks: {status['tasks']['total']} total | "
        f"{status['tasks']['completed']} completed | "
        f"{status['tasks']['running']} running | "
        f"{status['tasks']['blocked']} blocked | "
        f"{status['tasks']['failed']} failed | "
        f"{status['tasks']['pending']} pending",
        "",
    ]

    if status["current_activity"]:
        lines.append("Current activity:")
        for act in status["current_activity"][:5]:
            lines.append(f"  - {act['assigned_to']}: {act['objective'][:60]} ({act['status']}, {act['progress']}%)")
        lines.append("")

    if status["blocked_tasks"]:
        lines.append("Blocked tasks:")
        for bt in status["blocked_tasks"][:3]:
            lines.append(f"  - {bt['task_id']}: {bt['blocked_reason'][:80]} (approval: {bt['requires_approval']})")
        lines.append("")

    lines.extend(
        [
            f"Findings: {status['findings']['total']} total | "
            f"{status['findings']['verified']} verified | "
            f"{status['findings']['candidates']} candidates | "
            f"{status['findings']['rejected']} rejected | "
            f"{status['findings']['under_verification']} verifying",
            "",
        ]
    )

    if status["findings"]["verified_list"]:
        lines.append("Verified findings (L3/L4):")
        for vf in status["findings"]["verified_list"][:3]:
            lines.append(f"  - {vf['id']}: {vf['vuln_class']} at {vf['endpoint']} [{vf['severity']}/{vf['confidence']}]")
        lines.append("")

    if status["findings"]["candidate_list"]:
        lines.append("Candidate findings (L1/L2 pending verification):")
        for cf in status["findings"]["candidate_list"][:3]:
            lines.append(f"  - {cf['id']}: {cf['vuln_class']} at {cf['endpoint']} [{cf['severity']}/{cf['confidence']}]")
        lines.append("")

    lines.extend(
        [
            f"Discoveries: {status['discoveries']}",
            f"Hypotheses: {status['hypotheses']['total']} total, {status['hypotheses']['pending']} pending",
            f"Blockers: {status['blockers']}",
            "",
            f"Anti-loop: {status['anti_loop']['total_detections']} detections, {status['anti_loop']['total_failures']} failures",
        ]
    )

    if status["anti_loop"]["recent_detections"]:
        lines.append("Recent loop detections:")
        for det in status["anti_loop"]["recent_detections"][-3:]:
            lines.append(f"  - {det['type']}: {det['description'][:60]} ({det['severity']})")

    return "\n".join(lines)


def get_whats_happening(mission: MissionState) -> str:
    """Answer 'What's happening?' from real mission state."""
    status = get_mission_status(mission)
    return format_status_for_operator(status)


def get_what_completed(mission: MissionState) -> str:
    """Answer 'What has been completed?' from real state."""
    completed_tasks = mission.tasks.list_by_status(TaskStatus.COMPLETED)
    verified_findings = mission.findings.list_verified()

    lines = [
        f"Mission {mission.id} — Completed items:",
        "",
        f"Tasks completed: {len(completed_tasks)}",
    ]

    for task in completed_tasks[-10:]:
        lines.append(f"  - {task.id}: {task.objective[:60]} → {task.assigned_to}")

    lines.extend(["", f"Verified findings: {len(verified_findings)}"])

    for finding in verified_findings[:5]:
        lines.append(f"  - {finding.id}: {finding.vuln_class.value} at {finding.endpoint} [{finding.severity.value}]")

    lines.extend(["", f"Discoveries: {mission.discoveries}", f"Timeline events: {len(mission.timeline)}"])

    return "\n".join(lines)


def get_what_agents_doing(mission: MissionState) -> str:
    """Answer 'What are agents doing?' from real state."""
    running = mission.tasks.list_by_status(TaskStatus.RUNNING)
    assigned = mission.tasks.list_by_status(TaskStatus.ASSIGNED)

    lines = [f"Agents doing — Mission {mission.id}:", ""]

    if not running and not assigned:
        lines.append("No active tasks — mission idle or waiting for next phase")
    else:
        if running:
            lines.append(f"Running ({len(running)}):")
            for task in running:
                lines.append(f"  - {task.assigned_to} ({task.id}): {task.objective[:70]} — {task.progress}% {task.progress_message}")

        if assigned:
            lines.append(f"Assigned ({len(assigned)}):")
            for task in assigned:
                lines.append(f"  - {task.assigned_to} ({task.id}): {task.objective[:70]}")

    return "\n".join(lines)


def get_active_tasks(mission: MissionState) -> str:
    """Answer 'Show active tasks' from real state."""
    all_tasks = list(mission.tasks.tasks.values())

    lines = [f"Active tasks — Mission {mission.id}: {len(all_tasks)} total", ""]

    for task in sorted(all_tasks, key=lambda t: t.created_at):
        lines.append(f"  [{task.status.value}] {task.id}: {task.objective[:60]} → {task.assigned_to} ({task.progress}%)")

    return "\n".join(lines)


def get_findings_summary(mission: MissionState) -> str:
    """Answer 'Show findings' — verified vs candidates vs rejected with evidence."""
    verified = mission.findings.list_verified()
    candidates = mission.findings.list_candidates()
    rejected = mission.findings.list_rejected()

    lines = [
        f"Findings — Mission {mission.id}:",
        f"  Total: {mission.findings.get_stats()['total']}",
        f"  Verified (L3/L4 reportable): {len(verified)}",
        f"  Candidates (L1/L2 pending): {len(candidates)}",
        f"  Rejected: {len(rejected)}",
        "",
    ]

    if verified:
        lines.append("Verified findings:")
        for f in verified:
            lines.append(
                f"  - {f.id}: {f.vuln_class.value} at {f.endpoint} | "
                f"{f.severity.value}/{f.confidence.value} | {f.target} | Evidence: {len(f.evidence)} items"
            )
        lines.append("")

    if candidates:
        lines.append("Candidate findings (pending verification):")
        for f in candidates[:10]:
            lines.append(
                f"  - {f.id}: {f.vuln_class.value} at {f.endpoint} | "
                f"{f.severity.value}/{f.confidence.value} | {f.status.value}"
            )
        lines.append("")

    if rejected:
        lines.append("Rejected findings:")
        for f in rejected[:5]:
            lines.append(f"  - {f.id}: {f.vuln_class.value} at {f.endpoint} — {f.rejected_reason or 'no reason'}")
        lines.append("")

    return "\n".join(lines)
