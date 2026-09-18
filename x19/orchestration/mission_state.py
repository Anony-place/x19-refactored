"""
X19 Mission State — persistent mission state MISSION tree.

Mission state includes:
- scope, objectives, constraints
- agents, tasks, discoveries, hypotheses
- verified_findings, rejected_findings, evidence, blockers, timeline, final_report
- status (real-time, no mock)

Persisted via hermes_state or file, derived from runtime, no mock data.

Uses existing Hermes session persistence where possible, but provides
X19-specific overlay for mission tracking.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Optional, Any, Set
import json
import uuid
from pathlib import Path

from x19.scope.scope import ScopeDefinition
from x19.findings.finding import FindingStore, Finding, FindingStatus
from x19.orchestration.task import TaskStore, Task, TaskStatus
from x19.safety.anti_loop import AntiLoopDetector


class MissionPhase(str, Enum):
    """Autonomous security loop phases."""

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
    COMPLETED = "completed"
    PAUSED = "paused"
    STOPPED = "stopped"


class MissionStatus(str, Enum):
    """Overall mission status."""

    ACTIVE = "active"
    PAUSED = "paused"
    STOPPED = "stopped"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class MissionState:
    """Persistent mission state — single source of truth."""

    # Identity
    id: str = field(default_factory=lambda: f"M-{uuid.uuid4().hex[:8].upper()}")
    name: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    created_by: str = "operator"

    # Scope
    scope: Optional[ScopeDefinition] = None

    # Objectives and constraints
    objectives: List[str] = field(default_factory=list)
    constraints: Dict[str, Any] = field(default_factory=dict)  # time, budget, concurrency

    # Phase and status
    phase: MissionPhase = MissionPhase.SCOPE
    status: MissionStatus = MissionStatus.ACTIVE

    # Agents and tasks
    agents: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # agent_id → {role, status, current_task}
    tasks: TaskStore = field(default_factory=TaskStore)

    # Discoveries
    discoveries: Dict[str, List[str]] = field(default_factory=dict)  # type → list of discovered items
    # e.g., {"subdomains": ["a.target.com"], "endpoints": ["/api/users"], "tech": ["nginx"]}

    # Hypotheses
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    # e.g., {"id": "H-1", "vuln_class": "xss", "endpoint": "/search", "rationale": "...", "status": "pending"}

    # Findings
    findings: FindingStore = field(default_factory=FindingStore)

    # Evidence
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    evidence_dir: Optional[str] = None  # Path to evidence files (gitignored)

    # Blockers and timeline
    blockers: List[Dict[str, Any]] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)  # {timestamp, phase, event, agent, details}

    # Anti-loop
    anti_loop: AntiLoopDetector = field(default_factory=AntiLoopDetector)

    # Final report
    final_report: Optional[str] = None
    report_path: Optional[str] = None

    # Learning
    lessons: List[Dict[str, Any]] = field(default_factory=list)  # FACT, OBSERVATION, LESSON, SKILL, HYPOTHESIS with provenance

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for persistence."""
        return {
            "id": self.id,
            "name": self.name,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "created_by": self.created_by,
            "scope": self.scope.to_dict() if self.scope else None,
            "objectives": self.objectives,
            "constraints": self.constraints,
            "phase": self.phase.value,
            "status": self.status.value,
            "agents": self.agents,
            "tasks": self.tasks.to_dict(),
            "discoveries": self.discoveries,
            "hypotheses": self.hypotheses,
            "findings": self.findings.to_dict(),
            "evidence": self.evidence,
            "evidence_dir": self.evidence_dir,
            "blockers": self.blockers,
            "timeline": self.timeline,
            "final_report": self.final_report,
            "report_path": self.report_path,
            "lessons": self.lessons,
            "anti_loop_stats": self.anti_loop.get_stats(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MissionState":
        """Create from dict."""
        from x19.scope.scope import ScopeDefinition

        def parse_dt(val):
            if isinstance(val, str):
                try:
                    return datetime.fromisoformat(val)
                except Exception:
                    return datetime.utcnow()
            return val if isinstance(val, datetime) else datetime.utcnow()

        scope_data = data.get("scope")
        scope = ScopeDefinition.from_dict(scope_data) if scope_data else None

        try:
            phase = MissionPhase(data.get("phase", "scope"))
        except ValueError:
            phase = MissionPhase.SCOPE

        try:
            status = MissionStatus(data.get("status", "active"))
        except ValueError:
            status = MissionStatus.ACTIVE

        state = cls(
            id=data.get("id", f"M-{uuid.uuid4().hex[:8].upper()}"),
            name=data.get("name", ""),
            created_at=parse_dt(data.get("created_at")),
            updated_at=parse_dt(data.get("updated_at")),
            created_by=data.get("created_by", "operator"),
            scope=scope,
            objectives=data.get("objectives", []),
            constraints=data.get("constraints", {}),
            phase=phase,
            status=status,
            agents=data.get("agents", {}),
            tasks=TaskStore.from_dict(data.get("tasks", {})),
            discoveries=data.get("discoveries", {}),
            hypotheses=data.get("hypotheses", []),
            findings=FindingStore.from_dict(data.get("findings", {})),
            evidence=data.get("evidence", []),
            evidence_dir=data.get("evidence_dir"),
            blockers=data.get("blockers", []),
            timeline=data.get("timeline", []),
            final_report=data.get("final_report"),
            report_path=data.get("report_path"),
            lessons=data.get("lessons", []),
        )

        return state

    def add_timeline_event(self, phase: MissionPhase, event: str, agent: str = "boss", details: str = ""):
        """Add event to timeline."""
        self.timeline.append(
            {
                "timestamp": datetime.utcnow().isoformat(),
                "phase": phase.value,
                "event": event,
                "agent": agent,
                "details": details,
            }
        )
        self.updated_at = datetime.utcnow()

    def set_phase(self, phase: MissionPhase):
        """Transition to new phase."""
        old_phase = self.phase
        self.phase = phase
        self.updated_at = datetime.utcnow()
        self.add_timeline_event(phase, f"Phase transition: {old_phase.value} → {phase.value}", "boss")

    def add_discovery(self, discovery_type: str, item: str):
        """Add discovery (e.g., subdomain, endpoint)."""
        if discovery_type not in self.discoveries:
            self.discoveries[discovery_type] = []
        if item not in self.discoveries[discovery_type]:
            self.discoveries[discovery_type].append(item)
            self.updated_at = datetime.utcnow()
            self.add_timeline_event(self.phase, f"Discovered {discovery_type}: {item}", "recon_manager")

    def add_hypothesis(self, hypothesis: Dict[str, Any]):
        """Add hypothesis."""
        if "id" not in hypothesis:
            hypothesis["id"] = f"H-{uuid.uuid4().hex[:6].upper()}"
        hypothesis["created_at"] = datetime.utcnow().isoformat()
        hypothesis["status"] = hypothesis.get("status", "pending")
        self.hypotheses.append(hypothesis)
        self.updated_at = datetime.utcnow()

    def add_blocker(self, blocker_type: str, description: str, task_id: Optional[str] = None, agent_id: Optional[str] = None):
        """Add blocker."""
        self.blockers.append(
            {
                "id": f"B-{uuid.uuid4().hex[:6].upper()}",
                "type": blocker_type,
                "description": description,
                "task_id": task_id,
                "agent_id": agent_id,
                "timestamp": datetime.utcnow().isoformat(),
                "resolved": False,
            }
        )
        self.updated_at = datetime.utcnow()

    def add_lesson(self, lesson_type: str, content: str, provenance: str, confidence: str = "medium"):
        """Add lesson with provenance: FACT, OBSERVATION, LESSON, SKILL, HYPOTHESIS."""
        valid_types = ["FACT", "OBSERVATION", "LESSON", "SKILL", "HYPOTHESIS"]
        if lesson_type not in valid_types:
            raise ValueError(f"Invalid lesson type {lesson_type}, must be one of {valid_types}")

        self.lessons.append(
            {
                "id": f"L-{uuid.uuid4().hex[:6].upper()}",
                "type": lesson_type,
                "content": content,
                "provenance": provenance,
                "confidence": confidence,
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
        self.updated_at = datetime.utcnow()

    def get_stats(self) -> Dict[str, Any]:
        """Get mission stats — real-time, no mock."""
        task_stats = self.tasks.get_stats()
        finding_stats = self.findings.get_stats()

        return {
            "mission_id": self.id,
            "name": self.name,
            "status": self.status.value,
            "phase": self.phase.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "scope_target": self.scope.target if self.scope else "none",
            "objectives": self.objectives,
            "agents": {
                "total": len(self.agents),
                "by_role": self._count_agents_by_role(),
                "active": len([a for a in self.agents.values() if a.get("status") == "active"]),
            },
            "tasks": task_stats,
            "discoveries": {k: len(v) for k, v in self.discoveries.items()},
            "hypotheses": {
                "total": len(self.hypotheses),
                "pending": len([h for h in self.hypotheses if h.get("status") == "pending"]),
                "tested": len([h for h in self.hypotheses if h.get("status") == "tested"]),
                "failed": len([h for h in self.hypotheses if h.get("status") == "failed"]),
            },
            "findings": finding_stats,
            "blockers": len([b for b in self.blockers if not b.get("resolved")]),
            "timeline_events": len(self.timeline),
            "lessons": len(self.lessons),
            "anti_loop": self.anti_loop.get_stats(),
        }

    def _count_agents_by_role(self) -> Dict[str, int]:
        """Count agents by role."""
        counts = {}
        for agent in self.agents.values():
            role = agent.get("role", "unknown")
            counts[role] = counts.get(role, 0) + 1
        return counts

    def save_to_file(self, path: str):
        """Save mission state to file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load_from_file(cls, path: str) -> "MissionState":
        """Load mission state from file."""
        p = Path(path)
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)


class MissionStateManager:
    """Manages mission state persistence using Hermes state or file."""

    def __init__(self, storage_dir: Optional[str] = None):
        if storage_dir:
            self.storage_dir = Path(storage_dir)
        else:
            # Default to ~/.hermes/x19/missions or ./x19_missions
            try:
                from hermes_cli.config import get_hermes_home
                self.storage_dir = Path(get_hermes_home()) / "x19" / "missions"
            except Exception:
                self.storage_dir = Path.cwd() / "x19_missions"

        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._current_mission: Optional[MissionState] = None

    def create_mission(
        self,
        name: str,
        scope: ScopeDefinition,
        objectives: Optional[List[str]] = None,
        created_by: str = "operator",
    ) -> MissionState:
        """Create new mission."""
        mission = MissionState(
            name=name,
            scope=scope,
            objectives=objectives or [],
            created_by=created_by,
            status=MissionStatus.ACTIVE,
            phase=MissionPhase.SCOPE,
        )
        mission.add_timeline_event(MissionPhase.SCOPE, f"Mission created: {name}", "boss", f"Target: {scope.target}")
        self._current_mission = mission
        self.save_mission(mission)
        return mission

    def save_mission(self, mission: MissionState):
        """Save mission to storage."""
        path = self.storage_dir / f"{mission.id}.json"
        mission.save_to_file(str(path))
        self._current_mission = mission

    def load_mission(self, mission_id: str) -> Optional[MissionState]:
        """Load mission by ID."""
        path = self.storage_dir / f"{mission_id}.json"
        if not path.exists():
            return None
        try:
            mission = MissionState.load_from_file(str(path))
            self._current_mission = mission
            return mission
        except Exception:
            return None

    def get_current_mission(self) -> Optional[MissionState]:
        """Get current mission."""
        return self._current_mission

    def list_missions(self) -> List[str]:
        """List mission IDs."""
        return [p.stem for p in self.storage_dir.glob("M-*.json")]

    def get_mission_stats(self, mission_id: str) -> Optional[Dict[str, Any]]:
        """Get mission stats."""
        mission = self.load_mission(mission_id)
        if not mission:
            return None
        return mission.get_stats()
