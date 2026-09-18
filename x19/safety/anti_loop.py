"""
X19 Anti-Loop / Anti-Waste System.

Detects:
- Repeated identical commands/tool calls
- No-progress loops
- Repeated failed hypotheses
- Duplicate tasks
- Stale tasks
- Conflicting conclusions
- Hallucinated evidence
- Missing evidence
- Endless recon

Strategy:
detect → record failure → change strategy → ask another specialist → escalate to Boss → stop if no productive path
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set, Tuple, Any
from enum import Enum
import hashlib


class LoopType(str, Enum):
    """Types of loops/waste."""

    REPEATED_COMMAND = "repeated_command"  # Same command/tool call repeated
    NO_PROGRESS = "no_progress"  # No new findings, assets, evidence after N iterations
    REPEATED_FAILED_HYPOTHESIS = "repeated_failed_hypothesis"  # Same hypothesis failing repeatedly
    DUPLICATE_TASK = "duplicate_task"  # Same task assigned twice
    STALE_TASK = "stale_task"  # Task running too long without progress
    CONFLICTING_CONCLUSIONS = "conflicting_conclusions"  # Same endpoint, conflicting vuln claims
    HALLUCINATED_EVIDENCE = "hallucinated_evidence"  # Evidence without tool output
    MISSING_EVIDENCE = "missing_evidence"  # Finding claimed without evidence
    ENDLESS_RECON = "endless_recon"  # Recon looping without new assets
    IDENTICAL_PAYLOAD = "identical_payload"  # Same payload sent repeatedly


@dataclass
class LoopDetection:
    """Detected loop/waste."""

    type: LoopType
    description: str
    evidence: str  # What shows loop
    task_id: Optional[str] = None
    agent_id: Optional[str] = None
    count: int = 1  # How many times repeated
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    severity: str = "medium"  # low, medium, high, critical
    suggested_action: str = ""  # What to do


@dataclass
class FailureRecord:
    """Record of failure for learning."""

    task_id: str
    agent_id: str
    failure_type: LoopType
    description: str
    evidence: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    strategy_tried: List[str] = field(default_factory=list)
    next_strategy: Optional[str] = None


class AntiLoopDetector:
    """Detects loops and waste in mission execution."""

    def __init__(
        self,
        max_repeated_commands: int = 3,
        max_no_progress_iterations: int = 3,
        max_failed_hypothesis: int = 3,
        stale_task_seconds: int = 600,  # 10 minutes
        max_recon_iterations_without_new_assets: int = 2,
    ):
        self.max_repeated_commands = max_repeated_commands
        self.max_no_progress_iterations = max_no_progress_iterations
        self.max_failed_hypothesis = max_failed_hypothesis
        self.stale_task_seconds = stale_task_seconds
        self.max_recon_iterations_without_new_assets = max_recon_iterations_without_new_assets

        # Tracking
        self.command_history: List[Dict[str, Any]] = []  # {command, hash, timestamp, agent_id, task_id}
        self.task_history: Dict[str, Dict[str, Any]] = {}  # task_id → {status, started_at, last_progress, progress_count}
        self.hypothesis_failures: Dict[str, int] = {}  # hypothesis_hash → count
        self.recon_assets_history: List[Set[str]] = []  # List of asset sets per recon iteration
        self.finding_evidence_map: Dict[str, bool] = {}  # finding_id → has_evidence
        self.payload_history: List[Dict[str, Any]] = []  # {payload, endpoint, timestamp}

        # Detected loops
        self.detections: List[LoopDetection] = []
        self.failures: List[FailureRecord] = []

    def _hash_command(self, command: str, args: str = "") -> str:
        """Hash command for comparison."""
        content = f"{command}:{args}".strip()
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _hash_hypothesis(self, hypothesis: str) -> str:
        """Hash hypothesis for tracking failures."""
        return hashlib.sha256(hypothesis.encode()).hexdigest()[:16]

    def record_command(self, command: str, args: str = "", agent_id: str = "", task_id: str = "") -> Optional[LoopDetection]:
        """Record command execution, detect repeated identical commands."""
        cmd_hash = self._hash_command(command, args)
        now = datetime.utcnow()

        # Check for recent identical commands
        recent_same = [
            c for c in self.command_history
            if c["hash"] == cmd_hash and (now - c["timestamp"]).total_seconds() < 300  # 5 min window
        ]

        self.command_history.append(
            {
                "command": command,
                "args": args,
                "hash": cmd_hash,
                "timestamp": now,
                "agent_id": agent_id,
                "task_id": task_id,
            }
        )

        # Keep only last 100 commands
        if len(self.command_history) > 100:
            self.command_history = self.command_history[-100:]

        if len(recent_same) >= self.max_repeated_commands - 1:
            detection = LoopDetection(
                type=LoopType.REPEATED_COMMAND,
                description=f"Repeated identical command: {command} {args}",
                evidence=f"Command hash {cmd_hash} repeated {len(recent_same)+1} times in 5 min",
                task_id=task_id,
                agent_id=agent_id,
                count=len(recent_same) + 1,
                severity="high" if len(recent_same) >= 5 else "medium",
                suggested_action="Change strategy, try different payload/method, or escalate to Boss",
            )
            self.detections.append(detection)
            return detection

        return None

    def record_task_start(self, task_id: str, agent_id: str = ""):
        """Record task start."""
        self.task_history[task_id] = {
            "status": "running",
            "started_at": datetime.utcnow(),
            "last_progress": datetime.utcnow(),
            "progress_count": 0,
            "agent_id": agent_id,
        }

    def record_task_progress(self, task_id: str):
        """Record task progress."""
        if task_id in self.task_history:
            self.task_history[task_id]["last_progress"] = datetime.utcnow()
            self.task_history[task_id]["progress_count"] += 1

    def check_stale_tasks(self) -> List[LoopDetection]:
        """Check for stale tasks (running too long without progress)."""
        now = datetime.utcnow()
        detections = []

        for task_id, info in self.task_history.items():
            if info["status"] != "running":
                continue

            elapsed_since_progress = (now - info["last_progress"]).total_seconds()
            if elapsed_since_progress > self.stale_task_seconds:
                detection = LoopDetection(
                    type=LoopType.STALE_TASK,
                    description=f"Stale task: {task_id} no progress for {elapsed_since_progress:.0f}s",
                    evidence=f"Task started {info['started_at']}, last progress {info['last_progress']}, count {info['progress_count']}",
                    task_id=task_id,
                    agent_id=info.get("agent_id"),
                    severity="medium",
                    suggested_action="Check if task blocked, retry, or escalate to Boss",
                )
                detections.append(detection)
                self.detections.append(detection)

        return detections

    def record_hypothesis_failure(self, hypothesis: str, agent_id: str = "", task_id: str = "") -> Optional[LoopDetection]:
        """Record failed hypothesis, detect repeated failures."""
        h_hash = self._hash_hypothesis(hypothesis)
        self.hypothesis_failures[h_hash] = self.hypothesis_failures.get(h_hash, 0) + 1

        count = self.hypothesis_failures[h_hash]

        if count >= self.max_failed_hypothesis:
            detection = LoopDetection(
                type=LoopType.REPEATED_FAILED_HYPOTHESIS,
                description=f"Repeated failed hypothesis: {hypothesis[:100]}",
                evidence=f"Hypothesis hash {h_hash} failed {count} times",
                task_id=task_id,
                agent_id=agent_id,
                count=count,
                severity="medium",
                suggested_action="Change strategy, ask another specialist, or escalate to Boss",
            )
            self.detections.append(detection)
            return detection

        return None

    def record_recon_assets(self, assets: Set[str]) -> Optional[LoopDetection]:
        """Record recon assets, detect endless recon."""
        self.recon_assets_history.append(assets)

        # Keep last 10
        if len(self.recon_assets_history) > 10:
            self.recon_assets_history = self.recon_assets_history[-10:]

        # Check if no new assets in last N iterations
        if len(self.recon_assets_history) >= self.max_recon_iterations_without_new_assets + 1:
            recent = self.recon_assets_history[-self.max_recon_iterations_without_new_assets :]
            previous = self.recon_assets_history[-self.max_recon_iterations_without_new_assets - 1]

            # If all recent are subsets of previous (no new assets)
            no_new = all(r.issubset(previous) or r == previous for r in recent)
            if no_new:
                detection = LoopDetection(
                    type=LoopType.ENDLESS_RECON,
                    description=f"Endless recon: no new assets in last {self.max_recon_iterations_without_new_assets} iterations",
                    evidence=f"Previous: {len(previous)} assets, recent: {[len(r) for r in recent]}",
                    severity="medium",
                    suggested_action="Stop recon, move to next phase (attack surface modeling, hypothesis generation)",
                )
                self.detections.append(detection)
                return detection

        return None

    def check_duplicate_task(self, task_id: str, objective: str, target: str) -> Optional[LoopDetection]:
        """Check if task is duplicate of existing."""
        # Simple check: same objective + target
        task_hash = self._hash_command(objective, target)

        existing_hashes = [
            self._hash_command(info.get("objective", ""), info.get("target", ""))
            for info in self.task_history.values()
            if "objective" in info
        ]

        if task_hash in existing_hashes:
            detection = LoopDetection(
                type=LoopType.DUPLICATE_TASK,
                description=f"Duplicate task: {objective} for {target}",
                evidence=f"Task hash {task_hash} already exists",
                task_id=task_id,
                severity="low",
                suggested_action="Skip duplicate, check if previous task completed or failed",
            )
            self.detections.append(detection)
            return detection

        return None

    def check_evidence(self, finding_id: str, has_tool_output: bool, tool_output_ref: str) -> Optional[LoopDetection]:
        """Check for hallucinated or missing evidence."""
        if not has_tool_output or not tool_output_ref:
            detection = LoopDetection(
                type=LoopType.MISSING_EVIDENCE if not has_tool_output else LoopType.HALLUCINATED_EVIDENCE,
                description=f"Finding {finding_id} missing evidence or tool output reference",
                evidence=f"has_tool_output={has_tool_output}, ref={tool_output_ref}",
                severity="high",
                suggested_action="Require tool output and evidence before reporting finding",
            )
            self.detections.append(detection)
            return detection
        return None

    def record_payload(self, payload: str, endpoint: str, agent_id: str = "", task_id: str = "") -> Optional[LoopDetection]:
        """Record payload, detect identical payloads."""
        now = datetime.utcnow()
        payload_hash = self._hash_command(payload, endpoint)

        recent_same = [
            p for p in self.payload_history
            if p["hash"] == payload_hash and (now - p["timestamp"]).total_seconds() < 300
        ]

        self.payload_history.append(
            {
                "payload": payload[:200],
                "endpoint": endpoint,
                "hash": payload_hash,
                "timestamp": now,
                "agent_id": agent_id,
                "task_id": task_id,
            }
        )

        if len(self.payload_history) > 100:
            self.payload_history = self.payload_history[-100:]

        if len(recent_same) >= self.max_repeated_commands - 1:
            detection = LoopDetection(
                type=LoopType.IDENTICAL_PAYLOAD,
                description=f"Repeated identical payload to {endpoint}: {payload[:50]}",
                evidence=f"Payload hash {payload_hash} repeated {len(recent_same)+1} times",
                task_id=task_id,
                agent_id=agent_id,
                count=len(recent_same) + 1,
                severity="medium",
                suggested_action="Change payload, try different encoding, or record failure and change strategy",
            )
            self.detections.append(detection)
            return detection

        return None

    def get_strategy_change_suggestion(self, detection: LoopDetection) -> str:
        """Suggest strategy change for detected loop."""
        suggestions = {
            LoopType.REPEATED_COMMAND: "Try different tool, different args, or ask another specialist",
            LoopType.NO_PROGRESS: "Change approach, check if blocked, escalate to Boss",
            LoopType.REPEATED_FAILED_HYPOTHESIS: "Try different vuln class, different endpoint, or defensive validation",
            LoopType.DUPLICATE_TASK: "Skip, merge with existing, or check previous result",
            LoopType.STALE_TASK: "Check logs, retry, or escalate",
            LoopType.CONFLICTING_CONCLUSIONS: "Request verification specialist, defensive validation",
            LoopType.HALLUCINATED_EVIDENCE: "Require real tool output, never simulate",
            LoopType.MISSING_EVIDENCE: "Execute real tool, capture output, then report",
            LoopType.ENDLESS_RECON: "Stop recon, move to hypothesis generation, testing",
            LoopType.IDENTICAL_PAYLOAD: "Try encoding, different payload type, or bypass technique",
        }
        return suggestions.get(detection.type, "Record failure, change strategy, escalate to Boss")

    def record_failure(self, task_id: str, agent_id: str, detection: LoopDetection, strategy_tried: List[str]) -> FailureRecord:
        """Record failure for learning."""
        failure = FailureRecord(
            task_id=task_id,
            agent_id=agent_id,
            failure_type=detection.type,
            description=detection.description,
            evidence=detection.evidence,
            strategy_tried=strategy_tried,
            next_strategy=self.get_strategy_change_suggestion(detection),
        )
        self.failures.append(failure)
        return failure

    def should_stop_mission(self) -> Tuple[bool, str]:
        """Check if mission should stop due to loops."""
        # Count high/critical detections in last 10 minutes
        now = datetime.utcnow()
        recent_critical = [
            d for d in self.detections
            if d.severity in ("high", "critical") and (now - d.last_seen).total_seconds() < 600
        ]

        if len(recent_critical) >= 5:
            return True, f"Too many high/critical loop detections ({len(recent_critical)}) in last 10 min — no productive path"

        # Check if all recent detections are endless recon + no progress
        recent = [d for d in self.detections if (now - d.last_seen).total_seconds() < 600]
        if len(recent) >= 3:
            types = [d.type for d in recent]
            if all(t in (LoopType.ENDLESS_RECON, LoopType.NO_PROGRESS) for t in types):
                return True, "Endless recon and no progress — scope covered or blocked"

        return False, "OK"

    def get_stats(self) -> Dict[str, Any]:
        """Get anti-loop stats."""
        type_counts = {}
        for d in self.detections:
            type_counts[d.type.value] = type_counts.get(d.type.value, 0) + 1

        return {
            "total_detections": len(self.detections),
            "total_failures": len(self.failures),
            "by_type": type_counts,
            "recent_detections": [
                {
                    "type": d.type.value,
                    "description": d.description,
                    "count": d.count,
                    "severity": d.severity,
                    "suggested_action": d.suggested_action,
                }
                for d in self.detections[-10:]
            ],
        }
