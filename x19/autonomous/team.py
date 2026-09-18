"""
X19 Fully Autonomous Offensive Team — like overall offensive team.

Makes X19 fully autonomous:
- Boss owns mission, defines scope, splits assessment, delegates to Managers
- Managers coordinate Specialists
- Specialists use real tools, knowledge base, payloads, methodology
- Knowledge base provides vuln classes, payloads, verification, remediation
- Datasets provide bug bounty methodology, examples, program patterns
- Offensive methodology generates hypotheses from recon, prioritizes, builds attack surface
- Loop runs SCOPE→...→REASSESS autonomously with termination checks
- Anti-loop detects and mitigates waste
- Operator retains PAUSE/STOP/KILL ALL/RESET

This module wires everything together for fully autonomous operation.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import time

from x19.scope import create_scope, ScopeDefinition, ScopeEnforcer
from x19.orchestration import MissionStateManager, MissionState, MissionPhase, MissionStatus, Task, TaskStatus
from x19.orchestration.boss import BossOrchestrator
from x19.knowledge import get_knowledge_base
from x19.datasets import get_datasets
from x19.offensive import OffensiveMethodology, PayloadGenerator
from x19.loop import AutonomousSecurityLoop, LoopPhase
from x19.interface import OperatorInterface
from x19.safety import AntiLoopDetector
from x19.findings import Finding, FindingStore, FindingStatus


@dataclass
class AutonomousTeamConfig:
    """Config for autonomous team."""

    target: str
    authorized_domains: List[str]
    excluded_assets: List[str] = None
    program_name: Optional[str] = None
    objectives: List[str] = None
    max_iterations: int = 5
    time_limit_seconds: Optional[int] = None
    concurrency_limit: int = 3
    rate_limit_ms: int = 200
    auto_verify: bool = True
    auto_report: bool = True


class AutonomousOffensiveTeam:
    """Fully autonomous offensive team — Boss + Managers + Specialists with knowledge and datasets."""

    def __init__(self, storage_dir: Optional[str] = None):
        self.mission_manager = MissionStateManager(storage_dir=storage_dir)
        self.boss = BossOrchestrator(self.mission_manager)
        self.kb = get_knowledge_base()
        self.ds = get_datasets()
        self.offensive = OffensiveMethodology()
        self.payload_gen = PayloadGenerator()
        self.loop = AutonomousSecurityLoop(self.boss)
        self.operator = OperatorInterface(self.mission_manager)

    def create_autonomous_mission(self, config: AutonomousTeamConfig) -> Tuple[MissionState, str]:
        """Create autonomous mission with explicit scope and objectives."""

        mission, errors = self.boss.create_mission(
            name=f"Autonomous Assessment of {config.target}",
            target=config.target,
            authorized_domains=config.authorized_domains,
            excluded_assets=config.excluded_assets or [],
            program_name=config.program_name,
            objectives=config.objectives or [f"Autonomously assess {config.target} for OWASP Top 10, API Top 10"],
            time_limit_seconds=config.time_limit_seconds,
            concurrency_limit=config.concurrency_limit,
            rate_limit_ms=config.rate_limit_ms,
        )

        if not mission:
            return None, f"Failed to create mission: {errors}"

        # Decompose
        plan = self.boss.decompose_mission(mission)
        self.boss.assign_tasks(mission, plan)

        # Set operator current mission
        self.operator._current_mission_id = mission.id

        return mission, (
            f"Autonomous mission created: {mission.id}\n"
            f"Target: {config.target}\n"
            f"Authorized: {config.authorized_domains}\n"
            f"Excluded: {config.excluded_assets}\n"
            f"Tasks: {len(plan.tasks)} in {len(plan.parallel_groups)} parallel groups\n"
            f"Knowledge: {self.kb.get_stats()['total_entries']} entries, {len(self.kb.list_vuln_classes())} vuln classes\n"
            f"Datasets: {self.ds.get_stats()['total_examples']} examples, {self.ds.get_stats()['total_methodologies']} methodologies\n"
            f"Ready for autonomous execution"
        )

    def autonomous_recon(self, mission: MissionState, discoveries: Dict[str, List[str]]) -> Dict[str, Any]:
        """Autonomous recon using methodology from knowledge base."""

        # Get recon methodology
        recon_method = self.kb.get_methodology("recon")
        if not recon_method:
            recon_method = self.kb.get_methodology("information_gathering")

        # These discoveries must originate from real tool/runtime output. This method only records evidence and derives an attack-surface model.

        for dtype, items in discoveries.items():
            for item in items:
                mission.add_discovery(dtype, item)

        # Build attack surface model
        attack_surface = self.offensive.build_attack_surface_model(mission.discoveries)

        mission.add_timeline_event(MissionPhase.RECON, f"Autonomous recon completed: {attack_surface['model_summary']}", "recon_manager")

        self.mission_manager.save_mission(mission)

        return {
            "status": "completed",
            "discoveries": mission.discoveries,
            "attack_surface": attack_surface,
            "methodology": recon_method,
        }

    def autonomous_hypothesis_generation(self, mission: MissionState) -> List[Any]:
        """Autonomous hypothesis generation from recon observations using knowledge base."""

        # Generate hypotheses from discoveries
        attack_surface = self.offensive.build_attack_surface_model(mission.discoveries)
        hypotheses = self.offensive.generate_hypotheses_from_recon(mission.discoveries, attack_surface)

        # Prioritize
        prioritized = self.offensive.prioritize_hypotheses(hypotheses)

        # Add to mission
        for h in prioritized:
            mission.add_hypothesis(
                {
                    "id": h.id,
                    "vuln_class": h.vuln_class,
                    "endpoint": h.endpoint,
                    "param": h.param,
                    "rationale": h.rationale,
                    "observation": h.observation,
                    "test_method": h.test_method,
                    "expected_evidence": h.expected_evidence,
                    "severity": h.severity,
                    "confidence": h.confidence,
                    "cwe": h.cwe,
                    "owasp": h.owasp,
                    "payloads": h.payloads,
                    "status": h.status,
                }
            )

        mission.add_timeline_event(MissionPhase.HYPOTHESIS, f"Generated {len(prioritized)} hypotheses from recon", "vuln_research")

        self.mission_manager.save_mission(mission)

        return prioritized

    def autonomous_testing(self, mission: MissionState, hypotheses: List[Any]) -> Dict[str, Any]:
        """Autonomous testing using payloads and methodology from knowledge base."""

        # For each hypothesis, generate payloads and testing tasks
        testing_tasks = []

        for hypothesis in hypotheses[:5]:  # Limit for safety
            # Get payloads for vuln class
            payloads = self.payload_gen.generate_payloads_for_endpoint(
                vuln_class=hypothesis.vuln_class,
                endpoint=hypothesis.endpoint,
                param=hypothesis.param or "id",
                context=None,
            )

            # Get testing methodology
            testing_method = self.offensive.get_testing_methodology(hypothesis.vuln_class)

            # Create testing task (in real autonomous, this would be delegated to specialist via delegate_task)
            task = Task(
                mission_id=mission.id,
                objective=f"Test {hypothesis.vuln_class} at {hypothesis.endpoint} via {hypothesis.param}: {hypothesis.test_method}",
                target=mission.scope.target if mission.scope else hypothesis.endpoint,
                assigned_to=self._get_specialist_for_vuln(hypothesis.vuln_class),
                scope=mission.scope.to_dict() if mission.scope else {},
                expected_evidence=[f"{hypothesis.vuln_class}_test_evidence", "candidate_finding", "tool_output"],
            )

            mission.tasks.add(task)
            testing_tasks.append({"hypothesis": hypothesis, "task": task, "payloads": payloads, "methodology": testing_method})

        mission.add_timeline_event(MissionPhase.TEST, f"Created {len(testing_tasks)} autonomous testing tasks", "boss")

        self.mission_manager.save_mission(mission)

        return {
            "status": "completed",
            "testing_tasks": len(testing_tasks),
            "tasks": testing_tasks,
        }

    def _get_specialist_for_vuln(self, vuln_class: str) -> str:
        """Map vuln class to specialist role."""
        mapping = {
            "xss": "web_security",
            "sqli": "web_security",
            "ssti": "web_security",
            "ssrf": "web_security",
            "xxe": "web_security",
            "open_redirect": "web_security",
            "bola": "api_security",
            "bfla": "api_security",
            "idor": "auth",
            "auth_bypass": "auth",
            "s3_exposure": "cloud_infra",
            "cors_misconfig": "web_security",
            "csrf": "web_security",
        }

        return mapping.get(vuln_class.lower(), "web_security")

    def autonomous_verification(self, mission: MissionState) -> Dict[str, Any]:
        """Queue candidates for real specialist verification; never self-certify findings."""
        candidates = mission.findings.list_by_status(FindingStatus.CANDIDATE)
        queued = 0
        for finding in candidates[:3]:
            if finding.evidence and any(e.tool_output for e in finding.evidence):
                if finding.transition_to(FindingStatus.UNDER_VERIFICATION):
                    queued += 1
            else:
                finding.transition_to(FindingStatus.NEEDS_MORE_EVIDENCE, reason="Missing tool evidence")
            mission.findings.update(finding)

        mission.add_timeline_event(
            MissionPhase.VERIFY,
            f"Verification queue prepared: {queued} evidence-backed candidates",
            "verification",
        )
        self.mission_manager.save_mission(mission)
        return {
            "status": "pending" if queued else "completed",
            "candidates": len(candidates),
            "queued_for_verification": queued,
            "verified": len(mission.findings.list_verified()),
            "note": "Verified status is written only from real verification results.",
        }

    def autonomous_report(self, mission: MissionState) -> str:
        """Autonomous reporting — evidence-based, L3/L4 only for verified."""

        self.operator._current_mission_id = mission.id
        report = self.operator.generate_report(mission.id)

        mission.add_timeline_event(MissionPhase.REPORT, f"Autonomous report generated: {len(report)} chars", "evidence_reporting")

        self.mission_manager.save_mission(mission)

        return report

    def run_autonomous_mission(
        self,
        config: AutonomousTeamConfig,
        initial_discoveries: Optional[Dict[str, List[str]]] = None,
        parent_agent: Any = None,
    ) -> Dict[str, Any]:
        """Create and advance an X19 mission from real runtime evidence only.

        Planning never implies execution. When parent_agent is supplied, ready work is
        dispatched through Hermes' real delegate_task rail. Without it, the mission remains
        active and reports that a live agent context is required for delegation.
        """
        mission, msg = self.create_autonomous_mission(config)
        if not mission:
            return {"status": "failed", "error": msg}

        results: Dict[str, Any] = {
            "mission_id": mission.id,
            "status": "active",
            "phases": {
                "scope": {"status": "completed", "target": config.target},
                "plan": {"status": "completed", "tasks": mission.tasks.get_stats()["total"]},
            },
        }

        if initial_discoveries is not None:
            results["phases"]["recon"] = self.autonomous_recon(mission, initial_discoveries)

        if parent_agent is not None:
            dispatched = self.boss.delegate_ready_tasks(mission, parent_agent, background=True)
            results["delegation"] = {
                "status": "dispatched" if dispatched else "idle",
                "tasks": [{"task_id": d["task_id"], "assigned_to": d["assigned_to"]} for d in dispatched],
            }
        else:
            results["delegation"] = {
                "status": "pending",
                "reason": "Live parent agent context required to invoke delegate_task",
            }

        results["final_status"] = mission.get_stats()
        results["note"] = ("Mission remains active until real delegated work reports completion; no synthetic discoveries, "
                            "findings, verification, or completion are emitted.")
        self.mission_manager.save_mission(mission)
        return results
    def get_team_status(self) -> Dict[str, Any]:
        """Get offensive team status — like overall offensive team."""

        return {
            "team": "X19 Autonomous Offensive Team",
            "hierarchy": "OPERATOR → BOSS → MANAGERS (Recon, Web, API) → SPECIALISTS (9) → TOOLS",
            "boss": "Owns mission, defines scope, splits assessment, delegates, tracks state, reports to Operator",
            "managers": {
                "recon_manager": "Asset discovery, endpoint enum, tech fingerprint, auth surface (read-only)",
                "web_manager": "Web app assessment coordination, delegates to Web, Auth, Verification",
                "api_manager": "API assessment coordination, delegates to API, Auth, Cloud, Verification",
            },
            "specialists": {
                "web_security": "XSS, SQLi, SSTI, SSRF, XXE, open redirect, etc.",
                "api_security": "BOLA, BFLA, injection, mass assignment, excessive data exposure",
                "auth": "Auth bypass, IDOR, BOLA, BFLA, privilege escalation, session management",
                "cloud_infra": "S3 exposure, IAM misconfig, metadata, open ports, exposed configs",
                "vuln_research": "Correlate observations against CWE, OWASP, CVE, generate hypotheses",
                "bugbounty_research": "Program scope interpretation, impact assessment, report quality",
                "verification": "Reproduce candidate findings, bypass exhaustion before false-positive",
                "evidence_reporting": "Collect evidence, prepare evidence-based reports, L3/L4 only for verified",
                "defensive_validation": "False-positive review, defensive validation, alternative explanations",
            },
            "knowledge": self.kb.get_stats(),
            "datasets": self.ds.get_stats(),
            "offensive_capabilities": {
                "payloads": "Witness payloads, bypass payloads, context-aware, encoding variations, minimal proof, not destructive",
                "methodology": "Recon, attack surface modeling, hypothesis generation, testing, verification, classification, reporting, learning, reassessment",
                "verification": "Bypass exhaustion before false-positive dismissal, reproduction with minimal proof",
                "evidence_first": "OBSERVATION/HYPOTHESIS/TEST/EVIDENCE/VERIFIED FINDING, never auto-convert observation to vulnerability",
            },
            "autonomous_loop": "SCOPE→PLAN→RECON→ATTACK_SURFACE→HYPOTHESIS→TEST→OBSERVE→CORRELATE→VERIFY→CLASSIFY→REPORT→LEARN→REASSESS",
            "controls": "Operator retains PAUSE/STOP/KILL ALL/RESET, high-impact requires approval, scope enforcement, anti-loop",
            "toolsets": "x19-recon, x19-web, x19-api, x19-auth, x19-cloud, x19-vuln-research, x19-bugbounty, x19-verification, x19-evidence, x19-defensive, x19-boss, x19-manager, x19-all — reuses Hermes tool infrastructure",
        }
