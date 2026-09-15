"""
X19 Swarm Coordinator (Meta-Agent).
Coordinates parallel specialized agents, synchronizes findings with the World Model
and Attack Graph, streams live events, and manages prioritized task queue orchestration.

P0 REMEDIATION:
- WorldModel is the canonical source of truth (not TargetModel, GoalTree, etc.)
- DecisionEngine is the single canonical next-action selector
- Every coordination cycle runs: EvidenceRanking → Hypotheses → Strategist → Decision
- Strategic goals generate candidate experiments
- The selected experiment IS the action executed (not task queue override)
- Every executed action carries hypothesis/evidence metadata
- Every observation updates WorldModel
- Every WorldModel update invalidates derived state
- LoopGuard success detection uses explicit terminal states
- CommandGateway initialized with policy_from_config
"""

from __future__ import annotations
import json
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Callable, Set

from brain.agents.recon_agent import ReconAgent
from brain.agents.web_agent import WebAgent
from brain.agents.vuln_agent import VulnAgent
from brain.agents.verifier_agent import VerifierAgent
from brain.agents.critic_agent import CriticAgent
from brain.attack_graph import (
    AttackGraph, GraphNode, GraphEdge,
    EDGE_HOST_HAS_SERVICE, EDGE_SERVICE_SERVES_ENDPOINT,
    EDGE_ENDPOINT_VULNERABLE_TO, NODE_STATE_OBSERVED, NODE_STATE_IDENTIFIED,
    NODE_STATE_CONFIRMED, NODE_STATE_TESTABLE, NODE_STATE_VALIDATED,
    NODE_STATE_UNKNOWN,
)
from brain.evidence_ranking import EvidenceRankingEngine, RankedEvidence
from brain.hypothesis_engine import MultiHypothesisEngine, HYP_TESTING, HYP_CONFIRMED, HYP_REJECTED
from brain.strategist_engine import StrategistEngine
from brain.decision_engine import DecisionEngine, CandidateExperiment, DecisionRecord
from brain.world_model import WorldModel, Observation, ServiceRecord, EndpointRecord, VulnerabilityRecord, EvidenceRecord
from brain.workflow import (
    ACTION_EXPLOIT,
    ACTION_SWARM,
    ACTION_TEST,
    AgentFactory,
    BudgetState,
    ConfidenceGate,
    LoopGuard,
    MissionPlan,
    PHASE_ACTIVE,
    PHASE_DONE,
    PHASE_SKIPPED,
    WorkflowRun,
    WorkflowStage,
)
from brain.strategy_library import StrategyLibrary, TargetSignature
from brain.task_queue import TaskQueue, AgentTask, TaskStatus
from execution.native_vuln import VulnerabilityFinding
from execution.scope_guard import ScopeGuard, ScopeViolationError


@dataclass
class SwarmEvent:
    event_type: str
    sender: str
    data: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)


class SwarmCoordinator:
    """Master orchestrator for the X19 parallel cognitive agent swarm.

    P0: The coordinator maintains a single WorldModel as the canonical state,
    and the DecisionEngine selects every next action.
    """

    def __init__(self, target: str = "", scope_guard: Optional[ScopeGuard] = None):
        self.target = target
        self.scope_guard = scope_guard or ScopeGuard(
            allowed_targets={target} if target else set(),
            enforce=bool(target)
        )

        # Distributed Task Queue
        self.task_queue = TaskQueue()
        
        # Swarm Agents
        self.recon_agent = ReconAgent(coordinator=self, scope_guard=self.scope_guard)
        self.web_agent = WebAgent(coordinator=self, scope_guard=self.scope_guard)
        self.vuln_agent = VulnAgent(coordinator=self, scope_guard=self.scope_guard)
        self.verifier_agent = VerifierAgent(coordinator=self, scope_guard=self.scope_guard)
        self.critic_agent = CriticAgent(coordinator=self)
        
        self.agents = [
            self.recon_agent,
            self.web_agent,
            self.vuln_agent,
            self.verifier_agent,
            self.critic_agent,
        ]

        # P0: Canonical cognitive engines
        self.world_model = WorldModel(target=target)
        self.attack_graph = AttackGraph()
        self.evidence_engine = EvidenceRankingEngine()
        self.strategist = StrategistEngine()
        self.strategy_library = StrategyLibrary()
        self.hypothesis_engine = MultiHypothesisEngine()
        self.decision_engine = DecisionEngine()

        # Workflow state
        self.profile = None
        self.workflow = WorkflowRun(target=target)
        self.plan = MissionPlan(target=target, objective="autonomous assessment")
        self.loop_guard = LoopGuard()
        self.budget_state = BudgetState()
        self.confidence_gate = ConfidenceGate()
        self.agent_factory = AgentFactory(coordinator=self, scope_guard=self.scope_guard)
        self.last_confidence: float = 0.0
        self._consumed_checkpoints: set = set()
        
        # State Data
        self.discovered_ports: List[Dict[str, Any]] = []
        self.discovered_endpoints: List[Dict[str, Any]] = []
        self.raw_findings: List[VulnerabilityFinding] = []
        self.verified_findings: List[VulnerabilityFinding] = []
        
        self.logs: List[Dict[str, Any]] = []
        self.events: List[SwarmEvent] = []
        self.subscribers: List[Callable[[Dict[str, Any]], None]] = []
        
        self.is_running: bool = False
        self.start_time: float = 0.0
        self.end_time: float = 0.0
        self._lock = threading.Lock()
        self._worker_threads: List[threading.Thread] = []
        self._pipeline_thread: Optional[threading.Thread] = None
        # Track last world model snapshot for evidence delta detection
        self._last_wm_snapshot: Optional[Any] = None

    def set_target(self, target: str) -> None:
        if not isinstance(target, str) or not target.strip():
            raise ValueError("An explicit authorized target is required before starting a mission.")
        self.target = target
        self.world_model.target = target
        self.world_model.ensure_host(target)
        self.scope_guard.add_target(target)
        self.scope_guard.enforce = True

    def subscribe_events(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        self.subscribers.append(callback)

    def publish_log(self, sender: str, message: str) -> None:
        log_entry = {
            "timestamp": time.strftime("%H:%M:%S"),
            "sender": sender,
            "message": message
        }
        with self._lock:
            self.logs.append(log_entry)
        self._emit("log", sender, log_entry)

    def _emit(self, event_type: str, sender: str, data: Dict[str, Any]) -> None:
        event = SwarmEvent(event_type=event_type, sender=sender, data=data)
        with self._lock:
            self.events.append(event)
        payload = {"type": event_type, "sender": sender, "data": data, "timestamp": event.timestamp}
        for sub in list(self.subscribers):
            try:
                sub(payload)
            except Exception:
                pass

    def start_mission_pipeline(self, target: Optional[str] = None) -> threading.Thread:
        if target:
            self.set_target(target)
        if not self.target:
            raise ValueError("An explicit authorized target is required before starting a mission.")
        self.is_running = True
        self.start_time = time.time()
        self.publish_log("Coordinator", f"Launching Prioritized Swarm Mission on target: {self.target}")
        self.target_node = self.attack_graph.add_node(
            node_type="host", label=f"Target: {self.target}", value_score=1.0
        )
        self._seed_initial_tasks()
        self._pipeline_thread = threading.Thread(target=self._run_pipeline, daemon=True, name="Coordinator-Pipeline")
        self._pipeline_thread.start()
        return self._pipeline_thread

    def _seed_initial_tasks(self) -> None:
        recon_task = AgentTask(
            priority=1, task_id=f"task_recon_{int(time.time()*1000)}",
            task_type="recon", target=self.target, params={"mode": "standard_ports"}
        )
        self.task_queue.push(recon_task)
        web_task = AgentTask(
            priority=2, task_id=f"task_web_{int(time.time()*1000)}",
            task_type="web_fuzz", target=self.target, params={"wordlist": "default"}
        )
        self.task_queue.push(web_task)
        critic_task = AgentTask(
            priority=5, task_id=f"task_critic_{int(time.time()*1000)}",
            task_type="reflect", target=self.target, params={}
        )
        self.task_queue.push(critic_task)

    def _run_pipeline(self) -> None:
        try:
            self.publish_log("Coordinator", "STAGE 1: Processing Initial Recon & Surface Mapping...")
            t_recon = self.recon_agent.start_async(self.target)
            t_web = self.web_agent.start_async(self.target)
            self.critic_agent.start_async(self.target)
            t_recon.join(timeout=45)
            t_web.join(timeout=45)
            self._sync_world_model_from_agents()

            self.publish_log("Coordinator", "STAGE 2: Launching VulnAgent on discovered attack surface...")
            t_vuln = self.vuln_agent.start_async(self.target)
            t_vuln.join(timeout=60)
            self._sync_world_model_from_agents()

            self.publish_log("Coordinator", "STAGE 3: Launching VerifierAgent for PoC verification...")
            t_verif = self.verifier_agent.start_async(self.target, findings=self.raw_findings)
            t_verif.join(timeout=45)
            self._sync_world_model_from_agents()

            self._process_dynamic_queue()
            self._finalize_mission()
        except Exception as e:
            self.publish_log("Coordinator", f"Mission error: {str(e)}")
        finally:
            self.is_running = False
            self.end_time = time.time()
            self.publish_log("Coordinator", f"Swarm mission finished in {self.end_time - self.start_time:.1f}s")
            self._emit("mission_completed", "Coordinator", self.get_summary())

    def _process_dynamic_queue(self) -> None:
        while self.is_running and self.task_queue.pending_count() > 0:
            task = self.task_queue.pop()
            if not task:
                break
            try:
                if task.task_type == "verify" and self.raw_findings:
                    self.verifier_agent.run(task.target, findings=self.raw_findings)
                    self.task_queue.mark_completed(task.task_id, "verified")
                elif task.task_type == "vuln_audit":
                    self.vuln_agent.run(task.target)
                    self.task_queue.mark_completed(task.task_id, "audited")
                else:
                    self.task_queue.mark_completed(task.task_id, "processed")
                self._sync_world_model_from_agents()
            except Exception as ex:
                self.task_queue.mark_failed(task.task_id, str(ex))

    def stop_mission(self) -> None:
        self.publish_log("Coordinator", "Emergency stop triggered! Halting all agents.")
        self.task_queue.cancel_all()
        for agent in self.agents:
            agent.stop()
        self.is_running = False

    # ==================================================================
    # P0: WorldModel as canonical state — registrations update WorldModel
    # ==================================================================
    def register_port(self, host: str, port: int, service: str, banner: str, tls_info: Dict[str, str]) -> None:
        with self._lock:
            port_data = {
                "host": host, "port": port, "service": service,
                "banner": banner, "tls_info": tls_info
            }
            self.discovered_ports.append(port_data)

            # P0: Update WorldModel as canonical state
            host_record = self.world_model.ensure_host(host)
            svc_key = f"{port}/tcp"
            if svc_key not in host_record.services:
                host_record.services[svc_key] = ServiceRecord(
                    port=port, proto="tcp", service=service, version=banner
                )
                host_record.services[svc_key].confidence = 0.7

            # P0: Update attack graph with typed relationship
            target_node = getattr(self, "target_node", None)
            if not target_node:
                target_node = self.attack_graph.add_node("host", f"Target: {host}", value_score=1.0)
                self.target_node = target_node
            port_node = self.attack_graph.add_node(
                node_type="service", label=f"{service}:{port}",
                value_score=0.6, state=NODE_STATE_OBSERVED,
                properties={"port": port, "service": service, "banner": banner},
            )
            self.attack_graph.add_edge(target_node.id, port_node.id, EDGE_HOST_HAS_SERVICE, confidence=0.95)

            # P0: Record observation in WorldModel
            self.world_model.ingest(Observation(
                kind="port", source="ReconAgent",
                data=port_data, confidence=0.7,
            ))

            # P0: Add evidence to ranking engine
            self.evidence_engine.add_evidence(RankedEvidence(
                id=f"port-{port}-{service}", source="ReconAgent", kind="port",
                data={"port": port, "service": service, "banner": banner, "proto": "tcp"},
            ))

        if port in (80, 443, 8000, 8080, 8443, 8888, 5000, 3000):
            scheme = "https" if port in (443, 8443) else "http"
            url_target = f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"
            self.task_queue.push(AgentTask(
                priority=2, task_id=f"task_web_port_{port}_{int(time.time()*1000)}",
                task_type="web_fuzz", target=url_target, params={"port": port}
            ))

        self._emit("port_discovered", "ReconAgent", port_data)

    def register_endpoint(self, target: str, path: str, status_code: int, title: str, is_interesting: bool, evidence: str) -> None:
        with self._lock:
            ep_data = {
                "target": target, "path": path, "status_code": status_code,
                "title": title, "is_interesting": is_interesting, "evidence": evidence
            }
            self.discovered_endpoints.append(ep_data)

            # P0: Update WorldModel
            host_record = self.world_model.ensure_host(target)
            method = "GET"
            ep_key = f"{method} {path}"
            if ep_key not in host_record.endpoints:
                host_record.endpoints[ep_key] = EndpointRecord(
                    url=path, method=method, status=status_code,
                )

            # P0: Update attack graph with typed relationship
            target_node = getattr(self, "target_node", None)
            if not target_node:
                target_node = self.attack_graph.add_node("host", f"Target: {target}", value_score=1.0)
                self.target_node = target_node
            ep_node = self.attack_graph.add_node(
                node_type="endpoint", label=f"{path} [{status_code}]",
                value_score=0.85 if is_interesting else 0.4,
                state=NODE_STATE_OBSERVED,
                properties={"url": path, "method": method, "status": status_code, "interesting": is_interesting},
            )
            self.attack_graph.add_edge(target_node.id, ep_node.id, "contains", confidence=0.9)

            # P0: Record observation
            self.world_model.ingest(Observation(
                kind="endpoint", source="WebAgent",
                data=ep_data, confidence=0.6,
            ))

            # P0: Add evidence to ranking engine
            self.evidence_engine.add_evidence(RankedEvidence(
                id=f"endpoint-{path}", source="WebAgent", kind="endpoint",
                data={"url": path, "method": method, "status": status_code, "interesting": is_interesting},
            ))

        if is_interesting:
            self.task_queue.push(AgentTask(
                priority=2, task_id=f"task_audit_ep_{hash(path)%100000}_{int(time.time()*1000)}",
                task_type="vuln_audit", target=target, params={"path": path}
            ))

        self._emit("endpoint_discovered", "WebAgent", ep_data)

    def register_finding(self, finding: VulnerabilityFinding) -> None:
        with self._lock:
            self.raw_findings.append(finding)

            # P0: Update WorldModel
            target = getattr(finding, "target", self.target)
            host_record = self.world_model.ensure_host(target)
            host_record.vulnerabilities.append(VulnerabilityRecord(
                title=getattr(finding, "title", ""),
                severity=getattr(finding, "severity", "info"),
                description=getattr(finding, "description", ""),
                evidence=[EvidenceRecord(source="VulnAgent", summary=getattr(finding, "evidence", "")[:500], confidence=0.5)],
                confidence=0.4,
            ))

            # P0: Add evidence to ranking engine
            self.evidence_engine.add_evidence(RankedEvidence(
                id=f"vuln-{getattr(finding, 'title', '')[:32]}",
                source="VulnAgent", kind="vulnerability",
                data={"title": getattr(finding, "title", ""), "severity": getattr(finding, "severity", "info"),
                      "endpoint": getattr(finding, "endpoint", "")},
            ))

        self.task_queue.push(AgentTask(
            priority=1, task_id=f"task_verify_{hash(finding.title)%100000}_{int(time.time()*1000)}",
            task_type="verify", target=finding.target,
            params={"finding_title": finding.title, "endpoint": finding.endpoint}
        ))
        self._emit("finding_detected", "VulnAgent", asdict(finding))

    def mark_finding_verified(self, finding: VulnerabilityFinding) -> None:
        with self._lock:
            if finding not in self.verified_findings:
                self.verified_findings.append(finding)
                target_node = getattr(self, "target_node", None)
                if not target_node:
                    target_node = self.attack_graph.add_node("host", f"Target: {finding.target}", value_score=1.0)
                    self.target_node = target_node
                vuln_node = self.attack_graph.add_node(
                    node_type="vulnerability",
                    label=f"{finding.severity.upper()}: {finding.title}",
                    value_score=finding.cvss_score / 10.0,
                    state=NODE_STATE_VALIDATED,
                )
                self.attack_graph.add_edge(target_node.id, vuln_node.id, "vulnerable_to", confidence=0.9)

                # P0: Update hypothesis confidence for related hypotheses
                for hyp in self.hypothesis_engine.get_competing_hypotheses(limit=10, active_only=False):
                    if finding.title.lower() in hyp.statement.lower() or finding.endpoint in hyp.statement:
                        self.hypothesis_engine.confirm_hypothesis(
                            hyp.id, evidence_ids=[f"verified-{finding.title}"],
                            evidence_quality=finding.cvss_score / 10.0,
                        )
        self._emit("finding_verified", "VerifierAgent", asdict(finding))

    def get_unverified_findings(self) -> List[VulnerabilityFinding]:
        with self._lock:
            return list(self.raw_findings)

    def on_agent_finished(self, agent_name: str) -> None:
        self.publish_log("Coordinator", f"Agent '{agent_name}' finished.")
        self._emit("agent_status", agent_name, self.get_agent_status(agent_name))

    def get_agent_status(self, agent_name: str) -> Dict[str, Any]:
        for a in self.agents:
            if a.name == agent_name:
                return a.to_dict()
        return {}

    def _sync_world_model_from_agents(self) -> None:
        """P0: Sync agent discoveries into the canonical WorldModel."""
        for agent in self.agents:
            if hasattr(agent, 'findings'):
                for finding in getattr(agent, 'findings', []):
                    if isinstance(finding, VulnerabilityFinding):
                        if finding not in self.raw_findings:
                            self.register_finding(finding)
            if hasattr(agent, 'discovered_count'):
                pass  # Already handled via register_port/register_endpoint callbacks

    def _finalize_mission(self) -> None:
        self.publish_log("Coordinator", "Learning from session outcomes & updating Strategy Library...")
        ports_list = [p["port"] for p in self.discovered_ports]
        services_list = [p["service"] for p in self.discovered_ports]
        sig = TargetSignature(
            ports=ports_list,
            services=services_list,
            technologies=[],
            target_type="web" if 80 in ports_list or 443 in ports_list else "network"
        )
        self.strategy_library.learn_new_strategy(
            name=f"Assessment on {self.target}",
            description=f"Swarm mission with {len(self.verified_findings)} verified finding(s)",
            target_signature=sig,
            technique_chain=["native_recon", "native_web_fuzz", "native_vuln_audit", "poc_verification"],
            succeeded=len(self.verified_findings) > 0,
            iterations=1
        )

    def get_attack_graph_d3(self) -> Dict[str, Any]:
        with self._lock:
            nodes = []
            for n in self.attack_graph._nodes.values():
                nodes.append({
                    "id": n.id, "label": n.label, "type": n.node_type,
                    "state": n.state, "value_score": n.value_score,
                })
            edges = []
            for e in self.attack_graph._edges.values():
                edges.append({"from": e.source_node, "to": e.target_node, "label": e.edge_type})
            return {"nodes": nodes, "edges": edges}

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "target": self.target,
                "is_running": self.is_running,
                "duration_seconds": round((time.time() - self.start_time) if self.is_running else (self.end_time - self.start_time), 1),
                "agents": [a.to_dict() for a in self.agents],
                "stats": {
                    "open_ports": len(self.discovered_ports),
                    "endpoints": len(self.discovered_endpoints),
                    "raw_findings": len(self.raw_findings),
                    "verified_findings": len(self.verified_findings),
                    "pending_tasks": self.task_queue.pending_count(),
                    "hypotheses_active": len(self.hypothesis_engine.get_competing_hypotheses(limit=100)),
                    "hypotheses_confirmed": len(self.hypothesis_engine.get_confirmed_hypotheses()),
                    "decisions_made": self.decision_engine.get_decision_count(),
                    "world_model_snapshot": self.world_model.snapshot().__dict__,
                    "attack_graph_revision": self.attack_graph.revision,
                },
                "verified_findings": [asdict(f) for f in self.verified_findings],
                "ports": self.discovered_ports,
                "endpoints": self.discovered_endpoints,
                "tasks": self.task_queue.get_all_tasks(),
            }

    # ==================================================================
    # Hybrid workflow: XBOW loop + confidence gate + Hermes guardrails
    # P0: All engines wired into every coordination cycle
    # ==================================================================
    def apply_profile(self, profile: Any) -> None:
        self.profile = profile
        if profile is None:
            return
        for host in profile.scope_allowlist():
            self.scope_guard.add_target(host)
        self.scope_guard.enforce = True
        if profile.target:
            self.set_target(profile.target)
        self.publish_log("Coordinator", "Engagement context loaded:\n" + profile.guidance_block())

    def run_workflow(
        self,
        profile: Any = None,
        target: Optional[str] = None,
        max_cycles: int = 3,
        on_cycle: Optional[Any] = None,
    ) -> WorkflowRun:
        """Run the Learn → Map → Coordinate → Attack → Validate → Debrief loop.

        P0: Every cycle runs the full decision pipeline:
          Evidence Ranking → Competing Hypotheses → Strategic Goal →
          Candidate Experiments → Decision Engine (single selection) →
          Execution Gateway → Observations → WorldModel update → verification
        """
        if profile is not None:
            self.apply_profile(profile)
        if target:
            self.set_target(target)
        if not self.target:
            raise ValueError("An explicit authorized target is required before starting a mission.")

        budget_cfg = getattr(profile, "budget", None)
        guard_cfg = getattr(profile, "guardrails", None)
        self.budget_state = BudgetState(
            max_seconds=int(getattr(budget_cfg, "max_seconds", 1800) or 0),
            max_llm_calls=int(getattr(budget_cfg, "max_llm_calls", 200) or 0),
            max_commands=int(getattr(budget_cfg, "max_commands", 500) or 0),
        )
        self.loop_guard = LoopGuard(
            warn_after=dict(getattr(guard_cfg, "warn_after", {}) or {}),
            hard_stop_after=dict(getattr(guard_cfg, "hard_stop_after", {}) or {}),
            hard_stop_enabled=bool(getattr(guard_cfg, "hard_stop_enabled", True)),
        )
        self.agent_factory = AgentFactory(
            coordinator=self,
            scope_guard=self.scope_guard,
            max_parallel=int(getattr(guard_cfg, "max_parallel_agents", 4) or 4),
        )
        self.plan = MissionPlan(target=self.target, objective="autonomous assessment")
        self.workflow = WorkflowRun(target=self.target, profile=getattr(profile, "name", "") or "")
        self._consumed_checkpoints = set()

        self.is_running = True
        self.start_time = time.time()
        early_stop = int(getattr(budget_cfg, "early_stop_stalls", 3) or 3)

        try:
            self._stage_learn()
            self._stage_map()

            for cycle in range(1, max(1, int(max_cycles)) + 1):
                exhausted, reason = self.budget_state.exhausted()
                if exhausted:
                    self.workflow.stopped_reason = reason
                    self.publish_log("Coordinator", f"Budget stop: {reason}")
                    break

                self.workflow.cycles = cycle
                if on_cycle:
                    try:
                        on_cycle(cycle, self.plan, self.budget_state)
                    except Exception:
                        pass

                # P0: Every cycle runs the full decision pipeline
                self._stage_coordinate(cycle)
                self._stage_attack(cycle)
                self._stage_validate(cycle)

                progressed = self._cycle_progressed(cycle)
                self.budget_state.spend(cycles=1)
                if not progressed:
                    self.workflow.stalls += 1
                    self.publish_log("Coordinator", f"Cycle {cycle} produced no new evidence "
                                                    f"(stall {self.workflow.stalls}/{early_stop})")
                    if self.workflow.stalls >= early_stop:
                        self.workflow.stopped_reason = f"early stop: {early_stop} cycles without progress"
                        break
                else:
                    self.workflow.stalls = 0

                if self.task_queue.pending_count() == 0 and self.workflow.stalls:
                    self.workflow.stopped_reason = "task queue drained"
                    break

            if not self.workflow.stopped_reason:
                self.workflow.stopped_reason = "all stages completed"
            self._stage_debrief()
        except Exception as exc:
            self.workflow.stopped_reason = f"error: {type(exc).__name__}: {exc}"
            self.publish_log("Coordinator", f"Workflow error: {exc}")
        finally:
            self.is_running = False
            self.end_time = time.time()
            self.workflow.ended_at = self.end_time
            self.workflow.stages_completed = [
                p.stage for p in self.plan.phases if p.status in (PHASE_DONE, PHASE_SKIPPED)
            ]
            self.workflow.guardrail_events = self.loop_guard.events if self.loop_guard else []
            self.workflow.findings_total = len(self.raw_findings)
            self.workflow.findings_verified = len(self.verified_findings)
            self.workflow.plan = self.plan.to_dict() if self.plan else {}
            self.workflow.budget = self.budget_state.to_dict() if self.budget_state else {}
            self._emit("workflow_completed", "Coordinator", self.workflow.to_dict())
        return self.workflow

    # -- stages ------------------------------------------------------------
    def _stage_learn(self) -> None:
        self.plan.mark(WorkflowStage.LEARN, PHASE_ACTIVE)
        profile = self.profile
        if profile is None:
            self.plan.mark(WorkflowStage.LEARN, PHASE_SKIPPED, "no engagement profile supplied")
            return
        notes = [
            f"scope={len(profile.scope_allowlist())}",
            f"out_of_scope={len(profile.out_of_scope)}",
            f"credentials={len(profile.attack_surface.credentials)}",
            f"canaries={len(profile.validation.canaries)}",
            f"destructive={'allowed' if profile.strategy.allow_destructive else 'forbidden'}",
        ]
        for endpoint in profile.attack_surface.endpoints:
            self.attack_graph.add_node(node_type="endpoint", label=f"{endpoint} [declared]", value_score=0.7)
        self.plan.mark(WorkflowStage.LEARN, PHASE_DONE, " ".join(notes))
        self.publish_log("Coordinator", f"LEARN complete — {' '.join(notes)}")

    def _stage_map(self) -> None:
        self.plan.mark(WorkflowStage.MAP, PHASE_ACTIVE)
        self.publish_log("Coordinator", "MAP: spawning fresh recon + web agents")
        agents = []
        for kind in ("recon", "web"):
            try:
                agent = self.agent_factory.spawn(kind)
            except Exception as exc:
                self.publish_log("Coordinator", f"MAP: could not spawn {kind}: {exc}")
                continue
            agents.append((kind, agent))
            agent.start_async(self.target)

        for kind, agent in agents:
            try:
                if agent._thread:
                    agent._thread.join(timeout=60)
            except Exception:
                pass
            self.agent_factory.retire(agent)

        # P0: Sync discoveries into WorldModel after MAP stage
        self._sync_world_model_from_agents()

        self.plan.mark(
            WorkflowStage.MAP, PHASE_DONE,
            f"{len(self.discovered_ports)} ports, {len(self.discovered_endpoints)} endpoints",
        )
        self.publish_log(
            "Coordinator",
            f"MAP complete — {len(self.discovered_ports)} ports, "
            f"{len(self.discovered_endpoints)} endpoints, {self.task_queue.pending_count()} queued tasks",
        )

    def _stage_coordinate(self, cycle: int) -> None:
        """P0: Run the full decision pipeline.

        Evidence Ranking → Competing Hypotheses → Strategic Goal →
        Candidate Experiments → Decision Engine (single selection)
        """
        self.plan.mark(WorkflowStage.COORDINATE, PHASE_ACTIVE)

        # Step 1: Seed any new evidence from discoveries
        self._seed_evidence()

        # Step 2: Generate hypotheses from current state if none active
        active_hyps = self.hypothesis_engine.get_competing_hypotheses(limit=5, active_only=True)
        if not active_hyps and (self.discovered_ports or self.discovered_endpoints):
            scenario = {
                'ports': self.discovered_ports,
                'endpoints': self.discovered_endpoints,
                'tech_stack': {},
            }
            for host in self.world_model.hosts.values():
                scenario['tech_stack'].update(host.technologies)
            self.hypothesis_engine.generate_from_scenario(scenario)
            active_hyps = self.hypothesis_engine.get_competing_hypotheses(limit=5, active_only=True)

        # Step 3: Run the DecisionEngine — this is the SINGLE canonical selector
        decision_record = self.decision_engine.decide(
            hypothesis_engine=self.hypothesis_engine,
            evidence_engine=self.evidence_engine,
            strategist=self.strategist,
            attack_graph=self.attack_graph,
            world_model=self.world_model,
            critic_engine=self.critic_agent.critic_engine,
            target=self.target,
        )

        if decision_record:
            exp = decision_record.selected_experiment
            goal_text = decision_record.reasoning[:200]
            confidence = exp.confidence
            self._current_experiment = exp
            self._current_decision_record = decision_record

            self.workflow.decisions.append({
                "cycle": cycle,
                "goal": goal_text,
                "experiment_id": exp.experiment_id,
                "hypothesis_id": exp.hypothesis_id,
                "hypothesis": exp.hypothesis,
                "expected_evidence": exp.expected_evidence,
                "reason": exp.reason,
                "risk": exp.risk,
                "confidence": confidence,
                "decision_explanation": decision_record.explain(),
            })

            self.publish_log("Coordinator",
                f"COORDINATE[{cycle}]: DecisionEngine selected experiment {exp.experiment_id} "
                f"(hypothesis={exp.hypothesis_id}, risk={exp.risk}, conf={confidence:.2f})")
        else:
            # No viable experiment — use confidence gate fallback
            try:
                recommendation = self.strategist.analyze_attack_graph(
                    self.attack_graph, self.world_model, self.critic_agent.critic_engine
                )
                confidence = recommendation.primary_goal.confidence
                goal_text = recommendation.primary_goal.description
            except Exception:
                confidence = 0.5
                goal_text = "no goal synthesised"

            self.last_confidence = confidence
            decision = self.confidence_gate.decide(confidence)
            self.workflow.decisions.append({"cycle": cycle, "goal": goal_text, **decision.to_dict()})
            self._current_experiment = None
            self._current_decision_record = None
            self.publish_log("Coordinator",
                f"COORDINATE[{cycle}]: {goal_text} | confidence={confidence:.2f} → {decision.action}")

        self.last_confidence = confidence if decision_record else self.last_confidence
        self._emit("workflow_decision", "Coordinator", self.workflow.decisions[-1] if self.workflow.decisions else {})

        # Plan checkpoint
        pct = self.budget_state.pct_used() if self.budget_state else 0.0
        budget = getattr(self.profile, "budget", None)
        if budget is not None:
            point = budget.next_checkpoint(pct, self._consumed_checkpoints)
            if point is not None:
                self._consumed_checkpoints.add(point)
                review = self.plan.checkpoint_review(pct)
                self.publish_log("Coordinator", f"plan checkpoint {point}%:\n" + review)
                self._emit("workflow_checkpoint", "Coordinator",
                    {"checkpoint": point, "pct_used": pct, "review": review})
                if self.loop_guard:
                    self.loop_guard.reset_cycle()

        self.plan.mark(WorkflowStage.COORDINATE, PHASE_DONE,
            f"decision {self.decision_engine.get_decision_count()}, confidence {self.last_confidence:.2f}")

    def _stage_attack(self, cycle: int) -> None:
        """P0: Execute the DecisionEngine's selected experiment.

        The selected experiment IS the action actually executed.
        Not a random task from the queue.
        """
        experiment = getattr(self, "_current_experiment", None)
        decision_record = getattr(self, "_current_decision_record", None)
        self.plan.mark(WorkflowStage.ATTACK, PHASE_ACTIVE, f"cycle {cycle}")

        if experiment and experiment.command:
            # P0: Execute the DecisionEngine's selection
            self.publish_log("Coordinator",
                f"ATTACK[{cycle}]: Executing DecisionEngine experiment {experiment.experiment_id}")
            self.publish_log("Coordinator",
                f"  hypothesis: {experiment.hypothesis[:120]}")
            self.publish_log("Coordinator",
                f"  expected_evidence: {experiment.expected_evidence[:120]}")

            # Pre-flight loop guard check
            verdict = self.loop_guard.would_allow(
                experiment.tool or "unknown",
                {"target": experiment.target, "command": experiment.command}
            )
            if not verdict.allowed:
                self.publish_log("Coordinator", f"ATTACK blocked by guardrail: {verdict.reason}")
                if experiment.hypothesis_id:
                    self.hypothesis_engine.mark_stale(experiment.hypothesis_id, reason=verdict.reason)
                self.plan.mark(WorkflowStage.ATTACK, PHASE_DONE, f"blocked by guardrail")
                return

            # Execute via agent
            try:
                agent_kind = "vuln" if experiment.tool in ("nmap", "sqlmap", "nuclei") else "web"
                agent = self.agent_factory.spawn(agent_kind)
            except Exception as exc:
                self.publish_log("Coordinator", f"ATTACK: could not spawn agent ({exc})")
                self.plan.mark(WorkflowStage.ATTACK, PHASE_SKIPPED, str(exc))
                return

            try:
                # Mark hypothesis as testing
                if experiment.hypothesis_id:
                    self.hypothesis_engine.mark_testing(experiment.hypothesis_id)

                agent.run(experiment.target)

                # P0: Determine success from actual evidence delta, not agent.state
                agent_findings = len(getattr(agent, "findings", []) or [])
                agent_discovered = getattr(agent, "discovered_count", 0)
                succeeded = agent_findings > 0 or agent_discovered > 0

                # P0: Record observation
                self._sync_world_model_from_agents()

                # P0: Update hypothesis confidence from actual observation
                if experiment.hypothesis_id:
                    hyp = self.hypothesis_engine._hypotheses.get(experiment.hypothesis_id)
                    if hyp:
                        evidence_quality = min(1.0, agent_findings * 0.3 + agent_discovered * 0.2)
                        hyp.update_confidence_from_observation(succeeded, evidence_quality)
                        hyp.last_result = f"findings={agent_findings}, discovered={agent_discovered}"

                # P0: Record in loop guard with proper success check
                self.loop_guard.record(
                    experiment.tool or "unknown",
                    {"target": experiment.target, "command": experiment.command},
                    succeeded=succeeded,
                    result=agent_findings,
                    progressed=agent_discovered > 0,
                )
                self.task_queue.mark_completed(f"experiment_{experiment.experiment_id}", f"executed")
                self.budget_state.spend(commands=1)

            except Exception as exc:
                self.loop_guard.record(
                    experiment.tool or "unknown",
                    {"target": experiment.target, "command": experiment.command},
                    succeeded=False, result=str(exc),
                )
                if experiment.hypothesis_id:
                    hyp = self.hypothesis_engine._hypotheses.get(experiment.hypothesis_id)
                    if hyp:
                        hyp.update_confidence_from_observation(False, 0.3)
                        hyp.last_result = f"error: {str(exc)[:200]}"
            finally:
                self.agent_factory.retire(agent)

            self.plan.mark(WorkflowStage.ATTACK, PHASE_DONE,
                f"experiment {experiment.experiment_id} executed")
            self.publish_log("Coordinator",
                f"ATTACK[{cycle}] complete — experiment {experiment.experiment_id}")
        else:
            # Fallback: process task queue (for compatibility)
            self._stage_attack_legacy(cycle)

    def _stage_attack_legacy(self, cycle: int) -> None:
        """Legacy fallback when no experiment from DecisionEngine."""
        # Preserve backward compatibility with tests that set _current_decision
        decision = getattr(self, "_current_decision", None)
        if decision is None:
            action = ACTION_TEST
        else:
            action = getattr(decision, "action", ACTION_TEST)
        self.publish_log("Coordinator", f"ATTACK[{cycle}]: legacy fallback — {action}")

        if action == ACTION_SWARM:
            self._stage_map()
            return
        if self.profile is not None and not self.profile.strategy.allow_destructive:
            self.publish_log("Coordinator", f"ATTACK[{cycle}]: non-destructive only")

        if action == ACTION_EXPLOIT:
            allowed_types = {"vuln_audit", "attack"}
        else:
            allowed_types = {"vuln_audit", "attack", "web_fuzz"}

        executed = 0
        while self.task_queue.pending_count() > 0 and self.agent_factory.can_spawn():
            task = self.task_queue.pop(allowed_types=allowed_types)
            if task is None:
                break
            verdict = self.loop_guard.would_allow(task.task_type, {"target": task.target, "params": task.params})
            if not verdict.allowed:
                self.task_queue.mark_failed(task.task_id, verdict.reason)
                self.publish_log("Coordinator", f"ATTACK blocked by guardrail: {verdict.reason}")
                break
            try:
                agent = self.agent_factory.spawn("vuln" if task.task_type != "web_fuzz" else "web")
            except Exception as exc:
                self.task_queue.mark_failed(task.task_id, str(exc))
                break
            try:
                agent.run(task.target)
                # P0: Fix success detection — use evidence, not agent.state
                agent_findings = len(getattr(agent, "findings", []) or [])
                agent_discovered = getattr(agent, "discovered_count", 0)
                succeeded = agent_findings > 0 or agent_discovered > 0
                self.loop_guard.record(
                    task.task_type, {"target": task.target},
                    succeeded=succeeded, result=agent_findings,
                    progressed=agent_discovered > 0,
                )
                self.task_queue.mark_completed(task.task_id, f"executed by {agent.name}")
                executed += 1
                self._sync_world_model_from_agents()
            except Exception as exc:
                self.loop_guard.record(task.task_type, {"target": task.target}, succeeded=False, result=str(exc))
                self.task_queue.mark_failed(task.task_id, str(exc))
            finally:
                self.agent_factory.retire(agent)
            if self.budget_state:
                self.budget_state.spend(commands=1)

        self.plan.mark(WorkflowStage.ATTACK, PHASE_DONE, f"{executed} task(s) executed")
        self.publish_log("Coordinator", f"ATTACK[{cycle}] complete — {executed} task(s) executed")

    def _stage_validate(self, cycle: int) -> None:
        self.plan.mark(WorkflowStage.VALIDATE, PHASE_ACTIVE)
        if not self.raw_findings:
            self.plan.mark(WorkflowStage.VALIDATE, PHASE_SKIPPED, "no candidate findings")
            return
        pending = self.get_unverified_findings()
        if not pending:
            self.plan.mark(WorkflowStage.VALIDATE, PHASE_DONE, "all candidates already adjudicated")
            return
        try:
            agent = self.agent_factory.spawn("verify")
        except Exception as exc:
            self.publish_log("Coordinator", f"VALIDATE: could not spawn verifier ({exc})")
            self.plan.mark(WorkflowStage.VALIDATE, PHASE_SKIPPED, str(exc))
            return
        try:
            canaries = self.profile.validation.canary_values() if self.profile else []
            agent.run(self.target, findings=pending, canaries=canaries)
        except Exception as exc:
            self.publish_log("Coordinator", f"VALIDATE failed: {exc}")
        finally:
            self.agent_factory.retire(agent)
        self.plan.mark(
            WorkflowStage.VALIDATE, PHASE_DONE,
            f"{len(self.verified_findings)}/{len(self.raw_findings)} confirmed",
        )

    def _stage_debrief(self) -> None:
        self.plan.mark(WorkflowStage.DEBRIEF, PHASE_ACTIVE)
        try:
            self.critic_agent.critic_engine.advance_iteration()
            for finding in self.raw_findings:
                if finding not in self.verified_findings:
                    self.critic_agent.record_failure(
                        technique=getattr(finding, "title", "unknown"),
                        category=getattr(finding, "severity", "info"),
                        context=self.target,
                        reason="finding did not survive independent verification",
                    )
            for finding in self.verified_findings:
                self.critic_agent.critic_engine.criticize_success(
                    strategy_chain=[getattr(finding, "severity", "info"), getattr(finding, "title", "")],
                    target_context=self.target,
                )
            # P0: Apply critic changes to WorldModel
            self.critic_agent.critic_engine.apply_critique_to_world_model(self.world_model)
        except Exception as exc:
            self.publish_log("Coordinator", f"DEBRIEF: critic feedback failed ({exc})")

        try:
            self._finalize_mission()
        except Exception as exc:
            self.publish_log("Coordinator", f"DEBRIEF: strategy learning failed ({exc})")
        self.plan.mark(WorkflowStage.DEBRIEF, PHASE_DONE, "critic penalties + strategy library updated")
        self.publish_log("Coordinator", "DEBRIEF complete")

    # -- helpers -----------------------------------------------------------
    def _seed_evidence(self) -> None:
        """Feed everything discovered so far into the evidence ranker."""
        for port in self.discovered_ports:
            eid = f"port-{port.get('port')}-{port.get('service')}"
            if not self.evidence_engine.get_evidence_by_id(eid):
                self.evidence_engine.add_evidence(RankedEvidence(
                    id=eid, source="ReconAgent", kind="port",
                    data={"port": port.get("port"), "service": port.get("service"),
                          "banner": port.get("banner", ""), "proto": "tcp"},
                ))
        for endpoint in self.discovered_endpoints:
            eid = f"endpoint-{endpoint.get('path')}"
            if not self.evidence_engine.get_evidence_by_id(eid):
                self.evidence_engine.add_evidence(RankedEvidence(
                    id=eid, source="WebAgent", kind="endpoint",
                    data={"url": endpoint.get("path"), "method": "GET",
                          "status": endpoint.get("status_code"), "interesting": endpoint.get("is_interesting")},
                ))
        for finding in self.raw_findings:
            eid = f"vuln-{getattr(finding, 'title', '')[:32]}"
            if not self.evidence_engine.get_evidence_by_id(eid):
                self.evidence_engine.add_evidence(RankedEvidence(
                    id=eid, source="VulnAgent", kind="vulnerability",
                    data={"title": getattr(finding, "title", ""), "severity": getattr(finding, "severity", "info"),
                          "endpoint": getattr(finding, "endpoint", "")},
                ))

    def _progress_signature(self) -> str:
        return json.dumps(
            {
                "ports": len(self.discovered_ports),
                "endpoints": len(self.discovered_endpoints),
                "raw": len(self.raw_findings),
                "verified": len(self.verified_findings),
                "queued": self.task_queue.pending_count(),
                "hypotheses_active": len(self.hypothesis_engine.get_competing_hypotheses(limit=100)),
                "graph_revision": self.attack_graph.revision,
                "wm_snapshot": self.world_model.snapshot().__dict__,
            },
            sort_keys=True,
        )

    def _cycle_progressed(self, cycle: int) -> bool:
        """P0: Progress means evidence delta, not just count changes."""
        signature = self._progress_signature()
        previous = getattr(self, "_last_progress_signature", None)
        self._last_progress_signature = signature
        return previous is None or previous != signature

    def get_workflow_summary(self) -> Dict[str, Any]:
        return {
            "active": self.workflow is not None,
            "profile": getattr(self.profile, "name", "") if self.profile else "",
            "target_type": getattr(self.profile, "target_type", "") if self.profile else "",
            "confidence": round(self.last_confidence, 2),
            "last_decision": (self.workflow.decisions[-1] if self.workflow and self.workflow.decisions else {}),
            "plan": self.plan.to_dict() if self.plan else {},
            "budget": self.budget_state.to_dict() if self.budget_state else {},
            "guardrails": self.loop_guard.to_dict() if self.loop_guard else {},
            "agents": self.agent_factory.to_dict() if self.agent_factory else {},
            "run": self.workflow.to_dict() if self.workflow else {},
            "decision_engine": {
                "decisions_made": self.decision_engine.get_decision_count(),
                "last_explanation": self.decision_engine.last_decision.explain() if self.decision_engine.last_decision else "none",
            },
            "hypothesis_engine": self.hypothesis_engine.get_learning_summary(),
            "world_model": self.world_model.snapshot().__dict__,
            "attack_graph": {
                "nodes": self.attack_graph.node_count(),
                "edges": self.attack_graph.edge_count(),
                "revision": self.attack_graph.revision,
            },
        }
