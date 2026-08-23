"""
X19 Swarm Coordinator (Meta-Agent).
Coordinates parallel specialized agents, synchronizes findings with the World Model
and Attack Graph, streams live events, and ensures fast, deterministic mission execution.
"""

from __future__ import annotations
import json
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Callable

from brain.agents.recon_agent import ReconAgent
from brain.agents.web_agent import WebAgent
from brain.agents.vuln_agent import VulnAgent
from brain.agents.verifier_agent import VerifierAgent
from brain.agents.critic_agent import CriticAgent
from brain.attack_graph import AttackGraph, GraphNode, GraphEdge
from brain.evidence_ranking import EvidenceRankingEngine, RankedEvidence
from brain.strategist_engine import StrategistEngine
from brain.strategy_library import StrategyLibrary, TargetSignature
from execution.native_vuln import VulnerabilityFinding
from execution.scope_guard import ScopeGuard


@dataclass
class SwarmEvent:
    event_type: str  # "log", "agent_status", "finding", "port", "endpoint", "graph_update"
    sender: str
    data: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)


class SwarmCoordinator:
    """Master orchestrator for the X19 parallel cognitive agent swarm."""

    def __init__(self, target: str = "", scope_guard: Optional[ScopeGuard] = None):
        self.target = target
        self.scope_guard = scope_guard or ScopeGuard(allowed_targets={target} if target else set(), enforce=bool(target))
        
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

        # Cognitive Engines & State
        self.attack_graph = AttackGraph()
        self.evidence_engine = EvidenceRankingEngine()
        self.strategist = StrategistEngine()
        self.strategy_library = StrategyLibrary()
        
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

    def set_target(self, target: str) -> None:
        self.target = target
        self.scope_guard.add_target(target)
        self.scope_guard.enforce = True

    def subscribe_events(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Register an event listener for live UI updates."""
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
        payload = {
            "type": event_type,
            "sender": sender,
            "data": data,
            "timestamp": event.timestamp
        }
        for sub in list(self.subscribers):
            try:
                sub(payload)
            except Exception:
                pass

    def start_mission_pipeline(self, target: Optional[str] = None) -> threading.Thread:
        """Execute the coordinated multi-agent assessment pipeline asynchronously."""
        if target:
            self.set_target(target)
        
        self.is_running = True
        self.start_time = time.time()
        self.publish_log("Coordinator", f"🚀 Launching Parallel Swarm Mission on target: {self.target}")
        
        # Initialize target node in attack graph
        self.target_node = self.attack_graph.add_node(
            node_type="host",
            label=f"Target: {self.target}",
            value_score=1.0
        )

        t = threading.Thread(target=self._run_pipeline, daemon=True, name="Coordinator-Pipeline")
        t.start()
        return t

    def _run_pipeline(self) -> None:
        try:
            # Stage 1: Parallel Recon & Initial Web Crawling
            self.publish_log("Coordinator", "⚡ STAGE 1: Launching ReconAgent and WebAgent in parallel...")
            t_recon = self.recon_agent.start_async(self.target)
            t_web = self.web_agent.start_async(self.target)
            self.critic_agent.start_async(self.target)

            t_recon.join(timeout=45)
            t_web.join(timeout=45)

            # Stage 2: Security & Vulnerability Audits
            self.publish_log("Coordinator", "🔍 STAGE 2: Launching VulnAgent on discovered attack surface...")
            t_vuln = self.vuln_agent.start_async(self.target)
            t_vuln.join(timeout=60)

            # Stage 3: Deterministic PoC Verification (Zero False-Positive Gate)
            self.publish_log("Coordinator", "🛡️ STAGE 3: Launching VerifierAgent for PoC verification...")
            t_verif = self.verifier_agent.start_async(self.target, findings=self.raw_findings)
            t_verif.join(timeout=45)

            # Stage 4: Synthesis & Learning
            self._finalize_mission()

        except Exception as e:
            self.publish_log("Coordinator", f"❌ Mission error: {str(e)}")
        finally:
            self.is_running = False
            self.end_time = time.time()
            self.publish_log("Coordinator", f"🏁 Swarm mission finished in {self.end_time - self.start_time:.1f}s")
            self._emit("mission_completed", "Coordinator", self.get_summary())

    def stop_mission(self) -> None:
        """Emergency stop for all active agents in swarm."""
        self.publish_log("Coordinator", "🛑 Emergency stop triggered! Halting all agents.")
        for agent in self.agents:
            agent.stop()
        self.is_running = False

    def register_port(self, host: str, port: int, service: str, banner: str, tls_info: Dict[str, str]) -> None:
        with self._lock:
            port_data = {
                "host": host, "port": port, "service": service,
                "banner": banner, "tls_info": tls_info
            }
            self.discovered_ports.append(port_data)
            
            # Add to AttackGraph
            target_node = getattr(self, "target_node", None)
            if not target_node:
                target_node = self.attack_graph.add_node("host", f"Target: {host}", value_score=1.0)
                self.target_node = target_node

            port_node = self.attack_graph.add_node(
                node_type="service",
                label=f"{service}:{port}",
                value_score=0.6
            )
            self.attack_graph.add_edge(
                source_node=target_node.id,
                target_node=port_node.id,
                edge_type="runs"
            )

        self._emit("port_discovered", "ReconAgent", port_data)

    def register_endpoint(self, target: str, path: str, status_code: int, title: str, is_interesting: bool, evidence: str) -> None:
        with self._lock:
            ep_data = {
                "target": target, "path": path, "status_code": status_code,
                "title": title, "is_interesting": is_interesting, "evidence": evidence
            }
            self.discovered_endpoints.append(ep_data)

            # Add to AttackGraph
            target_node = getattr(self, "target_node", None)
            if not target_node:
                target_node = self.attack_graph.add_node("host", f"Target: {target}", value_score=1.0)
                self.target_node = target_node

            ep_node = self.attack_graph.add_node(
                node_type="endpoint",
                label=f"{path} [{status_code}]",
                value_score=0.85 if is_interesting else 0.4
            )
            self.attack_graph.add_edge(
                source_node=target_node.id,
                target_node=ep_node.id,
                edge_type="contains"
            )

        self._emit("endpoint_discovered", "WebAgent", ep_data)

    def register_finding(self, finding: VulnerabilityFinding) -> None:
        with self._lock:
            self.raw_findings.append(finding)
        self._emit("finding_detected", "VulnAgent", asdict(finding))

    def mark_finding_verified(self, finding: VulnerabilityFinding) -> None:
        with self._lock:
            if finding not in self.verified_findings:
                self.verified_findings.append(finding)
                
                # Add to AttackGraph as vulnerability node
                target_node = getattr(self, "target_node", None)
                if not target_node:
                    target_node = self.attack_graph.add_node("host", f"Target: {finding.target}", value_score=1.0)
                    self.target_node = target_node

                vuln_node = self.attack_graph.add_node(
                    node_type="vulnerability",
                    label=f"{finding.severity.upper()}: {finding.title}",
                    value_score=finding.cvss_score / 10.0
                )
                self.attack_graph.add_edge(
                    source_node=target_node.id,
                    target_node=vuln_node.id,
                    edge_type="vulnerable_to"
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

    def _finalize_mission(self) -> None:
        self.publish_log("Coordinator", "🧠 Learning from session outcomes & updating Strategy Library...")
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
        """Convert AttackGraph to D3/Vis.js format for modern UI rendering."""
        with self._lock:
            nodes = []
            for n in self.attack_graph._nodes.values():
                nodes.append({
                    "id": n.id,
                    "label": n.label,
                    "type": n.node_type,
                    "value_score": n.value_score
                })
            edges = []
            for e in self.attack_graph._edges.values():
                edges.append({
                    "from": e.source_node,
                    "to": e.target_node,
                    "label": e.edge_type
                })
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
                    "verified_findings": len(self.verified_findings)
                },
                "verified_findings": [asdict(f) for f in self.verified_findings],
                "ports": self.discovered_ports,
                "endpoints": self.discovered_endpoints
            }
