"""
X19 Recon Agent.
Specialized in port scanning, banner grabbing, TLS inspection, and service fingerprinting.
Uses native in-process socket engine.
"""

from __future__ import annotations
import time
from typing import Optional, List, Any

from brain.agents.base_agent import BaseSwarmAgent, AgentState
from execution.native_net import NativeNetScanner, PortResult
from execution.scope_guard import ScopeGuard


class ReconAgent(BaseSwarmAgent):
    """Discovers host state, open ports, and running service banners."""

    def __init__(self, coordinator: Optional[Any] = None, scope_guard: Optional[ScopeGuard] = None):
        super().__init__(name="ReconAgent", role="Network & Service Discovery", coordinator=coordinator)
        self.scope_guard = scope_guard or ScopeGuard(enforce=False)
        self.scanner = NativeNetScanner(scope_guard=self.scope_guard)
        self.open_ports: List[PortResult] = []

    def run(self, target: str, **kwargs) -> None:
        self.current_task = f"Scanning common ports on {target}"
        self.progress_pct = 10
        self.log(f"Initiating socket-level port discovery for {target}...")

        if self.is_stopped():
            return

        # Perform port discovery
        results = self.scanner.scan_target(target)
        self.open_ports = results
        self.discovered_count = len(results)
        self.progress_pct = 80

        self.log(f"Discovery complete. Found {len(results)} open port(s).")
        for p in results:
            self.log(f" -> Port {p.port}/tcp OPEN ({p.service}) [Banner: {p.banner[:50] or 'N/A'}]")
            
            # Feed into Coordinator / WorldModel
            if self.coordinator and hasattr(self.coordinator, "register_port"):
                self.coordinator.register_port(
                    host=target,
                    port=p.port,
                    service=p.service,
                    banner=p.banner,
                    tls_info=p.tls_info
                )

        self.progress_pct = 100
        self.current_task = "Recon completed"
