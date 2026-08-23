"""
X19 Vulnerability & Misconfiguration Audit Agent.
Specialized in automated security testing, misconfiguration detection, and hypothesis validation.
"""

from __future__ import annotations
from typing import Optional, List, Any

from brain.agents.base_agent import BaseSwarmAgent
from execution.native_vuln import NativeVulnEngine, VulnerabilityFinding
from execution.scope_guard import ScopeGuard


class VulnAgent(BaseSwarmAgent):
    """Executes deterministic security audits and vulnerability checks on targets."""

    def __init__(self, coordinator: Optional[Any] = None, scope_guard: Optional[ScopeGuard] = None):
        super().__init__(name="VulnAgent", role="Vulnerability & Security Auditor", coordinator=coordinator)
        self.scope_guard = scope_guard or ScopeGuard(enforce=False)
        self.vuln_engine = NativeVulnEngine(scope_guard=self.scope_guard)
        self.findings: List[VulnerabilityFinding] = []

    def run(self, target: str, **kwargs) -> None:
        base_url = target if target.startswith(("http://", "https://")) else f"http://{target}"
        self.current_task = f"Auditing security vulnerabilities on {base_url}"
        self.progress_pct = 20
        self.log(f"Running deterministic security audit suite on {base_url}...")

        if self.is_stopped():
            return

        findings = self.vuln_engine.run_all_audits(base_url)
        self.findings = findings
        self.discovered_count = len(findings)
        self.progress_pct = 90

        self.log(f"Audit completed. Found {len(findings)} potential security finding(s).")
        for f in findings:
            self.log(f" [!] {f.severity.upper()}: {f.title} at {f.endpoint}")

            # Notify Coordinator / WorldModel
            if self.coordinator and hasattr(self.coordinator, "register_finding"):
                self.coordinator.register_finding(f)

        self.progress_pct = 100
        self.current_task = "Audit completed"
