"""
X19 Web Fuzzing & Surface Mapping Agent.
Specialized in endpoint discovery, directory fuzzing, and web route mapping.
Uses native in-process fuzzer engine with zero external CLI dependencies.
"""

from __future__ import annotations
from typing import Optional, List, Any

from brain.agents.base_agent import BaseSwarmAgent
from execution.native_fuzzer import NativeWebFuzzer, FuzzResult
from execution.scope_guard import ScopeGuard


class WebAgent(BaseSwarmAgent):
    """Maps web attack surfaces, routes, sensitive endpoints, and configuration files."""

    def __init__(self, coordinator: Optional[Any] = None, scope_guard: Optional[ScopeGuard] = None):
        super().__init__(name="WebAgent", role="Web Surface & Endpoint Fuzzer", coordinator=coordinator)
        self.scope_guard = scope_guard or ScopeGuard(enforce=False)
        self.fuzzer = NativeWebFuzzer(scope_guard=self.scope_guard)
        self.discovered_endpoints: List[FuzzResult] = []

    def run(self, target: str, **kwargs) -> None:
        base_url = target if target.startswith(("http://", "https://")) else f"http://{target}"
        self.current_task = f"Fuzzing web directories & endpoints on {base_url}"
        self.progress_pct = 15
        self.log(f"Starting native web surface fuzzing on {base_url}...")

        if self.is_stopped():
            return

        results = self.fuzzer.fuzz(base_url)
        self.discovered_endpoints = results
        self.discovered_count = len(results)
        self.progress_pct = 85

        self.log(f"Fuzzing complete. Found {len(results)} accessible endpoint(s).")
        for res in results:
            tag = " [INTERESTING]" if res.is_interesting else ""
            self.log(f" -> [{res.status_code}] /{res.path} ({res.content_length} bytes){tag}")

            # Notify Coordinator / WorldModel
            if self.coordinator and hasattr(self.coordinator, "register_endpoint"):
                self.coordinator.register_endpoint(
                    target=target,
                    path=f"/{res.path}",
                    status_code=res.status_code,
                    title=res.title,
                    is_interesting=res.is_interesting,
                    evidence=res.evidence_snippet
                )

        self.progress_pct = 100
        self.current_task = "Web fuzzing completed"
