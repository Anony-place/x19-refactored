"""
X19 Metacognition & Critic Agent.
Monitors swarm execution, detects anti-loops, applies numerical penalties, and guides strategy.
"""

from __future__ import annotations
from typing import Optional, Dict, Any

from brain.agents.base_agent import BaseSwarmAgent
from brain.critic_engine import CriticEngine, TechniquePenalty


class CriticAgent(BaseSwarmAgent):
    """Metacognitive supervisor enforcing anti-loop rules and strategy adaptation."""

    def __init__(self, coordinator: Optional[Any] = None):
        super().__init__(name="CriticAgent", role="Metacognition & Strategy Critic", coordinator=coordinator)
        self.critic_engine = CriticEngine()
        self.iteration: int = 0

    def run(self, target: str, **kwargs) -> None:
        self.current_task = f"Supervising swarm operations on {target}"
        self.progress_pct = 50
        self.iteration += 1
        self.critic_engine.advance_iteration()
        self.log(f"Metacognitive cycle {self.iteration} active. Monitoring swarm strategy health.")
        self.progress_pct = 100
        self.current_task = "Supervision active"

    def record_failure(self, technique: str, category: str, context: str, reason: str) -> TechniquePenalty:
        penalty = self.critic_engine.criticize_failure(
            technique=technique,
            category=category,
            target_context=context,
            failure_reason=reason
        )
        self.log(f"Penalty issued for '{technique}': multiplier={penalty.penalty_value:.2f} (Reason: {reason})")
        return penalty

    def is_blocked(self, technique: str, context: str) -> bool:
        return self.critic_engine.is_blocked(technique, context)
