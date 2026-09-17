"""Attack credit budgeting — XBOW pattern.

XBOW lets operators say "40 credits lightweight vs full pentest" and agents
prioritize. X19 previously had iter caps and token accounting but no per-chain
credit. This module provides a deterministic credit budget that the planner
and team can consume.

Borrow pattern, not payload: credits are a deterministic budget on how many
high-cost probes (chains, frontier escalations, browser/proxy sessions) the
run may spend before it must converge.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, Optional


def _env_int(name: str, default: int) -> int:
    try:
        raw = (os.getenv(name, "") or "").strip()
        if not raw:
            return default
        return max(1, min(200, int(raw)))
    except ValueError:
        return default


@dataclass
class AttackCreditBudget:
    """Deterministic budget for attack-credit consumption."""

    total: int = field(default_factory=lambda: _env_int("X19_ATTACK_CREDITS", 40))
    spent: int = 0
    # cost table — operator-visible, deterministic, not LLM-supplied
    costs: Dict[str, int] = field(default_factory=lambda: {
        "probe": 1,             # single shell probe
        "chain_step": 2,         # one exploit-chain step
        "chain_pov": 4,          # full chain PoV re-run (P1)
        "browser_session": 3,    # proxy+browser stateful session
        "frontier_escalation": 5, # frontier model call
        "whitebox_correlation": 2,
        "oob_oracle": 1,
    })
    history: list[tuple[str, int, str]] = field(default_factory=list)

    @property
    def remaining(self) -> int:
        return max(0, self.total - self.spent)

    @property
    def utilization(self) -> float:
        if self.total <= 0:
            return 1.0
        return min(1.0, self.spent / self.total)

    def can_spend(self, kind: str, n: int = 1) -> bool:
        cost = self.costs.get(kind, 1) * max(1, n)
        return (self.spent + cost) <= self.total

    def spend(self, kind: str, n: int = 1, reason: str = "") -> bool:
        """Try to spend. Return True if allowed and debited, False if would exceed."""
        if not self.can_spend(kind, n):
            return False
        cost = self.costs.get(kind, 1) * max(1, n)
        self.spent += cost
        self.history.append((kind, cost, reason[:80]))
        return True

    def spend_or_raise(self, kind: str, n: int = 1, reason: str = "") -> None:
        if not self.spend(kind, n, reason):
            raise BudgetExhausted(f"attack credits exhausted: need {self.costs.get(kind,1)*n} for {kind}, have {self.remaining}/{self.total} — {reason}")

    def status_line(self) -> str:
        return f"credits {self.spent}/{self.total} ({self.utilization:.0%})"

    def treemap_hint(self) -> Dict[str, int]:
        """Spend by kind, for UI treemap."""
        agg: Dict[str, int] = {}
        for kind, cost, _ in self.history:
            agg[kind] = agg.get(kind, 0) + cost
        return agg


class BudgetExhausted(RuntimeError):
    pass


# Global per-run budget — created by agent.py at mission start, injected where needed.
_default_budget: Optional[AttackCreditBudget] = None


def get_budget() -> AttackCreditBudget:
    global _default_budget
    if _default_budget is None:
        _default_budget = AttackCreditBudget()
    return _default_budget


def reset_budget(total: Optional[int] = None) -> AttackCreditBudget:
    global _default_budget
    if total is not None:
        _default_budget = AttackCreditBudget(total=total)
    else:
        _default_budget = AttackCreditBudget()
    return _default_budget
