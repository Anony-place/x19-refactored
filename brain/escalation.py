"""Frontier escalation: hard steps get a stronger model, with accounting.

The research audit (docs/AGENT_AUTONOMY_AUDIT.md §5) called for reasoning
escalation: confirmed-critical deep-dives and flailing streaks deserve a
bigger model than routine enumeration — the same way a human lead brings a
senior reviewer in only for the hard calls.

Design:
- **Dynamic chain**: ``X19_ESCALATE="provider/model,provider/model"`` names
  the escalation models. Empty (default) = escalation off; nothing is
  hardcoded because stronger models are account/key specific.
- **Hard-step detection** from live session state only: deep-dive on a
  critical/high focus finding, a high-impact open hypothesis, an empty-reply
  flail streak, or a no-progress streak. No fixed playbooks — signals come
  from what is happening.
- **Gate-respecting**: escalation to a critical-tier model during
  exploitation on an unauthorised engagement is refused via the existing
  ``brain.frontier_gate`` verdict (fails closed).
- **Cooldown**: at most one escalated decision per ``X19_ESCALATE_EVERY``
  decision cycles (default 4) so cost stays bounded.
- Backend construction is delegated to ``providers.build_backend`` (same
  one-shot rules as the failover chain; missing keys simply skip an entry).
"""

from __future__ import annotations

import os
from typing import Any, List, Tuple

from logging_utils import log

#: Live-state thresholds (process guarantees — tune here, not in the loop).
DEPTH_MIN = 2                  # exploitation steps into the focus finding
IMPACT_THRESHOLD = 0.8         # open hypothesis worth a stronger model
FLAIL_STREAK = 3               # consecutive empty/parse-failed AI replies
STUCK_STREAK = 3               # consecutive no-progress iterations


def escalation_chain() -> List[Tuple[str, str]]:
    """Parse X19_ESCALATE into (provider, model) pairs. [] = disabled."""
    raw = (os.getenv("X19_ESCALATE", "") or "").strip()
    if not raw:
        return []
    chain: List[Tuple[str, str]] = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry or "/" not in entry:
            continue
        provider, model = entry.split("/", 1)
        if provider.strip() and model.strip():
            chain.append((provider.strip(), model.strip()))
    return chain


def escalate_every() -> int:
    """One escalated decision per N decision cycles (min 1)."""
    try:
        return max(1, int((os.getenv("X19_ESCALATE_EVERY", "") or "4").strip()))
    except ValueError:
        return 4


def hard_reasons(agent: Any) -> List[str]:
    """Why this decision deserves a stronger model (live state only)."""
    reasons: List[str] = []
    focus = getattr(agent, "_current_focus_finding", None)
    depth = int(getattr(agent, "_exploit_depth", 0) or 0)
    if focus and depth >= DEPTH_MIN:
        reasons.append(f"deep-dive on '{str(focus)[:50]}' (depth {depth})")
    flail = int(getattr(agent, "_ai_empty_streak", 0) or 0)
    if flail >= FLAIL_STREAK:
        reasons.append(f"flailing: {flail} empty/failed replies")
    stuck = int(getattr(agent, "_no_progress_streak", 0) or 0)
    if stuck >= STUCK_STREAK:
        reasons.append(f"no progress for {stuck} iterations")
    try:
        for hyp in agent.hyp_engine.get_competing_hypotheses(limit=3, active_only=True):
            if float(getattr(hyp, "expected_impact", 0.0) or 0.0) >= IMPACT_THRESHOLD:
                reasons.append(f"high-impact hypothesis open: {hyp.title[:50]}")
                break
    except Exception:
        pass
    return reasons


class Escalator:
    """Decides whether the current decision call should use the chain."""

    def __init__(self):
        self.chain = escalation_chain()
        self.every = escalate_every()
        self._cycles_since = 0
        self._cache: dict = {}          # (provider, model) -> backend or None
        self.escalations = 0
        self.last_reason = ""

    def pick(self, agent: Any) -> Tuple[Any, str]:
        """Return (backend, reason). Falls back to the agent's own AI when
        escalation is off, cooled down, unauthorised, or unbuildable."""
        if not self.chain:
            return getattr(agent, "ai", None), ""
        self._cycles_since += 1
        if self._cycles_since < self.every:
            return getattr(agent, "ai", None), ""
        reasons = hard_reasons(agent)
        if not reasons:
            return getattr(agent, "ai", None), ""
        # Respect the critical-tier gate: the escalated call may serve an
        # exploitation deep-dive, so it is judged as the exploitation phase.
        phase = "exploitation" if getattr(agent, "_current_focus_finding", None) else ""
        from brain.frontier_gate import check_model_for_phase
        for provider, model in self.chain:
            verdict = check_model_for_phase(model, getattr(agent, "target_type", ""), phase)
            if not verdict.allowed:
                log(f"[ESCALATE] {provider}/{model} blocked by frontier gate: {verdict.reason}")
                continue
            backend = self._backend_for(provider, model)
            if backend is None:
                continue
            self._cycles_since = 0
            self.escalations += 1
            self.last_reason = reasons[0]
            return backend, f"{provider}/{model}: {reasons[0]}"
        return getattr(agent, "ai", None), ""

    def _backend_for(self, provider: str, model: str):
        """One-shot backend via providers.build_backend (cached, missing keys
        skip the entry)."""
        key = (provider, model)
        if key in self._cache:
            return self._cache[key]
        try:
            from providers import build_backend
            backend = build_backend(provider, model)
        except Exception as e:
            log(f"[ESCALATE] build {provider}/{model} failed: {e}")
            backend = None
        self._cache[key] = backend
        return backend
