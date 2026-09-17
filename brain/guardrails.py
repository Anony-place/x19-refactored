"""Guardrails — modularized from agent.py god object.

`agent.py` is ~6900 lines with soft gates converted to advisories in place.
Roadmap says they belong in `brain/guardrails.py` that can be tested without
an X19 instance. This module extracts the advisory checks so agent.py can call
them and tests can own them.

No behavior change here — just extraction + testability.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

# --- Justification quality advisory (agent.py justification gate) ---
_JUSTIFICATION_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|https?://\S+|HTTP\s+\d{3}|open_ports|endpoints?|finding|evidence", re.I)

def justification_score(command: str, justification: str, session_excerpt: str = "") -> Tuple[int, int, str]:
    """Return (score, max, reason). Score counts how many justification signals appear."""
    max_score = 6
    score = 0
    signals = []
    if _JUSTIFICATION_RE.search(justification or ""):
        score += 2
        signals.append("session data referenced")
    else:
        signals.append("no real session data referenced")
    if (session_excerpt or "") and (session_excerpt[:40] in (justification or "") or justification.strip() in session_excerpt):
        score += 2
        signals.append("verbatim evidence")
    if len((justification or "").strip()) >= 40:
        score += 1
    if (command or "").strip():
        score += 1
    # clamp
    score = max(0, min(max_score, score))
    reason = "; ".join(signals) if signals else "weak justification"
    return score, max_score, reason

def is_justification_weak(score: int, max_score: int, threshold: int = 3) -> bool:
    return score < threshold


# --- Loop / saturation advisories ---
def saturation_advice(recent_commands: List[str], threshold: int = 3) -> str:
    if len(recent_commands) >= threshold and len(set(recent_commands[-threshold:])) == 1:
        return f"loop advisory: same command {threshold}× — pivot (recon-saturation) suggested"
    return ""

def duplicate_probe_advice(command: str, history: List[str]) -> str:
    if command in set(history or []):
        return "advisory: duplicate probe (same command seen) — consider dedup guard"
    return ""


# --- Evidence staleness ---
def stale_evidence_advice(evidence_ts: float | None, now: float, ttl: float = 300) -> str:
    if evidence_ts is None:
        return ""
    age = now - evidence_ts
    if age > ttl:
        return f"stale-evidence advisory: evidence {int(age)}s old (> {int(ttl)}s) — re-probe suggested"
    return ""


# --- Command risk advisory ---

_DESTRUCTIVE_MARKERS = re.compile(r"\brm\s+-rf\b|mkfs|shutdown|reboot|dd\s+if=.*of=/dev|:\(\)\{\s*:\|:&\s*;\}\s*:", re.I)

def destructive_command_advice(command: str) -> str:
    if _DESTRUCTIVE_MARKERS.search(command or ""):
        return "risk advisory: potentially destructive — blocked by policy (denylist)"
    return ""
