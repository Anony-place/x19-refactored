"""Independent, deterministic quality checks for planned commands.

This guard is intentionally separate from the planner. It does not authorize
commands; the execution policy remains authoritative. Its job is to expose
missing reasoning provenance before execution and make weak decisions visible
in the trajectory ledger.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DecisionGuardResult:
    ok: bool
    level: str
    reasons: tuple[str, ...]


def evaluate_request(request: Any) -> DecisionGuardResult:
    reasons = []
    command = str(getattr(request, "command", "") or "").strip()
    risk = str(getattr(request, "risk", "normal") or "normal").lower()
    reason = str(getattr(request, "reason", "") or "").strip()
    hypothesis = str(getattr(request, "hypothesis", "") or "").strip()
    expected = str(getattr(request, "expected_evidence", "") or "").strip()
    target = str(getattr(request, "target", "") or "").strip()

    if not command:
        reasons.append("empty command")
    if not target and risk in {"high", "critical"}:
        reasons.append("high-risk request has no explicit target")
    if risk in {"high", "critical"} and not reason:
        reasons.append("no decision reason")
        reasons.append("high-risk request has no decision reason")
    if risk in {"high", "critical"} and not hypothesis:
        reasons.append("no hypothesis")
        reasons.append("high-risk request has no hypothesis")
    if risk in {"high", "critical"} and not expected:
        reasons.append("no expected evidence")
        reasons.append("high-risk request has no expected evidence")

    if reasons:
        return DecisionGuardResult(False, "weak", tuple(reasons))
    if reason or hypothesis or expected:
        return DecisionGuardResult(True, "provenance-present", tuple())
    return DecisionGuardResult(True, "legacy-compatible", tuple())
