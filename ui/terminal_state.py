"""Compact operator-facing state for the X19 terminal workspace.

The view model is derived from live agent state. It contains no synthetic
progress, findings, commands, or model output.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class TerminalMissionState:
    target: str = "—"
    provider: str = "—"
    status: str = "READY"
    health: str = "unknown"
    coverage: str = "0/0"
    findings: int = 0
    iteration: str = "—"
    activity: str = "idle"


def snapshot(app: Any) -> TerminalMissionState:
    agent = getattr(app, "agent", None)
    task = getattr(app, "_assessment_task", None)
    target = str(getattr(agent, "target", "") or "—")
    try:
        provider = app.ai.name() if getattr(app, "ai", None) else "—"
    except Exception:
        provider = "—"

    active = bool(task is not None and getattr(task, "active", False))
    status = "RUNNING" if active else ("WORKING" if getattr(agent, "running", False) else "READY")

    health = "unknown"
    coverage = "0/0"
    telemetry = getattr(agent, "telemetry", None)
    if telemetry is not None:
        health = str(getattr(getattr(telemetry, "health", None), "state", "unknown"))
        try:
            summary = telemetry.coverage.summary()
            coverage = f"{summary.get('covered', 0)}/{summary.get('total', 0)}"
        except Exception:
            pass

    findings = 0
    try:
        data = getattr(getattr(agent, "session", None), "data", {}) or {}
        findings = len(data.get("findings") or [])
    except Exception:
        pass

    iteration = "—"
    try:
        data = getattr(getattr(agent, "session", None), "data", {}) or {}
        used = int(data.get("iterations", 0) or 0)
        cap = int(data.get("max_iterations", 0) or 0)
        iteration = f"{used}/{cap}" if cap else str(used)
    except Exception:
        pass

    activity = "idle"
    try:
        events = getattr(telemetry, "events", []) or []
        if events:
            last = events[-1]
            activity = f"{last.phase}: {last.command[:72]}"
    except Exception:
        pass

    return TerminalMissionState(
        target=target,
        provider=str(provider),
        status=status,
        health=health,
        coverage=coverage,
        findings=findings,
        iteration=iteration,
        activity=activity,
    )
