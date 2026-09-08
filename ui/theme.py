"""Palette and styling for the X19 terminal application.

Kept free of runtime imports so it can be used from anywhere (including the
report writer) without pulling the agent in.
"""
from __future__ import annotations

from rich.theme import Theme

# ---------------------------------------------------------------------------
# Brand
# ---------------------------------------------------------------------------
BRAND = "cyan"
BRAND_DIM = "grey50"
ACCENT = "bright_cyan"

# ---------------------------------------------------------------------------
# Severity — shared by findings tables, the dashboard and exported reports
# ---------------------------------------------------------------------------
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold bright_red",
    "medium": "bold yellow",
    "low": "cyan",
    "info": "grey62",
}

SEVERITY_GLYPH = {
    "critical": "!!",
    "high": "!",
    "medium": "~",
    "low": "-",
    "info": "i",
}


def severity_style(severity: str) -> str:
    """Return the rich style name for a severity string (unknown -> info)."""
    return SEVERITY_STYLE.get(str(severity or "").strip().lower(), SEVERITY_STYLE["info"])


def severity_rank(severity: str) -> int:
    """Lower == more severe. Unknown severities sort last."""
    try:
        return SEVERITY_ORDER.index(str(severity or "").strip().lower())
    except ValueError:
        return len(SEVERITY_ORDER)


# ---------------------------------------------------------------------------
# Agent / mission state
# ---------------------------------------------------------------------------
STATE_STYLE = {
    "running": "bold green",
    "working": "bold green",
    "active": "bold green",
    "idle": "grey58",
    "done": "bright_green",
    "finished": "bright_green",
    "completed": "bright_green",
    "error": "bold red",
    "failed": "bold red",
    "stopped": "yellow",
    "paused": "yellow",
    "pending": "grey62",
    "queued": "grey62",
}

STATE_GLYPH = {
    "running": "▶",
    "working": "▶",
    "active": "●",
    "idle": "○",
    "done": "✔",
    "finished": "✔",
    "completed": "✔",
    "error": "✖",
    "failed": "✖",
    "stopped": "■",
    "paused": "‖",
    "pending": "…",
    "queued": "…",
}


def state_style(state: str) -> str:
    return STATE_STYLE.get(str(state or "").strip().lower(), "grey62")


def state_glyph(state: str) -> str:
    return STATE_GLYPH.get(str(state or "").strip().lower(), "?")


# ---------------------------------------------------------------------------
# Rich theme
# ---------------------------------------------------------------------------
X19_THEME = Theme(
    {
        "app.title": f"bold {BRAND}",
        "app.dim": "grey50",
        "app.accent": f"bold {ACCENT}",
        "app.ok": "bold green",
        "app.warn": "bold yellow",
        "app.err": "bold red",
        "app.info": "bold cyan",
        "app.key": "bold magenta",
        "panel.border": "cyan",
        "panel.border.dim": "grey37",
        "panel.title": f"bold {ACCENT}",
        "metric.value": "bold bright_white",
        "metric.label": "grey62",
        "target": "bold bright_white",
        "command": "bold bright_magenta",
        "evidence": "grey74",
        "sev.critical": SEVERITY_STYLE["critical"],
        "sev.high": SEVERITY_STYLE["high"],
        "sev.medium": SEVERITY_STYLE["medium"],
        "sev.low": SEVERITY_STYLE["low"],
        "sev.info": SEVERITY_STYLE["info"],
    }
)


def plain_ascii() -> bool:
    """True when the environment cannot render unicode box/glyph characters."""
    import os

    return os.getenv("X19_ASCII", "").strip().lower() in ("1", "true", "yes")
