"""Design system for the X19 terminal application.

Every colour, glyph and severity/state mapping the UI uses lives here, so the
whole application can be re-skinned without touching a single screen.

Palettes are data, not code. Pick one with ``UI_THEME`` in the config file or
the ``X19_UI_THEME`` environment variable (environment wins). Unknown names
fall back to the default palette — nothing anywhere else may hard-code a hex
value or a style string.

Kept free of runtime imports so it can be used from anywhere (including the
report writer) without pulling the agent in.
"""
from __future__ import annotations

import os
from typing import Dict, Optional

from rich.theme import Theme

# ---------------------------------------------------------------------------
# Palettes — the only place raw colours are named.
# ---------------------------------------------------------------------------
#: ``name -> role -> rich colour``. Roles are semantic: a screen never asks for
#: "cyan", it asks for "accent". Adding a palette is a data change only.
PALETTES: Dict[str, Dict[str, str]] = {
    # Default: cool dark "midnight" look — teal accent on soft greys.
    "midnight": {
        "brand": "#67E8F9",        # headline brand colour
        "accent": "#22D3EE",       # interactive accent (links, keys, focus)
        "accent2": "#A78BFA",      # secondary accent (user/you colour)
        "ok": "#34D399",
        "warn": "#FBBF24",
        "err": "#F87171",
        "info": "#93C5FD",
        "text": "#E5E7EB",
        "muted": "#94A3B8",
        "faint": "#64748B",
        "border": "#475569",
        "border_dim": "#334155",
        "evidence": "#CBD5E1",
    },
    # Classic terminal green.
    "matrix": {
        "brand": "#4ADE80",
        "accent": "#22C55E",
        "accent2": "#FDE047",
        "ok": "#4ADE80",
        "warn": "#FACC15",
        "err": "#EF4444",
        "info": "#67E8F9",
        "text": "#DCFCE7",
        "muted": "#86EFAC",
        "faint": "#166534",
        "border": "#15803D",
        "border_dim": "#14532D",
        "evidence": "#BBF7D0",
    },
    # Warm amber-on-dark, for operators who dislike blue-ish themes.
    "ember": {
        "brand": "#FDBA74",
        "accent": "#FB923C",
        "accent2": "#F472B6",
        "ok": "#A3E635",
        "warn": "#FBBF24",
        "err": "#F87171",
        "info": "#FCA5A5",
        "text": "#F5F5F4",
        "muted": "#D6D3D1",
        "faint": "#78716C",
        "border": "#A8A29E",
        "border_dim": "#57534E",
        "evidence": "#E7E5E4",
    },
    # Colour-blind-safe / true monochrome.
    "mono": {
        "brand": "#FFFFFF",
        "accent": "#E5E7EB",
        "accent2": "#9CA3AF",
        "ok": "#F3F4F6",
        "warn": "#D1D5DB",
        "err": "#FFFFFF",
        "info": "#D1D5DB",
        "text": "#F9FAFB",
        "muted": "#9CA3AF",
        "faint": "#6B7280",
        "border": "#6B7280",
        "border_dim": "#4B5563",
        "evidence": "#E5E7EB",
    },
}

DEFAULT_PALETTE = "midnight"

#: Environment / config keys that select the palette (first match wins).
THEME_ENV_VARS = ("X19_UI_THEME",)
THEME_CONFIG_KEY = "UI_THEME"


def _resolve_palette_name() -> str:
    for var in THEME_ENV_VARS:
        value = os.getenv(var, "").strip().lower()
        if value:
            return value
    try:  # optional: config may not exist in stripped-down environments
        from config import load_config

        value = str(load_config().get(THEME_CONFIG_KEY, "") or "").strip().lower()
        if value:
            return value
    except Exception:
        pass
    return DEFAULT_PALETTE


def palette(name: Optional[str] = None) -> Dict[str, str]:
    """Return palette ``name`` (default: resolved from env/config)."""
    key = (name or _resolve_palette_name()).strip().lower()
    return PALETTES.get(key, PALETTES[DEFAULT_PALETTE])


def theme_name() -> str:
    """The palette actually in effect (may be the fallback)."""
    key = _resolve_palette_name().strip().lower()
    return key if key in PALETTES else DEFAULT_PALETTE


# ---------------------------------------------------------------------------
# Brand aliases (kept for backwards compatibility with earlier UI code)
# ---------------------------------------------------------------------------
def _brand_role(role: str) -> str:
    return palette()[role]


class _LazyColor:
    """Resolve a palette role lazily so env/config changes after import work."""

    def __init__(self, role: str):
        self._role = role

    def __str__(self) -> str:
        return _brand_role(self._role)


BRAND = _LazyColor("brand")        # type: ignore[assignment]
BRAND_DIM = _LazyColor("muted")    # type: ignore[assignment]
ACCENT = _LazyColor("accent")      # type: ignore[assignment]

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
    "cancelled": "yellow",
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
    "cancelled": "■",
    "pending": "…",
    "queued": "…",
}


def state_style(state: str) -> str:
    return STATE_STYLE.get(str(state or "").strip().lower(), "grey62")


def state_glyph(state: str) -> str:
    return STATE_GLYPH.get(str(state or "").strip().lower(), "?")


# ---------------------------------------------------------------------------
# Rich theme — semantic roles -> concrete styles
# ---------------------------------------------------------------------------
def build_theme(name: Optional[str] = None) -> Theme:
    """Compose the application theme from a palette. Data-driven."""
    p = palette(name)
    return Theme(
        {
            # -- semantic roles ------------------------------------------------
            "brand": f"bold {p['brand']}",
            "brand.dim": p["muted"],
            "accent": f"bold {p['accent']}",
            "accent2": f"bold {p['accent2']}",
            "ok": f"bold {p['ok']}",
            "warn": f"bold {p['warn']}",
            "err": f"bold {p['err']}",
            "info": f"bold {p['info']}",
            "key": f"bold {p['accent2']}",
            "text": p["text"],
            "muted": p["muted"],
            "faint": p["faint"],
            "border": p["border"],
            "border.dim": p["border_dim"],
            "evidence": p["evidence"],
            # -- derived compounds (rich Table columns cannot use
            # multi-word styles with theme words, so pre-composed roles exist)
            "text.strong": f"bold {p['text']}",
            "brand.strong": f"bold {p['brand']}",
            "accent.strong": f"bold {p['accent']}",
            "accent2.strong": f"bold {p['accent2']}",
            "ok.strong": f"bold {p['ok']}",
            "warn.strong": f"bold {p['warn']}",
            "err.strong": f"bold {p['err']}",
            "info.strong": f"bold {p['info']}",
            "muted.strong": f"bold {p['muted']}",
            # -- legacy role names (existing screens keep working) -------------
            "app.title": f"bold {p['brand']}",
            "app.dim": p["muted"],
            "app.accent": f"bold {p['accent']}",
            "app.ok": f"bold {p['ok']}",
            "app.warn": f"bold {p['warn']}",
            "app.err": f"bold {p['err']}",
            "app.info": f"bold {p['info']}",
            "app.key": f"bold {p['accent2']}",
            "panel.border": p["border"],
            "panel.border.dim": p["border_dim"],
            "panel.title": f"bold {p['brand']}",
            "metric.value": f"bold {p['text']}",
            "metric.label": p["muted"],
            "target": f"bold {p['text']}",
            "command": f"bold {p['accent2']}",
            # -- severity ------------------------------------------------------
            "sev.critical": SEVERITY_STYLE["critical"],
            "sev.high": SEVERITY_STYLE["high"],
            "sev.medium": SEVERITY_STYLE["medium"],
            "sev.low": SEVERITY_STYLE["low"],
            "sev.info": SEVERITY_STYLE["info"],
        }
    )


#: The active theme (evaluated at import; ``init_console`` re-resolves).
X19_THEME = build_theme()


def plain_ascii() -> bool:
    """True when the environment cannot render unicode box/glyph characters."""
    return os.getenv("X19_ASCII", "").strip().lower() in ("1", "true", "yes")
