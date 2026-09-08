"""X19 terminal application.

This package is the *only* user interface X19 ships. The Flask web dashboard
was removed in 4.0.0; everything it could do is served here, in the terminal,
with the same layout vocabulary (header bar, panels, live stream, footer
key hints) so it reads like a real application rather than a pile of prints.

Modules
-------
theme       palette, severity styling, rich Theme
console     process-wide Console plus ok/warn/err helpers and JSON mode
widgets     banner, panels, tables, trees, progress, key hints
keys        non-blocking keyboard capture for the live dashboard
dashboard   MissionDashboard — live swarm mission control
app         ConsoleApp — the default interactive experience
"""
from __future__ import annotations

from ui.console import (
    get_console,
    init_console,
    is_json_mode,
    is_plain_mode,
    emit_json,
    emit_jsonl,
    ok,
    warn,
    err,
    info,
    step,
    fail,
    rule,
    banner,
    die,
    working,
)
from ui.theme import (
    SEVERITY_STYLE,
    SEVERITY_ORDER,
    severity_style,
    severity_rank,
    state_style,
    state_glyph,
    X19_THEME,
)

__all__ = [
    "get_console",
    "init_console",
    "is_json_mode",
    "is_plain_mode",
    "emit_json",
    "emit_jsonl",
    "ok",
    "warn",
    "err",
    "info",
    "step",
    "fail",
    "rule",
    "banner",
    "die",
    "working",
    "SEVERITY_STYLE",
    "SEVERITY_ORDER",
    "severity_style",
    "severity_rank",
    "state_style",
    "state_glyph",
    "X19_THEME",
]
