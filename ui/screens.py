"""Rendered screens shared by the CLI subcommands and the interactive app.

Every function returns a rich renderable (or prints nothing and returns data in
``--json`` mode) so the same view is used whether it is reached from
``x19 providers`` or from ``/providers`` inside the app.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Sequence, Tuple

from rich.console import Group
from rich.table import Table
from rich.text import Text

from ui import widgets
from ui.theme import severity_rank, state_style

SECRET_HINTS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")


def mask_secret(value: Any) -> str:
    text = str(value or "")
    if not text:
        return ""
    if len(text) <= 8:
        return "•" * len(text)
    return f"{text[:4]}{'•' * 6}{text[-4:]}"


def is_secret_key(key: str) -> bool:
    upper = str(key).upper()
    return any(hint in upper for hint in SECRET_HINTS)


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------
def providers_screen(
    providers: Dict[str, Dict[str, Any]],
    *,
    current: str = "",
    chain: Sequence[Dict[str, str]] = (),
    priority: Sequence[str] = (),
) -> Table:
    table = Table(expand=True, title="[panel.title]AI providers[/]", title_justify="left")
    table.add_column("", width=3, justify="center")
    table.add_column("id", style="cyan", no_wrap=True)
    table.add_column("provider", style="bold bright_white")
    table.add_column("default model", style="grey74", ratio=2)
    table.add_column("key", width=12, justify="center")
    table.add_column("role", width=12)

    chain_map: Dict[str, str] = {}
    for index, entry in enumerate(chain or []):
        chain_map[str(entry.get("provider"))] = "primary" if index == 0 else f"fallback {index}"

    for pid, info in providers.items():
        key_env = info.get("api_key_env", "")
        has_key = bool(key_env and os.getenv(key_env)) or bool(info.get("configured"))
        if not info.get("needs_key"):
            key_state = Text("local", style="bold cyan")
        elif has_key:
            key_state = Text("set", style="bold green")
        else:
            key_state = Text("missing", style="grey50")
        role = chain_map.get(pid, "")
        marker = "●" if pid == current else " "
        table.add_row(
            Text(marker, style="bold bright_cyan"),
            pid,
            str(info.get("name", pid)),
            widgets.truncate(info.get("default_model", ""), 42),
            key_state,
            Text(role, style="bold yellow" if role == "primary" else "grey62"),
        )
    return table


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
def config_screen(config: Dict[str, Any], *, path: str = "", reveal: bool = False) -> Any:
    rows: List[Tuple[str, Any]] = []
    for key in sorted(config):
        value = config[key]
        if is_secret_key(key) and not reveal:
            value = mask_secret(value) if value else "(unset)"
        if isinstance(value, (dict, list)):
            value = f"{type(value).__name__}[{len(value)}]"
        rows.append((key, value))
    body = widgets.kv_table(rows) if rows else Text("no configuration saved yet", style="app.dim")
    return widgets.panel(
        "configuration",
        body,
        subtitle=path or "",
    )


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
def sessions_screen(sessions: Sequence[Dict[str, Any]]) -> Table:
    table = Table(expand=True, title="[panel.title]assessment sessions[/]", title_justify="left")
    table.add_column("session", style="bold bright_white", no_wrap=True)
    table.add_column("target", style="cyan", ratio=2)
    table.add_column("started", style="grey62")
    table.add_column("iters", justify="right")
    table.add_column("findings", justify="right")
    table.add_column("status")
    for session in sessions:
        status = str(session.get("status", ""))
        table.add_row(
            str(session.get("id", "?")),
            widgets.truncate(session.get("target", ""), 34),
            widgets.truncate(session.get("started", ""), 19),
            str(session.get("iterations", 0)),
            str(session.get("findings", 0)),
            Text(status, style=state_style(status)),
        )
    if not sessions:
        table.add_row("[app.dim]—[/]", "[app.dim]no sessions recorded[/]", "", "", "", "")
    return table


def session_detail_screen(data: Dict[str, Any], session_id: str = "") -> Any:
    findings = data.get("findings") or []
    commands = data.get("commands") or []
    head = widgets.panel(
        f"session {session_id or data.get('session_id', '?')}",
        widgets.kv_table(
            [
                ("target", data.get("target", "")),
                ("started", data.get("started", "")),
                ("status", data.get("status", "")),
                ("iterations", data.get("iterations", 0)),
                ("os", data.get("os_info", "") or "—"),
                ("ports", data.get("ports_discovered", "") or "—"),
            ]
        ),
    )
    finding_rows = widgets.panel("findings", widgets.findings_table(findings, limit=25))

    cmd_table = Table(expand=True, box=None, pad_edge=False)
    cmd_table.add_column("#", width=4, justify="right", style="grey50")
    cmd_table.add_column("command", style="command", ratio=4)
    cmd_table.add_column("rc", width=4, justify="right")
    for index, command in enumerate(commands[-25:], 1):
        cmd_table.add_row(
            str(index),
            widgets.truncate(command.get("cmd", ""), 80),
            str(command.get("rc", 0)),
        )
    if not commands:
        cmd_table.add_row("", "[app.dim]no commands recorded[/]", "")
    return Group(head, finding_rows, widgets.panel("command history", cmd_table, subtitle=f"{len(commands)} total"))


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
def findings_screen(findings: Sequence[Dict[str, Any]], *, target: str = "") -> Any:
    counts = widgets.findings_by_severity(findings)
    strip = widgets.metric_strip(
        [
            ("total", len(findings), "bright_white"),
            ("critical", counts.get("critical", 0), "bright_red"),
            ("high", counts.get("high", 0), "bright_red"),
            ("medium", counts.get("medium", 0), "yellow"),
            ("low", counts.get("low", 0), "cyan"),
            ("info", counts.get("info", 0), "grey62"),
        ]
    )
    ordered = sorted(findings, key=lambda f: severity_rank(f.get("severity", "info")))
    return Group(
        chrome(strip),
        widgets.panel("findings", widgets.findings_table(ordered, limit=200), subtitle=target),
    )


# ---------------------------------------------------------------------------
# Doctor
# ---------------------------------------------------------------------------
STATUS_STYLE = {
    "pass": ("bold green", "PASS"),
    "warn": ("bold yellow", "WARN"),
    "fail": ("bold red", "FAIL"),
    "skip": ("grey50", "SKIP"),
}


def doctor_screen(checks: Sequence[Dict[str, Any]], *, score: int = 100, detail: str = "") -> Any:
    table = Table(expand=True, box=None, pad_edge=False)
    table.add_column("", width=6, justify="center")
    table.add_column("check", style="bold bright_white", ratio=2)
    table.add_column("detail", style="grey70", ratio=3)
    for check in checks:
        status = str(check.get("status", "skip")).lower()
        style, label = STATUS_STYLE.get(status, STATUS_STYLE["skip"])
        table.add_row(
            Text(label, style=style),
            widgets.truncate(check.get("name", ""), 40),
            widgets.truncate(check.get("detail", ""), 90),
        )
    score_style = "bright_green" if score >= 90 else ("yellow" if score >= 60 else "bright_red")
    head = widgets.metric_strip([("health score", f"{score}/100", score_style), ("checks", len(checks), "grey74")])
    body = widgets.panel("self diagnostics", table)
    if detail:
        body = Group(body, Text(detail, style="app.dim"))
    return Group(chrome(head), body)


def tools_screen(rows: Sequence[Dict[str, Any]]) -> Table:
    table = Table(expand=True, title="[panel.title]toolchain[/]", title_justify="left")
    table.add_column("", width=3, justify="center")
    table.add_column("binary", style="bold bright_white", no_wrap=True)
    table.add_column("used by", style="cyan", ratio=2)
    table.add_column("state", width=12)
    for row in rows:
        available = bool(row.get("available"))
        table.add_row(
            Text("✔" if available else "○", style="bold green" if available else "grey42"),
            row.get("binary", ""),
            widgets.truncate(", ".join(row.get("presets", [])) or "—", 60),
            Text("installed" if available else "not found", style="bold green" if available else "grey50"),
        )
    return table


def chrome(renderable: Any) -> Any:
    from rich.padding import Padding

    return Padding(renderable, (0, 0, 1, 0))


# ---------------------------------------------------------------------------
# Help / usage
# ---------------------------------------------------------------------------
def help_screen(commands: Sequence[Dict[str, str]], *, version: str = "") -> Any:
    groups: Dict[str, List[Dict[str, str]]] = {}
    for command in commands:
        groups.setdefault(command.get("group", "commands"), []).append(command)

    parts: List[Any] = []
    for group_name, entries in groups.items():
        table = Table(expand=True, box=None, pad_edge=False, show_header=False, padding=(0, 2))
        table.add_column(style="bold bright_cyan", no_wrap=True, width=14)
        table.add_column(style="grey74", ratio=1)
        for entry in entries:
            table.add_row(entry["name"], entry["help"])
        parts.append(widgets.panel(group_name, table))
    return Group(*parts)


def env_screen(info: Dict[str, Any]) -> Any:
    return widgets.panel(
        "environment",
        widgets.kv_table(
            [
                ("x19", info.get("version", "")),
                ("release", info.get("release", "")),
                ("python", info.get("python", "")),
                ("platform", info.get("platform", "")),
                ("commit", info.get("git_commit") or "n/a"),
                ("branch", info.get("git_branch") or "n/a"),
                ("interface", info.get("interface", "cli")),
                ("web ui", "removed (4.0.0)" if not info.get("web_ui") else "present"),
            ]
        ),
    )
