"""Rendered screens shared by the CLI subcommands and the interactive app.

Every function returns a rich renderable (or prints nothing and returns data in
``--json`` mode) so the same view is used whether it is reached from
``x19 providers`` or from ``/providers`` inside the app.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Sequence, Tuple

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


# ---------------------------------------------------------------------------
# Engagements
# ---------------------------------------------------------------------------
def engagement_list_screen(rows: Sequence[Dict[str, Any]], *, directory: str = "") -> Any:
    table = Table(expand=True, title="[panel.title]engagement profiles[/]", title_justify="left")
    table.add_column("profile", style="bold bright_cyan", no_wrap=True)
    table.add_column("target", style="bright_white", ratio=2)
    table.add_column("type", width=16)
    table.add_column("hosts", width=6, justify="right")
    table.add_column("context", ratio=2)
    table.add_column("updated", style="grey62", width=19)
    for row in rows:
        flags = []
        if row.get("has_canaries"):
            flags.append("canaries")
        if row.get("has_credentials"):
            flags.append("creds")
        table.add_row(
            str(row.get("name", "?")),
            widgets.truncate(row.get("target", ""), 30),
            Text(str(row.get("target_type", "auto")), style="bold yellow"),
            str(row.get("targets", 0)),
            widgets.truncate(", ".join(flags) or "—", 24),
            widgets.truncate(row.get("updated_at", ""), 19),
        )
    if not rows:
        table.add_row("[app.dim]—[/]", "[app.dim]no profiles — run: x19 setup engagement[/]", "", "", "", "")
    body = table
    if directory:
        body = Group(table, Text(directory, style="app.dim"))
    return body


def engagement_detail_screen(profile: Any, *, problems: Sequence[str] = ()) -> Any:
    """Render an engagement profile as the four XBOW guidance cards + budget."""
    surface = profile.attack_surface
    head = widgets.panel(
        f"engagement · {profile.name}",
        widgets.kv_table(
            [
                ("target", profile.target or "—"),
                ("in scope", ", ".join(profile.scope_allowlist()) or "—"),
                ("out of scope", ", ".join(profile.out_of_scope) or "—"),
                ("type", profile.target_type),
                ("rules", profile.rules_of_engagement or "—"),
                ("updated", profile.updated_at),
            ]
        ),
    )

    cards = Group(
        widgets.panel(
            "1 · attack surface",
            widgets.kv_table(
                [
                    ("api specs", len(surface.api_specs)),
                    ("docs", len(surface.docs)),
                    ("endpoints", len(surface.endpoints)),
                    ("source files", len(surface.source_files)),
                    ("credentials", len(surface.credentials)),
                    ("limit to listed", "yes" if surface.limit_to_listed else "no"),
                ]
            ),
        ),
        widgets.panel(
            "2 · priorities",
            widgets.kv_table(
                [
                    ("focus", ", ".join(profile.priorities.focus) or "—"),
                    ("deprioritize", ", ".join(profile.priorities.deprioritize) or "—"),
                    ("vuln classes", ", ".join(profile.priorities.vuln_classes) or "—"),
                    ("max findings", profile.priorities.max_findings or "unlimited"),
                ]
            ),
        ),
        widgets.panel(
            "3 · attack strategy",
            widgets.kv_table(
                [
                    ("payload formats", ", ".join(profile.strategy.payload_formats) or "—"),
                    ("known weaknesses", ", ".join(profile.strategy.known_weaknesses) or "—"),
                    ("destructive", "ALLOWED" if profile.strategy.allow_destructive else "forbidden"),
                    ("notes", profile.strategy.notes or "—"),
                ]
            ),
        ),
        widgets.panel(
            "4 · validation",
            widgets.kv_table(
                [
                    ("require poc", "yes" if profile.validation.require_poc else "no"),
                    ("min severity", profile.validation.min_severity),
                    ("canaries", len(profile.validation.canaries)),
                ]
            ),
        ),
    )

    budget = widgets.panel(
        "budget & guardrails",
        widgets.kv_table(
            [
                ("max seconds", profile.budget.max_seconds),
                ("max commands", profile.budget.max_commands),
                ("max llm calls", profile.budget.max_llm_calls),
                ("early stop stalls", profile.budget.early_stop_stalls),
                ("checkpoints", ", ".join(f"{c}%" for c in profile.budget.checkpoints)),
                ("hard stops", "on" if profile.guardrails.hard_stop_enabled else "off"),
                ("max parallel agents", profile.guardrails.max_parallel_agents),
            ]
        ),
    )

    parts: List[Any] = [head, cards, budget]
    if problems:
        rows = Table.grid(padding=(0, 2))
        rows.add_column(style="bold yellow", no_wrap=True)
        rows.add_column(style="grey74")
        for problem in problems:
            rows.add_row("!", widgets.truncate(problem, 96))
        parts.append(widgets.panel("validation warnings", rows, border_style="yellow"))
    return Group(*parts)


# ---------------------------------------------------------------------------
# Workflow (hybrid orchestration state)
# ---------------------------------------------------------------------------
PHASE_STYLE = {
    "pending": ("grey50", "·"),
    "active": ("bold bright_cyan", "▶"),
    "done": ("bold bright_green", "✔"),
    "skipped": ("grey46", "↷"),
}

CONFIDENCE_STYLE = {
    "exploit": "bold bright_red",
    "test_hypothesis": "bold yellow",
    "pivot": "cyan",
    "deploy_swarm": "bold magenta",
}


def workflow_panel(summary: Dict[str, Any]) -> Any:
    """Plan phases + confidence decision + budget burn for the dashboard."""
    plan = summary.get("plan") or {}
    phases = plan.get("phases") or []

    table = Table.grid(padding=(0, 2))
    table.add_column(width=2, no_wrap=True)
    table.add_column(width=12, no_wrap=True)
    table.add_column(ratio=1)
    for phase in phases:
        status = str(phase.get("status", "pending"))
        style, glyph = PHASE_STYLE.get(status, PHASE_STYLE["pending"])
        notes = phase.get("notes") or []
        table.add_row(
            Text(glyph, style=style),
            Text(str(phase.get("stage", "")), style=style),
            Text(widgets.truncate(notes[-1] if notes else phase.get("goal", ""), 70), style="grey66"),
        )
    if not phases:
        table.add_row("", Text("no plan", style="app.dim"), "")
    plan_panel = widgets.panel(
        "mission plan",
        table,
        subtitle=f"{plan.get('pct_complete', 0)}% complete",
    )

    decision = summary.get("last_decision") or {}
    action = str(decision.get("action", "") or "—")
    confidence = summary.get("confidence", 0.0)
    budget = summary.get("budget") or {}
    guardrails = summary.get("guardrails") or {}
    agents = summary.get("agents") or {}
    events = guardrails.get("events") or []

    state = widgets.panel(
        "coordinator",
        widgets.kv_table(
            [
                ("profile", summary.get("profile") or "—"),
                ("engagement type", summary.get("target_type") or "—"),
                ("confidence", f"{float(confidence):.2f}"),
                ("decision", action.replace("_", " ")),
                ("goal", widgets.truncate(decision.get("goal", "—"), 60)),
                ("budget used", f"{budget.get('pct_used', 0)}%"),
                ("cycles", budget.get("cycles", 0)),
                ("commands", f"{budget.get('commands', 0)} / {budget.get('limits', {}).get('max_commands', '∞')}"),
                ("agents live", f"{agents.get('active', 0)} / {agents.get('max_parallel', 0)}"),
                ("agents retired", len(agents.get("retired") or [])),
                ("guardrail events", len(events)),
            ]
        ),
    )

    event_rows: List[Text] = []
    for event in events[-6:]:
        line = Text()
        level = str(event.get("level", ""))
        line.append(f"{level.upper():<5} ", style="bold yellow" if level == "warn" else "bold red")
        line.append(f"{str(event.get('guardrail', '')):<24} ", style="grey62")
        line.append(widgets.truncate(event.get("reason", ""), 60), style="grey74")
        event_rows.append(line)
    if not event_rows:
        event_rows.append(Text("no guardrail events", style="app.dim"))

    return Group(plan_panel, state, widgets.panel("guardrails", Group(*event_rows)))


def decision_table(decisions: Sequence[Dict[str, Any]]) -> Table:
    table = Table(expand=True, box=None, pad_edge=False)
    table.add_column("cycle", width=6, justify="right", style="grey50")
    table.add_column("confidence", width=11, justify="right")
    table.add_column("action", width=16)
    table.add_column("goal", ratio=1)
    for decision in decisions:
        action = str(decision.get("action", ""))
        table.add_row(
            str(decision.get("cycle", "")),
            Text(f"{float(decision.get('confidence', 0)):.2f}", style="bold bright_white"),
            Text(action.replace("_", " "), style=CONFIDENCE_STYLE.get(action, "grey74")),
            widgets.truncate(decision.get("goal", ""), 60),
        )
    if not decisions:
        table.add_row("", "", "", "[app.dim]no coordinator decisions yet[/]")
    return table


# ---------------------------------------------------------------------------
# Workspace home
# ---------------------------------------------------------------------------
GROUP_LABEL = {
    "assessment": "assessment",
    "interactive": "interactive",
    "configuration": "configuration",
    "operations": "operations",
}
GROUP_ORDER = ("assessment", "interactive", "configuration", "operations")


def _two_column(left: Any, right: Any) -> Any:
    grid = Table.grid(expand=True, padding=(0, 1))
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_row(left, right)
    return grid


def _status_row(label: str, value: Any, style: str = "bright_white") -> Tuple[str, Any]:
    return (f"[app.dim]{label}[/]", f"[{style}]{value}[/]")


def function_index(commands: Sequence[Dict[str, str]]) -> Table:
    """Every X19 function, grouped, with its one-line purpose."""
    table = Table(expand=True, box=None, pad_edge=False, show_header=False)
    table.add_column(width=18, style="app.accent", no_wrap=True)
    table.add_column(width=16, style="bold bright_white", no_wrap=True)
    table.add_column(ratio=1, style="grey70")

    grouped: Dict[str, List[Dict[str, str]]] = {}
    for row in commands:
        grouped.setdefault(str(row.get("group", "operations")), []).append(row)

    for group in GROUP_ORDER:
        rows = grouped.pop(group, None)
        if not rows:
            continue
        first = True
        for row in rows:
            table.add_row(
                f"[app.dim]{GROUP_LABEL.get(group, group)}[/]" if first else "",
                str(row.get("name", "")),
                str(row.get("help", "")),
            )
            first = False
    for group, rows in grouped.items():  # anything ungrouped still shows up
        for row in rows:
            table.add_row(f"[app.dim]{group}[/]", str(row.get("name", "")), str(row.get("help", "")))
    return table


def next_actions_panel(actions: Sequence[Tuple[str, str]]) -> Any:
    """Contextual "do this next" list: ``(command, why)``."""
    if not actions:
        return Text("nothing outstanding — every subsystem is configured.", style="app.ok")
    body = Table(expand=True, box=None, pad_edge=False, show_header=False)
    body.add_column(width=3, no_wrap=True)
    body.add_column(width=44, no_wrap=True)
    body.add_column(ratio=1, style="grey62")
    for index, (command, why) in enumerate(actions, 1):
        body.add_row(f"[app.dim]{index}[/]", f"[app.key]{command}[/]", why)
    return body


def workspace_screen(
    *,
    version: str = "",
    provider: Optional[Dict[str, Any]] = None,
    toolchain: Optional[Dict[str, Any]] = None,
    engagements: Sequence[Dict[str, Any]] = (),
    sessions: Sequence[Dict[str, Any]] = (),
    findings: Sequence[Dict[str, Any]] = (),
    commands: Sequence[Dict[str, str]] = (),
    next_actions: Sequence[Tuple[str, str]] = (),
    health: Optional[Dict[str, Any]] = None,
    store_dir: str = "",
    sessions_dir: str = "",
) -> Any:
    """The X19 landing view: status, state and every function on one screen."""
    provider = provider or {}
    toolchain = toolchain or {}
    health = health or {}

    blocks: List[Any] = []
    # No `mode` here: the model is shown in the ai-chain panel, and putting it in
    # the header too forces the right cell wider than half the terminal, which
    # squeezes the brand rule into an ellipsis.
    blocks.append(widgets.header_bar(
        version,
        status="ready",
        brand="WORKSPACE",
        provider=str(provider.get("primary") or ""),
    ))

    chain = list(provider.get("chain") or [])
    score = health.get("score")
    blocks.append(widgets.metric_strip([
        ("AI chain", f"{len(chain)} live" if chain else "none", "app.ok" if chain else "app.err"),
        (
            "tools",
            f"{toolchain.get('installed', 0)}/{toolchain.get('total', 0)}",
            "app.ok" if toolchain.get("installed") else "app.warn",
        ),
        ("engagements", len(engagements), "app.info" if engagements else "app.warn"),
        ("sessions", len(sessions), "app.info" if sessions else "app.dim"),
        (
            "findings",
            len(findings),
            "app.warn" if findings else "app.dim",
        ),
        (
            "health",
            f"{score}/100" if isinstance(score, int) else "n/a",
            "app.ok" if isinstance(score, int) and score >= 90 else "app.warn",
        ),
    ]))

    # -- system + AI -------------------------------------------------------
    left_rows = [
        _status_row("version", f"X19 {version}"),
        _status_row("interface", "terminal workspace"),
        _status_row("engagements", store_dir or "n/a"),
        _status_row("sessions", sessions_dir or "n/a"),
    ]
    checks = health.get("checks") or []
    failed = [c for c in checks if str(c.get("status", "")).lower() not in ("pass", "ok")]
    left_rows.append(_status_row(
        "diagnostics",
        f"{len(checks) - len(failed)}/{len(checks)} checks passing" if checks else "not run",
        "app.ok" if checks and not failed else "app.warn",
    ))

    if chain:
        chain_text = " [app.dim]→[/] ".join(f"[app.ok]{p}[/]" for p in chain[:4])
        if len(chain) > 4:
            chain_text += f" [app.dim]…(+{len(chain) - 4})[/]"
    else:
        chain_text = "[app.err]no provider key configured[/]"
    right_rows = [
        _status_row("chain", chain_text),
        _status_row("primary", provider.get("primary") or "unset",
                    "app.ok" if chain else "app.err"),
        _status_row("model", provider.get("model") or "provider default"),
        _status_row("local ollama", "available" if provider.get("ollama") else "not installed",
                    "app.ok" if provider.get("ollama") else "app.dim"),
    ]
    blocks.append(_two_column(
        widgets.panel("system", widgets.kv_table(left_rows)),
        widgets.panel("ai chain", widgets.kv_table(right_rows)),
    ))

    # -- engagements + toolchain ------------------------------------------
    if engagements:
        eng_table = Table(expand=True, box=None, pad_edge=False, show_header=False)
        eng_table.add_column(style="bold bright_white", no_wrap=True)
        eng_table.add_column(style="grey70", no_wrap=True)
        eng_table.add_column(style="app.info", no_wrap=True, justify="right")
        eng_table.add_column(style="app.warn", no_wrap=True, justify="right")
        for row in engagements[:5]:
            eng_table.add_row(
                str(row.get("name", "")),
                str(row.get("target", "")) or "—",
                str(row.get("target_type", "")) or "—",
                "canary" if row.get("has_canaries") else "",
            )
        if len(engagements) > 5:
            eng_table.add_row(f"[app.dim]+{len(engagements) - 5} more[/]", "", "", "")
        engagement_body: Any = eng_table
    else:
        engagement_body = Text(
            "no engagement profile yet\nx19 engagement new <name> -t <target> --target-type authorized",
            style="app.warn",
        )

    preferred_missing = toolchain.get("preferred_missing") or []
    tool_rows = [
        _status_row("installed", f"{toolchain.get('installed', 0)} / {toolchain.get('total', 0)}"),
        _status_row(
            "preferred",
            f"{toolchain.get('preferred_installed', 0)} / {toolchain.get('preferred_total', 0)}",
            "app.ok" if not preferred_missing else "app.warn",
        ),
    ]
    if preferred_missing:
        tool_rows.append(_status_row(
            "missing", ", ".join(preferred_missing[:6])
            + (f" +{len(preferred_missing) - 6}" if len(preferred_missing) > 6 else ""),
            "app.warn",
        ))
    tool_rows.append(_status_row(
        "coverage",
        widgets.progress_bar(
            100.0 * toolchain.get("installed", 0) / max(1, int(toolchain.get("total", 0) or 1))
        ),
    ))
    blocks.append(_two_column(
        widgets.panel("engagements", engagement_body),
        widgets.panel("toolchain", widgets.kv_table(tool_rows)),
    ))

    # -- recent activity ---------------------------------------------------
    if sessions:
        blocks.append(widgets.panel("recent missions", sessions_screen(sessions[:5])))
    if findings:
        blocks.append(widgets.panel(
            "latest findings",
            widgets.findings_table(findings[:6]),
            subtitle=f"{len(findings)} recorded",
        ))

    # -- functions + next actions -----------------------------------------
    blocks.append(widgets.panel(
        "functions", function_index(commands), subtitle="x19 <function> --help",
    ))
    blocks.append(widgets.panel("next actions", next_actions_panel(next_actions)))
    blocks.append(widgets.key_hint_bar([
        ("x19 dash -t <target> --engagement <name>", "start an assessment"),
        ("x19 chat", "interactive console"),
        ("x19 -h", "all options"),
    ]))
    return Group(*blocks)
