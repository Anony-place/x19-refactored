"""Reusable renderables for the X19 terminal application.

Each helper returns a rich renderable so screens can be composed the same way
a web dashboard composes components: header bar → KPI strip → panels → footer.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from rich.console import Group
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from ui.theme import (
    severity_rank,
    state_glyph,
    state_style,
)

SEV_TAG = {
    "critical": "[sev.critical] CRITICAL [/]",
    "high": "[sev.high] HIGH [/]",
    "medium": "[sev.medium] MEDIUM [/]",
    "low": "[sev.low] LOW [/]",
    "info": "[sev.info] INFO [/]",
}


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------
def human_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return "—"
    seconds = max(0, int(seconds))
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours:d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def truncate(value: Any, width: int) -> str:
    text = str(value if value is not None else "")
    text = " ".join(text.split())
    if width <= 1:
        return text[:width]
    return text if len(text) <= width else text[: width - 1] + "…"


def sev_tag(severity: str) -> str:
    return SEV_TAG.get(str(severity or "").strip().lower(), SEV_TAG["info"])


def state_tag(state: str) -> str:
    low = str(state or "idle").strip().lower()
    return f"[{state_style(low)}]{state_glyph(low)} {escape(low.upper())}[/]"


# ---------------------------------------------------------------------------
# Chrome
# ---------------------------------------------------------------------------
def panel(
    title: str,
    body: Any,
    *,
    border_style: str = "cyan",
    subtitle: str = "",
    height: Optional[int] = None,
    padding: Tuple[int, int] = (0, 1),
) -> Panel:
    return Panel(
        body,
        title=f"[panel.title]{escape(title)}[/]",
        title_align="left",
        subtitle=f"[app.dim]{escape(subtitle)}[/]" if subtitle else None,
        subtitle_align="right",
        border_style=border_style,
        padding=padding,
        height=height,
    )


def header_bar(
    version: str,
    *,
    target: str = "",
    status: str = "standby",
    elapsed: Optional[float] = None,
    mode: str = "",
    provider: str = "",
    brand: str = "MISSION CONTROL",
) -> Table:
    """The always-present top bar: brand left, live status right."""
    left = Text()
    left.append("X19", style="bold bright_cyan")
    left.append(f" v{version}", style="grey50")
    left.append(f"  {brand}", style="bold white")

    right = Text()
    if target:
        right.append("target ", style="grey50")
        right.append(target, style="bold bright_white")
        right.append("   ", style="grey37")
    if mode:
        right.append("mode ", style="grey50")
        # Truncated like the provider: an unbounded model name forces the right
        # column wide and squeezes the brand rule into an ellipsis.
        right.append(truncate(mode, 24), style="bold yellow")
        right.append("   ", style="grey37")
    if provider:
        right.append("ai ", style="grey50")
        right.append(truncate(provider, 26), style="cyan")
        right.append("   ", style="grey37")
    right.append("● ", style=state_style(status))
    right.append(str(status).upper(), style=f"bold {state_style(status)}")
    right.append(f"   {human_duration(elapsed)}", style="grey62")

    grid = Table.grid(padding=(0, 1))
    grid.add_column(justify="left", ratio=1)
    grid.add_column(justify="right", no_wrap=True)
    grid.add_row(left, right)
    grid.add_row(
        Text("─" * 34, style="grey27"),
        Text("─" * 34, style="grey27", justify="right"),
    )
    return grid


def metric_strip(metrics: Sequence[Tuple[str, Any, str]]) -> Table:
    """KPI cards: ``(label, value, style)`` triples laid out horizontally."""
    grid = Table.grid(padding=(0, 2), expand=True)
    for _label, _value, _style in metrics:
        grid.add_column(justify="center", ratio=1)
    if not metrics:
        return grid

    labels = Table.grid(expand=True)
    values = Table.grid(expand=True)
    for _label, _value, _style in metrics:
        labels.add_column(justify="center", ratio=1)
        values.add_column(justify="center", ratio=1)

    labels.add_row(*[Text(label.upper(), style="metric.label") for label, _v, _s in metrics])
    values.add_row(*[Text(str(value), style=f"metric.value {style}") for _l, value, style in metrics])
    grid = Table.grid(expand=True)
    grid.add_column(ratio=1)
    grid.add_row(values)
    grid.add_row(labels)
    return grid


def progress_bar(pct: float, width: int = 18) -> Text:
    pct = max(0.0, min(100.0, float(pct or 0)))
    filled = int(round(width * pct / 100.0))
    colour = "bright_green" if pct >= 100 else ("cyan" if pct > 0 else "grey37")
    text = Text()
    text.append("▰" * filled, style=colour)
    text.append("▱" * (width - filled), style="grey30")
    text.append(f" {pct:5.1f}%", style="grey62")
    return text


def key_hint_bar(hints: Sequence[Tuple[str, str]]) -> Text:
    """Footer key legend, e.g. ``ctrl-c stop · r report · q quit``."""
    text = Text()
    for i, (key, label) in enumerate(hints):
        if i:
            text.append("   ·   ", style="grey37")
        text.append(key, style="app.key")
        text.append(f" {label}", style="grey62")
    return text


# ---------------------------------------------------------------------------
# Domain panels
# ---------------------------------------------------------------------------
def agents_table(agents: Sequence[Dict[str, Any]]) -> Table:
    table = Table(expand=True, box=None, pad_edge=False, show_header=False)
    table.add_column("state", width=2, no_wrap=True)
    table.add_column("name", ratio=2, no_wrap=True)
    table.add_column("progress", ratio=3, no_wrap=True)
    table.add_column("found", width=4, justify="right", no_wrap=True)

    if not agents:
        table.add_row("", "[app.dim]no agents registered[/]", "", "")
        return table

    for agent in agents:
        name = str(agent.get("name", "?"))
        state = str(agent.get("state", "idle"))
        table.add_row(
            Text(state_glyph(state), style=state_style(state)),
            Text(truncate(name, 12), style="bold bright_white"),
            progress_bar(float(agent.get("progress_pct", 0) or 0), width=10),
            Text(str(agent.get("discovered_count", 0)), style="cyan"),
        )
        task = str(agent.get("current_task") or agent.get("last_log") or "").strip()
        if task:
            table.add_row("", Text(truncate(task, 60), style="app.dim"), "", "")
    return table


def attack_graph_tree(graph: Dict[str, Any], max_nodes: int = 24) -> Tree:
    """Render the attack graph (D3 payload shape) as an indented tree."""
    nodes = {n.get("id"): n for n in graph.get("nodes", [])}
    edges = graph.get("edges", [])

    children: Dict[str, List[Dict[str, Any]]] = {}
    incoming: Dict[str, int] = {}
    for edge in edges:
        src, dst = edge.get("from"), edge.get("to")
        children.setdefault(src, []).append(edge)
        incoming[dst] = incoming.get(dst, 0) + 1

    roots = [nid for nid in nodes if not incoming.get(nid)]
    if not roots:
        roots = list(nodes)[:1]

    root = Tree("[bold bright_cyan]attack graph[/]")
    if not roots:
        root.add("[app.dim]no nodes yet — waiting for recon[/]")
        return root

    seen: set = set()
    budget = {"n": max_nodes}

    def label_for(node: Dict[str, Any]) -> Text:
        ntype = str(node.get("type", "")).lower()
        style = {
            "host": "bold bright_white",
            "service": "cyan",
            "endpoint": "magenta",
            "credential": "bold yellow",
            "finding": "bold red",
        }.get(ntype, "grey74")
        text = Text()
        text.append(f"{ntype[:4]:<4} ", style="grey50")
        text.append(truncate(node.get("label", "?"), 40), style=style)
        score = node.get("value_score")
        if score is not None:
            text.append(f"  ({float(score):.1f})", style="grey50")
        return text

    def walk(node_id: str, branch: Tree, depth: int = 0) -> None:
        if node_id in seen or budget["n"] <= 0 or depth > 6:
            return
        seen.add(node_id)
        budget["n"] -= 1
        node = nodes.get(node_id, {"label": node_id, "type": "?"})
        child_branch = branch.add(label_for(node))
        for edge in sorted(children.get(node_id, []), key=lambda e: str(e.get("label"))):
            target = edge.get("to")
            if target in seen:
                continue
            walk(target, child_branch, depth + 1)

    for root_id in roots:
        walk(root_id, root)
    return root


def ports_table(ports: Sequence[Dict[str, Any]], limit: int = 12) -> Table:
    table = Table(expand=True, box=None, pad_edge=False)
    table.add_column("port", style="bold bright_white", no_wrap=True, width=9)
    table.add_column("service", style="cyan", ratio=2)
    table.add_column("detail", style="grey62", ratio=4)
    for port in list(ports)[:limit]:
        banner_text = str(port.get("banner", "") or "")
        tls = port.get("tls_info") or {}
        detail = " ".join(x for x in (banner_text, tls.get("subject", "") if isinstance(tls, dict) else "") if x)
        table.add_row(
            f"{port.get('port', '?')}/{port.get('protocol', 'tcp')}",
            truncate(port.get("service", "unknown"), 18),
            truncate(detail, 46),
        )
    if not ports:
        table.add_row("[app.dim]—[/]", "[app.dim]no open ports recorded[/]", "")
    return table


def endpoints_table(endpoints: Sequence[Dict[str, Any]], limit: int = 12) -> Table:
    table = Table(expand=True, box=None, pad_edge=False)
    table.add_column("code", width=4, no_wrap=True)
    table.add_column("path", style="bright_white", ratio=3)
    table.add_column("title", style="grey62", ratio=2)
    for endpoint in list(endpoints)[:limit]:
        code = str(endpoint.get("status_code", ""))
        interesting = bool(endpoint.get("is_interesting"))
        table.add_row(
            Text(code, style="bold bright_green" if interesting else "grey62"),
            truncate(endpoint.get("path", ""), 40),
            truncate(endpoint.get("title", ""), 24),
        )
    if not endpoints:
        table.add_row("[app.dim]—[/]", "[app.dim]no endpoints discovered[/]", "")
    return table


def findings_table(findings: Sequence[Dict[str, Any]], limit: int = 20, detail: bool = True) -> Table:
    table = Table(expand=True, box=None, pad_edge=False, show_header=False)
    table.add_column("sev", width=10, no_wrap=True)
    table.add_column("finding", ratio=4)
    table.add_column("cvss", width=6, justify="right")

    ordered = sorted(findings, key=lambda f: severity_rank(f.get("severity", "info")))
    for finding in ordered[:limit]:
        severity = str(finding.get("severity", "info")).lower()
        table.add_row(
            sev_tag(severity),
            Text(truncate(finding.get("title") or finding.get("description", ""), 64), style="bold bright_white"),
            Text(str(finding.get("cvss_score", "—")), style="grey62"),
        )
        if detail:
            evidence = str(finding.get("evidence", "") or "").strip()
            if evidence:
                table.add_row("", Text(truncate(evidence, 96), style="evidence"), "")
    if not findings:
        table.add_row("", Text("no findings recorded", style="app.dim"), "")
    return table


def findings_by_severity(findings: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity", "info")).strip().lower() or "info"
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def task_queue_table(tasks: Sequence[Dict[str, Any]], limit: int = 10) -> Table:
    table = Table(expand=True, box=None, pad_edge=False)
    table.add_column("prio", width=4, justify="right", style="grey62")
    table.add_column("type", style="cyan", ratio=2)
    table.add_column("target", style="bright_white", ratio=3)
    table.add_column("status", ratio=2)
    for task in list(tasks)[:limit]:
        status = str(task.get("status", ""))
        table.add_row(
            str(task.get("priority", "")),
            truncate(task.get("task_type", ""), 16),
            truncate(task.get("target", ""), 34),
            Text(truncate(status, 14), style=state_style(status)),
        )
    if not tasks:
        table.add_row("", "[app.dim]queue empty[/]", "", "")
    return table


def event_stream(events: Sequence[Dict[str, Any]], limit: int = 14) -> Group:
    """The live log — the terminal equivalent of the SSE stream."""
    rows: List[Text] = []
    for event in list(events)[-limit:]:
        stamp = event.get("timestamp") or time.time()
        try:
            clock = time.strftime("%H:%M:%S", time.localtime(float(stamp)))
        except Exception:
            clock = "--:--:--"
        sender = str(event.get("sender", ""))[:14]
        payload = event.get("data") or {}
        message = payload.get("message") or payload.get("text") or ""
        if not message and isinstance(payload, dict):
            message = ", ".join(f"{k}={payload[k]}" for k in list(payload)[:3])
        etype = str(event.get("event_type", "log"))
        style = {
            "finding": "bold red",
            "port": "cyan",
            "endpoint": "magenta",
            "agent_status": "grey62",
            "mission_completed": "bold green",
        }.get(etype, "grey74")
        line = Text()
        line.append(f"{clock} ", style="grey42")
        line.append(f"{sender:<14} ", style="grey58")
        line.append(truncate(message, 90), style=style)
        rows.append(line)
    if not rows:
        rows.append(Text("waiting for events…", style="app.dim"))
    return Group(*rows)


def log_lines(lines: Sequence[Dict[str, Any]], limit: int = 14) -> Group:
    rows: List[Text] = []
    for entry in list(lines)[-limit:]:
        stamp = entry.get("timestamp") or time.time()
        try:
            clock = time.strftime("%H:%M:%S", time.localtime(float(stamp)))
        except Exception:
            clock = "--:--:--"
        line = Text()
        line.append(f"{clock} ", style="grey42")
        line.append(f"{str(entry.get('sender', ''))[:14]:<14} ", style="grey58")
        line.append(truncate(entry.get("message", ""), 90), style="grey74")
        rows.append(line)
    if not rows:
        rows.append(Text("no log output yet", style="app.dim"))
    return Group(*rows)


def kv_table(rows: Sequence[Tuple[str, Any]], value_style: str = "bright_white") -> Table:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="metric.label", no_wrap=True)
    table.add_column(style=value_style, overflow="fold")
    for key, value in rows:
        table.add_row(str(key), "" if value is None else str(value))
    return table


def sparkline(values: Sequence[float], width: int = 24) -> Text:
    """Tiny inline bar chart used for throughput / iteration history."""
    blocks = "▁▂▃▄▅▆▇█"
    if not values:
        return Text("─" * width, style="grey30")
    data = list(values)[-width:]
    if len(data) < width:
        data = [0.0] * (width - len(data)) + data
    peak = max(data) or 1.0
    text = Text()
    for value in data:
        index = int((float(value) / peak) * (len(blocks) - 1))
        text.append(blocks[index], style="cyan")
    return text
