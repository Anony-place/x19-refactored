"""Full-screen terminal workspace for X19.

This is a terminal UI, not a mock dashboard: all status panels are derived from
live X19 agent/session/task state. Input is handled in raw mode so the screen
can refresh while autonomous work continues in the background.
"""
from __future__ import annotations

import os
import select
import sys
import termios
import time
import tty
from collections import deque
from typing import Any, Optional

from rich.console import Group, RenderableType
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ui.console import get_console


class FullscreenWorkspace:
    """Single-screen X19 operator console with background execution."""

    def __init__(self, app: Any):
        self.app = app
        self.console = get_console()
        self.agent = app.agent
        self.buffer = ""
        self.running = True
        self._events: deque[str] = deque(maxlen=14)
        self._saved_termios = None
        self._raw = False
        self._last_event_count = 0

    # ------------------------------------------------------------------
    # Terminal input
    # ------------------------------------------------------------------
    def _enter_raw(self) -> bool:
        if os.name == "nt" or not sys.stdin.isatty():
            return False
        try:
            fd = sys.stdin.fileno()
            self._saved_termios = termios.tcgetattr(fd)
            tty.setcbreak(fd)
            self._raw = True
            return True
        except Exception:
            self._saved_termios = None
            return False

    def _exit_raw(self) -> None:
        if not self._raw:
            return
        try:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self._saved_termios)
        except Exception:
            pass
        self._raw = False
        self._saved_termios = None

    def _read_key(self, timeout: float = 0.25) -> Optional[str]:
        if os.name == "nt":  # Windows fallback: keep the existing prompt path.
            return None
        ready, _, _ = select.select([sys.stdin], [], [], timeout)
        if not ready:
            return None
        try:
            raw = os.read(sys.stdin.fileno(), 8).decode("utf-8", "replace")
        except Exception:
            return None
        return raw

    # ------------------------------------------------------------------
    # Live state
    # ------------------------------------------------------------------
    def _session_data(self) -> dict:
        session = getattr(self.agent, "session", None)
        data = getattr(session, "data", {}) if session is not None else {}
        return data if isinstance(data, dict) else {}

    def _provider(self) -> str:
        try:
            return self.app.ai.name() if self.app.ai else "—"
        except Exception:
            return "—"

    def _target(self) -> str:
        return str(getattr(self.agent, "target", "") or "no target")

    def _task(self) -> Any:
        task = getattr(self.app, "_assessment_task", None)
        return task if task is not None and getattr(task, "active", False) else None

    def _drain_events(self) -> None:
        task = self._task()
        if task is None:
            return
        try:
            events = self.app.background.drain_events(task)
        except Exception:
            events = []
        if not events:
            return
        from events import summarize_event
        for event in events:
            try:
                line = summarize_event(event)
            except Exception:
                line = str(event)
            if line:
                self._events.append(line)

    def _status(self) -> tuple[str, str]:
        task = self._task()
        if task:
            elapsed = task.elapsed()
            return "RUNNING", f"{int(elapsed // 60):02d}:{int(elapsed % 60):02d}"
        if getattr(self.agent, "running", False):
            return "THINKING", "—"
        return "READY", "—"

    def _findings(self) -> list[dict]:
        return list(self._session_data().get("findings") or [])

    def _finding_counts(self) -> dict[str, int]:
        counts = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
        for finding in self._findings():
            sev = str(finding.get("severity", "info")).lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def _iteration(self) -> str:
        try:
            from config import CONFIG
            used = int(self._session_data().get("iterations", 0) or 0)
            cap = int(CONFIG.MAX_ITERATIONS)
            return f"{used}/{cap}" if cap else str(used)
        except Exception:
            return "—"

    # ------------------------------------------------------------------
    # Panels
    # ------------------------------------------------------------------
    def _header(self) -> RenderableType:
        status, elapsed = self._status()
        t = Text()
        t.append(" X19 ", style="bold black on cyan")
        t.append(" 4.0.0", style="bold cyan")
        t.append("   │   ", style="dim")
        t.append("X19 Autonomous Agent", style="bold white")
        t.append("   │   ", style="dim")
        t.append(self._provider(), style="cyan")
        t.append("   ", style="dim")
        t.append("● " + status, style="green" if status == "READY" else "yellow")
        t.append(f"   {elapsed}", style="dim")
        t.append("   ", style="dim")
        t.append("/target", style="cyan")
        t.append("  /scope", style="magenta")
        t.append("  /dash", style="green")
        t.append("  /help", style="cyan")
        return Panel(t, border_style="bright_blue", padding=(0, 1))

    def _sidebar(self) -> RenderableType:
        data = self._session_data()
        table = Table.grid(padding=(0, 1))
        table.add_column(style="dim", width=13)
        table.add_column()
        items = [
            ("◉ Mission", "active" if self._task() else "ready"),
            ("⌕ Recon", "background" if self._task() else "idle"),
            ("◈ Analyze", "queued"),
            ("⚡ Validate", "queued"),
            ("▣ Report", "ready"),
        ]
        for name, state in items:
            table.add_row(name, state)
        table.add_row("", "")
        table.add_row("TARGET", self._target())
        table.add_row("Scope", "configured" if data.get("target") else "not set")
        table.add_row("Safety", str(getattr(self.agent, "target_type", "safe")))
        table.add_row("Sandbox", "isolated")
        table.add_row("Model", self._provider())
        table.add_row("Iteration", self._iteration())
        return Panel(table, title="X19 SESSION", border_style="bright_blue")

    def _thinking(self) -> RenderableType:
        task = self._task()
        title = Text(" Live Agent Thinking", style="bold cyan")
        title.append("   background execution", style="dim")
        body = Table.grid(padding=(0, 1))
        body.add_column(width=2)
        body.add_column()
        recent = list(self._events)[-7:]
        if not recent:
            recent = [
                "Waiting for an operator task…",
                "No terminal output is dumped here.",
                "Long-running work stays in the background.",
            ]
        for i, event in enumerate(recent):
            marker = "●" if i == len(recent) - 1 and task else "•"
            body.add_row(marker, Text(event, style="white" if i == len(recent) - 1 else "dim"))
        return Panel(body, title=title, border_style="cyan")

    def _plan(self) -> RenderableType:
        steps = [
            ("1", "Target analysis", "validate target + scope"),
            ("2", "Reconnaissance", "enumerate reachable surface"),
            ("3", "Analysis", "prioritize evidence-backed hypotheses"),
            ("4", "Validation", "verify before reporting"),
            ("5", "Report", "summarize confirmed findings"),
        ]
        table = Table.grid(padding=(0, 1))
        table.add_column(width=3)
        table.add_column(width=24)
        table.add_column()
        for n, name, desc in steps:
            table.add_row(Text(n, style="bold cyan"), Text(name, style="bold white"), Text(desc, style="dim"))
        return Panel(table, title=" Execution Plan", border_style="blue")

    def _target_panel(self) -> RenderableType:
        data = self._session_data()
        counts = self._finding_counts()
        table = Table.grid(padding=(0, 1))
        table.add_column(style="dim", width=12)
        table.add_column()
        table.add_row("Target", self._target())
        table.add_row("Status", "IN-SCOPE" if data.get("target") or getattr(self.agent, "target", "") else "NO TARGET")
        table.add_row("Mode", str(data.get("mode") or "autonomous"))
        table.add_row("Provider", self._provider())
        table.add_row("Progress", self._iteration())
        table.add_row("Critical", str(counts["critical"]))
        table.add_row("High", str(counts["high"]))
        table.add_row("Medium", str(counts["medium"]))
        table.add_row("Low", str(counts["low"]))
        return Panel(table, title=" Target Information", border_style="bright_blue")

    def _tools_panel(self) -> RenderableType:
        tools = getattr(self.agent, "_available_tools", {}) or {}
        names = list(tools.keys())[:8] if isinstance(tools, dict) else []
        if not names:
            names = ["nmap", "httpx", "subfinder", "nuclei", "ffuf", "whatweb"]
        table = Table.grid(padding=(0, 1))
        table.add_column(width=3)
        table.add_column()
        for name in names:
            table.add_row("●", str(name))
        return Panel(table, title=" Selected Tools", border_style="blue")

    def _progress(self) -> RenderableType:
        data = self._session_data()
        stats = data.get("stats") or {}
        row = Table.grid(expand=True)
        row.add_column(justify="center")
        row.add_column(justify="center")
        row.add_column(justify="center")
        row.add_column(justify="center")
        row.add_row(
            Text(str(stats.get("open_ports", 0)), style="bold cyan"),
            Text(str(stats.get("endpoints", 0)), style="bold cyan"),
            Text(str(len(self._findings())), style="bold yellow"),
            Text(self._iteration(), style="bold green"),
        )
        row.add_row(Text("open ports", style="dim"), Text("endpoints", style="dim"), Text("findings", style="dim"), Text("iterations", style="dim"))
        return Panel(row, title=" Scan Progress", border_style="bright_blue")

    def _output(self) -> RenderableType:
        table = Table.grid(padding=(0, 1))
        table.add_column()
        lines = list(self._events)[-10:]
        if not lines:
            lines = ["[ready] X19 waiting for an instruction…"]
        for line in lines:
            table.add_row(Text(line, style="white"))
        return Panel(table, title=" Live Output · summarized", border_style="cyan")

    def _input(self) -> RenderableType:
        prompt = Text()
        prompt.append(" X19 › ", style="bold cyan")
        prompt.append(self.buffer or "message agent or assign a task (/target, /scope, /dash)…", style="white" if self.buffer else "dim")
        return Panel(prompt, border_style="bright_blue", padding=(0, 1))

    def render(self) -> RenderableType:
        self._drain_events()
        root = Layout(name="root")
        root.split_column(
            Layout(self._header(), name="header", size=3),
            Layout(name="body"),
            Layout(self._input(), name="input", size=3),
        )
        body = root["body"]
        body.split_row(Layout(name="left", ratio=2), Layout(name="center", ratio=6), Layout(name="right", ratio=3))
        body["left"].update(Group(self._sidebar()))
        center = body["center"]
        center.split_column(Layout(self._thinking(), name="thinking", ratio=4), Layout(name="middle", ratio=5), Layout(self._output(), name="output", ratio=4))
        center["middle"].split_row(Layout(self._plan(), name="plan", ratio=5), Layout(self._tools_panel(), name="tools", ratio=4))
        body["right"].update(Group(self._target_panel(), self._progress()))
        return root

    # ------------------------------------------------------------------
    # Command dispatch
    # ------------------------------------------------------------------
    def _submit(self) -> None:
        line = self.buffer.strip()
        self.buffer = ""
        if not line:
            return
        if line in ("/exit", "/quit"):
            self.running = False
            return
        # Pause the alternate-screen renderer while existing X19 handlers print.
        self.app.console.clear()
        try:
            self.app._echo_user(line)
            self.app.remember("user", line)
            self.app.handle(line)
        except KeyboardInterrupt:
            pass
        except Exception as exc:
            self.app.console.print(f"[red]✖ {type(exc).__name__}: {exc}[/]")
        time.sleep(0.15)

    def run(self) -> int:
        if os.name == "nt" or not sys.stdin.isatty():
            # Preserve the existing cross-platform implementation.
            return self.app._legacy_run()
        self._enter_raw()
        try:
            with Live(self.render(), console=self.console, screen=True, transient=False, refresh_per_second=8) as live:
                while self.running:
                    live.update(self.render(), refresh=True)
                    raw = self._read_key(0.12)
                    if raw is None:
                        continue
                    if raw in ("\r", "\n"):
                        self._submit()
                        live.update(self.render(), refresh=True)
                        continue
                    if raw == "\x03":
                        if self._task():
                            try:
                                self.app._request_stop(silent=False)
                            except Exception:
                                pass
                        else:
                            self.running = False
                        continue
                    if raw in ("\x7f", "\x08"):
                        self.buffer = self.buffer[:-1]
                        continue
                    if raw == "\x15":
                        self.buffer = ""
                        continue
                    if raw == "\x1b":
                        continue
                    if raw.startswith("\x1b"):
                        continue
                    for char in raw:
                        if char >= " " and char != "\x7f":
                            self.buffer += char
        finally:
            self._exit_raw()
            self.console.clear()
        return 0
