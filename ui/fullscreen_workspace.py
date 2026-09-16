"""Production terminal workspace for X19.

The workspace is deliberately data-driven. It does not manufacture tool names,
workflow stages, findings, progress values, or agent messages. The center of the
screen is the actual X19 conversation; assessment activity is sourced from the
agent event bus and session state, while the existing ConsoleApp remains the
source of truth for command handling and execution.
"""
from __future__ import annotations

import os
import select
import sys
import termios
import time
import tty
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Optional

from rich.console import Group, RenderableType
from rich.layout import Layout
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ui.console import get_console, info, warn


class FullscreenWorkspace:
    """A restrained, production terminal workspace backed by live X19 state."""

    INTERACTIVE_COMMANDS = {
        "/target", "/provider", "/shell", "/model", "/resume",
        "/scope",
    }

    def __init__(self, app: Any):
        self.app = app
        self.console = get_console()
        self.agent = app.agent
        self.buffer = ""
        self.running = True
        self._events: deque[Any] = deque(maxlen=80)
        self._saved_termios = None
        self._raw = False
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="x19-ui")
        self._chat_busy = False
        self._last_history_len = 0

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
            self._raw = False
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

    def _read_key(self, timeout: float = 0.15) -> Optional[str]:
        if os.name == "nt":
            return None
        try:
            ready, _, _ = select.select([sys.stdin], [], [], timeout)
        except Exception:
            return None
        if not ready:
            return None
        try:
            return os.read(sys.stdin.fileno(), 16).decode("utf-8", "replace")
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Live state — no synthetic values
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
        return str(getattr(self.agent, "target", "") or "—")

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
        for event in events or []:
            self._events.append(event)

    def _history(self) -> list[dict]:
        history = getattr(self.app, "history", []) or []
        return [h for h in history if isinstance(h, dict) and h.get("content") is not None]

    def _findings(self) -> list[dict]:
        return list(self._session_data().get("findings") or [])

    def _counts(self) -> dict[str, int]:
        counts = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
        for finding in self._findings():
            sev = str(finding.get("severity", "info")).lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def _stats(self) -> dict:
        value = self._session_data().get("stats") or {}
        return value if isinstance(value, dict) else {}

    def _iteration(self) -> str:
        data = self._session_data()
        used = data.get("iterations")
        if used is None:
            return "—"
        try:
            from config import CONFIG
            cap = int(getattr(CONFIG, "MAX_ITERATIONS", 0) or 0)
            return f"{int(used)}/{cap}" if cap else str(int(used))
        except Exception:
            return str(used)

    def _status(self) -> tuple[str, str]:
        task = self._task()
        if task is not None:
            try:
                return "RUNNING", f"{task.elapsed():.0f}s"
            except Exception:
                return "RUNNING", ""
        if getattr(self.agent, "running", False):
            return "WORKING", ""
        return "READY", ""

    # ------------------------------------------------------------------
    # Conversation
    # ------------------------------------------------------------------
    def _conversation(self) -> RenderableType:
        history = self._history()
        width = max(30, self.console.width - 34)
        # Keep the visible window bounded. The complete history remains owned by
        # ConsoleApp; this is only the viewport, not a second transcript store.
        visible = history[-18:]
        rows: list[RenderableType] = []
        for item in visible:
            role = str(item.get("role", "assistant"))
            content = str(item.get("content", ""))
            if role == "user":
                head = Text()
                head.append("you", style="bold cyan")
                head.append("  ", style="dim")
                rows.append(Group(head, Text(content, style="white")))
            else:
                head = Text()
                head.append("X19", style="bold")
                rows.append(Group(head, Markdown(content)))
        if not rows:
            rows.append(Text("No conversation yet. Type a message below.", style="dim"))
        return Panel(Group(*rows), title="Conversation", border_style="bright_blue", padding=(1, 2))

    def _activity(self) -> RenderableType:
        from events import summarize_event

        lines: list[Text] = []
        for event in list(self._events)[-12:]:
            try:
                text = summarize_event(event)
            except Exception:
                text = str(event)
            if text:
                lines.append(Text(text, style="dim"))
        if not lines:
            return Panel(Text("No agent activity yet.", style="dim"), title="Activity", border_style="border")
        return Panel(Group(*lines), title="Activity", border_style="border", padding=(0, 1))

    # ------------------------------------------------------------------
    # Context panels — only facts exposed by X19
    # ------------------------------------------------------------------
    def _context(self) -> RenderableType:
        data = self._session_data()
        stats = self._stats()
        counts = self._counts()
        table = Table.grid(padding=(0, 1))
        table.add_column(style="dim", width=11)
        table.add_column(style="white")
        table.add_row("target", self._target())
        table.add_row("provider", self._provider())
        session = getattr(getattr(self.agent, "session", None), "id", "")
        if session:
            table.add_row("session", str(session))
        table.add_row("state", self._status()[0].lower())
        table.add_row("iterations", self._iteration())
        if "open_ports" in stats:
            table.add_row("ports", str(stats["open_ports"]))
        if "endpoints" in stats:
            table.add_row("endpoints", str(stats["endpoints"]))
        table.add_row("findings", str(len(self._findings())))
        for sev in ("critical", "high", "medium"):
            if counts[sev]:
                table.add_row(sev, str(counts[sev]))
        mode = data.get("mode")
        if mode:
            table.add_row("mode", str(mode))
        return Panel(table, title="Session", border_style="border")

    def _tools(self) -> RenderableType:
        # Prefer the agent's runtime-discovered inventory. Fall back to the
        # global registry only when discovery has not populated an inventory.
        tools = getattr(self.agent, "_available_tools", None)
        if isinstance(tools, dict) and tools:
            names = list(tools.keys())
            source = "runtime"
        else:
            try:
                from tools import TOOLS
                names = list(TOOLS.keys())
                source = "registry"
            except Exception:
                names = []
                source = "none"
        table = Table.grid(padding=(0, 1))
        table.add_column(style="dim", width=7)
        table.add_column(style="white")
        for name in names[:16]:
            table.add_row("tool", str(name))
        if not names:
            table.add_row("tool", "none discovered")
        return Panel(table, title=f"Tools · {source}", border_style="border")

    def _current_work(self) -> RenderableType:
        task = self._task()
        current_plan = getattr(self.agent, "_current_plan", None)
        plan_index = getattr(self.agent, "_plan_step_index", None)
        table = Table.grid(padding=(0, 1))
        table.add_column(style="dim", width=10)
        table.add_column(style="white")
        if task is not None:
            table.add_row("task", str(getattr(task, "label", "assessment")))
            note = str(getattr(task, "note", "") or "")
            if note:
                table.add_row("activity", note)
        if isinstance(current_plan, dict):
            title = current_plan.get("title") or current_plan.get("goal")
            if title:
                table.add_row("plan", str(title))
            steps = current_plan.get("steps")
            if isinstance(steps, list):
                table.add_row("steps", str(len(steps)))
                if plan_index is not None:
                    table.add_row("step", f"{plan_index + 1}/{len(steps)}")
        if not task and not isinstance(current_plan, dict):
            table.add_row("state", "idle")
        return Panel(table, title="Current Work", border_style="border")

    def _footer(self) -> RenderableType:
        status, elapsed = self._status()
        line = Text()
        line.append(" X19", style="bold")
        line.append("  ·  ", style="dim")
        line.append(f"{status.lower()}", style="cyan" if status != "READY" else "dim")
        if elapsed:
            line.append(f"  {elapsed}", style="dim")
        line.append("      ", style="dim")
        line.append("Enter", style="bold")
        line.append(" send   ", style="dim")
        line.append("Ctrl+C", style="bold")
        line.append(" stop/exit   ", style="dim")
        line.append("/help", style="bold")
        line.append(" commands", style="dim")
        return Panel(line, border_style="bright_blue", padding=(0, 1))

    def _input(self) -> RenderableType:
        line = Text()
        line.append("› ", style="bold cyan")
        line.append(self.buffer, style="white")
        if not self.buffer:
            line.append("Type a message or /command", style="dim")
        return Panel(line, title="Input", border_style="bright_blue", padding=(0, 1))

    def render(self) -> RenderableType:
        self._drain_events()
        root = Layout(name="root")
        root.split_column(
            Layout(self._header(), name="header", size=3),
            Layout(name="body"),
            Layout(self._input(), name="input", size=3),
            Layout(self._footer(), name="footer", size=3),
        )
        body = root["body"]
        body.split_row(Layout(name="main", ratio=7), Layout(name="side", ratio=3))
        main = body["main"]
        main.split_column(Layout(self._conversation(), name="conversation", ratio=7), Layout(self._activity(), name="activity", ratio=3))
        side = body["side"]
        side.split_column(Layout(self._context(), name="context", ratio=4), Layout(self._current_work(), name="work", ratio=3), Layout(self._tools(), name="tools", ratio=5))
        return root

    def _header(self) -> RenderableType:
        status, _ = self._status()
        text = Text()
        text.append(" X19 ", style="bold black on cyan")
        text.append("  ", style="dim")
        text.append(self._target(), style="bold white")
        text.append("   ·   ", style="dim")
        text.append(self._provider(), style="cyan")
        text.append("   ·   ", style="dim")
        text.append(status, style="bold cyan" if status != "READY" else "dim")
        return Panel(text, border_style="bright_blue", padding=(0, 1))

    # ------------------------------------------------------------------
    # Input dispatch
    # ------------------------------------------------------------------
    def _run_chat(self, message: str) -> None:
        self._chat_busy = True
        try:
            self.app.remember("user", message)
            reply = self.app._chat_reply(message)
            if reply:
                self.app.remember("assistant", reply)
        finally:
            self._chat_busy = False

    def _submit_chat(self, line: str) -> None:
        if self._chat_busy:
            warn("X19 is still responding — wait for the current reply")
            return
        self._executor.submit(self._run_chat, line)

    def _submit_command(self, line: str) -> None:
        """Reuse ConsoleApp's real command handlers; this UI owns no fake logic."""
        self._exit_raw()
        try:
            self.app._echo_user(line)
            self.app.remember("user", line)
            self.app.handle(line)
        except KeyboardInterrupt:
            pass
        except Exception as exc:
            self.console.print(f"[err]✖ {type(exc).__name__}: {exc}[/]")
        finally:
            if self.running:
                self._enter_raw()

    def _submit(self) -> None:
        line = self.buffer.strip()
        self.buffer = ""
        if not line:
            return
        if line in {"/exit", "/quit"}:
            self.running = False
            return
        if line.startswith("/"):
            self._submit_command(line)
            return
        self._submit_chat(line)

    def run(self) -> int:
        if os.name == "nt" or not sys.stdin.isatty():
            return self.app._legacy_run()
        self._enter_raw()
        try:
            with Live(self.render(), console=self.console, screen=True, transient=False, refresh_per_second=8) as live:
                while self.running:
                    live.update(self.render(), refresh=True)
                    raw = self._read_key()
                    if raw is None:
                        continue
                    if raw in ("\r", "\n"):
                        self._submit()
                        continue
                    if raw == "\x03":
                        task = self._task()
                        if task:
                            try:
                                self.app._request_stop(silent=False)
                            except Exception:
                                pass
                        elif self._chat_busy:
                            warn("chat cancellation is provider-dependent; wait for the response")
                        else:
                            self.running = False
                        continue
                    if raw in ("\x7f", "\x08"):
                        self.buffer = self.buffer[:-1]
                        continue
                    if raw == "\x15":
                        self.buffer = ""
                        continue
                    if raw == "\x04" and not self.buffer:
                        self.running = False
                        continue
                    if raw.startswith("\x1b"):
                        continue
                    for char in raw:
                        if char >= " " and char != "\x7f":
                            self.buffer += char
        finally:
            self._exit_raw()
            self._executor.shutdown(wait=False, cancel_futures=False)
            self.console.clear()
        return 0
