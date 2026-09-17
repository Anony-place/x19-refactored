"""Production terminal workspace for X19.

The workspace is a thin presentation layer over the existing ConsoleApp. It
renders real conversation history, provider output, assessment events and
runtime state. The visual language is intentionally terminal-first: one status
bar, one transcript, one command line and a compact activity strip. It avoids
nested panels and dashboard-like chrome so the operator can focus on the agent.
"""
from __future__ import annotations

import os
import select
import sys
import termios
import threading
import tty
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Optional

from rich.console import Group, RenderableType
from rich.live import Live
from rich.markdown import Markdown
from rich.rule import Rule
from rich.text import Text

from ui.console import get_console, warn
from ui.terminal_state import snapshot as terminal_snapshot


class FullscreenWorkspace:
    """Chat-first operator console backed by the real X19 runtime."""

    def __init__(self, app: Any):
        self.app = app
        self.console = get_console()
        self.agent = app.agent
        self.buffer = ""
        self.running = True
        self._events: deque[Any] = deque(maxlen=80)
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="x19-ui")
        self._state_lock = threading.RLock()
        self._chat_busy = False
        self._streaming_reply = ""
        self._chat_error = ""
        self._live: Optional[Live] = None
        self._saved_termios = None
        self._raw = False

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

    def _read_key(self, timeout: float = 0.12) -> Optional[str]:
        if os.name == "nt":
            return None
        try:
            ready, _, _ = select.select([sys.stdin], [], [], timeout)
        except Exception:
            return None
        if not ready:
            return None
        try:
            return os.read(sys.stdin.fileno(), 32).decode("utf-8", "replace")
        except Exception:
            return None

    def _provider(self) -> str:
        try:
            return self.app.ai.name() if self.app.ai else "—"
        except Exception:
            return "—"

    def _target(self) -> str:
        return str(getattr(self.agent, "target", "") or "—")

    def _task(self) -> Any:
        return getattr(self.app, "_assessment_task", None)

    def _drain_events(self) -> None:
        task = self._task()
        if task is None:
            return
        try:
            events = self.app.background.drain_events(task)
        except Exception:
            events = []
        if events:
            with self._state_lock:
                self._events.extend(events)

    def _history(self) -> list[dict]:
        with self._state_lock:
            history = list(getattr(self.app, "history", []) or [])
        return [h for h in history if isinstance(h, dict) and h.get("content") is not None]

    def _status(self) -> tuple[str, str]:
        task = self._task()
        if task is not None and getattr(task, "active", False):
            try:
                return "RUNNING", f"{task.elapsed():.0f}s"
            except Exception:
                return "RUNNING", ""
        with self._state_lock:
            busy = self._chat_busy
        if busy or getattr(self.agent, "running", False):
            return "WORKING", ""
        if task is not None and getattr(task, "status", ""):
            return str(task.status).upper(), ""
        return "READY", ""

    @staticmethod
    def _user_line(content: str) -> RenderableType:
        line = Text()
        line.append("you", style="bold cyan")
        line.append("  ›  ", style="dim")
        line.append(content, style="white")
        return line

    @staticmethod
    def _assistant_block(content: str) -> RenderableType:
        head = Text("X19", style="bold bright_cyan")
        return Group(head, Markdown(content))

    def _conversation(self) -> RenderableType:
        history = self._history()
        rows: list[RenderableType] = []

        for item in history[-14:]:
            role = str(item.get("role", "assistant"))
            content = str(item.get("content", ""))
            if not content:
                continue
            if role == "user":
                rows.append(self._user_line(content))
            else:
                rows.append(self._assistant_block(content))
            rows.append(Text(""))

        with self._state_lock:
            streaming = self._streaming_reply
            busy = self._chat_busy
            error = self._chat_error

        if busy:
            if streaming:
                rows.append(self._assistant_block(streaming))
            else:
                rows.append(Text("X19  thinking…", style="dim"))
        elif error:
            rows.append(Text(f"X19  {error}", style="red"))

        if not rows:
            rows.append(Text("No messages yet. Start with a target, question, or /command.", style="dim"))

        return Group(*rows)

    def _activity(self) -> RenderableType:
        from events import summarize_event

        with self._state_lock:
            events = list(self._events)[-1:]

        task = self._task()
        status, elapsed = self._status()
        detail = "idle"

        if events:
            try:
                detail = summarize_event(events[-1]) or "activity"
            except Exception:
                detail = str(events[-1])
        elif status in {"RUNNING", "WORKING"}:
            detail = status.lower()

        text = Text()
        text.append("activity", style="bold dim")
        text.append("  ·  ", style="dim")
        text.append(detail, style="dim")
        if elapsed:
            text.append(f"  ·  {elapsed}", style="dim")
        return text

    def _telemetry(self) -> RenderableType:
        state = terminal_snapshot(self.app)
        text = Text()
        text.append("health ", style="bold dim")
        text.append(state.health, style="dim")
        text.append("  ·  coverage ", style="bold dim")
        text.append(state.coverage, style="dim")
        text.append("  ·  findings ", style="bold dim")
        text.append(str(state.findings), style="dim")
        text.append("  ·  iter ", style="bold dim")
        text.append(state.iteration, style="dim")
        # 2026: attack credits (XBOW) + tools (MCP)
        text.append("  ·  credits ", style="bold dim")
        text.append(state.credits, style="dim")
        text.append("  ·  tools ", style="bold dim")
        text.append(state.tools, style="dim")
        return text

    def _header(self) -> RenderableType:
        status, elapsed = self._status()
        text = Text()
        text.append("X19", style="bold bright_cyan")
        text.append("  ", style="dim")
        text.append(self._target(), style="bold white")
        text.append("   ", style="dim")
        text.append("·", style="dim")
        text.append("   ", style="dim")
        text.append(self._provider(), style="cyan")
        text.append("   ", style="dim")
        text.append("·", style="dim")
        text.append("   ", style="dim")
        text.append("● ", style="bold green" if status in {"RUNNING", "WORKING", "READY"} else "dim")
        text.append(status, style="bold" if status in {"RUNNING", "WORKING"} else "dim")
        if elapsed:
            text.append(f" {elapsed}", style="dim")
        return text

    def _input(self) -> RenderableType:
        line = Text()
        line.append("x19", style="bold bright_cyan")
        line.append(" › ", style="bold cyan")
        if self.buffer:
            line.append(self.buffer, style="white")
        else:
            line.append("message or /command", style="dim")
        return line

    def _footer(self) -> RenderableType:
        return Text("/help  /status  /stop  /exit    ·    enter send    ·    ctrl+c stop/exit", style="dim")

    def render(self) -> RenderableType:
        """Build the complete terminal view without Rich Layout objects."""
        self._drain_events()
        return Group(
            self._header(),
            self._telemetry(),
            Rule(style="border.dim"),
            self._conversation(),
            Rule(style="border.dim"),
            self._activity(),
            Text(""),
            self._input(),
            self._footer(),
        )

    def _on_chunk(self, piece: str) -> None:
        with self._state_lock:
            self._streaming_reply += piece

    def _run_chat(self, message: str) -> None:
        try:
            reply = self.app._chat_reply(message, render=False, on_chunk=self._on_chunk)
            with self._state_lock:
                if reply:
                    self.app.remember("assistant", reply)
                elif not self._streaming_reply:
                    self._chat_error = "provider request failed or returned no response"
        except Exception as exc:
            with self._state_lock:
                self._chat_error = f"provider error: {type(exc).__name__}"
        finally:
            with self._state_lock:
                self._chat_busy = False

    def _submit_chat(self, message: str) -> None:
        with self._state_lock:
            if self._chat_busy:
                warn("X19 is still responding — wait for the current reply")
                return
            self._chat_busy = True
            self._streaming_reply = ""
            self._chat_error = ""
            self.app.remember("user", message)
        self._executor.submit(self._run_chat, message)

    def _submit_command(self, line: str) -> None:
        self._exit_raw()
        live = self._live
        if live is not None:
            live.stop()
        try:
            self.app.handle(line)
        except KeyboardInterrupt:
            pass
        except Exception as exc:
            self.console.print(f"[err]✖ {type(exc).__name__}: {exc}[/]")
        finally:
            if self.running and live is not None:
                live.start(refresh=True)
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
        # Naming a target is how an operator starts work, so it is routed through
        # the application's deterministic intake (scope resolves, then the
        # operator picks passive / active / verify / cancel) instead of being
        # sent to the model — which answers with a policy lecture and invented
        # program details. Prose still goes to chat.
        if self.app._parse_target_request(line):
            self._submit_command(line)
            return
        self._submit_chat(line)

    def run(self) -> int:
        if os.name == "nt" or not sys.stdin.isatty():
            return self.app._legacy_run()
        self._enter_raw()
        try:
            live = Live(
                self.render(),
                console=self.console,
                screen=True,
                transient=False,
                refresh_per_second=10,
                vertical_overflow="ellipsis",
            )
            self._live = live
            with live:
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
                        if task is not None and getattr(task, "active", False):
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
            self._live = None
            self._executor.shutdown(wait=False, cancel_futures=False)
            self.console.clear()
        return 0
