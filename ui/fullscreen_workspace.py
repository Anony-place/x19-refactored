"""Production terminal workspace for X19.

The workspace is a presentation layer over the existing ConsoleApp. It renders
real conversation history, real provider output, real assessment events and
real runtime state. It deliberately uses one Rich Live renderable (a Group of
normal renderables) rather than a nested Rich Layout tree so the terminal can
never expose ``Layout(...)`` object representations as chat output.
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
from rich.panel import Panel
from rich.text import Text

from ui.console import get_console, warn


class FullscreenWorkspace:
    """Chat-first terminal workspace backed entirely by the real X19 runtime."""

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
    def _message_block(role: str, content: str) -> RenderableType:
        if role == "user":
            head = Text()
            head.append("you", style="bold cyan")
            head.append("  ")
            return Group(head, Text(content, style="white"))
        head = Text()
        head.append("X19", style="bold bright_cyan")
        head.append("  ")
        return Group(head, Markdown(content))

    def _conversation(self) -> RenderableType:
        history = self._history()
        rows: list[RenderableType] = []
        for item in history[-16:]:
            rows.append(self._message_block(str(item.get("role", "assistant")), str(item.get("content", ""))))

        with self._state_lock:
            streaming = self._streaming_reply
            busy = self._chat_busy
            error = self._chat_error

        if busy:
            if streaming:
                rows.append(Group(Text("X19  ", style="bold bright_cyan"), Text(streaming)))
            else:
                rows.append(Text("X19  responding…", style="dim"))
        elif error:
            rows.append(Text(f"X19  {error}", style="red"))

        if not rows:
            rows.append(Text("No conversation yet. Type a message below.", style="dim"))

        return Panel(
            Group(*rows),
            title=" conversation ",
            title_align="left",
            border_style="border",
            padding=(1, 2),
            expand=True,
        )

    def _activity(self) -> RenderableType:
        from events import summarize_event
        lines: list[Text] = []
        with self._state_lock:
            events = list(self._events)[-4:]
        for event in events:
            try:
                text = summarize_event(event)
            except Exception:
                text = str(event)
            if text:
                lines.append(Text(text, style="dim"))
        task = self._task()
        if task is not None and not getattr(task, "active", False):
            status = str(getattr(task, "status", "")).lower()
            if status:
                lines.append(Text(f"assessment · {status}", style="dim"))
        if not lines:
            return Text("activity  ·  idle", style="dim")
        return Panel(Group(*lines), title=" activity ", border_style="border", padding=(0, 1), expand=True)

    def _input(self) -> RenderableType:
        line = Text()
        line.append("you  ", style="bold cyan")
        line.append("› ", style="bold bright_cyan")
        if self.buffer:
            line.append(self.buffer, style="white")
        else:
            line.append("message or /command", style="dim")
        return Panel(line, title=" input ", title_align="left", border_style="border", padding=(0, 1), expand=True)

    def _header(self) -> RenderableType:
        status, elapsed = self._status()
        text = Text()
        text.append("X19", style="bold bright_cyan")
        text.append("  ", style="dim")
        text.append(self._target(), style="bold white")
        text.append("  ·  ", style="dim")
        text.append(self._provider(), style="cyan")
        text.append("  ·  ", style="dim")
        text.append(status, style="bold cyan" if status in {"RUNNING", "WORKING"} else "dim")
        if elapsed:
            text.append(f" {elapsed}", style="dim")
        return Panel(text, border_style="border", padding=(0, 1), expand=True)

    def _footer(self) -> RenderableType:
        return Text(" Enter send   Ctrl+C stop/exit   Ctrl+U clear input   /help commands", style="dim")

    def render(self) -> RenderableType:
        """Build one renderable tree; never return a Rich Layout instance."""
        self._drain_events()
        return Group(
            self._header(),
            self._conversation(),
            self._activity(),
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
        """Run existing command handling outside raw-input mode."""
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
