"""A single-line prompt that owns the bottom of the screen.

``input()``/``Prompt.ask`` block the thread, which makes a live status ribbon
impossible: the app could never refresh "assessment running · 00:12 · 3
findings" while the operator is typing. :class:`LivePrompt` reads the keyboard
in small non-blocking slices and re-renders a one-line ribbon above the input
line whenever its content changes:

* POSIX  — ``termios`` cbreak mode + ``select`` with a poll timeout.
* Windows — ``msvcrt.kbhit``/``getwch``.
* No TTY (pipes, CI, tests) — falls back to plain ``input()`` and the ribbon
  is rendered once, statically.

Owning the bottom of the screen has one hard consequence: **nothing else may
write to the terminal while the prompt is painted**, or the cursor maths desync
and the operator ends up with ghost prompt rows and duplicated ribbons. X19 has
plenty of code that prints on its own (the provider failover router announces
every request, tools warn, background threads report), so the prompt installs a
thread-safe output guard for as long as it is reading:

    erase prompt area → write the foreign text → repaint prompt area

Foreign writes therefore always land *above* the prompt, exactly like they do
in Claude Code / Codex CLI. The guard is transparent: it delegates every other
attribute to the wrapped stream, stays out of the way of the background task
manager's per-thread output capture, and is removed again in a ``finally``.

Editing support is deliberately minimal (typing, backspace, ctrl-u, ctrl-c,
ctrl-d) — this is a command line, not an editor. The original terminal mode is
always restored, including on exceptions, so a crash can never leave the
user's shell in cbreak mode.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import threading
from contextlib import contextmanager
from typing import Any, Callable, List, Optional, Tuple

try:  # POSIX
    import select
    import termios
    import tty

    _POSIX = True
except ImportError:  # pragma: no cover - Windows
    _POSIX = False

try:  # Windows
    import msvcrt

    _WINDOWS = True
except ImportError:
    _WINDOWS = False

import time as _time

time_sleep = _time.sleep

#: ANSI/VT escape sequences — stripped when measuring what is really on screen.
_ANSI_RE = re.compile(
    r"\x1b\[[0-9;?]*[ -/]*[@-~]"     # CSI sequences (colors, cursor moves, erase)
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC sequences (title, hyperlinks)
    r"|\x1b[=>]"                      # keypad modes
    r"|[\x00-\x08\x0b-\x1f]"          # other control characters
)

#: cbreak mode turns OPOST off, so a bare "\n" no longer returns the cursor to
#: column 0. Foreign writes get their newlines fixed up before they hit the tty.
_LONE_NEWLINE_RE = re.compile(r"(?<!\r)\n")


def interactive_stdin() -> bool:
    """True when single-key reads from stdin are possible here."""
    if not (_POSIX or _WINDOWS):
        return False
    try:
        return bool(sys.stdin and sys.stdin.isatty())
    except Exception:
        return False


if _POSIX:
    from os import read as os_read  # noqa: E402
else:  # pragma: no cover
    os_read = None


# ---------------------------------------------------------------------------
# Screen geometry helpers
# ---------------------------------------------------------------------------
def visible_width(text: str) -> int:
    """Display width of ``text``: ANSI-free, East-Asian wide glyphs counted twice."""
    import unicodedata

    plain = _ANSI_RE.sub("", str(text))
    width = 0
    for char in plain:
        width += 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
    return width


def rows_for(text: str, columns: int) -> int:
    """How many terminal rows ``text`` occupies when written at ``columns``."""
    columns = max(1, int(columns))
    return max(1, -(-visible_width(text) // columns))


def terminal_columns(fallback: int = 0) -> int:
    """The real terminal width right now, or ``fallback`` when there is no tty.

    Rich caches the width it detected at startup; people resize terminals. The
    prompt asks the OS on every repaint so a resize cannot leave the ribbon
    wrapping onto a second row (which used to desync the cursor maths).
    """
    for stream in (sys.__stdout__, sys.stdout, sys.__stderr__):
        try:
            fileno = stream.fileno()
        except Exception:
            continue
        try:
            columns = os.get_terminal_size(fileno).columns
        except (OSError, ValueError, AttributeError):
            continue
        if columns and columns > 0:
            return int(columns)
    try:
        detected = shutil.get_terminal_size((0, 0)).columns
    except Exception:
        detected = 0
    if detected and detected > 0:
        return int(detected)
    return int(fallback or 0)


def fit_to_width(text: str, columns: int) -> str:
    """Crop ``text`` so it occupies at most one row of ``columns`` cells.

    Colour is dropped when a styled line does not fit — a ribbon that wraps is
    worse than a ribbon without colour.
    """
    columns = max(8, int(columns))
    if visible_width(text) <= columns:
        return text
    plain = _ANSI_RE.sub("", str(text))
    while visible_width(plain) > columns - 1 and plain:
        plain = plain[:-1]
    return plain + "…"


def _foreign_output_is_captured() -> bool:
    """True when this thread's writes are captured by the background manager.

    Captured output never reaches the terminal, so the prompt must not erase
    and repaint itself for it (that would flicker on every worker line).
    """
    try:
        from ui.background import output_is_captured

        return bool(output_is_captured())
    except Exception:
        return False


class _PromptSafeStream:
    """stdout/stderr wrapper that keeps the prompt area intact.

    Everything that is not ``write``/``flush`` is delegated, so rich, logging
    and plain ``print()`` keep working unchanged.
    """

    def __init__(self, inner: Any, prompt: "LivePrompt"):
        self._inner = inner
        self._prompt = prompt

    # -- the only two methods that matter ---------------------------------
    def write(self, data: Any) -> int:
        text = data if isinstance(data, str) else str(data)
        if not text:
            return 0
        prompt = self._prompt
        if not prompt.guard_active() or _foreign_output_is_captured():
            return self._inner.write(text)
        return prompt.write_foreign(text)

    def flush(self) -> None:
        try:
            self._inner.flush()
        except Exception:
            pass

    def writelines(self, lines: Any) -> None:
        for line in lines:
            self.write(line)

    # -- transparent delegation -------------------------------------------
    def isatty(self) -> bool:
        try:
            return bool(self._inner.isatty())
        except Exception:
            return False

    def fileno(self) -> int:
        return self._inner.fileno()

    @property
    def encoding(self) -> str:
        return getattr(self._inner, "encoding", "utf-8")

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<_PromptSafeStream {self._inner!r}>"


class LivePrompt:
    """Read a line while re-drawing ``ribbon_fn()`` above it on change.

    ``committed_fn`` optionally turns the prompt row into a permanent
    transcript line on Enter (``app.py`` uses it so the operator never sees the
    same message twice — once as the live prompt, once as an echo).
    """

    def __init__(
        self,
        console: Any = None,
        ribbon_fn: Optional[Callable[[], str]] = None,
        poll: float = 0.4,
        completer: Optional[Callable[[str], list]] = None,
        on_tick: Optional[Callable[[], bool]] = None,
        on_escape: Optional[Callable[[], bool]] = None,
        committed_fn: Optional[Callable[[str], Any]] = None,
    ):
        self.console = console
        self.ribbon_fn = ribbon_fn
        self.poll = max(0.1, float(poll))
        self.completer = completer
        #: called on every idle poll; return True when it printed output
        #: (the prompt area is cleared first and redrawn after)
        self.on_tick = on_tick
        #: called on a bare Esc press; return True when the press was consumed
        self.on_escape = on_escape
        #: called with the final buffer on Enter; returns a renderable that
        #: replaces the prompt row in the scrollback (or None to erase it)
        self.committed_fn = committed_fn
        #: True when the last ``ask()`` left its input line in the scrollback
        self.last_committed = False

        self._saved = None
        self._raw = False
        #: stream the prompt paints on directly (never the guarded wrapper)
        self._real_stream: Any = None
        self._installed: List[Tuple[str, Any, Any]] = []
        self._lock = threading.RLock()
        self._suspended = 0
        #: what is currently painted, so foreign writes know what to erase
        self._painted = False
        self._painted_ribbon = ""
        self._painted_prompt = ""
        self._painted_buffer = ""
        #: foreign output waiting for a line terminator
        self._foreign = ""
        #: kept for callers that still ask which ribbon is on screen
        self._last_ribbon = ""

    # ------------------------------------------------------------------
    # Terminal mode
    # ------------------------------------------------------------------
    def _enter_raw(self) -> bool:
        if not interactive_stdin():
            return False
        if _POSIX:
            try:
                fd = sys.stdin.fileno()
                self._saved = termios.tcgetattr(fd)
                tty.setcbreak(fd)
                self._raw = True
            except Exception:
                self._saved = None
                self._raw = False
                return False
        elif _WINDOWS:  # pragma: no cover - Windows
            self._raw = True
        else:  # pragma: no cover
            return False

        stream = getattr(self.console, "file", None) or sys.stdout
        self._real_stream = getattr(stream, "_inner", stream)
        self._install_guard()
        return True

    def _exit_raw(self) -> None:
        # Stop painting *before* flushing, so the tail of a foreign write is
        # emitted without a prompt row being redrawn behind it.
        was_raw = self._raw
        self._raw = False
        try:
            self.flush_foreign()
            with self._lock:
                self._erase()
        finally:
            self._uninstall_guard()
            self._painted = False
            self._foreign = ""
            if was_raw and _POSIX and self._saved is not None:
                try:
                    termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self._saved)
                except Exception:
                    pass
            self._saved = None

    # ------------------------------------------------------------------
    # Output guard
    # ------------------------------------------------------------------
    def _install_guard(self) -> None:
        """Route sys.stdout/sys.stderr through the prompt for the raw window."""
        if self._installed:
            return
        for name in ("stdout", "stderr"):
            stream = getattr(sys, name, None)
            if stream is None or isinstance(stream, _PromptSafeStream):
                continue
            try:
                if not bool(stream.isatty()):
                    continue
            except Exception:
                continue
            wrapper = _PromptSafeStream(stream, self)
            try:
                setattr(sys, name, wrapper)
            except Exception:
                continue
            self._installed.append((name, stream, wrapper))

    def _uninstall_guard(self) -> None:
        for name, original, wrapper in reversed(self._installed):
            try:
                if getattr(sys, name, None) is wrapper:
                    setattr(sys, name, original)
            except Exception:
                pass
        self._installed = []

    def guard_active(self) -> bool:
        """True when foreign writes must be routed around the prompt area."""
        return bool(self._raw and self._painted and not self._suspended)

    def write_foreign(self, text: str) -> int:
        """Buffer a foreign write and paint complete lines above the prompt.

        ``print("x")`` reaches a stream as *two* writes ("x", then "\\n"). Erasing
        and repainting for each of them puts a blank row between the output and
        the prompt, so writes are joined into whole lines first and each line is
        emitted in one erase → write → repaint cycle. Anything left over is
        flushed on the next poll tick, so an unterminated write is never lost.
        """
        with self._lock:
            self._foreign += text
            pending = self._take_flushable()
            if pending:
                self._emit_foreign(pending)
            return len(text)

    def _take_flushable(self, everything: bool = False) -> str:
        """Split the foreign buffer into "safe to paint now" and "keep buffering"."""
        buf = self._foreign
        if not buf:
            self._foreign = ""
            return ""
        if everything or len(buf) > 4096:
            self._foreign = ""
            return buf
        cut = max(buf.rfind("\n"), buf.rfind("\r"))
        if cut < 0:
            return ""
        self._foreign = buf[cut + 1:]
        return buf[:cut + 1]

    def flush_foreign(self) -> None:
        """Paint whatever a foreign writer left unterminated (poll tick / exit)."""
        with self._lock:
            pending = self._take_flushable(everything=True)
            if pending:
                self._emit_foreign(pending)

    def _emit_foreign(self, text: str) -> None:
        with self._lock:
            self._erase()
            payload = _LONE_NEWLINE_RE.sub("\r\n", text)
            try:
                self._raw_write(payload)
            except Exception:
                return
            if payload and not payload.endswith(("\n", "\r")):
                # stopped mid-row: the prompt gets its own row back
                self._raw_write("\r\n")
            self._paint()

    @contextmanager
    def suspended(self):
        """Temporarily hand the screen to the caller (multi-line renders)."""
        with self._lock:
            self._suspended += 1
            self._erase()
        try:
            yield self
        finally:
            with self._lock:
                self._suspended -= 1
                if self._suspended <= 0:
                    self._suspended = 0
                    self._paint()

    def print_above(self, render: Callable[[], Any]) -> None:
        """Run ``render()`` with the prompt area lifted out of the way."""
        with self.suspended():
            render()

    # ------------------------------------------------------------------
    # Painting primitives
    # ------------------------------------------------------------------
    def _raw_write(self, text: str) -> int:
        stream = self._real_stream
        if stream is None:
            stream = getattr(self.console, "file", None) or sys.stdout
            stream = getattr(stream, "_inner", stream)
        try:
            stream.write(text)
            stream.flush()
        except Exception:
            return 0
        return len(text)

    def _columns(self) -> int:
        return max(20, terminal_columns(fallback=getattr(self.console, "width", 80) or 80))

    def _area_rows(self) -> int:
        """Rows the painted prompt area occupies, including the ribbon."""
        if not self._painted:
            return 0
        columns = self._columns()
        rows = rows_for(f"{self._painted_prompt} {self._painted_buffer}", columns)
        if self._painted_ribbon:
            rows += rows_for(self._painted_ribbon, columns)
        return rows

    def _erase(self) -> None:
        """Lift the cursor to the first prompt row and clear down from there."""
        rows = self._area_rows()
        self._painted = False
        if rows <= 1:
            self._raw_write("\r\x1b[K" if rows else "\r")
            return
        self._raw_write("\r" + "\x1b[1A" * (rows - 1) + "\x1b[J")

    def _paint(self) -> None:
        """Repaint ribbon + input line from the remembered state."""
        if not self._raw or self._suspended:
            return
        ribbon = self._painted_ribbon
        prompt = self._painted_prompt
        buffer_ = self._painted_buffer
        columns = self._columns()
        if ribbon:
            ribbon = fit_to_width(ribbon, columns)
        seq = ""
        if ribbon:
            seq += ribbon + "\r\n"
        seq += f"{prompt} {buffer_}"
        self._raw_write(seq)
        self._painted = True
        self._painted_ribbon = ribbon
        self._last_ribbon = ribbon

    def _repaint(self, prompt: str, buffer: str, ribbon: str) -> None:
        with self._lock:
            self._erase()
            self._painted_prompt = prompt
            self._painted_buffer = buffer
            self._painted_ribbon = ribbon or ""
            self._paint()

    # Kept for callers that managed the screen themselves before the guard
    # existed (``app.py`` used to clear, print, and hope).
    def _redraw(self, prompt: str, buffer: str, ribbon: str) -> None:
        self._repaint(prompt, buffer, ribbon)

    def _clear_prompt_area(self, ribbon: str = "") -> None:
        self._last_ribbon = ribbon or self._last_ribbon
        with self._lock:
            self._erase()

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------
    def _read_char(self) -> Optional[str]:
        """Return one decoded keypress, or None when nothing was pressed."""
        if _POSIX:
            ready, _, _ = select.select([sys.stdin], [], [], self.poll)
            if not ready:
                return None
            try:
                data = os_read(sys.stdin.fileno(), 8)
            except (OSError, ValueError):
                return None
            return data.decode("utf-8", "replace")
        if _WINDOWS:  # pragma: no cover - Windows
            if not msvcrt.kbhit():
                time_sleep(self.poll)
                return None
            char = msvcrt.getwch()
            if char in ("\x00", "\xe0"):  # named keys — swallow the second code
                msvcrt.getwch()
                return ""
            return char
        time_sleep(self.poll)  # pragma: no cover - no TTY path never gets here
        return None

    def _complete(self, buffer: str) -> str:
        """Return the longest common prefix completion for ``buffer``."""
        if self.completer is None or not buffer or " " in buffer:
            return buffer
        try:
            options = [str(o) for o in self.completer(buffer) if str(o).startswith(buffer)]
        except Exception:
            return buffer
        if not options:
            return buffer
        if len(options) == 1:
            return options[0]
        prefix = options[0]
        for option in options[1:]:
            while not option.startswith(prefix):
                prefix = prefix[:-1]
                if not prefix:
                    break
        return prefix

    def _commit(self, buffer: str) -> None:
        """Turn the live prompt row into a permanent transcript line."""
        text = buffer.strip()
        renderable = None
        if text and self.committed_fn is not None:
            try:
                renderable = self.committed_fn(text)
            except Exception:
                renderable = None
        with self._lock:
            self._erase()
            self.last_committed = renderable is not None
            if renderable is None:
                return
            self._suspended += 1
            try:
                console = self.console
                if console is not None:
                    console.print(renderable)
                else:
                    self._raw_write(_LONE_NEWLINE_RE.sub("\r\n", str(renderable)) + "\r\n")
            finally:
                self._suspended -= 1

    def ask(self, prompt: str) -> str:
        """Prompt for one line. Raises EOFError (ctrl-d) / KeyboardInterrupt."""
        ribbon_fn = self.ribbon_fn
        ribbon = str(ribbon_fn() or "") if ribbon_fn else ""
        self.last_committed = False

        if not self._enter_raw():
            # Non-interactive fallback: static ribbon, plain blocking input.
            if ribbon:
                print(ribbon)
            return input(f"{prompt} ")

        buffer = ""
        last_ribbon = ribbon
        self._last_ribbon = ribbon
        self._repaint(prompt, buffer, ribbon)
        try:
            while True:
                raw = self._read_char()
                if raw is None:  # poll tick — ribbon refresh + agent activity
                    if ribbon_fn:
                        ribbon = str(ribbon_fn() or "")
                    # A foreign writer that never sent a newline still gets on
                    # screen within one poll interval.
                    self.flush_foreign()
                    # Anything the tick prints goes through the output guard,
                    # so it lands above the prompt and the prompt survives.
                    self.on_tick and self.on_tick()
                    if ribbon != last_ribbon:
                        last_ribbon = ribbon
                        self._repaint(prompt, buffer, ribbon)
                    continue
                if raw == "\x1b":  # bare Esc — interrupt hook (arrows come as
                    consumed = False  # multi-char sequences and fall through)
                    if self.on_escape is not None:
                        consumed = bool(self.on_escape())
                    if consumed:
                        last_ribbon = ""
                        self._repaint(prompt, buffer, "")
                    continue
                if raw.startswith("\x1b"):
                    continue  # arrow key / escape sequence — ignore
                for char in raw:
                    if char in ("\r", "\n"):
                        self._commit(buffer)
                        return buffer
                    if char in ("\x7f", "\x08"):
                        buffer = buffer[:-1]
                    elif char == "\x15":  # ctrl-u — clear line
                        buffer = ""
                    elif char == "\x03":  # ctrl-c
                        self._clear_prompt_area(last_ribbon)
                        raise KeyboardInterrupt
                    elif char == "\x04":  # ctrl-d
                        if not buffer:
                            self._clear_prompt_area(last_ribbon)
                            raise EOFError
                        buffer = buffer[:-1]
                    elif char == "\x09":  # tab — complete the first token
                        buffer = self._complete(buffer)
                    elif char == "\x1b":
                        continue  # escape / arrow leads — ignore
                    elif char == "":
                        continue
                    elif char >= " ":
                        buffer += char
                self._repaint(prompt, buffer, last_ribbon)
        finally:
            self._exit_raw()
