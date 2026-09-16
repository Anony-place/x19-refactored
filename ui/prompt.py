"""A single-line prompt that stays alive while background work runs.

``input()``/``Prompt.ask`` block the thread, which makes a live status ribbon
impossible: the app could never refresh "assessment running · 00:12 · 3
findings" while the operator is typing. :class:`LivePrompt` reads the keyboard
in small non-blocking slices and re-renders a one-line ribbon above the input
line whenever its content changes:

* POSIX  — ``termios`` cbreak mode + ``select`` with a poll timeout.
* Windows — ``msvcrt.kbhit``/``getwch``.
* No TTY (pipes, CI, tests) — falls back to plain ``input()`` and the ribbon
  is rendered once, statically.

Editing support is deliberately minimal (typing, backspace, ctrl-u, ctrl-c,
ctrl-d) — this is a command line, not an editor. The original terminal mode is
always restored, including on exceptions, so a crash can never leave the
user's shell in cbreak mode.
"""
from __future__ import annotations

import sys
from typing import Any, Callable, Optional

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


def interactive_stdin() -> bool:
    """True when single-key reads from stdin are possible here."""
    if not (_POSIX or _WINDOWS):
        return False
    try:
        return bool(sys.stdin and sys.stdin.isatty())
    except Exception:
        return False


class LivePrompt:
    """Read a line while re-drawing ``ribbon_fn()`` above it on change."""

    def __init__(
        self,
        console: Any = None,
        ribbon_fn: Optional[Callable[[], str]] = None,
        poll: float = 0.4,
        completer: Optional[Callable[[str], list]] = None,
        on_tick: Optional[Callable[[], bool]] = None,
        on_escape: Optional[Callable[[], bool]] = None,
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
        self._saved = None
        self._raw = False
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
                return True
            except Exception:
                self._saved = None
                self._raw = False
                return False
        if _WINDOWS:  # pragma: no cover - Windows
            self._raw = True
            return True
        return False

    def _exit_raw(self) -> None:
        if not self._raw:
            return
        self._raw = False
        if _POSIX and self._saved is not None:
            try:
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self._saved)
            except Exception:
                pass
        self._saved = None

    # ------------------------------------------------------------------
    # Output helpers
    # ------------------------------------------------------------------
    def _write(self, text: str) -> None:
        stream = getattr(self.console, "file", None) or sys.stdout
        try:
            stream.write(text)
            stream.flush()
        except Exception:
            pass

    def _redraw(self, prompt: str, buffer: str, ribbon: str) -> None:
        # Ribbon sits one line above the input line; both get cleared and
        # repainted. Only ANSI-capable terminals get the two-line dance.
        seq = "\r\x1b[K"
        if ribbon:
            seq += f"\x1b[1A\r\x1b[K{ribbon}\n\r"
        self._write(seq + f"{prompt} {buffer}")

    def _clear_prompt_area(self, ribbon: str) -> None:
        self._last_ribbon = ribbon
        seq = "\r\x1b[K"
        if ribbon:
            seq = "\r\x1b[K\x1b[1A\r\x1b[K" + seq
        self._write(seq)

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

    def ask(self, prompt: str) -> str:
        """Prompt for one line. Raises EOFError (ctrl-d) / KeyboardInterrupt."""
        ribbon_fn = self.ribbon_fn
        ribbon = str(ribbon_fn() or "") if ribbon_fn else ""

        if not self._enter_raw():
            # Non-interactive fallback: static ribbon, plain blocking input.
            if ribbon:
                print(ribbon)
            return input(f"{prompt} ")

        buffer = ""
        last_ribbon = ribbon
        self._last_ribbon = ribbon
        self._redraw(prompt, buffer, ribbon)
        try:
            while True:
                raw = self._read_char()
                if raw is None:  # poll tick — ribbon refresh + agent activity
                    if ribbon_fn:
                        ribbon = str(ribbon_fn() or "")
                    printed = bool(self.on_tick and self.on_tick())
                    if printed or ribbon != last_ribbon:
                        last_ribbon = ribbon
                        self._last_ribbon = ribbon
                        self._redraw(prompt, buffer, ribbon)
                    continue
                if raw == "\x1b":  # bare Esc — interrupt hook (arrows come as
                    consumed = False  # multi-char sequences and fall through)
                    if self.on_escape is not None:
                        consumed = bool(self.on_escape())
                    if consumed:
                        last_ribbon = ""
                        self._redraw(prompt, buffer, "")
                    continue
                if raw.startswith("\x1b"):
                    continue  # arrow key / escape sequence — ignore
                for char in raw:
                    if char in ("\r", "\n"):
                        self._clear_prompt_area(last_ribbon)
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
                self._redraw(prompt, buffer, last_ribbon)
        finally:
            self._exit_raw()


# Imported lazily by platform above; kept as tiny aliases so the methods read
# cleanly and patches are easy in tests.
if _POSIX:
    from os import read as os_read  # noqa: E402
else:  # pragma: no cover
    os_read = None

import time as _time  # noqa: E402

time_sleep = _time.sleep
