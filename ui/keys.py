"""Non-blocking keyboard capture for the live mission dashboard.

The dashboard needs key bindings (``q`` quit, ``r`` report, ``g`` graph) while
it is redrawing itself, so it cannot use ``input()``. This module gives it a
best-effort, always-safe key reader:

* POSIX  — ``termios``/``tty`` raw mode + non-blocking ``select``.
* Windows — ``msvcrt.kbhit``/``getwch``.
* Anything else, or no TTY (pipes, CI, tests) — reads nothing and never raises.

The original terminal settings are always restored on exit, including on
exceptions, so a crash inside the dashboard can never leave the user's shell
in raw mode.
"""
from __future__ import annotations

import os
import sys
from typing import Optional

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


def key_capture_supported() -> bool:
    """True when single-key reads are possible in this environment."""
    if not (_POSIX or _WINDOWS):
        return False
    try:
        return bool(sys.stdin and sys.stdin.isatty())
    except Exception:
        return False


class KeyListener:
    """Context manager that yields single key presses without blocking."""

    def __init__(self, enabled: Optional[bool] = None):
        self.enabled = key_capture_supported() if enabled is None else bool(enabled)
        self._saved = None
        self._active = False

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self) -> "KeyListener":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def start(self) -> None:
        if not self.enabled or self._active:
            return
        if _POSIX:
            try:
                self._saved = termios.tcgetattr(sys.stdin.fileno())
                tty.setcbreak(sys.stdin.fileno())
                self._active = True
            except Exception:
                self.enabled = False
                self._saved = None

    def stop(self) -> None:
        if not self._active or not self._saved:
            return
        try:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self._saved)
        except Exception:
            pass
        finally:
            self._active = False
            self._saved = None

    # -- reading -----------------------------------------------------------
    def read(self) -> Optional[str]:
        """Return one normalised key name, or ``None`` if nothing was pressed."""
        if not self.enabled:
            return None
        try:
            if _POSIX and self._active:
                ready, _, _ = select.select([sys.stdin], [], [], 0)
                if not ready:
                    return None
                raw = os.read(sys.stdin.fileno(), 8)
                return self._normalise(raw.decode("utf-8", "replace"))
            if _WINDOWS and msvcrt.kbhit():
                char = msvcrt.getwch()
                if char in ("\x00", "\xe0"):
                    return self._normalise(msvcrt.getwch())
                return self._normalise(char)
        except Exception:
            return None
        return None

    @staticmethod
    def _normalise(raw: str) -> Optional[str]:
        if not raw:
            return None
        first = raw[0]
        if first == "\x1b":
            # Arrow keys / escape sequences — only the named ones matter here.
            if raw in ("\x1b[A", "\x1bOA"):
                return "up"
            if raw in ("\x1b[B", "\x1bOB"):
                return "down"
            return "esc"
        if first in ("\r", "\n"):
            return "enter"
        if first == "\x03":
            return "ctrl-c"
        if first == "\x0c":
            return "ctrl-l"
        if first == "\x7f" or first == "\x08":
            return "backspace"
        if first == "\t":
            return "tab"
        if first < " ":
            return f"ctrl-{chr(ord(first) + 96)}"
        return first
