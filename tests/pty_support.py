"""Shared pty harness for the terminal-integrity tests.

Runs a child Python process with its stdin/stdout on a real pseudo-terminal,
feeds it keystrokes only *after* the live prompt is on screen, and reconstructs
the resulting terminal screen from the byte stream.

Screen reconstruction uses ``pyte`` (a terminal emulator) when it is installed
— that is the only way to see what the operator sees, because the byte stream is
full of cursor moves and erases. Without pyte the harness falls back to
stripping escape sequences, which is enough for "this text appeared / did not
appear" assertions but not for row-ghost checks.
"""
from __future__ import annotations

import os
import re
import select
import sys
import time
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parent.parent
TESTS = Path(__file__).resolve().parent

try:
    import pty as _pty

    HAVE_PTY = hasattr(_pty, "fork")
except ImportError:  # pragma: no cover - Windows
    HAVE_PTY = False

try:
    import pyte as _pyte

    HAVE_PYTE = True
except ImportError:  # pragma: no cover
    HAVE_PYTE = False

_ANSI_RE = re.compile(
    r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[=>]|[\x00-\x08\x0b-\x1f]"
)

#: Preamble every child script needs: repo on sys.path, deterministic width.
_PRELUDE = """
import os, sys, threading, time
sys.path.insert(0, {root!r})
sys.path.insert(0, {tests!r})
os.environ.setdefault("TERM", "xterm-256color")
"""


class FakeProvider:
    """A provider that streams a canned reply and announces its route."""

    def __init__(self, reply: str = "Hello. How can I help you today?"):
        self.reply = reply
        self.calls: List[Tuple[str, str]] = []

    def name(self) -> str:
        return "OpenRouter/openrouter/free"

    def chat(self, system: str, message: str) -> str:
        return "".join(self.chat_stream(system, message))

    def chat_stream(self, system: str, message: str):
        from providers import notice

        self.calls.append((system, message))
        notice("[router] OpenRouter/openrouter/free")
        for word in self.reply.split(" "):
            time.sleep(0.02)
            yield word + " "


def _child_body(noisy: bool) -> str:
    """The workspace, a fake agent/provider, and (optionally) a noisy thread."""
    noise = ""
    if noisy:
        noise = '''
def noisy():
    """Raw prints from an unrelated thread, like the toolchain does."""
    for _ in range(4):
        time.sleep(0.35)
        print("\\033[2m[tool] banner grabbed from 93.184.216.34:443\\033[0m", flush=True)


threading.Thread(target=noisy, daemon=True).start()
'''
    return f'''
from ui.console import init_console
from ui.app import ConsoleApp

console = init_console(force_terminal=True, width=int(os.environ.get("X19_TEST_COLS", "100")))


class FakeSession:
    data = {{"findings": [], "iterations": 0, "usage": {{}}}}


class FakeAgent:
    target = ""
    session = FakeSession()


import pty_support as harness  # noqa: E402  (tests dir is on sys.path)

ai = harness.FakeProvider()
app = ConsoleApp(FakeAgent(), version="4.0.0-test", ai=ai)
{noise}
sys.exit(app.run())
'''


NOISY_CHILD = _PRELUDE.format(root=str(ROOT), tests=str(TESTS)) + _child_body(noisy=True)
QUIET_CHILD = _PRELUDE.format(root=str(ROOT), tests=str(TESTS)) + _child_body(noisy=False)


class Screen:
    """The terminal screen a byte stream produced."""

    def __init__(self, rows: Sequence[str], data: bytes = b""):
        self._rows = [row.rstrip() for row in rows]
        self.data = data

    def rows(self) -> List[str]:
        return list(self._rows)

    def text(self) -> str:
        return "\n".join(self._rows)

    def rows_containing(self, needle: str) -> int:
        return sum(1 for row in self._rows if needle in row)

    def row_indexes(self, needle: str) -> List[int]:
        return [i for i, row in enumerate(self._rows) if needle in row]

    def __str__(self) -> str:  # pragma: no cover - failure messages
        return self.text()


def _render(data: bytes, cols: int, rows: int) -> Screen:
    if HAVE_PYTE:
        screen = _pyte.Screen(cols, rows)
        _pyte.ByteStream(screen).feed(data)
        lines = ["".join(screen.buffer[y][x].data for x in range(cols)) for y in sorted(screen.buffer)]
        return Screen(lines, data)
    text = _ANSI_RE.sub("", data.decode("utf-8", "replace"))
    return Screen(text.replace("\r\n", "\n").replace("\r", "\n").split("\n"), data)


def run_child(
    script: str,
    keys: Sequence[Tuple[float, str]] = (),
    *,
    cols: int = 100,
    rows: int = 30,
    ready: str = "you ❯",
    settle: float = 1.5,
    timeout: float = 45.0,
) -> Screen:
    """Run ``script`` on a pty, type ``keys`` (seconds after the prompt appears)."""
    if not HAVE_PTY:  # pragma: no cover - Windows
        raise RuntimeError("run_child needs a pty; guard the test with HAVE_PTY")

    pid, fd = _pty.fork()
    if pid == 0:  # child
        os.environ["TERM"] = "xterm-256color"
        os.environ["X19_TEST_COLS"] = str(cols)
        os.environ["LINES"] = str(rows)
        os.environ["COLUMNS"] = str(cols)
        try:
            os.execv(sys.executable, [sys.executable, "-c", script])
        finally:  # pragma: no cover
            os._exit(127)

    captured = bytearray()
    queue = list(keys)
    started: Optional[float] = None
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            readable, _, _ = select.select([fd], [], [], 0.1)
            if readable:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                captured += chunk
            if started is None:
                if not ready or ready.encode() in bytes(captured):
                    started = time.time()
                continue
            elapsed = time.time() - started
            if queue and elapsed >= queue[0][0]:
                _, text = queue.pop(0)
                try:
                    os.write(fd, text.encode() if isinstance(text, str) else text)
                except OSError:
                    break
            if not queue and elapsed > (keys[-1][0] + settle if keys else settle):
                break
        # drain whatever the child still has to say
        while time.time() < deadline:
            readable, _, _ = select.select([fd], [], [], 1.0)
            if not readable:
                break
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            captured += chunk
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
    return _render(bytes(captured), cols, rows)
