"""Small terminal behavior fixes kept outside the UI renderer.

The interactive console is intentionally simple.  Natural assessment phrases
such as ``target example.com`` should enter the real X19 assessment path,
not be sent to the LLM as ordinary chat where a model may falsely claim it
cannot access tools.
"""
from __future__ import annotations

import shlex
from typing import Any


_ASSESSMENT_WORDS = {"target", "scan", "pentest", "assess", "enumerate", "recon"}


def _natural_target(line: str) -> str:
    try:
        parts = shlex.split(line)
    except ValueError:
        parts = line.split()
    if not parts or parts[0].lower() not in _ASSESSMENT_WORDS:
        return ""
    if len(parts) < 2:
        return ""
    return parts[1].strip().rstrip(".,")


def install() -> None:
    """Patch ConsoleApp input routing once, without replacing the UI."""
    try:
        from ui.app import ConsoleApp
    except Exception:
        return
    if getattr(ConsoleApp, "_x19_terminal_behavior_installed", False):
        return
    original = ConsoleApp.handle

    def handle(self: Any, line: str) -> None:
        if not line.startswith("/"):
            target = _natural_target(line)
            if target:
                self.cmd_target(target)
                return
        return original(self, line)

    ConsoleApp.handle = handle
    ConsoleApp._x19_terminal_behavior_installed = True
