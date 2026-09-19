"""Resolve X19_HOME for standalone skill scripts.

Skill scripts may run outside the X19 process (e.g. system Python,
nix env, CI) where ``x19_constants`` is not importable.  This module
provides the same ``get_x19_home()`` and ``display_x19_home()``
contracts as ``x19_constants`` without requiring it on ``sys.path``.

When ``x19_constants`` IS available it is used directly so that any
future enhancements (profile resolution, Docker detection, etc.) are
picked up automatically.  The fallback path replicates the core logic
from ``x19_constants.py`` using only the stdlib.

All scripts under ``google-workspace/scripts/`` should import from here
instead of duplicating the ``X19_HOME = Path(os.getenv(...))`` pattern.
"""

from __future__ import annotations

import os
from pathlib import Path

try:
    from x19_constants import display_x19_home as display_x19_home
    from x19_constants import get_x19_home as get_x19_home
except (ModuleNotFoundError, ImportError):

    def get_x19_home() -> Path:
        """Return the X19 home directory (default: ~/.x19).

        Mirrors ``x19_constants.get_x19_home()``."""
        val = os.environ.get("X19_HOME", "").strip()
        return Path(val) if val else Path.home() / ".x19"

    def display_x19_home() -> str:
        """Return a user-friendly ``~/``-shortened display string.

        Mirrors ``x19_constants.display_x19_home()``."""
        home = get_x19_home()
        try:
            return "~/" + home.relative_to(Path.home()).as_posix()
        except ValueError:
            return str(home)
