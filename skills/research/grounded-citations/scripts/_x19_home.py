"""Resolve X19_HOME for standalone skill scripts.

Skill scripts may run outside the X19 process (system Python, nix env,
CI) where ``x19_constants`` is not importable.  This module provides the
same ``get_x19_home()`` contract without requiring it on ``sys.path``.

When ``x19_constants`` IS available it is used directly so profile
resolution and any future enhancements are picked up automatically.
"""

from __future__ import annotations

import os
from pathlib import Path

try:
    from x19_constants import get_x19_home as get_x19_home
except (ModuleNotFoundError, ImportError):

    def get_x19_home() -> Path:
        """Return the X19 home directory (default: ``~/.x19``)."""
        val = os.environ.get("X19_HOME", "").strip()
        return Path(val) if val else Path.home() / ".x19"
