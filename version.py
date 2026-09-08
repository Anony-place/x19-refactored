"""X19 version metadata — single source of truth.

Every place that needs to report a version (banner, ``x19 --version``,
``x19 doctor``, generated reports, the self-upgrade pipeline) must read it
from here. Nothing else in the codebase may hard-code a version string.

Release notes
-------------
4.0.0  Terminal-native release.
       - The Flask web dashboard is removed. X19 is a CLI/TUI application only.
       - Every capability the web dashboard exposed (live mission control,
         swarm monitor, attack graph, finding triage, self-diagnostics,
         report export, provider configuration) is served by the terminal
         application in :mod:`ui`.
       - Subcommand CLI (``x19 <command>``) with ``--version``/``--help``
         working before provider setup runs.

3.0.0  Refactored architecture (brain / execution / parsers / learning).
"""
from __future__ import annotations

import os
import platform
import subprocess
import sys
from typing import Any, Dict, Optional

__version__ = "4.0.0"

#: Convenience alias — some tooling looks for ``VERSION``.
VERSION = __version__

APP_NAME = "X19"
APP_TAGLINE = "autonomous AI security assessment platform"
RELEASE_NAME = "Terminal Release"

#: Bumped when the stored session/config schema changes in a breaking way.
SCHEMA_VERSION = 2

#: Oldest Python this release is tested against.
MIN_PYTHON = (3, 9)

_ROOT = os.path.dirname(os.path.abspath(__file__))


def _parts() -> tuple:
    core = __version__.split("+", 1)[0].split("-", 1)[0]
    out = []
    for chunk in core.split("."):
        try:
            out.append(int(chunk))
        except ValueError:
            out.append(0)
    while len(out) < 3:
        out.append(0)
    return tuple(out[:3])


MAJOR, MINOR, PATCH = _parts()


def git_commit(short: bool = True) -> Optional[str]:
    """Return the current git commit, or ``None`` when unavailable."""
    if not os.path.isdir(os.path.join(_ROOT, ".git")):
        return None
    args = ["git", "rev-parse", "--short" if short else "HEAD", "HEAD"]
    try:
        proc = subprocess.run(
            args, cwd=_ROOT, capture_output=True, text=True, timeout=5
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def git_branch() -> Optional[str]:
    """Return the current git branch, or ``None`` when unavailable."""
    if not os.path.isdir(os.path.join(_ROOT, ".git")):
        return None
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=_ROOT, capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def version_info() -> Dict[str, Any]:
    """Machine-readable build metadata (used by ``--version --json``/doctor)."""
    return {
        "app": APP_NAME,
        "version": __version__,
        "release": RELEASE_NAME,
        "schema_version": SCHEMA_VERSION,
        "major": MAJOR,
        "minor": MINOR,
        "patch": PATCH,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "os": platform.system(),
        "arch": platform.machine(),
        "git_commit": git_commit(),
        "git_branch": git_branch(),
        "interface": "cli",
        "web_ui": False,
    }


def version_line() -> str:
    """One-line human version, e.g. ``X19 4.0.0 (abc1234)``."""
    commit = git_commit()
    suffix = f" ({commit})" if commit else ""
    return f"{APP_NAME} {__version__}{suffix}"


def python_supported() -> bool:
    return sys.version_info >= MIN_PYTHON


def python_requirement() -> str:
    return ".".join(str(p) for p in MIN_PYTHON)
