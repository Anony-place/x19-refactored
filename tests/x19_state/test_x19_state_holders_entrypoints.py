"""Holder detection must recognize every console script the package declares.

``x19_state_holders._looks_like_x19`` decides whether a running process is ours,
which is what the WAL holder scan, the safe-shutdown path and the "who has the
database open" diagnostics all rest on. A process it fails to recognize is
invisible to those paths.

The expected names are read from ``pyproject.toml``'s ``[project.scripts]``
rather than written out here. That is the point of the test: a brand rewrite once
mapped two distinct entry points onto one string, leaving
``frozenset({"x19", "x19", "x19-acp"})`` — a two-member set spelled as a
three-member literal, so the agent entry point stopped being recognized and
nothing failed. Deriving the expectation from the packaging metadata means
declaring a new console script without teaching holder detection about it is a
test failure, and so is losing one.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

from x19_state_holders import _X19_EXECUTABLES, _looks_like_x19

REPO_ROOT = Path(__file__).resolve().parents[2]


def _declared_console_scripts() -> set[str]:
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        data = tomllib.load(handle)
    scripts = data["project"]["scripts"]
    assert scripts, "pyproject.toml declares no console scripts; test is stale"
    return set(scripts)


def test_pyproject_declares_the_three_entry_points():
    """Guard the guard: if this set changes, the assertions below must be revisited."""
    assert _declared_console_scripts() == {"x19", "x19-agent", "x19-acp"}


def test_executable_set_matches_declared_console_scripts_exactly():
    """Equality, not subset: a collapsed duplicate shrinks the set silently."""
    assert _X19_EXECUTABLES == _declared_console_scripts()


def test_executable_set_has_no_duplicate_collapsed_member():
    """A frozenset literal cannot report its own lost member, so count the source."""
    source = (REPO_ROOT / "x19_state_holders.py").read_text(encoding="utf-8")
    line = next(ln for ln in source.splitlines() if "_X19_EXECUTABLES = frozenset(" in ln)
    names = re.findall(r'"([^"]+)"|\'([^\']+)\'', line)
    names = [a or b for a, b in names]
    assert len(names) == len(set(names)), f"duplicate entry in {line.strip()}"
    assert len(names) == len(_X19_EXECUTABLES), (
        f"{line.strip()} writes {len(names)} names but the set holds "
        f"{len(_X19_EXECUTABLES)} — a member was lost to a duplicate"
    )


@pytest.mark.parametrize("name", sorted(_declared_console_scripts()))
def test_every_entry_point_is_recognized_as_a_process(name):
    """Each console script, invoked directly, with and without the Windows suffix.

    Only bare basenames are asserted here: `_looks_like_x19` resolves argv[0]
    through `os.path.basename`, which is platform-specific, so a Windows-style
    path is not a meaningful input on POSIX.
    """
    assert _looks_like_x19([name, "--version"]), name
    assert _looks_like_x19([f"{name}.exe"]), name
    assert _looks_like_x19([f"/usr/local/bin/{name}"]), name


def test_python_module_and_script_forms_are_recognized():
    """The venv launchers run the interpreter against a module or a script."""
    assert _looks_like_x19(["python", "-m", "x19_cli.main", "chat"])
    assert _looks_like_x19(["python3", "-m", "acp_adapter"])
    assert _looks_like_x19(["/opt/x19/venv/bin/python", "/opt/x19/run_agent.py"])
    assert _looks_like_x19(["python", "/opt/x19/x19_cli/main.py"])


def test_unrelated_processes_are_not_claimed():
    """Recognition is a claim of ownership; it must stay narrow."""
    assert not _looks_like_x19([])
    assert not _looks_like_x19(["vim", "x19_state_holders.py"])
    assert not _looks_like_x19(["python", "-c", "print(1)"])
    assert not _looks_like_x19(["python", "-m", "pytest"])
    assert not _looks_like_x19(["x19-notes"])
    assert not _looks_like_x19(["node", "/opt/x19/run_agent.py"])
