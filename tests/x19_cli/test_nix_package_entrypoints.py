"""The Nix package must wrap, and its checks must verify, every console script.

``nix/x19.nix`` builds ``$out/bin/<name>`` by mapping ``makeWrapper`` over a
literal list of entry-point names, and ``nix/checks.nix`` has two derivations
whose whole job is to notice a missing one:

* ``package-contents`` -- ``test -x ${x19}/bin/<name>`` for each binary
* ``entry-points-sync`` -- "Verify every pyproject.toml [project.scripts] entry
  has a wrapped binary", iterating ``for bin in ...``

A brand rewrite once mapped two distinct entry points onto one string, so all
three collapsed together: the wrapper list became ``["x19" "x19" "x19-acp"]``,
``package-contents`` tested ``bin/x19`` twice, and ``entry-points-sync`` iterated
``x19 x19 x19-acp``. The Nix package therefore shipped without ``bin/x19-agent``,
and both guards that existed to detect exactly that were broken in the same way,
so nothing failed. ``nix`` is not runnable in every CI environment, which is why
the lists are checked here as text.

Expectations are read from ``pyproject.toml``'s ``[project.scripts]`` rather than
written out, so declaring a new console script without teaching the packaging
about it is a failure -- and so is losing one to a duplicate.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
NIX_PACKAGE = REPO_ROOT / "nix" / "x19.nix"
NIX_CHECKS = REPO_ROOT / "nix" / "checks.nix"


def _declared_console_scripts() -> set[str]:
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        data = tomllib.load(handle)
    scripts = data["project"]["scripts"]
    assert scripts, "pyproject.toml declares no console scripts; test is stale"
    return set(scripts)


def _nix_string_lists(text: str) -> list[list[str]]:
    """Every bracketed run of two or more quoted strings (Nix list syntax)."""
    return [
        re.findall(r'"([^"]*)"', body)
        for body in re.findall(r"\[\s*((?:\"[^\"]*\"\s*){2,})\]", text)
    ]


def _entry_point_lists(text: str) -> list[list[str]]:
    """Only the lists that actually look like console-script names.

    Two declared names are required, so a list of service names that happens to
    include ``x19`` (``["x19" "x19-backend"]`` in checks.nix) is not mistaken for
    a list of entry points.
    """
    declared = _declared_console_scripts()
    return [items for items in _nix_string_lists(text) if len(declared & set(items)) >= 2]


def test_pyproject_declares_the_three_entry_points():
    """Guard the guard: if this set changes, every assertion below must be revisited."""
    assert _declared_console_scripts() == {"x19", "x19-agent", "x19-acp"}


def test_nix_files_exist():
    for path in (NIX_PACKAGE, NIX_CHECKS):
        assert path.is_file(), f"{path.relative_to(REPO_ROOT)} is missing; test is stale"


def test_wrapper_list_covers_every_console_script():
    """``makeWrapper`` runs once per name here, so a lost name is a lost binary."""
    lists = _entry_point_lists(NIX_PACKAGE.read_text(encoding="utf-8"))
    assert lists, "no console-script list found in nix/x19.nix; test is stale"
    for items in lists:
        assert set(items) == _declared_console_scripts(), (
            f"nix/x19.nix wraps {sorted(set(items))} but pyproject declares "
            f"{sorted(_declared_console_scripts())}"
        )


def test_wrapper_list_has_no_collapsed_duplicate():
    """A duplicate entry hides a lost one: the list would still look complete."""
    for items in _entry_point_lists(NIX_PACKAGE.read_text(encoding="utf-8")):
        assert len(items) == len(set(items)), (
            f"nix/x19.nix lists {items} -- a name appears twice, so the literal "
            "is longer than the set of binaries actually wrapped"
        )


def _checked_binaries() -> list[str]:
    """``test -x ${x19}/bin/<name>`` targets in the package-contents check."""
    text = NIX_CHECKS.read_text(encoding="utf-8")
    block = re.search(r"package-contents = .*?''(.*?)''", text, re.S)
    assert block, "package-contents check not found in nix/checks.nix; test is stale"
    return re.findall(r"test -x \$\{x19\}/bin/([\w.-]+)", block.group(1))


def test_package_contents_checks_the_cli_and_no_binary_twice():
    """package-contents is a spot check, but it must not test one name twice."""
    checked = _checked_binaries()
    assert "x19" in checked, "package-contents no longer checks the CLI binary"
    assert len(checked) == len(set(checked)), (
        f"package-contents tests {checked} -- a binary is checked twice, which is "
        "how the collapsed wrapper list went unnoticed"
    )


def test_the_two_checks_together_cover_every_console_script():
    """entry-points-sync is the completeness guard; between them none may be lost."""
    covered = set(_checked_binaries()) | set(_entry_points_sync_loop())
    missing = _declared_console_scripts() - covered
    assert not missing, (
        f"neither Nix check verifies {sorted(missing)}, so the package could ship "
        "without it and every check would still pass"
    )


def _entry_points_sync_loop() -> list[str]:
    text = NIX_CHECKS.read_text(encoding="utf-8")
    block = re.search(r"entry-points-sync = .*?''(.*?)''", text, re.S)
    assert block, "entry-points-sync check not found in nix/checks.nix; test is stale"
    words = re.search(r"for bin in ([^;]+); do", block.group(1))
    assert words, "entry-points-sync no longer iterates a 'for bin in' list; test is stale"
    return words.group(1).split()


def test_entry_points_sync_iterates_every_console_script():
    """This check advertises itself as covering every [project.scripts] entry."""
    loop = _entry_points_sync_loop()
    assert set(loop) == _declared_console_scripts(), (
        f"entry-points-sync iterates {sorted(set(loop))} but pyproject declares "
        f"{sorted(_declared_console_scripts())}"
    )


def test_entry_points_sync_list_has_no_collapsed_duplicate():
    loop = _entry_points_sync_loop()
    assert len(loop) == len(set(loop)), (
        f"entry-points-sync iterates {loop} -- a name is repeated, so the loop is "
        "longer than the set of binaries it verifies"
    )


def test_no_nix_file_lists_a_console_script_twice_in_one_literal():
    """Generic net over every Nix file: the same collapse anywhere is a failure."""
    declared = _declared_console_scripts()
    offenders = []
    scanned = 0
    for path in sorted((REPO_ROOT / "nix").glob("*.nix")):
        scanned += 1
        for items in _entry_point_lists(path.read_text(encoding="utf-8")):
            if len(items) != len(set(items)):
                offenders.append(f"{path.name}: {items}")
    assert scanned > 1, "expected several nix/*.nix files; test is stale"
    assert not offenders, (
        "a Nix list of console scripts repeated a name, so it is shorter as a set "
        f"than it looks: " + "; ".join(offenders)
    )
