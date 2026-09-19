"""The harness must refuse to let a test mutate the checkout it runs in.

Incident 20260919: a test drove the ``x19 update`` post-swap tail, which
``tests/x19_cli/conftest.py`` runs in-process by default, without requesting the
``isolated_update_runtime`` fixture that repoints ``PROJECT_ROOT`` at a tmp dir.
The tail therefore ran against the developer's real working tree — it stashed the
session's uncommitted work under an ``x19-update-autostash-<timestamp>`` label, ran
``git reset --hard HEAD`` five times and checked out ``main``. Every test still
passed, so nothing noticed for forty minutes.

``tests/conftest.py::_block_destructive_git_on_the_host_checkout`` is the circuit
breaker. These tests cover both directions: it must refuse destructive git against
this checkout, and it must not interfere with read-only git here or with any git a
test runs inside its own ``tmp_path`` repository.

Ordering matters in the refusal tests. Each one asserts the wrapper is actually
installed *before* invoking anything, so a guard that silently failed to wire up
fails on that assertion instead of running real git against the working tree. The
probe command is ``checkout`` of a branch that does not exist, which git rejects
without touching HEAD or the worktree even if the guard were absent.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.conftest import (  # noqa: E402
    _HOST_CHECKOUT,
    _host_git_is_destructive,
)

from x19_cli import update_cmd, update_cmd_stash  # noqa: E402

# A branch that cannot exist, so the probe is inert even if the guard is not.
UNCREATABLE_BRANCH = "x19-guard-probe-branch-does-not-exist"


def _guarded(fn) -> bool:
    return getattr(fn, "_x19_host_git_guarded", False) is True


# ============================================================
# the classifier — what counts as destructive
# ============================================================


@pytest.mark.parametrize("argv", [
    ["checkout", "main"],
    ["checkout", "-B", "main", "origin/main"],
    ["switch", "feature"],
    ["reset", "--hard", "HEAD"],
    ["reset"],
    ["clean", "-fd"],
    ["restore", "."],
    ["stash", "push", "--include-untracked", "-m", "x19-update-autostash-1"],
    ["stash", "pop"],
    ["stash", "apply", "stash@{0}"],
    ["stash", "drop"],
    ["merge", "origin/main"],
    ["rebase", "origin/main"],
    ["pull", "--ff-only", "origin", "main"],
    ["fetch", "origin"],
    ["push", "origin", "main"],
    ["commit", "-m", "x"],
    ["add", "-A"],
    ["rm", "--cached", "f"],
    ["cherry-pick", "abc123"],
    ["revert", "abc123"],
    ["apply", "patch.diff"],
    ["tag", "v9"],
    ["branch", "-D", "old"],
    ["branch", "new-branch"],
    ["worktree", "add", "../x"],
    ["init"],
    ["clone", "https://example.invalid/r.git"],
])
def test_mutating_git_verbs_are_classified_destructive(argv):
    assert _host_git_is_destructive(argv) is True


@pytest.mark.parametrize("argv", [
    ["rev-parse", "--is-inside-work-tree"],
    ["rev-parse", "HEAD"],
    ["rev-parse", "--is-shallow-repository"],
    ["status", "--porcelain"],
    ["ls-files", "--unmerged"],
    ["log", "--oneline", "-5"],
    ["rev-list", "HEAD..origin/main", "--count"],
    ["diff", "--stat"],
    ["show", "HEAD"],
    ["describe", "--tags"],
    ["stash", "list"],
    ["stash", "list", "--format=%gd %H"],
    ["stash", "show", "stash@{0}"],
    ["branch", "--list"],
    ["branch"],
    ["branch", "-v"],
    ["config", "--get", "user.email"],
    ["remote", "-v"],
])
def test_read_only_git_verbs_are_not_classified_destructive(argv):
    """Tests legitimately inspect the repository they live in."""
    assert _host_git_is_destructive(argv) is False


def test_an_empty_argv_is_not_destructive():
    assert _host_git_is_destructive([]) is False
    assert _host_git_is_destructive(None) is False


# ============================================================
# cwd resolution — the bug that let a real reset through
# ============================================================


def test_the_cwd_is_read_from_whichever_position_the_runner_uses():
    """Regression, and the reason this is a pure function rather than a probe.

    ``_git_run(git_cmd, args, cwd=None)`` carries the cwd third, but
    ``_reset_hard(git_cmd, cwd)`` and ``_stash_local_changes_if_needed(git_cmd,
    cwd)`` carry it *second*. The first version of the guard read that second
    positional as the argv, so it computed no cwd at all, concluded the call was
    not aimed at the host checkout, and let a real ``git reset --hard HEAD``
    through — which discarded the uncommitted guard itself. Resolving this
    without executing git means a repeat of that bug fails here instead of
    eating the working tree.
    """
    from tests.conftest import _effective_git_cwd

    host = _HOST_CHECKOUT
    # third positional, and as a keyword
    assert _effective_git_cwd(["status"], (host,), None, forced_args=None, default_cwd=None) == host
    assert _effective_git_cwd(["status"], (), host, forced_args=None, default_cwd=None) == host
    # second positional: the (git_cmd, cwd, ...) runners
    assert _effective_git_cwd(host, (), None, forced_args=["reset"], default_cwd=None) == host
    # the default that makes PROJECT_ROOT dangerous in the first place
    assert _effective_git_cwd(["status"], (), None, forced_args=None, default_cwd=lambda: host) == host
    # an explicit cwd wins over the default
    assert _effective_git_cwd(["status"], (host,), None, forced_args=None,
                              default_cwd=lambda: "/elsewhere") == host
    assert _effective_git_cwd(["status"], (), None, forced_args=None, default_cwd=None) is None


# ============================================================
# the wiring — the guard is really installed
# ============================================================


def test_every_destructive_entry_point_is_wrapped_for_every_test():
    """Autouse means autouse: the runners a test would reach are already guarded."""
    assert _guarded(update_cmd._git_run), "update_cmd._git_run is the default-cwd choke point"
    assert _guarded(update_cmd_stash._git_quiet)
    assert _guarded(update_cmd_stash._reset_hard)
    assert _guarded(update_cmd_stash._stash_local_changes_if_needed)


def test_the_opt_out_marker_is_registered():
    """An unregistered marker would warn, and `--strict-markers` would error."""
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "real_host_git:" in pyproject


# ============================================================
# refusal — destructive git against this checkout
# ============================================================


def test_destructive_git_against_the_host_checkout_is_refused():
    assert _guarded(update_cmd._git_run), "guard not installed; refusing to run real git"
    with pytest.raises(AssertionError) as excinfo:
        update_cmd._git_run(["git"], ["checkout", UNCREATABLE_BRANCH], cwd=_HOST_CHECKOUT)
    message = str(excinfo.value)
    assert "destructive git inside the checkout the suite lives in" in message
    assert "isolated_update_runtime" in message and "real_host_git" in message


def test_the_default_cwd_is_what_makes_this_dangerous():
    """`_git_run` with no cwd runs in PROJECT_ROOT — under a test run, right here."""
    assert _guarded(update_cmd._git_run), "guard not installed; refusing to run real git"
    project_root = Path(update_cmd._m().PROJECT_ROOT).resolve()
    assert project_root == _HOST_CHECKOUT or _HOST_CHECKOUT in project_root.parents, (
        "this test proves the incident's path: PROJECT_ROOT is the host checkout"
    )
    with pytest.raises(AssertionError):
        update_cmd._git_run(["git"], ["checkout", UNCREATABLE_BRANCH])


def test_reset_hard_on_the_host_checkout_is_refused():
    assert _guarded(update_cmd_stash._reset_hard), "guard not installed; refusing to run real git"
    with pytest.raises(AssertionError):
        update_cmd_stash._reset_hard(["git"], _HOST_CHECKOUT)


def test_the_update_autostash_is_refused_on_the_host_checkout():
    """The exact call that stashed a session's uncommitted work."""
    assert _guarded(update_cmd_stash._stash_local_changes_if_needed), (
        "guard not installed; refusing to run real git"
    )
    with pytest.raises(AssertionError):
        update_cmd_stash._stash_local_changes_if_needed(["git"], _HOST_CHECKOUT)


def test_a_git_child_of_the_host_checkout_is_also_refused():
    """The guard resolves paths, so a nested cwd cannot slip underneath it."""
    assert _guarded(update_cmd._git_run), "guard not installed; refusing to run real git"
    with pytest.raises(AssertionError):
        update_cmd._git_run(
            ["git"], ["checkout", UNCREATABLE_BRANCH], cwd=_HOST_CHECKOUT / "scripts"
        )


# ============================================================
# pass-through — the guard must not break legitimate tests
# ============================================================


def test_read_only_git_against_the_host_checkout_still_runs():
    result = update_cmd._git_run(["git"], ["rev-parse", "--is-inside-work-tree"],
                                 cwd=_HOST_CHECKOUT)
    assert result.returncode == 0
    assert result.stdout.strip() == "true"


def test_stash_list_against_the_host_checkout_still_runs():
    """Reading the stash list is how a test would detect a leaked autostash."""
    result = update_cmd._git_run(["git"], ["stash", "list"], cwd=_HOST_CHECKOUT)
    assert result.returncode == 0


def test_destructive_git_inside_a_tmp_repository_passes_through(tmp_path):
    """Isolation still works: a test's own checkout is none of the guard's business."""
    repo = tmp_path / "managed"
    repo.mkdir()
    for args in (["init", "-q"], ["config", "user.email", "t@example.com"],
                 ["config", "user.name", "t"], ["checkout", "-q", "-b", "main"]):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
    (repo / "f.txt").write_text("one\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "seed"], cwd=repo, check=True, capture_output=True)

    created = update_cmd._git_run(["git"], ["checkout", "-b", "feature"], cwd=repo)
    assert created.returncode == 0, created.stderr
    head = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo,
                          check=True, capture_output=True, text=True)
    assert head.stdout.strip() == "feature"

    # and the mutating helpers run for real there too
    (repo / "dirty.txt").write_text("uncommitted\n", encoding="utf-8")
    stashed = update_cmd_stash._stash_local_changes_if_needed(["git"], repo)
    assert stashed, "the autostash must still work against a test's own checkout"
    listing = subprocess.run(["git", "stash", "list"], cwd=repo, check=True,
                             capture_output=True, text=True)
    assert "x19-update-autostash-" in listing.stdout


def test_no_autostash_was_left_on_the_host_checkout():
    """The incident's signature: an ``x19-update-autostash-*`` entry in this repo."""
    listing = subprocess.run(
        ["git", "stash", "list", "--format=%gd %s"], cwd=_HOST_CHECKOUT,
        check=True, capture_output=True, text=True,
    )
    leaked = [line for line in listing.stdout.splitlines() if "x19-update-autostash-" in line]
    assert not leaked, f"the update tail stashed this checkout: {leaked}"
