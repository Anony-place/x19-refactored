"""Tests for x19_cli.relaunch — unified self-relaunch utility."""

import sys

import pytest

from x19_cli import relaunch as relaunch_mod


class TestResolveX19Bin:
    def test_prefers_absolute_argv0_when_executable(self, monkeypatch):
        fake = "/nix/store/abc/bin/x19"
        monkeypatch.setattr(sys, "argv", [fake])
        monkeypatch.setattr(relaunch_mod.os.path, "isfile", lambda p: p == fake)
        monkeypatch.setattr(relaunch_mod.os, "access", lambda p, mode: p == fake)
        assert relaunch_mod.resolve_x19_bin() == fake

    def test_resolves_relative_argv0(self, monkeypatch, tmp_path):
        fake = tmp_path / "x19"
        fake.write_text("#!/bin/sh\n")
        fake.chmod(0o755)
        monkeypatch.setattr(sys, "argv", [str(fake.name)])
        monkeypatch.chdir(tmp_path)
        # Ensure we don't accidentally match a real 'x19' on PATH
        monkeypatch.setattr(relaunch_mod.shutil, "which", lambda _name: None)
        assert relaunch_mod.resolve_x19_bin() == str(fake)

    def test_falls_back_to_path_which(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["-c"])  # not a real path
        monkeypatch.setattr(
            relaunch_mod.shutil, "which", lambda name: "/usr/bin/x19" if name == "x19" else None
        )
        assert relaunch_mod.resolve_x19_bin() == "/usr/bin/x19"


class TestExtractInheritedFlags:
    def test_extracts_tui_and_dev(self):
        argv = ["--tui", "--dev", "chat"]
        assert relaunch_mod._extract_inherited_flags(argv) == ["--tui", "--dev"]


    def test_preserves_multiple_skills(self):
        argv = ["-s", "foo", "-s", "bar", "--tui"]
        assert relaunch_mod._extract_inherited_flags(argv) == ["-s", "foo", "-s", "bar", "--tui"]


class TestInheritedFlagTable:
    """Sanity-check the argparse-introspected table that drives extraction."""

    def test_short_and_long_aliases_are_paired(self):
        table = dict(relaunch_mod._INHERITED_FLAGS_TABLE)
        # Each pair declared together in the parser shares takes_value.
        for short, long_ in [
            ("-p", "--profile"),
            ("-m", "--model"),
            ("-s", "--skills"),
        ]:
            assert table[short] == table[long_], f"{short}/{long_} disagree"


    def test_excluded_flags_are_not_inherited(self):
        table = dict(relaunch_mod._INHERITED_FLAGS_TABLE)
        # --worktree creates a new worktree per process; inheriting would
        # orphan the parent's. Chat-only flags (--quiet/-Q, --verbose/-v,
        # --source) can't be in argv at the existing relaunch callsites.
        for flag in ["-w", "--worktree", "-Q", "--quiet", "-v", "--verbose", "--source"]:
            assert flag not in table, f"{flag} should not be inherited"


class TestBuildRelaunchArgv:
    def test_uses_bin_when_available(self, monkeypatch):
        monkeypatch.setattr(relaunch_mod, "resolve_x19_bin", lambda: "/usr/bin/x19")
        argv = relaunch_mod.build_relaunch_argv(["--resume", "abc"])
        assert argv[0] == "/usr/bin/x19"


    def test_preserves_inherited_flags(self, monkeypatch):
        monkeypatch.setattr(relaunch_mod, "resolve_x19_bin", lambda: "/usr/bin/x19")
        original = ["--tui", "--dev", "--profile", "work", "sessions", "browse"]
        argv = relaunch_mod.build_relaunch_argv(["--resume", "abc"], original_argv=original)
        assert "--tui" in argv
        assert "--dev" in argv
        assert "--profile" in argv
        assert "work" in argv
        assert "--resume" in argv
        assert "abc" in argv
        # The original subcommand should not survive
        assert "sessions" not in argv
        assert "browse" not in argv

    def test_can_disable_preserve(self, monkeypatch):
        monkeypatch.setattr(relaunch_mod, "resolve_x19_bin", lambda: "/usr/bin/x19")
        original = ["--tui", "chat"]
        argv = relaunch_mod.build_relaunch_argv(
            ["--resume", "abc"], preserve_inherited=False, original_argv=original
        )
        assert "--tui" not in argv
        assert argv == ["/usr/bin/x19", "--resume", "abc"]


class TestRelaunch:
    def test_calls_execvp(self, monkeypatch):
        calls = []

        def fake_execvp(path, argv):
            calls.append((path, argv))
            raise SystemExit(0)

        monkeypatch.setattr(relaunch_mod.os, "execvp", fake_execvp)
        monkeypatch.setattr(relaunch_mod, "resolve_x19_bin", lambda: "/usr/bin/x19")

        with pytest.raises(SystemExit):
            relaunch_mod.relaunch(["--resume", "abc"])

        assert calls == [("/usr/bin/x19", ["/usr/bin/x19", "--resume", "abc"])]

    @pytest.mark.windows_only
    def test_windows_uses_subprocess_not_execvp(self, monkeypatch):
        """On Windows, os.execvp raises OSError "Exec format error" when the
        target is a .cmd shim or console-script wrapper (both common for
        x19).  relaunch() must detect win32 and use subprocess.run +
        sys.exit instead.

        ``windows_only``: the bug is that ``os.execvp`` cannot exec a Windows
        console-script shim. On Linux ``execvp`` works fine, so a patched
        platform only re-asserted the branch we wrote, never the constraint
        that motivated it.
        """
        monkeypatch.setattr(relaunch_mod, "resolve_x19_bin", lambda: r"C:\Users\test\x19.exe")
        # Pin sys.argv: relaunch() preserves inherited flags from the LIVE
        # argv, so under pytest it happily inherited the runner's own
        # "-m 'windows_only and not integration'" and the assertion below saw
        # them in the child argv. Nothing to do with Windows — it only showed
        # up here because this is the first lane that actually executes the
        # test, and -m is how that lane selects it.
        monkeypatch.setattr(relaunch_mod.sys, "argv", [r"C:\Users\test\x19.exe"])

        import subprocess as _subprocess

        captured_argv = []

        def fake_subprocess_run(argv, **kwargs):
            captured_argv.append(list(argv))
            class _Result:
                returncode = 0
            return _Result()

        monkeypatch.setattr(_subprocess, "run", fake_subprocess_run)

        # execvp MUST NOT be called on Windows — route must go through subprocess
        execvp_calls = []

        def fake_execvp(*args, **kwargs):
            execvp_calls.append(args)
            raise AssertionError("os.execvp must not be called on Windows")

        monkeypatch.setattr(relaunch_mod.os, "execvp", fake_execvp)

        with pytest.raises(SystemExit) as exc_info:
            relaunch_mod.relaunch(["chat"])

        assert exc_info.value.code == 0
        assert execvp_calls == []
        assert captured_argv == [[r"C:\Users\test\x19.exe", "chat"]]

    @pytest.mark.windows_only
    def test_windows_propagates_child_exit_code(self, monkeypatch):
        """A non-zero exit from the child should flow through to sys.exit."""
        monkeypatch.setattr(relaunch_mod, "resolve_x19_bin", lambda: r"C:\x19.exe")

        import subprocess as _subprocess

        def fake_run(argv, **kwargs):
            class _Result:
                returncode = 42
            return _Result()

        monkeypatch.setattr(_subprocess, "run", fake_run)
        monkeypatch.setattr(relaunch_mod.os, "execvp", lambda *a, **kw: None)

        with pytest.raises(SystemExit) as exc_info:
            relaunch_mod.relaunch(["chat"])
        assert exc_info.value.code == 42


class TestResolveX19BinWindowsPyGuard:
    """On Windows, resolve_x19_bin MUST NOT return a .py path.
    os.access(x, os.X_OK) returns True for .py files on Windows because
    PATHEXT includes .py when the Python launcher is installed — but
    subprocess.run can't actually exec a .py directly, so the relaunch
    would fail with the cryptic "%1 is not a valid Win32 application" error.

    The Windows cases are ``windows_only``: the PATHEXT-driven ``os.access``
    result the guard defends against simply does not occur on POSIX, so a
    faked ``sys.platform`` could never reproduce the hazard.
    """

    @pytest.mark.windows_only
    def test_windows_rejects_py_argv0_falls_through_to_path(self, monkeypatch, tmp_path):
        """On Windows, if sys.argv[0] is a .py file, we must skip the
        argv[0] fast-path and fall through to PATH / python -m."""
        # Build a fake .py script that "passes" the isfile + X_OK checks.
        script = tmp_path / "main.py"
        script.write_text("# stub")

        monkeypatch.setattr(relaunch_mod.sys, "argv", [str(script), "chat"])
        # Force PATH lookup to return a x19.exe so the test doesn't
        # exercise the None-fallback path (that's a separate test).
        monkeypatch.setattr(
            relaunch_mod.shutil, "which",
            lambda name: r"C:\venv\Scripts\x19.exe" if name == "x19" else None,
        )

        bin_path = relaunch_mod.resolve_x19_bin()
        # Must NOT be the .py — must be the x19.exe PATH entry.
        assert bin_path == r"C:\venv\Scripts\x19.exe"

    def test_posix_python_launcher_falls_through_to_path(self, monkeypatch, tmp_path):
        """A Python source launcher must not be re-executed through its shebang.

        The git installer invokes ``x19`` with the venv interpreter while the
        source launcher's shebang uses ``/usr/bin/env python3``.  Re-executing
        that source file directly can therefore escape the venv and lose core
        dependencies such as PyYAML.
        """
        if sys.platform == "win32":
            pytest.skip("POSIX semantics")
        script = tmp_path / "x19"
        script.write_text("#!/usr/bin/env python3\n")
        script.chmod(0o755)
        wrapper = tmp_path / "bin" / "x19"
        wrapper.parent.mkdir()
        wrapper.write_text("#!/usr/bin/env bash\n")
        wrapper.chmod(0o755)
        monkeypatch.setattr(relaunch_mod.sys, "argv", [str(script), "chat"])
        monkeypatch.setattr(
            relaunch_mod.shutil, "which",
            lambda name: str(wrapper) if name == "x19" else None,
        )
        assert relaunch_mod.resolve_x19_bin() == str(wrapper)

    def test_posix_python_launcher_on_path_falls_back_to_current_python(
        self, monkeypatch, tmp_path
    ):
        """PATH must not re-select the Python launcher rejected from argv[0]."""
        if sys.platform == "win32":
            pytest.skip("POSIX semantics")
        script = tmp_path / "x19"
        script.write_text("#!/usr/bin/env python3\n")
        script.chmod(0o755)
        monkeypatch.setattr(relaunch_mod.sys, "argv", [str(script), "chat"])
        monkeypatch.setattr(
            relaunch_mod.shutil,
            "which",
            lambda name: str(script) if name == "x19" else None,
        )

        assert relaunch_mod.resolve_x19_bin() is None

        # A console script pinned to the running interpreter keeps the venv: still exec-able.
        pinned = tmp_path / "pinned" / "x19"
        pinned.parent.mkdir()
        pinned.write_text(f"#!{sys.executable}\n")
        pinned.chmod(0o755)
        monkeypatch.setattr(relaunch_mod.sys, "argv", [str(pinned), "chat"])
        assert relaunch_mod.resolve_x19_bin() == str(pinned)

    @pytest.mark.windows_only
    def test_windows_py_argv0_with_no_x19_on_path_returns_none(self, monkeypatch, tmp_path):
        """Bulletproof fallback: if argv0 is .py on Windows AND x19.exe
        isn't on PATH, return None so the caller falls back to
        python -m x19_cli.main."""
        script = tmp_path / "main.py"
        script.write_text("# stub")

        monkeypatch.setattr(relaunch_mod.sys, "argv", [str(script), "chat"])
        monkeypatch.setattr(relaunch_mod.shutil, "which", lambda name: None)

        assert relaunch_mod.resolve_x19_bin() is None
