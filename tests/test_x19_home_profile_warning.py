"""Tests for get_x19_home() profile-mode fallback warning.

Regression test for https://github.com/Anony-place/x19-refactored/issues/18594.

When X19_HOME is unset but an active_profile file indicates a non-default
profile is active, get_x19_home() should:
  1. STILL return ~/.x19 (raising would brick 30+ module-level callers)
  2. Emit a loud one-shot warning to stderr so operators can diagnose
     cross-profile data contamination after the fact.

The warning goes to stderr directly (not through logging) because this
function is called at module-import time from 30+ sites, often before the
logging subsystem has been configured.
"""

from pathlib import Path

import pytest


@pytest.fixture
def fresh_constants(monkeypatch, tmp_path):
    """Import x19_constants fresh and reset the one-shot warn flag."""
    import importlib
    import x19_constants
    importlib.reload(x19_constants)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.delenv("X19_HOME", raising=False)
    return x19_constants


class TestGetX19HomeProfileWarning:
    def test_classic_mode_no_active_profile_no_warning(
        self, fresh_constants, tmp_path, capsys
    ):
        """Classic mode: no active_profile file → silent, returns ~/.x19."""
        result = fresh_constants.get_x19_home()
        assert result == tmp_path / ".x19"
        assert "X19_HOME fallback" not in capsys.readouterr().err


    def test_named_profile_unset_home_warns_once(
        self, fresh_constants, tmp_path, capsys
    ):
        """active_profile=coder + X19_HOME unset → warn loudly, still return fallback."""
        x19_dir = tmp_path / ".x19"
        x19_dir.mkdir()
        (x19_dir / "active_profile").write_text("coder\n")

        result = fresh_constants.get_x19_home()

        # 1. Still returns the fallback — no import-time crash
        assert result == tmp_path / ".x19"
        # 2. Stderr got the warning exactly once
        err = capsys.readouterr().err
        assert err.count("X19_HOME fallback") == 1
        assert "'coder'" in err
        assert "#18594" in err

        # 3. One-shot: second and third calls don't re-warn
        fresh_constants.get_x19_home()
        fresh_constants.get_x19_home()
        err2 = capsys.readouterr().err
        assert "X19_HOME fallback" not in err2

    def test_x19_home_set_suppresses_warning(
        self, fresh_constants, tmp_path, capsys, monkeypatch
    ):
        """Even if active_profile is 'coder', setting X19_HOME suppresses warning."""
        profile_dir = tmp_path / ".x19" / "profiles" / "coder"
        profile_dir.mkdir(parents=True)
        (tmp_path / ".x19" / "active_profile").write_text("coder\n")
        monkeypatch.setenv("X19_HOME", str(profile_dir))

        result = fresh_constants.get_x19_home()

        assert result == profile_dir
        assert "X19_HOME fallback" not in capsys.readouterr().err

    def test_unreadable_active_profile_no_crash(
        self, fresh_constants, tmp_path, capsys
    ):
        """active_profile that can't be decoded → fall through silently."""
        x19_dir = tmp_path / ".x19"
        x19_dir.mkdir()
        # Write bytes that aren't valid utf-8
        (x19_dir / "active_profile").write_bytes(b"\xff\xfe\x00\x00")

        result = fresh_constants.get_x19_home()

        assert result == tmp_path / ".x19"
        # Shouldn't crash; shouldn't warn either (can't tell what profile was intended)
        assert "X19_HOME fallback" not in capsys.readouterr().err

