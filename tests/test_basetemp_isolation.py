"""pytest's basetemp must never sit inside the operator's platform-native X19 home.

Every per-test sandbox is ``<basetemp>/.../x19_test`` and ``get_default_x19_root()``
prefers the platform-native home whenever ``X19_HOME`` sits *under* it — so a basetemp
inside the home silently turns the sandbox back into the live install (#111101).
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import x19_constants
from tests import conftest as suite_conftest


def _config_with_basetemp(given: Path | None) -> SimpleNamespace:
    return SimpleNamespace(
        _tmp_path_factory=SimpleNamespace(_given_basetemp=given),
        option=SimpleNamespace(basetemp=str(given) if given else None),
    )


def test_basetemp_inside_the_native_home_is_relocated_outside_it(tmp_path, monkeypatch):
    native = tmp_path / "native-home"
    native.mkdir()
    monkeypatch.setattr(x19_constants, "_get_platform_default_x19_home", lambda: native)
    config = _config_with_basetemp(native / ".repro")

    suite_conftest._relocate_basetemp_outside_operator_home(config)

    relocated = config._tmp_path_factory._given_basetemp
    assert relocated is not None and not relocated.resolve().is_relative_to(native.resolve())
    assert config.option.basetemp == str(relocated)
    # The sandbox derived from it no longer resolves to the native root.
    monkeypatch.setenv("X19_HOME", str(relocated / "t0" / "x19_test"))
    assert x19_constants.get_default_x19_root() == relocated / "t0" / "x19_test"


def test_basetemp_outside_the_native_home_is_left_alone(tmp_path, monkeypatch):
    native = tmp_path / "native-home"
    native.mkdir()
    monkeypatch.setattr(x19_constants, "_get_platform_default_x19_home", lambda: native)
    given = tmp_path / "elsewhere"
    config = _config_with_basetemp(given)

    suite_conftest._relocate_basetemp_outside_operator_home(config)

    assert config._tmp_path_factory._given_basetemp == given
    assert config.option.basetemp == str(given)


def test_fallback_root_escapes_a_repo_checked_out_inside_the_native_home(tmp_path, monkeypatch):
    # Default install: repo at ~/.x19/x19 and TEMP under the home (Windows).
    native = tmp_path / "native-home"
    (native / "x19").mkdir(parents=True)
    monkeypatch.setattr(x19_constants, "_get_platform_default_x19_home", lambda: native)
    monkeypatch.setattr(suite_conftest, "PROJECT_ROOT", native / "x19")
    monkeypatch.setattr(suite_conftest.tempfile, "gettempdir", lambda: str(native / "tmp"))
    monkeypatch.delenv("PYTEST_DEBUG_TEMPROOT", raising=False)
    config = _config_with_basetemp(None)

    suite_conftest._relocate_basetemp_outside_operator_home(config)

    relocated = config._tmp_path_factory._given_basetemp
    assert relocated is not None and not relocated.resolve().is_relative_to(native.resolve())
