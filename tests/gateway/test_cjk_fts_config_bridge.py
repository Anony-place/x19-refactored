"""config.yaml sessions.* bridges for the search-index knobs (config-authoritative).

Salvaged from PR #65544 (adapted: agent.fts_v2_read → sessions.cjk_fts).
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml

import gateway.run as gateway_run


def _write_home(tmp_path: Path, sessions_cfg: dict, env_text: str = "") -> Path:
    x19_home = tmp_path / ".x19"
    x19_home.mkdir()
    (x19_home / "config.yaml").write_text(
        yaml.safe_dump({"sessions": sessions_cfg}), encoding="utf-8"
    )
    (x19_home / ".env").write_text(env_text, encoding="utf-8")
    return x19_home


def test_cjk_fts_bridged_from_config(tmp_path, monkeypatch):
    home = _write_home(tmp_path, {"cjk_fts": False})
    monkeypatch.setattr(gateway_run, "_x19_home", home)
    monkeypatch.setenv("X19_CJK_FTS", "1")
    gateway_run._reload_runtime_env_preserving_config_authority()
    assert os.environ["X19_CJK_FTS"] == "False"


def test_search_knobs_have_documented_defaults():
    """The advertised config surface must exist in DEFAULT_CONFIG (no
    user-facing env switch): cjk index default ON, slow-search log at 1s."""
    from x19_cli.config import DEFAULT_CONFIG

    assert DEFAULT_CONFIG["sessions"]["cjk_fts"] is True
    assert DEFAULT_CONFIG["sessions"]["search_slow_ms"] == 1000


