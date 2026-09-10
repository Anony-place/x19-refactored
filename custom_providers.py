"""Runtime registry for operator-defined OpenAI-compatible providers.

Custom providers live in X19 config so operators can add as many endpoints as
needed without editing the source provider registry.
"""
from __future__ import annotations

from typing import Dict, Any
from urllib.parse import urlparse

from config import load_config, save_config
from constants import PROVIDERS

CUSTOM_KEY = "CUSTOM_PROVIDERS"


def load_custom_providers() -> Dict[str, Dict[str, Any]]:
    cfg = load_config().get(CUSTOM_KEY, {})
    if not isinstance(cfg, dict):
        return {}
    loaded: Dict[str, Dict[str, Any]] = {}
    for provider_id, raw in cfg.items():
        if not isinstance(raw, dict):
            continue
        base_url = str(raw.get("base_url", "")).strip().rstrip("/")
        if not base_url:
            continue
        parsed = urlparse(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            continue
        pid = str(provider_id).strip().lower()
        if not pid or pid in PROVIDERS:
            continue
        entry = {
            "name": str(raw.get("name", pid)),
            "desc": str(raw.get("desc", "Operator-defined OpenAI-compatible provider")),
            "base_url": base_url,
            "default_model": str(raw.get("model", "")),
            "api_key_env": str(raw.get("api_key_env", "")),
            "api_key_config": str(raw.get("api_key_config", "")),
            "needs_key": bool(raw.get("needs_key", bool(raw.get("api_key_env") or raw.get("api_key_config")))),
            "format": "openai",
            "custom": True,
        }
        PROVIDERS[pid] = entry
        loaded[pid] = entry
    return loaded


def add_custom_provider(provider_id: str, name: str, base_url: str, model: str, *, api_key_env: str = "", api_key: str = "") -> Dict[str, Any]:
    pid = provider_id.strip().lower().replace(" ", "_")
    if not pid or pid in PROVIDERS:
        raise ValueError(f"provider id already exists or is invalid: {provider_id}")
    parsed = urlparse(base_url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("base URL must be a full http(s) URL")

    cfg = load_config()
    custom = cfg.get(CUSTOM_KEY, {})
    if not isinstance(custom, dict):
        custom = {}
    key_config = f"X19_CUSTOM_{pid.upper()}_API_KEY"
    entry = {
        "name": name.strip() or pid,
        "desc": "Operator-defined OpenAI-compatible provider",
        "base_url": base_url.strip().rstrip("/"),
        "model": model.strip(),
        "api_key_env": api_key_env.strip(),
        "api_key_config": key_config,
        "needs_key": bool(api_key_env.strip() or api_key.strip()),
    }
    custom[pid] = entry
    save_config({CUSTOM_KEY: custom})
    if api_key:
        save_config({key_config: api_key})
    PROVIDERS[pid] = {
        **entry,
        "default_model": entry["model"],
        "format": "openai",
        "custom": True,
    }
    return PROVIDERS[pid]


# Register persisted custom providers whenever this module is imported.
load_custom_providers()
