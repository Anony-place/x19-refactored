#!/usr/bin/env python3
"""Interactive first-run AI provider/model chain setup.

The setup is intentionally separate from the runtime so X19 never starts an
agent with an unverified provider configuration. The user chooses the exact
primary and fallback provider/model order; no hidden provider priority is
inserted ahead of that order.
"""
from __future__ import annotations

import getpass
import os
import requests
from typing import Dict, List, Tuple

from constants import C, PROVIDERS
from config import CONFIG_FILE, load_config, save_config, set_data

CHAIN_KEY = "AI_PROVIDER_CHAIN"


def _key(provider_id: str) -> str:
    info = PROVIDERS[provider_id]
    return os.getenv(info.get("api_key_env", ""), "") or load_config().get(info.get("api_key_config", ""), "")


def _save_key(provider_id: str, key: str) -> None:
    info = PROVIDERS[provider_id]
    env = info.get("api_key_env", "")
    cfg = info.get("api_key_config", "")
    if env:
        os.environ[env] = key
    if cfg:
        save_config({cfg: key})


def _model_list(provider_id: str) -> List[str]:
    info = PROVIDERS[provider_id]
    models = []
    try:
        from providers import PROVIDER_FREE_MODELS
        models.extend(PROVIDER_FREE_MODELS.get(provider_id, []))
    except Exception:
        pass
    default = info.get("default_model", "")
    if default and default not in models:
        models.insert(0, default)
    return models


def _choose_provider(used: set) -> str:
    choices = [p for p in PROVIDERS if p not in used]
    print(f"\n{C.BOLD}{C.Y}Select provider:{C.N}")
    for i, pid in enumerate(choices, 1):
        info = PROVIDERS[pid]
        local = " [LOCAL]" if not info.get("needs_key") else ""
        print(f"  {C.G}[{i}]{C.N} {info['name']}{local} — {info.get('desc','')[:70]}")
    while True:
        raw = input(f"{C.B}[?] Provider (1-{len(choices)}): {C.N}").strip()
        try:
            pid = choices[int(raw) - 1]
            return pid
        except (ValueError, IndexError):
            print(f"{C.R}[!] Invalid provider selection.{C.N}")


def _choose_model(provider_id: str) -> str:
    info = PROVIDERS[provider_id]
    models = _model_list(provider_id)
    print(f"\n{C.BOLD}{C.Y}Select model for {info['name']}:{C.N}")
    for i, model in enumerate(models, 1):
        print(f"  {C.G}[{i}]{C.N} {model}")
    print(f"  {C.G}[C]{C.N} Custom model")
    while True:
        raw = input(f"{C.B}[?] Model: {C.N}").strip()
        if raw.lower() == "c":
            model = input(f"{C.B}[?] Model name: {C.N}").strip()
            if model:
                return model
        else:
            try:
                model = models[int(raw) - 1]
                return model
            except (ValueError, IndexError):
                pass
        print(f"{C.R}[!] Invalid model selection.{C.N}")


def _verify(provider_id: str, model: str, key: str) -> Tuple[bool, str]:
    """Perform a real, provider-specific minimal API request."""
    info = PROVIDERS[provider_id]
    if provider_id == "ollama":
        try:
            r = requests.get(info["base_url"].rstrip("/") + "/api/tags", timeout=5)
            r.raise_for_status()
            names = [m.get("name", "") for m in r.json().get("models", [])]
            if not any(model == n or model in n for n in names):
                return False, f"model not installed (available: {', '.join(names[:5]) or 'none'})"
            return True, "local Ollama reachable and model installed"
        except Exception as exc:
            return False, f"Ollama check failed: {type(exc).__name__}"

    if not key:
        return False, "API key missing"

    base = info["base_url"].rstrip("/")
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    try:
        if info.get("format") == "anthropic":
            url = base + "/messages"
            headers = {"x-api-key": key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}
            body = {"model": model, "max_tokens": 8, "messages": [{"role": "user", "content": "Reply with OK"}]}
        elif info.get("format") == "google":
            url = base + f"/models/{model}:generateContent?key={key}"
            headers = {"Content-Type": "application/json"}
            body = {"contents": [{"parts": [{"text": "Reply with OK"}]}], "generationConfig": {"maxOutputTokens": 8}}
        else:
            url = base + "/chat/completions"
            body = {"model": model, "messages": [{"role": "user", "content": "Reply with OK"}], "max_tokens": 8, "temperature": 0}
        r = requests.post(url, headers=headers, json=body, timeout=15, allow_redirects=False)
        if r.ok:
            return True, "API request succeeded"
        try:
            detail = str(r.json().get("error", r.text))[:180]
        except Exception:
            detail = r.text[:180]
        return False, f"HTTP {r.status_code}: {detail}"
    except requests.RequestException as exc:
        return False, f"network error: {type(exc).__name__}"


def configured_chain() -> List[Dict[str, str]]:
    cfg = load_config().get(CHAIN_KEY, [])
    return cfg if isinstance(cfg, list) else []


def setup_if_needed(force: bool = False) -> bool:
    existing = configured_chain()
    if existing and not force:
        return True

    print(f"\n{C.BOLD}{C.C}X19 AI CONFIGURATION{C.N}")
    print(f"{C.D}Choose the exact provider/model failover order. X19 will not reorder it silently.{C.N}\n")
    chain: List[Dict[str, str]] = []
    used = set()

    while True:
        role = "Primary" if not chain else f"Fallback #{len(chain)}"
        print(f"\n{C.BOLD}{role}{C.N}")
        pid = _choose_provider(used)
        model = _choose_model(pid)

        key = ""
        if PROVIDERS[pid].get("needs_key"):
            key = _key(pid)
            if not key:
                key = getpass.getpass(f"{C.B}[?] {PROVIDERS[pid]['name']} API key: {C.N}").strip()
                if key:
                    _save_key(pid, key)

        print(f"{C.Y}[*] Verifying {PROVIDERS[pid]['name']} / {model} ...{C.N}")
        ok, detail = _verify(pid, model, key)
        if not ok:
            print(f"{C.R}[!] Verification failed: {detail}{C.N}")
            print(f"{C.Y}    This provider/model will NOT be saved as a working chain entry.{C.N}")
            retry = input(f"{C.B}[?] Try this provider again? (Y/n): {C.N}").strip().lower()
            if retry != "n":
                continue
            if not chain:
                print(f"{C.R}[!] A working primary provider is required. Setup cancelled.{C.N}")
                return False
            break

        chain.append({"provider": pid, "model": model})
        used.add(pid)
        print(f"{C.G}[+] Verified: {PROVIDERS[pid]['name']} / {model}{C.N}")

        more = input(f"{C.B}[?] Add another fallback provider? (y/N): {C.N}").strip().lower()
        if more != "y":
            break
        if len(used) == len(PROVIDERS):
            break

    save_config({CHAIN_KEY: chain})
    # Keep legacy primary fields synchronized with the user's explicit primary.
    primary = chain[0]
    set_data({"AI_PROVIDER": primary["provider"], "AI_MODEL": primary["model"]})
    print(f"\n{C.G}{C.BOLD}X19 AI setup complete ✓{C.N}")
    for i, entry in enumerate(chain):
        role = "PRIMARY" if i == 0 else f"FALLBACK {i}"
        print(f"  {role}: {PROVIDERS[entry['provider']]['name']} → {entry['model']}")
    print(f"{C.D}Saved to {CONFIG_FILE}{C.N}\n")
    return True
