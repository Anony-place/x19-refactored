#!/usr/bin/env python3
"""Provider control plane with explicit configuration and live model discovery.

The old setup path mixed UI, stale hard-coded model lists and verification. This
module keeps setup deterministic: choose provider -> discover/select model ->
store credentials -> perform a real request -> make it primary.
"""
from __future__ import annotations

import getpass
import os
from typing import Any, Dict, List, Tuple

import requests

from config import CONFIG_FILE, load_config, save_config, set_data
from constants import PROVIDERS

CHAIN_KEY = "AI_PROVIDER_CHAIN"
TIMEOUT = 15


def _credentials(pid: str) -> str:
    info = PROVIDERS[pid]
    env = info.get("api_key_env", "")
    cfg = info.get("api_key_config", "")
    return (os.getenv(env, "") if env else "") or (load_config().get(cfg, "") if cfg else "")


def _save_credentials(pid: str, key: str) -> None:
    info = PROVIDERS[pid]
    cfg = info.get("api_key_config", "")
    env = info.get("api_key_env", "")
    if cfg:
        save_config({cfg: key})
    if env and key:
        os.environ[env] = key


def _base(pid: str) -> str:
    return PROVIDERS[pid].get("base_url", "").rstrip("/")


def discover_models(pid: str) -> Tuple[bool, List[str], str]:
    """Discover currently available models instead of trusting a stale registry."""
    info = PROVIDERS[pid]
    key = _credentials(pid)
    if pid == "ollama":
        try:
            r = requests.get(_base(pid) + "/api/tags", timeout=TIMEOUT)
            r.raise_for_status()
            return True, [m.get("name", "") for m in r.json().get("models", []) if m.get("name")], "ok"
        except Exception as exc:
            return False, [], f"{type(exc).__name__}: {exc}"
    if not key and info.get("needs_key"):
        return False, [], "API key missing"
    try:
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        r = requests.get(_base(pid) + "/models", headers=headers, timeout=TIMEOUT)
        if r.ok:
            data = r.json()
            models = [x.get("id", "") for x in data.get("data", []) if x.get("id")]
            return True, models, "ok"
        return False, [], f"HTTP {r.status_code}: {r.text[:180]}"
    except Exception as exc:
        return False, [], f"{type(exc).__name__}: {exc}"


def _verify(pid: str, model: str) -> Tuple[bool, str]:
    info = PROVIDERS[pid]
    key = _credentials(pid)
    if pid == "ollama":
        try:
            r = requests.post(_base(pid) + "/api/chat", json={
                "model": model,
                "messages": [{"role": "user", "content": "Reply with OK"}],
                "stream": False,
            }, timeout=TIMEOUT)
            r.raise_for_status()
            return True, "local chat request succeeded"
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"
    if pid == "custom_openai" and not key:
        key = "x19-local"
    if info.get("needs_key") and not key:
        return False, "API key missing"
    try:
        if info.get("format") == "anthropic":
            r = requests.post(_base(pid) + "/messages", headers={
                "x-api-key": key, "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            }, json={"model": model, "max_tokens": 8,
                    "messages": [{"role": "user", "content": "Reply with OK"}]}, timeout=TIMEOUT)
        elif info.get("format") == "google":
            r = requests.post(_base(pid) + f"/models/{model}:generateContent?key={key}",
                              json={"contents": [{"parts": [{"text": "Reply with OK"}]}]}, timeout=TIMEOUT)
        else:
            r = requests.post(_base(pid) + "/chat/completions", headers={
                "Authorization": f"Bearer {key}", "Content-Type": "application/json",
            }, json={"model": model, "messages": [{"role": "user", "content": "Reply with OK"}],
                    "max_tokens": 8, "temperature": 0}, timeout=TIMEOUT)
        if r.ok:
            return True, "live API request succeeded"
        try:
            detail = r.json().get("error", r.text)
        except Exception:
            detail = r.text
        return False, f"HTTP {r.status_code}: {str(detail)[:300]}"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _choose_provider() -> str | None:
    ids = list(PROVIDERS)
    print("Providers:")
    for i, pid in enumerate(ids, 1):
        print(f"  {i:2}. {pid:14} {PROVIDERS[pid]['name']}")
    print(f"  {len(ids)+1:2}. ➕ Add custom OpenAI-compatible provider (base URL + API key)")
    raw = input("Provider number, id, or 'custom': ").strip()
    # custom trigger
    if raw.lower() in {"custom", "add", "new", str(len(ids)+1)}:
        return _create_custom_interactive()
    if raw.isdigit() and 1 <= int(raw) <= len(ids):
        return ids[int(raw) - 1]
    return raw if raw in PROVIDERS else None


def _create_custom_interactive() -> str | None:
    from custom_providers import add_custom_provider
    print("\nCustom provider -- OpenAI-compatible")
    pid = input("Provider id (e.g. my_vllm): ").strip().lower().replace(" ", "_")
    if not pid:
        print("[!] id required")
        return None
    if pid in PROVIDERS:
        print(f"[!] id already exists: {pid}")
        return None
    name = input("Display name: ").strip() or pid
    base_url = input("Base URL (https://.../v1 ): ").strip().rstrip("/")
    if not base_url or not (base_url.startswith("http://") or base_url.startswith("https://")):
        print("[!] valid http(s) base URL required")
        return None
    model = input("Default model: ").strip() or "local"
    api_key = getpass.getpass("API key (Enter to skip for local/no-auth): ").strip()
    api_key_env = input("Env var for key (optional): ").strip()
    try:
        add_custom_provider(pid, name, base_url, model, api_key_env=api_key_env, api_key=api_key)
        print(f"[+] Custom provider '{pid}' -> {base_url} / {model}")
        return pid
    except Exception as exc:
        print(f"[!] {exc}")
        return None


def interactive_setup() -> bool:
    print("X19 provider setup — plain terminal")
    pid = _choose_provider()
    if not pid:
        print("[!] Unknown provider")
        return False
    info = PROVIDERS[pid]
    if info.get("needs_key"):
        key = _credentials(pid)
        if not key:
            key = getpass.getpass(f"{info['name']} API key: ").strip()
        if not key:
            print("[!] API key required")
            return False
        _save_credentials(pid, key)

    ok, models, detail = discover_models(pid)
    if ok and models:
        print(f"[+] {len(models)} models discovered")
        for i, model in enumerate(models[:40], 1):
            print(f"  {i:2}. {model}")
        raw = input("Model number or exact model id (Enter = default): ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(models):
            model = models[int(raw) - 1]
        else:
            model = raw or info.get("default_model", "")
    else:
        print(f"[!] Model discovery failed: {detail}")
        model = input(f"Model id (Enter = {info.get('default_model','')}): ").strip() or info.get("default_model", "")

    if not model:
        print("[!] Model is required")
        return False
    good, verify_detail = _verify(pid, model)
    if not good:
        print(f"[!] Provider verification failed: {verify_detail}")
        return False

    save_config({"AI_PROVIDER": pid, "AI_MODEL": model,
                 CHAIN_KEY: [{"provider": pid, "model": model}]})
    set_data({"AI_PROVIDER": pid, "AI_MODEL": model}, save=True)
    print(f"[+] {info['name']} / {model} verified and saved to {CONFIG_FILE}")
    return True


def provider_command(argv: list[str]) -> int:
    if not argv or argv[0] in {"list", "ls"}:
        from plain_cli import providers
        return providers()
    action = argv[0]
    if action == "discover" and len(argv) >= 2:
        pid = argv[1]
        if pid not in PROVIDERS:
            print(f"[!] Unknown provider: {pid}")
            return 2
        ok, models, detail = discover_models(pid)
        if not ok:
            print(f"[!] {detail}")
            return 1
        print("\n".join(models))
        return 0
    if action == "test" and len(argv) >= 2:
        pid = argv[1]
        if pid not in PROVIDERS:
            print(f"[!] Unknown provider: {pid}")
            return 2
        cfg = load_config()
        model = cfg.get("AI_MODEL") if cfg.get("AI_PROVIDER") == pid else PROVIDERS[pid].get("default_model", "")
        good, detail = _verify(pid, model)
        print(f"[{'OK' if good else 'FAIL'}] {pid}/{model}: {detail}")
        return 0 if good else 1
    if action in {"use", "set"} and len(argv) >= 2:
        pid = argv[1]
        if pid not in PROVIDERS:
            print(f"[!] Unknown provider: {pid}")
            return 2
        model = None
        key = None
        i = 2
        while i < len(argv):
            if argv[i] == "--model" and i + 1 < len(argv):
                model = argv[i + 1]; i += 2; continue
            if argv[i] == "--key" and i + 1 < len(argv):
                key = argv[i + 1]; i += 2; continue
            i += 1
        if key:
            _save_credentials(pid, key)
        if model is None:
            model = load_config().get("AI_MODEL") or PROVIDERS[pid].get("default_model", "")
        good, detail = _verify(pid, model)
        if not good:
            print(f"[!] Refusing to activate unverified provider: {detail}")
            return 1
        save_config({"AI_PROVIDER": pid, "AI_MODEL": model,
                     CHAIN_KEY: [{"provider": pid, "model": model}]})
        set_data({"AI_PROVIDER": pid, "AI_MODEL": model}, save=True)
        print(f"[+] active provider: {pid}/{model}")
        return 0
    if action == "add" and len(argv) >= 2:
        # x19 provider add <id> --name NAME --base-url URL [--model M] [--key KEY] [--key-env ENV]
        pid = argv[1].lower().replace(" ", "_")
        if pid in PROVIDERS:
            print(f"[!] already exists: {pid}")
            return 2
        name = base_url = model = key = key_env = ""
        i = 2
        while i < len(argv):
            if argv[i] == "--name" and i+1 < len(argv): name = argv[i+1]; i+=2; continue
            if argv[i] == "--base-url" and i+1 < len(argv): base_url = argv[i+1]; i+=2; continue
            if argv[i] == "--model" and i+1 < len(argv): model = argv[i+1]; i+=2; continue
            if argv[i] == "--key" and i+1 < len(argv): key = argv[i+1]; i+=2; continue
            if argv[i] == "--key-env" and i+1 < len(argv): key_env = argv[i+1]; i+=2; continue
            i+=1
        if not base_url or not (base_url.startswith("http://") or base_url.startswith("https://")):
            print("[!] --base-url https://.../v1 required")
            return 2
        try:
            from custom_providers import add_custom_provider as _add
            _add(pid, name or pid, base_url.rstrip("/"), model or "local", api_key_env=key_env, api_key=key)
            print(f"[+] Custom provider '{pid}' added -> {base_url}")
            return 0
        except Exception as exc:
            print(f"[!] {exc}")
            return 1
    print("usage: x19 provider list | discover <provider> | test <provider> | use <provider> [--model MODEL] [--key KEY] | add <id> --base-url URL [--name NAME] [--model M] [--key KEY]")
    return 2
