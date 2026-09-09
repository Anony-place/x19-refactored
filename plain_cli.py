#!/usr/bin/env python3
"""Small, dependency-light terminal control plane for X19.

This intentionally avoids the Rich workspace/full-screen UI.  It is the
operator-facing surface for setup, provider management and runtime status.
Actual assessments remain on the existing ``run`` command.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict

from constants import PROVIDERS
from config import CONFIG, CONFIG_FILE, load_config


def _redact(value: str) -> str:
    value = str(value or "")
    if len(value) <= 8:
        return "***" if value else "-"
    return value[:4] + "…" + value[-4:]


def status() -> int:
    cfg = load_config()
    provider = cfg.get("AI_PROVIDER", CONFIG.AI_PROVIDER) or "-"
    model = cfg.get("AI_MODEL", CONFIG.AI_MODEL) or PROVIDERS.get(provider, {}).get("default_model", "-")
    chain = cfg.get("AI_PROVIDER_CHAIN", [])
    print("X19 — plain terminal mode")
    print(f"config   {CONFIG_FILE}")
    print(f"provider {provider}")
    print(f"model    {model}")
    if chain:
        print("chain    " + " -> ".join(f"{x.get('provider')}/{x.get('model')}" for x in chain))
    print("commands: x19 setup | x19 provider list | x19 provider test | x19 provider use")
    print("          x19 run -t <target> [--engagement <name>]")
    return 0


def providers() -> int:
    cfg = load_config()
    active = cfg.get("AI_PROVIDER", CONFIG.AI_PROVIDER)
    for pid, info in PROVIDERS.items():
        env = info.get("api_key_env", "")
        key = os.getenv(env, "") if env else ""
        if not key and info.get("api_key_config"):
            key = cfg.get(info["api_key_config"], "")
        mark = "*" if pid == active else " "
        auth = "local" if not info.get("needs_key") else ("key-set" if key else "no-key")
        print(f"{mark} {pid:14} {auth:8} {info.get('default_model','-')}  {info.get('base_url','')}")
    return 0


def _provider_args() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("provider")
    p.add_argument("--model")
    p.add_argument("--key")
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    if not argv or argv[0] in {"status", "workspace"}:
        return status()
    if argv[0] == "providers":
        return providers()
    if argv[0] == "provider":
        from provider_manager import provider_command
        return provider_command(argv[1:])
    if argv[0] == "setup":
        from provider_manager import interactive_setup
        return 0 if interactive_setup() else 1
    if argv[0] == "brain":
        from brain.cognitive_runtime import self_check
        print(json.dumps(self_check(), indent=2))
        return 0
    return 2
