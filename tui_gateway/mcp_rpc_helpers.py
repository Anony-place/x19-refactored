"""Shared helpers for the per-profile MCP lifecycle RPCs (mcp.servers.*).

Published onto ``tui_gateway.server`` as ``_mcp_summarize_server`` so the rebound handler
bodies in methods_tools resolve it.
"""

from __future__ import annotations

from typing import Any, Dict


def summarize_server(name: str, cfg: dict) -> Dict[str, Any]:
    """Serialize one server's config for a UI (no secret values).

    Mirrors web_server._mcp_server_summary plus ``oauth_tokens_present`` so a UI can
    tell an OAuth server that still needs authentication from one already authenticated.
    """
    from x19_cli.mcp_config import _oauth_tokens_present

    cfg = cfg if isinstance(cfg, dict) else {}
    transport = "http" if cfg.get("url") else ("stdio" if cfg.get("command") else "unknown")
    auth = cfg.get("auth")
    headers = cfg.get("headers") or {}
    if not auth and isinstance(headers, dict) and any(str(key).lower() == "authorization" for key in headers):
        auth = "header"
    return {
        "name": name,
        "transport": transport,
        "url": cfg.get("url"),
        "command": cfg.get("command"),
        "args": list(cfg.get("args") or []),
        "env": sorted(str(k) for k in (cfg.get("env") or {})),
        "auth": auth,
        "oauth_tokens_present": _oauth_tokens_present(name) if auth == "oauth" else None,
        "enabled": cfg.get("enabled", True) is not False,
        "tools": cfg.get("tools")}


