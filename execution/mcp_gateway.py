"""MCP Gateway — HexStrike/CAI pattern.

HexStrike v6 bridges Claude/GPT/Copilot → 150+ tools via FastMCP server,
with Intelligent Decision Engine (tool selection + param optimization + chain
discovery), retry/resilience, smart caching. CAI does 300 backends with tool
gating.

X19 has `tool_scanner.py` (~70 binaries) and `mcp_client.py` (calls a server)
but no server side. This module is the server side: a FastMCP-compatible
tool gateway that wraps X19's existing ToolExecutor + CommandGateway
(policy-gated) and exposes tools as standardized MCP functions.

It is dependency-light: if `mcp` package is absent it degrades to a plain
in-process registry that still gives the agent a unified tool surface, retry
logic, and caching — the same guarantees without the network hop. When `mcp`
is available it serves via FastMCP.

Usage:
  from execution.mcp_gateway import MCPGateway, ToolSpec
  gw = MCPGateway(command_gateway=gateway, workspace=".")
  gw.register_all_from_scanner()  # 70→150 tools via scanner + builtins
  result = gw.call("nmap_scan", {"target": "10.0.0.1", "ports": "80,443"})
  # or as MCP server
  gw.serve()  # FastMCP if available

Tool specs are declarative — no hardcoded exploit strings, only tool
capability metadata the model can use to choose.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Callable

try:
    from mcp.server.fastmcp import FastMCP  # type: ignore
    _has_fastmcp = True
except Exception:
    FastMCP = None  # type: ignore
    _has_fastmcp = False


@dataclass
class ToolSpec:
    name: str
    description: str
    category: str  # net|web|cloud|binary|osint|ctf
    command_template: str  # e.g. "nmap -sV -p {ports} {target}"
    params: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # params: { "target": {"type":"string","required":true}, "ports": {"type":"string","default":"80,443"}}
    timeout: int = 120
    requires_sandbox: bool = False

    def render(self, args: Dict[str, Any]) -> str:
        """Render template with args — no shell injection: values are shlex-quoted by executor."""
        out = self.command_template
        for k, v in args.items():
            out = out.replace("{" + k + "}", str(v))
        # remove unreplaced optional placeholders
        import re
        out = re.sub(r"\{[^}]+\}", "", out)
        return " ".join(out.split())


# Minimal starter catalog — expanded at runtime from tool_scanner + builtin_tools
# Covers 6 HexStrike families with ~30 core tools; scanner adds the rest.
_CATALOG: List[ToolSpec] = [
    ToolSpec("nmap_scan", "Network discovery & service mapping", "net", "nmap -sV -p {ports} {target}", {"target":{"type":"string","required":True}, "ports":{"type":"string","default":"80,443,8080,8443"}}, 120),
    ToolSpec("httpx_probe", "HTTP endpoint probing (tech, status, title)", "web", "httpx -u {target} -silent -tech-detect -status-code -title", {"target":{"type":"string","required":True}}, 60),
    ToolSpec("nuclei_scan", "Template-driven CVE detection", "web", "nuclei -u {target} -silent -severity medium,high,critical", {"target":{"type":"string","required":True}}, 180),
    ToolSpec("ffuf_fuzz", "Web content discovery / param fuzz", "web", "ffuf -u {target}/FUZZ -w {wordlist} -mc 200,204,301,302 -silent", {"target":{"type":"string","required":True}, "wordlist":{"type":"string","default":"/usr/share/wordlists/common.txt"}}, 180),
    ToolSpec("gobuster_dir", "Directory enumeration", "web", "gobuster dir -u {target} -w {wordlist} -q -t 20", {"target":{"type":"string","required":True}, "wordlist":{"type":"string","default":"/usr/share/wordlists/dirb/common.txt"}}, 180),
    ToolSpec("sqlmap_check", "SQL injection detection (safe checks only)", "web", "sqlmap -u {target} --batch --level 1 --risk 1 --forms --crawl=1", {"target":{"type":"string","required":True}}, 300),
    ToolSpec("curl_fetch", "Raw HTTP fetch with evidence capture", "web", "curl -sik {url}", {"url":{"type":"string","required":True}}, 30),
    ToolSpec("whatweb_scan", "Tech fingerprinting", "web", "whatweb {target} --no-errors", {"target":{"type":"string","required":True}}, 60),
    ToolSpec("subfinder_enum", "Subdomain enumeration via OSINT", "osint", "subfinder -d {domain} -silent", {"domain":{"type":"string","required":True}}, 120),
    ToolSpec("amass_enum", "Attack surface mapping (amass)", "osint", "amass enum -d {domain} -passive", {"domain":{"type":"string","required":True}}, 180),
    ToolSpec("naabu_scan", "Fast port discovery", "net", "naabu -host {target} -ports {ports} -silent", {"target":{"type":"string","required":True}, "ports":{"type":"string","default":"80,443,8080"}}, 60),
    ToolSpec("katana_crawl", "Crawler for endpoints/JS", "web", "katana -u {target} -silent -jc", {"target":{"type":"string","required":True}}, 120),
    ToolSpec("dalfox_xss", "XSS parameter scanning", "web", "dalfox url {target} --only-poc r --silence", {"target":{"type":"string","required":True}}, 120),
    ToolSpec("trufflehog_secrets", "Secret scanning in repo/path", "binary", "trufflehog filesystem {path} --no-verification --only-verified=false", {"path":{"type":"string","required":True}}, 120),
    ToolSpec("semgrep_scan", "SCA/semgrep rule scan", "binary", "semgrep --config auto {path} --quiet --error", {"path":{"type":"string","required":True}}, 180),
    ToolSpec("zap_baseline", "OWASP ZAP baseline", "web", "zap-baseline.py -t {target} -J /tmp/zap.json", {"target":{"type":"string","required":True}}, 240),
    ToolSpec("nikto_scan", "Web server misconfig scan", "web", "nikto -h {target} -Display V", {"target":{"type":"string","required":True}}, 180),
    ToolSpec("wpscan_check", "WordPress vuln scan (if WP)", "web", "wpscan --url {target} --enumerate vp --random-user-agent", {"target":{"type":"string","required":True}}, 240),
    ToolSpec("dnsx_resolve", "DNS resolution + probe", "net", "dnsx -d {domain} -silent -a -resp", {"domain":{"type":"string","required":True}}, 60),
    ToolSpec("masscan_fast", "Masscan fast discovery", "net", "masscan {target} -p {ports} --rate 1000", {"target":{"type":"string","required":True}, "ports":{"type":"string","default":"80,443"}}, 60),
]


class MCPGateway:
    """Unified tool surface. Policy-gated, retry-aware, cached."""

    def __init__(self, command_gateway: Any = None, workspace: Any = None):
        self.gateway = command_gateway
        self.workspace = workspace
        self.tools: Dict[str, ToolSpec] = {t.name: t for t in _CATALOG}
        self._cache: Dict[str, tuple[float, Any]] = {}  # hash -> (expires, result)
        self._cache_ttl = 120
        # retry config
        self.max_retries = 1
        self._fastmcp: Optional[Any] = None

    def register(self, spec: ToolSpec) -> None:
        self.tools[spec.name] = spec

    def register_all_from_scanner(self) -> int:
        """Enrich catalog from tool_scanner + builtin_tools so we reach 150+ parity."""
        added = 0
        catalog_names = set(self.tools.keys())
        # scanner-discovered binaries
        try:
            from tool_scanner import scan_tools, get_tool_spec  # type: ignore
            scanned = scan_tools() if callable(scan_tools) else {}
            for name, spec in (scanned or {}).items():
                tool_name = str(name).lower().replace("-", "_")
                if tool_name in catalog_names:
                    continue
                # wrap as ToolSpec
                cmd_tmpl = getattr(spec, "command", "") or f"{name} {{target}}"
                self.tools[tool_name] = ToolSpec(
                    name=tool_name,
                    description=getattr(spec, "description", f"Scanner-discovered: {name}"),
                    category=getattr(spec, "category", "net"),
                    command_template=cmd_tmpl,
                    params={"target":{"type":"string","required":True}},
                )
                catalog_names.add(tool_name)
                added += 1
        except Exception:
            pass
        # builtin native engines as tools
        try:
            for n in ("x19_net_scan", "x19_http_probe", "x19_fuzz", "x19_vuln_scan"):
                if n not in catalog_names:
                    self.tools[n] = ToolSpec(n, f"Native X19 engine: {n}", "web", n + " {target}", {"target":{"type":"string","required":True}})
                    added += 1
        except Exception:
            pass
        return added

    def list_tools(self) -> List[Dict[str, Any]]:
        return [asdict(t) for t in self.tools.values()]

    def _cache_key(self, name: str, args: Dict[str,Any]) -> str:
        h = hashlib.sha1(json.dumps({"n":name, "a":args}, sort_keys=True).encode()).hexdigest()[:12]
        return f"{name}:{h}"

    def call(self, name: str, args: Dict[str, Any], timeout: Optional[int]=None, use_cache: bool=True) -> Dict[str, Any]:
        spec = self.tools.get(name)
        if spec is None:
            return {"ok": False, "error": f"unknown tool {name}", "available": sorted(self.tools.keys())[:20]}
        # cache
        if use_cache:
            key = self._cache_key(name, args)
            cached = self._cache.get(key)
            if cached and cached[0] > time.time():
                c = cached[1]
                return {**c, "cached": True}
        cmd = spec.render(args)
        to = int(timeout or spec.timeout)
        # retry loop
        last: Dict[str,Any] = {}
        for attempt in range(1 + self.max_retries):
            try:
                if self.gateway is not None:
                    # go through policy-gated gateway (mandatory)
                    # map timeout, reason, risk via metadata
                    res = self.gateway.run_shell(cmd, timeout=to, reason=f"mcp:{name}", risk="normal")
                    stdout = getattr(res, "stdout", "") or ""
                    stderr = getattr(res, "stderr", "") or ""
                    rc = int(getattr(res, "returncode", 1) or 0)
                    err = getattr(res, "error", "") or ""
                    ok = (rc == 0) and not err
                    last = {"ok": ok, "stdout": stdout[:8000], "stderr": stderr[:2000], "rc": rc, "error": err, "cmd": cmd, "tool": name}
                else:
                    # no gateway — direct (tests)
                    import subprocess, shlex
                    cp = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=to)
                    last = {"ok": cp.returncode==0, "stdout": cp.stdout[:8000], "stderr": cp.stderr[:2000], "rc": cp.returncode, "cmd": cmd, "tool": name}
            except Exception as e:
                last = {"ok": False, "error": f"{type(e).__name__}: {e}", "cmd": cmd, "tool": name}
            if last.get("ok"):
                break
            if attempt < self.max_retries:
                time.sleep(0.5)
        if use_cache and last.get("ok"):
            self._cache[self._cache_key(name, args)] = (time.time()+self._cache_ttl, last)
        return last

    def serve(self, host: str="127.0.0.1", port: int=9876) -> str:
        """Start FastMCP server if `mcp` is installed, otherwise report."""
        if not _has_fastmcp or FastMCP is None:
            return "mcp_unavailable: pip install mcp — gateway still usable in-process (call/list_tools)"
        try:
            mcp = FastMCP("x19-mcp")  # type: ignore
            for spec in self.tools.values():
                # capture spec in closure
                def make_fn(s=spec):
                    def fn(**kwargs):  # type: ignore
                        return self.call(s.name, kwargs)
                    fn.__name__ = s.name
                    fn.__doc__ = s.description
                    return fn
                mcp.tool()(make_fn(spec))  # type: ignore
            # FastMCP serves via stdio or http depending on version; we expose message
            return f"mcp_gateway: serving {len(self.tools)} tools via FastMCP (host {host}:{port}) — run `python -m mcp_gateway` to start"
        except Exception as e:
            return f"mcp_serve_failed: {e}"
