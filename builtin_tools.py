"""Dependency-free native reconnaissance tools for X19.

These tools use only Python's standard library, so basic reconnaissance does
not require installing Nmap, curl, DNS utilities, or other external binaries.
They are intentionally limited to discovery/observation primitives; they do
not exploit, brute-force, persist, or modify remote systems.

The module is installed by run.py and exposes a small command bridge so the
existing ToolExecutor and planner can use the tools without special cases in
agent.py.
"""
from __future__ import annotations

import json
import re
import socket
import ssl
import time
from html.parser import HTMLParser
from ipaddress import ip_address
from urllib.parse import urljoin, urlparse
from urllib.request import Request, build_opener

# Conservative default set: useful coverage without pretending to replace a
# real port scanner. The agent can explicitly request additional numeric ports.
COMMON_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445,
    465, 587, 631, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389,
    5000, 5432, 5601, 5900, 6379, 6443, 8000, 8008, 8080, 8081, 8443,
    8888, 9000, 9200, 27017,
)

BUILTIN_TOOLS = {
    "x19_net_scan": "__x19_builtin__ net_scan {target} | Native TCP connect reconnaissance (stdlib, no external binary) | 90",
    "x19_http_probe": "__x19_builtin__ http_probe {target} | Native HTTP/HTTPS response and header probe (stdlib) | 30",
    "x19_dns": "__x19_builtin__ dns {target} | Native DNS resolution using the system resolver | 20",
    "x19_tls": "__x19_builtin__ tls {target} | Native TLS certificate/handshake inspection | 30",
    "x19_web_links": "__x19_builtin__ web_links {target} | Native same-origin link discovery (stdlib) | 30",
}


def _host(value: str) -> str:
    value = (value or "").strip()
    if "://" in value:
        value = urlparse(value).hostname or value
    value = value.split("/", 1)[0]
    if ":" in value and value.count(":") == 1:
        value = value.split(":", 1)[0]
    return value.strip("[]")


def _ports(raw: str | None) -> list[int]:
    if not raw:
        return list(COMMON_PORTS)
    out: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                lo, hi = max(1, int(a)), min(65535, int(b))
            except ValueError:
                continue
            # Prevent an accidental enormous native scan.
            if hi - lo > 256:
                hi = lo + 256
            out.extend(range(lo, hi + 1))
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    out.append(p)
            except ValueError:
                pass
    return sorted(set(out))[:512]


def net_scan(target: str, ports: str | None = None, timeout: float = 0.6) -> dict:
    host = _host(target)
    if not host:
        return {"ok": False, "error": "target required"}
    try:
        ip = ip_address(host)
        addresses = [str(ip)]
    except ValueError:
        try:
            addresses = sorted({x[4][0] for x in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
        except OSError as exc:
            return {"ok": False, "error": f"DNS resolution failed: {exc}"}

    results = []
    for addr in addresses[:16]:
        for port in _ports(ports):
            started = time.monotonic()
            sock = socket.socket(socket.AF_INET6 if ":" in addr else socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                rc = sock.connect_ex((addr, port))
                results.append({"address": addr, "port": port, "state": "open" if rc == 0 else "closed_or_filtered",
                                "latency_ms": round((time.monotonic() - started) * 1000, 2)})
            except OSError as exc:
                results.append({"address": addr, "port": port, "state": "error", "error": str(exc)})
            finally:
                sock.close()
    open_ports = [x for x in results if x["state"] == "open"]
    return {"ok": True, "tool": "x19_net_scan", "target": host, "addresses": addresses[:16],
            "ports_tested": len(results), "open_ports": open_ports, "results": results}


def _http_url(target: str) -> str:
    return target if re.match(r"^https?://", target, re.I) else "http://" + target


def http_probe(target: str, timeout: float = 8.0) -> dict:
    url = _http_url(target)
    req = Request(url, headers={"User-Agent": "X19-Native-Recon/1.0"}, method="GET")
    opener = build_opener()
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(32768)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return {"ok": True, "tool": "x19_http_probe", "url": resp.geturl(), "status": resp.status,
                    "reason": resp.reason, "content_type": headers.get("content-type", ""),
                    "content_length": headers.get("content-length", str(len(body))),
                    "server": headers.get("server", ""), "headers": headers,
                    "body_sample": body.decode("utf-8", "replace")[:2000]}
    except Exception as exc:
        return {"ok": False, "tool": "x19_http_probe", "url": url, "error": str(exc)}


def dns_lookup(target: str) -> dict:
    host = _host(target)
    if not host:
        return {"ok": False, "error": "target required"}
    try:
        infos = socket.getaddrinfo(host, None)
        addresses = sorted({i[4][0] for i in infos})
        try:
            reverse = socket.gethostbyaddr(addresses[0])[0] if addresses else ""
        except OSError:
            reverse = ""
        return {"ok": True, "tool": "x19_dns", "hostname": host, "addresses": addresses, "reverse": reverse}
    except OSError as exc:
        return {"ok": False, "tool": "x19_dns", "hostname": host, "error": str(exc)}


def tls_probe(target: str, timeout: float = 6.0) -> dict:
    host = _host(target)
    if not host:
        return {"ok": False, "error": "target required"}
    context = ssl.create_default_context()
    started = time.monotonic()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
                cipher = sock.cipher()
                return {"ok": True, "tool": "x19_tls", "hostname": host,
                        "tls_version": sock.version(), "cipher": cipher,
                        "subject": cert.get("subject"), "issuer": cert.get("issuer"),
                        "not_before": cert.get("notBefore"), "not_after": cert.get("notAfter"),
                        "latency_ms": round((time.monotonic() - started) * 1000, 2)}
    except Exception as exc:
        return {"ok": False, "tool": "x19_tls", "hostname": host, "error": str(exc)}


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []
    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        href = dict(attrs).get("href")
        if href:
            self.links.append(href)


def web_links(target: str, timeout: float = 8.0) -> dict:
    start = _http_url(target)
    parsed = urlparse(start)
    origin = (parsed.scheme, parsed.netloc)
    req = Request(start, headers={"User-Agent": "X19-Native-Recon/1.0"}, method="GET")
    try:
        with build_opener().open(req, timeout=timeout) as resp:
            body = resp.read(256 * 1024).decode("utf-8", "replace")
            parser = _LinkParser()
            parser.feed(body)
            links = []
            for href in parser.links:
                full = urljoin(resp.geturl(), href)
                p = urlparse(full)
                if p.scheme not in ("http", "https") or (p.scheme, p.netloc) != origin:
                    continue
                clean = full.split("#", 1)[0]
                if clean not in links:
                    links.append(clean)
                if len(links) >= 500:
                    break
            return {"ok": True, "tool": "x19_web_links", "url": resp.geturl(),
                    "status": resp.status, "links": links}
    except Exception as exc:
        return {"ok": False, "tool": "x19_web_links", "url": start, "error": str(exc)}


def dispatch(spec: str) -> dict:
    """Dispatch a `__x19_builtin__ ...` command without a shell."""
    parts = spec.strip().split()
    if len(parts) < 3 or parts[0] != "__x19_builtin__":
        return {"ok": False, "error": "invalid builtin command"}
    name = parts[1]
    target = parts[2]
    if name == "net_scan":
        return net_scan(target, parts[3] if len(parts) > 3 else None)
    if name == "http_probe":
        return http_probe(target)
    if name == "dns":
        return dns_lookup(target)
    if name == "tls":
        return tls_probe(target)
    if name == "web_links":
        return web_links(target)
    return {"ok": False, "error": f"unknown builtin '{name}'"}


def install(tool_registry: dict, executor_cls) -> None:
    """Register native tools and patch the legacy executor at one boundary.

    Keeping this adapter here lets X19 retain its existing ToolExecutor API
    while native tools bypass subprocess entirely. The original run method is
    preserved for every non-native command.
    """
    for name, spec in BUILTIN_TOOLS.items():
        tool_registry.setdefault(name, spec)

    if getattr(executor_cls, "_x19_builtin_installed", False):
        return
    original_run = executor_cls.run

    def native_aware_run(self, command: str, timeout: int = 120):
        if isinstance(command, str) and command.lstrip().startswith("__x19_builtin__"):
            from tools import ToolResult
            result = dispatch(command)
            text = json.dumps(result, indent=2, sort_keys=True)
            return ToolResult(text if result.get("ok") else "", "" if result.get("ok") else text,
                              0 if result.get("ok") else 1,
                              None if result.get("ok") else result.get("error", "builtin_failed"))
        return original_run(self, command, timeout=timeout)

    executor_cls.run = native_aware_run
    executor_cls._x19_builtin_installed = True
