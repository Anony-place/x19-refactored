"""Native remote OS fingerprinting for X19.

This is evidence-driven fingerprinting, not a magic OS guess.  It combines
optional Nmap OS detection (when installed), TCP reachability/port signals,
service banners and HTTP headers.  Every conclusion carries confidence and
supporting evidence so the agent can treat it as a hypothesis rather than a
fact until stronger evidence appears.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import time
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse
from urllib.request import Request, build_opener


OS_TOOL = "x19_os_detect"
COMMON_OS_PORTS = (22, 80, 135, 139, 443, 445, 3389, 5985, 5986, 8080, 8443)


def _host(value: str) -> str:
    value = (value or "").strip()
    if "://" in value:
        value = urlparse(value).hostname or value
    value = value.split("/", 1)[0]
    if value.count(":") == 1:
        value = value.split(":", 1)[0]
    return value.strip("[]")


def _connect(host: str, port: int, timeout: float = 1.2) -> Tuple[bool, str, float]:
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = b""
            if port in (22, 25, 110, 143, 587, 21):
                try:
                    banner = sock.recv(1024)
                except OSError:
                    pass
            return True, banner.decode("utf-8", "replace").strip(), round((time.monotonic() - started) * 1000, 2)
    except OSError:
        return False, "", round((time.monotonic() - started) * 1000, 2)


def _http_signals(host: str) -> List[str]:
    signals: List[str] = []
    for scheme, port in (("https", 443), ("http", 80), ("https", 8443), ("http", 8080)):
        url = f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"
        try:
            req = Request(url, headers={"User-Agent": "X19-OS-Fingerprint/1.0"}, method="HEAD")
            with build_opener().open(req, timeout=4) as resp:
                server = resp.headers.get("Server", "")
                powered = resp.headers.get("X-Powered-By", "")
                if server:
                    signals.append(f"HTTP Server: {server}")
                if powered:
                    signals.append(f"X-Powered-By: {powered}")
                if "microsoft" in server.lower() or "iis" in server.lower():
                    signals.append("HTTP stack suggests Microsoft/IIS")
                if "apache" in server.lower() or "nginx" in server.lower():
                    signals.append("HTTP stack suggests Unix/Linux-hosted web service (not conclusive)")
                break
        except Exception:
            continue
    return signals


def _nmap_os(host: str) -> Dict[str, Any]:
    nmap = shutil.which("nmap")
    if not nmap:
        return {"available": False, "evidence": []}
    try:
        proc = subprocess.run(
            [nmap, "-O", "--osscan-guess", "--open", "-Pn", "-T3", host],
            capture_output=True, text=True, timeout=45,
            check=False,
        )
        text = (proc.stdout or "") + "\n" + (proc.stderr or "")
        evidence = []
        for line in text.splitlines():
            if "Running:" in line or "OS details:" in line or "Aggressive OS guesses:" in line:
                evidence.append(line.strip())
        return {"available": True, "returncode": proc.returncode, "evidence": evidence[:20]}
    except subprocess.TimeoutExpired:
        return {"available": True, "error": "nmap OS scan timed out", "evidence": []}
    except Exception as exc:
        return {"available": True, "error": f"{type(exc).__name__}: {exc}", "evidence": []}


def detect_os(target: str, *, use_nmap: bool = True) -> Dict[str, Any]:
    host = _host(target)
    if not host:
        return {"ok": False, "tool": OS_TOOL, "error": "target required"}

    observations: List[Dict[str, Any]] = []
    scores: Dict[str, float] = {"windows": 0.0, "linux": 0.0, "unix": 0.0, "network_appliance": 0.0, "unknown": 0.0}

    for port in COMMON_OS_PORTS:
        opened, banner, latency = _connect(host, port)
        if not opened:
            continue
        observations.append({"port": port, "open": True, "banner": banner[:180], "latency_ms": latency})
        if port in (135, 139, 445, 3389, 5985, 5986):
            scores["windows"] += 2.5
        if port == 22:
            scores["linux"] += 1.0
            scores["unix"] += 1.0
        if port in (631,):
            scores["unix"] += 1.0
        low = banner.lower()
        if "openssh" in low:
            scores["linux"] += 1.5
            scores["unix"] += 1.0
        if "microsoft" in low or "windows" in low:
            scores["windows"] += 2.0

    http_signals = _http_signals(host)
    for signal in http_signals:
        low = signal.lower()
        if "iis" in low or "microsoft" in low:
            scores["windows"] += 2.0
        if "nginx" in low or "apache" in low:
            scores["linux"] += 0.8
            scores["unix"] += 0.5

    nmap = _nmap_os(host) if use_nmap else {"available": False, "evidence": []}
    nmap_text = " | ".join(nmap.get("evidence", []))
    low_nmap = nmap_text.lower()
    if low_nmap:
        if "microsoft" in low_nmap or "windows" in low_nmap:
            scores["windows"] += 6.0
        if "linux" in low_nmap:
            scores["linux"] += 6.0
        if "freebsd" in low_nmap or "openbsd" in low_nmap or "netbsd" in low_nmap:
            scores["unix"] += 6.0
        if "router" in low_nmap or "switch" in low_nmap or "firewall" in low_nmap:
            scores["network_appliance"] += 4.0

    best = max((k for k in scores if k != "unknown"), key=scores.get, default="unknown")
    total = sum(v for k, v in scores.items() if k != "unknown")
    confidence = min(0.98, max(0.0, scores[best] / max(total, 1.0)))
    if not observations and not http_signals and not nmap.get("evidence"):
        best, confidence = "unknown", 0.0

    return {
        "ok": True,
        "tool": OS_TOOL,
        "target": host,
        "os_family": best,
        "confidence": round(confidence, 3),
        "scores": {k: round(v, 2) for k, v in scores.items()},
        "tcp_observations": observations,
        "http_signals": http_signals,
        "nmap": nmap,
        "note": "OS family is a fingerprint hypothesis; require stronger corroboration before treating it as confirmed.",
    }


def dispatch(spec: str) -> Dict[str, Any]:
    parts = spec.strip().split()
    if len(parts) < 3 or parts[0] != "__x19_os__":
        return {"ok": False, "error": "invalid OS detection command"}
    target = parts[1]
    use_nmap = not any(p.lower() in ("--no-nmap", "no-nmap") for p in parts[2:])
    return detect_os(target, use_nmap=use_nmap)


def install(tool_registry: dict, executor_cls: Any) -> None:
    """Register OS detection through the same native ToolExecutor boundary."""
    tool_registry.setdefault(OS_TOOL, "__x19_os__ {target} | Multi-signal remote OS fingerprinting with optional Nmap | 60")
    if getattr(executor_cls, "_x19_os_installed", False):
        return
    original_run = executor_cls.run

    def os_aware_run(self, command: str, timeout: int = 120):
        if isinstance(command, str) and command.lstrip().startswith("__x19_os__"):
            from tools import ToolResult
            result = dispatch(command)
            text = json.dumps(result, indent=2, sort_keys=True)
            return ToolResult(text if result.get("ok") else "", "" if result.get("ok") else text,
                              0 if result.get("ok") else 1,
                              None if result.get("ok") else result.get("error", "os_detection_failed"))
        return original_run(self, command, timeout=timeout)

    executor_cls.run = os_aware_run
    executor_cls._x19_os_installed = True
