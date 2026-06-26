import json
import os
import re
import socket
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any

from constants import C, ICO
from config import CONFIG, CONFIG_DIR, load_config
from logging_utils import log, swallow as _swallow


class TrafficEntry:
    """Single captured HTTP request/response."""
    method: str = ""
    url: str = ""
    status: int = 0
    req_headers: str = ""
    req_body: str = ""
    resp_headers: str = ""
    resp_body: str = ""
    timestamp: float = 0.0
    size: int = 0

    def summary(self) -> str:
        path = self.url.split("?")[0][:80] if self.url else "?"
        params = ""
        if "?" in self.url:
            qs = self.url.split("?", 1)[1][:60]
            if qs:
                params = f" ?{qs}"
        return f"  {self.method} {path}{params} -> {self.status} ({self.size}b)"

    def detail(self, max_body: int = 500) -> str:
        lines = [f"=== {self.method} {self.url} ==="]
        if self.req_headers:
            lines.append(f"--- Request Headers ---\n{self.req_headers[:300]}")
        if self.req_body:
            lines.append(f"--- Request Body ---\n{self.req_body[:max_body]}")
        if self.resp_headers:
            lines.append(f"--- Response ({self.status}) ---\n{self.resp_headers[:300]}")
        if self.resp_body:
            lines.append(f"--- Response Body ---\n{self.resp_body[:max_body]}")
        return "\n".join(lines)


class TrafficCollector:
    """Captures HTTP traffic from proxy into structured entries."""

    def __init__(self):
        self.entries: List[TrafficEntry] = []
        self._seen: set = set()
        self._lock = threading.Lock()

    def add(self, entry: TrafficEntry):
        with self._lock:
            dedup_key = f"{entry.method}:{entry.url}:{entry.status}"
            if dedup_key not in self._seen:
                self._seen.add(dedup_key)
                self.entries.append(entry)

    def pop_new(self) -> List[TrafficEntry]:
        """Return and clear new entries since last pop."""
        with self._lock:
            new = list(self.entries)
            self.entries = []
            self._seen.clear()
            return new

    def count(self) -> int:
        return len(self.entries)

    def summary(self, max_items: int = 15) -> str:
        with self._lock:
            items = self.entries[-max_items:]
        if not items:
            return "  (no traffic captured)"
        return "\n".join(e.summary() for e in items)

    def captured_context(self, max_items: int = 10, detail: bool = False) -> str:
        """Format captured traffic for AI context."""
        with self._lock:
            items = self.entries[-max_items:]
        if not items:
            return ""
        lines = [f"CAPTURED TRAFFIC (last {len(items)} requests):"]
        for e in items:
            if detail:
                lines.append(e.detail(max_body=400))
            else:
                lines.append(e.summary())
        return "\n".join(lines)


class ProxyManager:
    """Manages Burp Suite + mitmproxy stack.

    Flow: Browser/curl → Burp Suite (:8080) → mitmproxy (:8081) → TrafficCollector → X19
    Falls back gracefully if Burp or mitmproxy not installed.
    """

    BURP_PATHS = [
        "/usr/bin/burpsuite", "/usr/local/bin/burpsuite",
        os.path.expanduser("~/.burp/burpsuite.jar"),
        "/opt/BurpSuiteCommunity.jar", "/opt/BurpSuitePro.jar",
        "/snap/bin/burpsuite",
    ]

    def __init__(self):
        self.collector = TrafficCollector()
        self.burp_proc = None
        self.mitm_proc = None
        self.running = False
        self.burp_available = self._detect_burp() is not None
        self.mitm_available = self._detect_mitmproxy()
        self.flows_dir = CONFIG_DIR / "proxy"
        self.flows_dir.mkdir(parents=True, exist_ok=True)

    def _detect_burp(self) -> Optional[str]:
        import shutil
        for p in self.BURP_PATHS:
            if os.path.exists(p):
                return p
        for name in ("burpsuite", "BurpSuiteCommunity", "BurpSuitePro", "burp"):
            found = shutil.which(name)
            if found:
                return found
        return None

    def _detect_mitmproxy(self) -> bool:
        import shutil
        names = ("mitmdump", "mitmproxy", "mitmweb")
        if any(shutil.which(n) for n in names):
            return True
        # pip-installed in a venv that is not on PATH: check next to the running interpreter
        bindir = os.path.dirname(sys.executable)
        exts = (".exe", ".cmd", "") if os.name == "nt" else ("",)
        return any(os.path.exists(os.path.join(bindir, n + e)) for n in names for e in exts)

    def start(self, with_burp: bool = True, with_mitm: bool = True) -> bool:
        """Start the proxy stack. Returns True if at least one proxy is running."""
        burp_path = self._detect_burp()
        self.burp_available = burp_path is not None
        self.mitm_available = self._detect_mitmproxy()

        # Start Burp Suite
        if with_burp and burp_path:
            try:
                proj_file = str(self.flows_dir / "burp_project")
                config_file = str(self.flows_dir / "burp_config.json")
                # Write minimal Burp config
                Path(config_file).write_text(json.dumps({"project": {"name": "x19"}}))
                cmd = ["java", "-jar", burp_path, "--headless",
                       "--project-file=" + proj_file,
                       "--config-file=" + config_file]
                self.burp_proc = subprocess.Popen(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                time.sleep(4)
                log(f"[Proxy] Burp Suite started (PID {self.burp_proc.pid})")
            except Exception as e:
                log(f"[Proxy] Burp start failed: {e}")
                self.burp_proc = None

        # Start mitmproxy for traffic capture
        if with_mitm and self.mitm_available:
            try:
                flow_file = str(self.flows_dir / "flows.mitm")
                self.mitm_proc = subprocess.Popen(
                    ["mitmdump", "-q", "--listen-port", "8081",
                     "--mode", "upstream:http://127.0.0.1:8080",
                     "-w", flow_file],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                time.sleep(2)
                log(f"[Proxy] mitmproxy started (PID {self.mitm_proc.pid})")
            except Exception as e:
                log(f"[Proxy] mitmproxy start failed: {e}")
                self.mitm_proc = None
        elif with_mitm:
            # Start mitmproxy standalone (no upstream Burp)
            try:
                flow_file = str(self.flows_dir / "flows.mitm")
                self.mitm_proc = subprocess.Popen(
                    ["mitmdump", "-q", "--listen-port", "8080",
                     "-w", flow_file],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                time.sleep(2)
                log(f"[Proxy] mitmproxy standalone started (PID {self.mitm_proc.pid})")
            except Exception as e:
                log(f"[Proxy] mitmproxy start failed: {e}")
                self.mitm_proc = None

        self.running = self.burp_proc is not None or self.mitm_proc is not None
        if self.running:
            # Verify the proxy is ACTUALLY listening before routing tools through it.
            # Otherwise every curl/httpx fails with connection-refused (HTTP 000).
            if not self._wait_proxy_listening(8080, timeout=8):
                log("[Proxy] Port 8080 not listening — running WITHOUT proxy (tools connect directly)")
                self.running = False
                return False
            # Start collector thread
            threading.Thread(target=self._collect_loop, daemon=True, name="x19-proxy-collect").start()
            # Set env vars for routing through proxy
            proxy_url = self.proxy_url()
            os.environ["http_proxy"] = proxy_url
            os.environ["https_proxy"] = proxy_url
            os.environ["HTTP_PROXY"] = proxy_url
            os.environ["HTTPS_PROXY"] = proxy_url
        return self.running

    @staticmethod
    def _wait_proxy_listening(port: int, timeout: int = 8, host: str = "127.0.0.1") -> bool:
        """Poll until the proxy port accepts a TCP connection, or timeout."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection((host, port), timeout=1):
                    return True
            except OSError:
                time.sleep(0.5)
        return False

    def proxy_url(self) -> str:
        """Return the proxy URL that tools should route through."""
        if self.mitm_proc and not self.burp_proc:
            return "http://127.0.0.1:8081"
        return "http://127.0.0.1:8080"

    def _collect_loop(self):
        """Background thread that periodically captures traffic."""
        while self.running:
            try:
                self._capture_flows()
            except Exception as e:
                _swallow(e)
            time.sleep(3)

    def _capture_flows(self):
        """Read flows from mitmproxy's flow file."""
        if not self.mitm_available:
            return
        flow_file = self.flows_dir / "flows.mitm"
        if not flow_file.exists():
            return
        try:
            # Try reading mitmproxy flow file
            from mitmproxy.io import FlowReader
            with open(flow_file, "rb") as f:
                reader = FlowReader(f)
                for flow in reader.stream():
                    if flow.request and flow.response:
                        entry = TrafficEntry(
                            method=flow.request.method,
                            url=flow.request.pretty_url,
                            status=flow.response.status_code,
                            req_headers=str(flow.request.headers),
                            req_body=flow.request.text[:2000],
                            resp_headers=str(flow.response.headers),
                            resp_body=flow.response.text[:2000],
                            timestamp=time.time(),
                            size=len(flow.response.content),
                        )
                        self.collector.add(entry)
                        # Auto-attack any JWTs seen in the request or response (one-shot per token)
                        try:
                            blob = " ".join([
                                str(flow.request.headers),
                                flow.request.text or "",
                                str(flow.response.headers),
                                flow.response.text or "",
                            ])
                            jwt_hits = jwt_auto_scan(blob)
                            for f in jwt_hits:
                                log(f"[JWT-AUTO] {f.get('severity','?')}: {f.get('title','')}")
                        except Exception as ex:
                            _swallow(ex)
        except ImportError:
            # mitmproxy library not available — parse file with fallback
            self._capture_fallback()
        except Exception as e:
            _swallow(e)

    def _capture_fallback(self):
        """Fallback: read any captured HTTP logs if mitmproxy lib unavailable."""
        log_file = self.flows_dir / "captured.log"
        if not log_file.exists():
            return
        try:
            for line in log_file.read_text().split("\n"):
                if line.strip():
                    parts = line.strip().split("|", 4)
                    if len(parts) >= 4:
                        entry = TrafficEntry(
                            method=parts[0], url=parts[1], status=int(parts[2]),
                            resp_headers=parts[3] if len(parts) > 3 else "",
                            timestamp=time.time(),
                        )
                        self.collector.add(entry)
            log_file.write_text("")  # Clear processed entries
        except Exception as e:
            _swallow(e)

    def traffic_context(self) -> str:
        """Get formatted traffic for AI context."""
        return self.collector.captured_context(max_items=12, detail=False)

    def traffic_detail(self) -> str:
        """Get formatted traffic for AI context."""
        return self.collector.captured_context(max_items=5, detail=True)

    def stop(self):
        """Stop proxies and cleanup."""
        self.running = False
        for var in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"]:
            os.environ.pop(var, None)
        if self.mitm_proc:
            try:
                self.mitm_proc.terminate()
                self.mitm_proc.wait(timeout=5)
            except Exception:
                self.mitm_proc.kill()
        if self.burp_proc:
            try:
                self.burp_proc.terminate()
                self.burp_proc.wait(timeout=5)
            except Exception:
                self.burp_proc.kill()
        log("[Proxy] Stopped")
