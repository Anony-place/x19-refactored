"""
X19 Native Network Scanner.
Pure-Python async/threaded port scanner, banner grabber, and TLS inspector.
Zero external dependencies (no nmap/masscan binary required).
"""

from __future__ import annotations
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

from execution.scope_guard import ScopeGuard, ScopeViolationError

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3000, 3306, 3389, 5000, 5432, 5900, 6379, 8000, 8080,
    8443, 8888, 9000, 9200, 27017
]

SERVICE_PROBES = {
    21: b"QUIT\r\n",
    22: b"SSH-2.0-X19Scanner\r\n",
    80: b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: X19-Scanner\r\n\r\n",
    443: b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: X19-Scanner\r\n\r\n",
    8080: b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: X19-Scanner\r\n\r\n",
    8443: b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: X19-Scanner\r\n\r\n",
}


@dataclass
class PortResult:
    port: int
    state: str  # "open", "closed", "filtered"
    service: str = "unknown"
    banner: str = ""
    tls_info: Dict[str, str] = field(default_factory=dict)
    response_time_ms: float = 0.0


class NativeNetScanner:
    """Fast, safe, in-process port and service scanner with strict scope validation."""

    def __init__(self, scope_guard: Optional[ScopeGuard] = None, timeout: float = 1.5, max_workers: int = 50):
        self.scope_guard = scope_guard or ScopeGuard(enforce=False)
        self.timeout = timeout
        self.max_workers = max_workers

    def scan_target(self, target: str, ports: Optional[List[int]] = None) -> List[PortResult]:
        """Scan target host for open ports within the scope."""
        self.scope_guard.assert_allowed(target)
        
        target_host = ScopeGuard._clean_target(target)
        port_list = ports or COMMON_PORTS
        open_ports: List[PortResult] = []

        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(port_list))) as executor:
            future_to_port = {
                executor.submit(self._probe_port, target_host, port): port
                for port in port_list
            }
            for future in as_completed(future_to_port):
                try:
                    res = future.result()
                    if res and res.state == "open":
                        open_ports.append(res)
                except Exception:
                    pass

        return sorted(open_ports, key=lambda x: x.port)

    def _probe_port(self, host: str, port: int) -> PortResult:
        start_time = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect((host, port))
            elapsed = (time.perf_counter() - start_time) * 1000.0
            
            # Service and banner grab
            service = self._guess_service_name(port)
            banner = ""
            tls_info: Dict[str, str] = {}

            if port in (443, 8443):
                tls_info, banner = self._probe_tls(host, port)
                if tls_info:
                    service = "https"
            else:
                banner = self._grab_banner(sock, host, port)

            return PortResult(
                port=port,
                state="open",
                service=service,
                banner=banner,
                tls_info=tls_info,
                response_time_ms=round(elapsed, 2)
            )
        except (socket.timeout, ConnectionRefusedError, OSError):
            return PortResult(port=port, state="closed")
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _grab_banner(self, sock: socket.socket, host: str, port: int) -> str:
        try:
            sock.settimeout(1.0)
            # Try passive banner first
            data = sock.recv(1024)
            if data:
                return data.decode("utf-8", errors="ignore").strip()

            # Active probe if no initial greeting
            probe = SERVICE_PROBES.get(port, b"\r\n\r\n")
            if b"Host: target" in probe:
                probe = probe.replace(b"target", host.encode())
            sock.sendall(probe)
            data = sock.recv(1024)
            return data.decode("utf-8", errors="ignore").strip()
        except Exception:
            return ""

    def _probe_tls(self, host: str, port: int) -> Tuple[Dict[str, str], str]:
        info: Dict[str, str] = {}
        banner: str = ""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    version = ssock.version() or ""
                    cipher = ssock.cipher() or ()
                    info["tls_version"] = version
                    info["cipher"] = cipher[0] if cipher else ""
                    if cert:
                        subj = dict(x[0] for x in cert.get("subject", ()))
                        info["common_name"] = subj.get("commonName", "")
                        info["issuer"] = dict(x[0] for x in cert.get("issuer", ())).get("commonName", "")
                    
                    # Try sending an HTTP GET over TLS
                    req = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: X19-Scanner\r\n\r\n".encode()
                    ssock.sendall(req)
                    res = ssock.recv(1024)
                    banner = res.decode("utf-8", errors="ignore").strip()
        except Exception:
            pass
        return info, banner

    @staticmethod
    def _guess_service_name(port: int) -> str:
        services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 135: "msrpc", 139: "netbios-ssn",
            143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps",
            995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
            3000: "http-dev", 3306: "mysql", 3389: "rdp", 5000: "http-flask",
            5432: "postgresql", 5900: "vnc", 6379: "redis", 8000: "http-alt",
            8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
            9000: "http-admin", 9200: "elasticsearch", 27017: "mongodb"
        }
        return services.get(port, f"service-{port}")
