"""
X19 Native Web Fuzzer and Endpoint Discovery Engine.
High-performance in-process web directory and parameter discovery.
Zero external dependencies (no gobuster/ffuf binary required).
"""

from __future__ import annotations
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
import requests

from execution.scope_guard import ScopeGuard, ScopeViolationError

DEFAULT_WORDLIST = [
    ".env", ".git/config", ".git/HEAD", ".gitignore", ".svn/entries",
    "admin", "administrator", "admin/login", "admin.php", "api", "api/v1",
    "api/v2", "api/swagger.json", "api/docs", "app", "assets", "auth",
    "backup", "backup.sql", "backup.zip", "bin", "config", "config.json",
    "config.php", "console", "dashboard", "data", "db", "debug", "dev",
    "docs", "download", "dump.sql", "graphql", "health", "healthz",
    "id_rsa", "id_rsa.pub", "info.php", "internal", "login", "metrics",
    "oauth", "phpinfo.php", "ping", "portal", "private", "public",
    "robots.txt", "root", "secret", "server-status", "setup", "sitemap.xml",
    "static", "status", "swagger", "swagger.json", "swagger-ui.html",
    "test", "upload", "uploads", "user", "v1", "v2", "version", "wp-admin",
    "wp-content", "wp-login.php"
]


@dataclass
class FuzzResult:
    path: str
    url: str
    status_code: int
    content_length: int
    content_type: str = ""
    redirect_url: str = ""
    title: str = ""
    is_interesting: bool = False
    evidence_snippet: str = ""


class NativeWebFuzzer:
    """High-speed in-process HTTP directory & endpoint fuzzer with strict scope guard."""

    def __init__(
        self,
        scope_guard: Optional[ScopeGuard] = None,
        timeout: float = 3.5,
        max_workers: int = 25,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) X19/3.0"
    ):
        self.scope_guard = scope_guard or ScopeGuard(enforce=False)
        self.timeout = timeout
        self.max_workers = max_workers
        self.user_agent = user_agent

    def fuzz(
        self,
        base_url: str,
        wordlist: Optional[List[str]] = None,
        status_filter: Optional[Set[int]] = None
    ) -> List[FuzzResult]:
        """Fuzz base URL for paths in wordlist within scope."""
        self.scope_guard.assert_allowed(base_url)

        if not base_url.startswith(("http://", "https://")):
            base_url = f"http://{base_url}"
        base_url = base_url.rstrip("/")

        paths = wordlist or DEFAULT_WORDLIST
        allowed_status = status_filter or {200, 201, 204, 301, 302, 307, 308, 401, 403, 500}
        results: List[FuzzResult] = []

        session = requests.Session()
        session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "*/*"
        })

        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(paths))) as executor:
            future_to_path = {
                executor.submit(self._probe_path, session, base_url, path): path
                for path in paths
            }
            for future in as_completed(future_to_path):
                try:
                    res = future.result()
                    if res and res.status_code in allowed_status:
                        results.append(res)
                except Exception:
                    pass

        return sorted(results, key=lambda x: (x.status_code != 200, x.path))

    def _probe_path(self, session: requests.Session, base_url: str, path: str) -> Optional[FuzzResult]:
        clean_path = path.lstrip("/")
        full_url = f"{base_url}/{clean_path}"

        try:
            # First attempt with GET (stream to avoid downloading huge files)
            resp = session.get(
                full_url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False,
                stream=True
            )

            status = resp.status_code
            length = int(resp.headers.get("Content-Length", 0))
            content_type = resp.headers.get("Content-Type", "")
            redirect_url = resp.headers.get("Location", "")
            
            # Read snippet
            snippet = ""
            try:
                raw_chunk = next(resp.iter_content(chunk_size=1024), b"")
                snippet = raw_chunk.decode("utf-8", errors="ignore")[:300]
            except Exception:
                pass

            # Extract title if HTML
            title = ""
            if "<title>" in snippet.lower():
                try:
                    title_part = snippet.lower().split("<title>")[1].split("</title>")[0]
                    title = title_part.strip()
                except Exception:
                    pass

            is_interesting = status in (200, 201) or (
                status in (301, 302) and any(kw in redirect_url for kw in ["admin", "login", "dashboard"])
            ) or (status == 403 and any(kw in clean_path for kw in [".git", ".env", "admin", "backup"]))

            return FuzzResult(
                path=clean_path,
                url=full_url,
                status_code=status,
                content_length=length,
                content_type=content_type,
                redirect_url=redirect_url,
                title=title,
                is_interesting=is_interesting,
                evidence_snippet=snippet
            )
        except (requests.RequestException, ScopeViolationError):
            return None
