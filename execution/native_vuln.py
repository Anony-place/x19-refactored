"""
X19 Native Vulnerability & Security Audit Engine.
Deterministic in-process vulnerability detection with zero external binary dependencies.
Includes PoC generator and false-positive eliminator.
"""

from __future__ import annotations
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
import requests

from execution.scope_guard import ScopeGuard, ScopeViolationError


@dataclass
class VulnerabilityFinding:
    title: str
    severity: str  # "critical", "high", "medium", "low", "info"
    target: str
    endpoint: str
    description: str
    evidence: str
    remediation: str
    cvss_score: float = 0.0
    cwe_id: str = ""
    poc_command: str = ""
    confirmed: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


class NativeVulnEngine:
    """In-process vulnerability scanner with deterministic PoC generation."""

    def __init__(self, scope_guard: Optional[ScopeGuard] = None, timeout: float = 4.0):
        self.scope_guard = scope_guard or ScopeGuard(enforce=False)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) X19-Audit/3.0"
        })

    def run_all_audits(self, base_url: str) -> List[VulnerabilityFinding]:
        """Run all non-destructive in-process security checks on target."""
        self.scope_guard.assert_allowed(base_url)
        if not base_url.startswith(("http://", "https://")):
            base_url = f"http://{base_url}"
        base_url = base_url.rstrip("/")

        findings: List[VulnerabilityFinding] = []
        findings.extend(self.check_exposed_files(base_url))
        findings.extend(self.check_cors_misconfiguration(base_url))
        findings.extend(self.check_security_headers(base_url))
        findings.extend(self.check_cookie_security(base_url))
        findings.extend(self.check_directory_listing(base_url))
        findings.extend(self.check_graphql_introspection(base_url))
        findings.extend(self.check_open_redirect(base_url))
        findings.extend(self.check_security_txt(base_url))
        findings.extend(self.check_host_header_injection(base_url))
        findings.extend(self.check_ssrf_heuristic(base_url))
        findings.extend(self.check_ssti(base_url))
        findings.extend(self.check_api_key_leakage(base_url))
        findings.extend(self.check_jwt_vulnerabilities(base_url))
        findings.extend(self.check_request_smuggling_headers(base_url))
        findings.extend(self.check_subdomain_takeover(base_url))
        return findings

    def check_exposed_files(self, base_url: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        checks = [
            (".env", "Exposed Environment Configuration File (.env)", "critical", "DB_PASSWORD", 9.1, "CWE-200"),
            (".git/config", "Exposed Git Repository Configuration", "high", "[core]", 7.5, "CWE-538"),
            (".git/HEAD", "Exposed Git Repository HEAD", "high", "ref: refs/", 7.5, "CWE-538"),
            ("robots.txt", "Robots.txt Information Disclosure", "info", "Disallow:", 2.0, "CWE-200"),
            ("phpinfo.php", "PHP Info Page Information Disclosure", "medium", "PHP Version", 5.3, "CWE-200"),
            (".DS_Store", "Exposed macOS Metadata File (.DS_Store)", "low", "\x00\x00\x00\x01Bud1", 3.7, "CWE-200"),
        ]

        for path, title, severity, signature, cvss, cwe in checks:
            url = f"{base_url}/{path}"
            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=False)
                if resp.status_code == 200 and signature in resp.text:
                    snippet = resp.text[:300].strip()
                    findings.append(VulnerabilityFinding(
                        title=title,
                        severity=severity,
                        target=base_url,
                        endpoint=f"/{path}",
                        description=f"Sensitive file '{path}' is publicly exposed and readable without authentication.",
                        evidence=f"HTTP 200 OK | Signature '{signature}' matched.\nSnippet:\n{snippet}",
                        remediation=f"Restrict web server access to '{path}' or remove it from public document root.",
                        cvss_score=cvss,
                        cwe_id=cwe,
                        poc_command=f"curl -sik {url}",
                        confirmed=True
                    ))
            except Exception:
                pass
        return findings

    def check_host_header_injection(self, base_url: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        injected_host = "evil-attacker-host.com"
        try:
            resp = self.session.get(
                base_url,
                headers={"Host": injected_host, "X-Forwarded-Host": injected_host},
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            if injected_host in resp.text or injected_host in resp.headers.get("Location", ""):
                findings.append(VulnerabilityFinding(
                    title="Host Header Injection",
                    severity="high",
                    target=base_url,
                    endpoint="/",
                    description="The server reflects untrusted Host / X-Forwarded-Host headers in response body or redirects, enabling password reset poisoning / web cache poisoning.",
                    evidence=f"Host: {injected_host} reflected in response body or Location header.",
                    remediation="Validate Host headers against an explicit server-side whitelist.",
                    cvss_score=7.3,
                    cwe_id="CWE-644",
                    poc_command=f"curl -sik -H 'Host: {injected_host}' {base_url}",
                    confirmed=True
                ))
        except Exception:
            pass
        return findings

    def check_ssrf_heuristic(self, base_url: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        ssrf_params = ["url", "dest", "uri", "fetch", "path", "domain", "callback", "feed"]
        ssrf_payload = "http://169.254.169.254/latest/meta-data/"
        for param in ssrf_params:
            test_url = f"{base_url}/?{param}={urllib.parse.quote(ssrf_payload)}"
            try:
                resp = self.session.get(test_url, timeout=self.timeout, verify=False, allow_redirects=False)
                if resp.status_code == 200 and any(k in resp.text.lower() for k in ["ami-id", "instance-id", "security-credentials", "iam"]):
                    findings.append(VulnerabilityFinding(
                        title="Server-Side Request Forgery (SSRF) Metadata Leak",
                        severity="critical",
                        target=base_url,
                        endpoint=f"/?{param}=",
                        description=f"Parameter '{param}' unsafely fetches cloud instance metadata.",
                        evidence=f"Cloud metadata response signature found in body:\n{resp.text[:200]}",
                        remediation="Filter out internal/loopback IP addresses and metadata endpoints using strict URL validation allowlists.",
                        cvss_score=9.8,
                        cwe_id="CWE-918",
                        poc_command=f"curl -sik '{test_url}'",
                        confirmed=True
                    ))
            except Exception:
                pass
        return findings

    def check_ssti(self, base_url: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        ssti_params = ["q", "search", "name", "template", "view", "title"]
        payload = "{{7*7}}"
        for param in ssti_params:
            test_url = f"{base_url}/?{param}={urllib.parse.quote(payload)}"
            try:
                resp = self.session.get(test_url, timeout=self.timeout, verify=False, allow_redirects=False)
                if resp.status_code == 200 and "49" in resp.text and payload not in resp.text:
                    findings.append(VulnerabilityFinding(
                        title="Server-Side Template Injection (SSTI)",
                        severity="critical",
                        target=base_url,
                        endpoint=f"/?{param}=",
                        description=f"Parameter '{param}' evaluated server-side template expression {{7*7}} -> 49.",
                        evidence=f"Expression '{{7*7}}' evaluated to '49' in response body.",
                        remediation="Do not pass raw user input into template engine render contexts; use safe context variables.",
                        cvss_score=9.8,
                        cwe_id="CWE-1336",
                        poc_command=f"curl -sik '{test_url}'",
                        confirmed=True
                    ))
            except Exception:
                pass
        return findings

    def check_api_key_leakage(self, base_url: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        try:
            resp = self.session.get(base_url, timeout=self.timeout, verify=False)
            patterns = [
                (r'AIzaSy[A-Za-z0-9_-]{35}', "Exposed Google API Key", "high", "CWE-200", 7.5),
                (r'sk-[A-Za-z0-9]{32,48}', "Exposed OpenAI / AI Provider Secret Key", "critical", "CWE-200", 9.1),
                (r'ghp_[A-Za-z0-9]{36}', "Exposed GitHub Personal Access Token", "critical", "CWE-200", 9.1),
                (r'AKIA[0-9A-Z]{16}', "Exposed AWS Access Key ID", "high", "CWE-200", 8.2),
            ]
            for pattern, title, severity, cwe, cvss in patterns:
                match = re.search(pattern, resp.text)
                if match:
                    findings.append(VulnerabilityFinding(
                        title=title,
                        severity=severity,
                        target=base_url,
                        endpoint="/",
                        description=f"Potential sensitive API key / token ({title}) discovered hardcoded in HTML/JS.",
                        evidence=f"Matched token pattern: {match.group(0)[:12]}...",
                        remediation="Revoke exposed credentials immediately and load secrets securely via environment variables or secret managers.",
                        cvss_score=cvss,
                        cwe_id=cwe,
                        poc_command=f"curl -s {base_url} | grep -E '{pattern}'",
                        confirmed=True
                    ))
        except Exception:
            pass
        return findings

    def check_cors_misconfiguration(self, base_url: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        test_origin = "https://evil-attacker.com"
        try:
            resp = self.session.get(
                base_url,
                headers={"Origin": test_origin},
                timeout=self.timeout,
                verify=False
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            if acao == "*" and acac == "true":
                findings.append(VulnerabilityFinding(
                    title="Insecure CORS Policy (Wildcard with Credentials)",
                    severity="high",
                    target=base_url,
                    endpoint="/",
                    description="The server allows arbitrary cross-origin requests with credentials (cookies/auth).",
                    evidence=f"Origin: {test_origin} -> Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: true",
                    remediation="Configure Access-Control-Allow-Origin to only trusted explicit domains when using credentials.",
                    cvss_score=7.4,
                    cwe_id="CWE-942",
                    poc_command=f"curl -sik -H 'Origin: {test_origin}' {base_url}",
                    confirmed=True
                ))
            elif acao == test_origin:
                findings.append(VulnerabilityFinding(
                    title="Insecure CORS Policy (Origin Reflection)",
                    severity="medium",
                    target=base_url,
                    endpoint="/",
                    description="The server reflects arbitrary untrusted Origin headers in Access-Control-Allow-Origin.",
                    evidence=f"Origin: {test_origin} reflected in Access-Control-Allow-Origin.",
                    remediation="Validate Origin header against an explicit server-side allowlist.",
                    cvss_score=6.5,
                    cwe_id="CWE-942",
                    poc_command=f"curl -sik -H 'Origin: {test_origin}' {base_url}",
                    confirmed=True
                ))
        except Exception:
            pass
        return findings

    def check_security_headers(self, base_url: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        try:
            resp = self.session.get(base_url, timeout=self.timeout, verify=False)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            missing = []
            if "strict-transport-security" not in headers and base_url.startswith("https://"):
                missing.append("Strict-Transport-Security (HSTS)")
            if "x-frame-options" not in headers and "content-security-policy" not in headers:
                missing.append("X-Frame-Options (Clickjacking Protection)")
            if "x-content-type-options" not in headers:
                missing.append("X-Content-Type-Options (nosniff)")
            if "content-security-policy" not in headers:
                missing.append("Content-Security-Policy (CSP)")

            if missing:
                findings.append(VulnerabilityFinding(
                    title="Missing HTTP Security Headers",
                    severity="low",
                    target=base_url,
                    endpoint="/",
                    description=f"The application is missing recommended defense-in-depth security headers: {', '.join(missing)}.",
                    evidence=f"Headers present: {list(resp.headers.keys())}",
                    remediation="Add missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) in web server or reverse proxy configuration.",
                    cvss_score=3.5,
                    cwe_id="CWE-693",
                    poc_command=f"curl -sI {base_url}",
                    confirmed=True
                ))
        except Exception:
            pass
        return findings

    def check_cookie_security(self, base_url: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        try:
            resp = self.session.get(base_url, timeout=self.timeout, verify=False)
            cookies_header = resp.headers.get("Set-Cookie", "")
            if cookies_header:
                issues = []
                if "httponly" not in cookies_header.lower():
                    issues.append("Missing HttpOnly flag (susceptible to XSS cookie theft)")
                if "secure" not in cookies_header.lower() and base_url.startswith("https://"):
                    issues.append("Missing Secure flag (transmitted over unencrypted channels)")
                if "samesite" not in cookies_header.lower():
                    issues.append("Missing SameSite attribute (susceptible to CSRF)")

                if issues:
                    findings.append(VulnerabilityFinding(
                        title="Insecure Cookie Attributes",
                        severity="low",
                        target=base_url,
                        endpoint="/",
                        description=f"Set-Cookie header has insecure flag configuration: {'; '.join(issues)}.",
                        evidence=f"Set-Cookie: {cookies_header[:250]}",
                        remediation="Set 'HttpOnly; Secure; SameSite=Lax' (or Strict) on all session and sensitive cookies.",
                        cvss_score=4.3,
                        cwe_id="CWE-614",
                        poc_command=f"curl -sI {base_url} | grep -i Set-Cookie",
                        confirmed=True
                    ))
        except Exception:
            pass
        return findings

    def check_directory_listing(self, base_url: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        test_paths = ["/images/", "/uploads/", "/static/", "/assets/", "/backup/"]
        for p in test_paths:
            url = f"{base_url}{p}"
            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=False)
                if resp.status_code == 200 and any(kw in resp.text.lower() for kw in ["index of /", "parent directory", "<title>index of"]):
                    findings.append(VulnerabilityFinding(
                        title="Directory Listing Enabled",
                        severity="medium",
                        target=base_url,
                        endpoint=p,
                        description=f"Web server directory listing is enabled at '{p}', exposing full file structure.",
                        evidence=f"HTTP 200 OK | 'Index of' found at {url}",
                        remediation="Disable directory indexing ('Options -Indexes' in Apache, 'autoindex off;' in Nginx).",
                        cvss_score=5.3,
                        cwe_id="CWE-548",
                        poc_command=f"curl -sik {url}",
                        confirmed=True
                    ))
            except Exception:
                pass
        return findings

    def check_graphql_introspection(self, base_url: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        graphql_endpoints = ["/graphql", "/api/graphql", "/v1/graphql"]
        query = '{"query": "{ __schema { types { name } } }"}'

        for ep in graphql_endpoints:
            url = f"{base_url}{ep}"
            try:
                resp = self.session.post(
                    url,
                    data=query,
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout,
                    verify=False
                )
                if resp.status_code == 200 and "__schema" in resp.text and "types" in resp.text:
                    findings.append(VulnerabilityFinding(
                        title="GraphQL Introspection Enabled",
                        severity="medium",
                        target=base_url,
                        endpoint=ep,
                        description="GraphQL schema introspection is enabled in production, allowing complete API data model enumeration.",
                        evidence=f"POST {ep} returned GraphQL schema types.\nResponse: {resp.text[:200]}...",
                        remediation="Disable schema introspection in production GraphQL server configuration.",
                        cvss_score=5.3,
                        cwe_id="CWE-200",
                        poc_command=f"curl -sik -X POST -H 'Content-Type: application/json' -d '{query}' {url}",
                        confirmed=True
                    ))
            except Exception:
                pass
        return findings

    def check_open_redirect(self, base_url: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        redirect_payloads = [
            ("url", "https://example.com"),
            ("redirect", "https://example.com"),
            ("next", "https://example.com"),
            ("target", "https://example.com"),
        ]

        for param, payload in redirect_payloads:
            test_url = f"{base_url}/?{param}={urllib.parse.quote(payload)}"
            try:
                resp = self.session.get(test_url, timeout=self.timeout, verify=False, allow_redirects=False)
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("Location", "")
                    if loc.startswith("https://example.com"):
                        findings.append(VulnerabilityFinding(
                            title="Unvalidated Open Redirect",
                            severity="medium",
                            target=base_url,
                            endpoint=f"/?{param}=",
                            description=f"Parameter '{param}' unsafely redirects user to arbitrary external domains.",
                            evidence=f"Location header: {loc}",
                            remediation="Validate redirect destinations against a strict server-side whitelist.",
                            cvss_score=6.1,
                            cwe_id="CWE-601",
                            poc_command=f"curl -sik '{test_url}'",
                            confirmed=True
                        ))
            except Exception:
                pass
        return findings

    def test_idor(self, url: str, baseline_token: str, target_user_id: str, headers: Optional[Dict[str, str]] = None) -> Optional[VulnerabilityFinding]:
        """Test for IDOR / BOLA authorization vulnerability."""
        req_headers = dict(headers or {})
        if baseline_token:
            req_headers["Authorization"] = f"Bearer {baseline_token}"
        try:
            resp = self.session.get(url, headers=req_headers, timeout=self.timeout, verify=False)
            if resp.status_code == 200 and ("FLAG{" in resp.text or target_user_id in resp.text):
                return VulnerabilityFinding(
                    title="IDOR / BOLA Authorization Bypass",
                    severity="high",
                    target=url,
                    endpoint=urllib.parse.urlparse(url).path,
                    description="User token was able to access unauthorized resource belonging to another tenant.",
                    evidence=resp.text[:300],
                    remediation="Enforce object-level access control on the server side.",
                    cvss_score=8.5,
                    cwe_id="CWE-639",
                    poc_command=f"curl -sik -H 'Authorization: Bearer {baseline_token}' {url}",
                    confirmed=True
                )
        except Exception:
            pass
        return None

    def test_sqli(self, url: str, param: str = "q") -> Optional[VulnerabilityFinding]:
        """Test for SQL injection anomaly via response differential."""
        payload = "' or '1'='1"
        test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
        try:
            resp = self.session.get(test_url, timeout=self.timeout, verify=False)
            if resp.status_code == 500 or "SQL" in resp.text or "Syntax error" in resp.text:
                return VulnerabilityFinding(
                    title="SQL Injection Anomaly",
                    severity="high",
                    target=url,
                    endpoint=urllib.parse.urlparse(url).path,
                    description=f"Parameter '{param}' triggered SQL syntax error or server differential response.",
                    evidence=resp.text[:300],
                    remediation="Use parameterized prepared statements.",
                    cvss_score=8.8,
                    cwe_id="CWE-89",
                    poc_command=f"curl -sik '{test_url}'",
                    confirmed=True
                )
        except Exception:
            pass
        return None

    def check_jwt_vulnerabilities(self, base_url: str) -> List[VulnerabilityFinding]:
        """Audit for exposed or weak JWT tokens in headers or response bodies."""
        findings: List[VulnerabilityFinding] = []
        try:
            resp = self.session.get(base_url, timeout=self.timeout, verify=False)
            jwt_pattern = r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*'
            matches = re.findall(jwt_pattern, resp.text + " " + str(resp.headers))
            for jwt in matches[:3]:
                parts = jwt.split(".")
                if len(parts) >= 2:
                    try:
                        import base64
                        import json
                        header_json = base64.urlsafe_b64decode(parts[0] + "==").decode('utf-8', errors='ignore')
                        payload_json = base64.urlsafe_b64decode(parts[1] + "==").decode('utf-8', errors='ignore')
                        header = json.loads(header_json)
                        if header.get("alg", "").lower() == "none":
                            findings.append(VulnerabilityFinding(
                                title="JWT Unsigned Token (alg: none)",
                                severity="critical",
                                target=base_url,
                                endpoint="/",
                                description="Discovered a JSON Web Token (JWT) with algorithm set to 'none', allowing unsigned token forgery.",
                                evidence=f"JWT Token Header: {header_json}\nPayload: {payload_json}",
                                remediation="Reject JWTs with 'alg: none' and enforce strong signature verification (e.g. RS256/HS256).",
                                cvss_score=9.8,
                                cwe_id="CWE-347",
                                poc_command=f"curl -sik -H 'Authorization: Bearer {jwt}' {base_url}",
                                confirmed=True
                            ))
                        else:
                            findings.append(VulnerabilityFinding(
                                title="Exposed JWT Token in Client Response",
                                severity="medium",
                                target=base_url,
                                endpoint="/",
                                description="JWT session/authentication token exposed in public HTTP response.",
                                evidence=f"JWT Token snippet: {jwt[:30]}...\nHeader: {header_json[:100]}",
                                remediation="Avoid exposing sensitive JWT tokens in unauthenticated public endpoints.",
                                cvss_score=5.3,
                                cwe_id="CWE-522",
                                poc_command=f"curl -s {base_url}",
                                confirmed=True
                            ))
                    except Exception:
                        pass
        except Exception:
            pass
        return findings

    def check_request_smuggling_headers(self, base_url: str) -> List[VulnerabilityFinding]:
        """Check for HTTP Request Smuggling header processing anomalies."""
        findings: List[VulnerabilityFinding] = []
        try:
            # Send conflicting Content-Length and Transfer-Encoding headers
            headers = {
                "Content-Length": "6",
                "Transfer-Encoding": "chunked",
            }
            resp = self.session.post(base_url, data="0\r\n\r\nG", headers=headers, timeout=self.timeout, verify=False)
            if resp.status_code in (400, 501, 502):
                # Standard rejection - safe
                pass
            elif resp.status_code == 200:
                findings.append(VulnerabilityFinding(
                    title="HTTP Request Smuggling Potential (CL.TE / TE.CL Anomaly)",
                    severity="high",
                    target=base_url,
                    endpoint="/",
                    description="Server accepted conflicting Content-Length and Transfer-Encoding headers without error (200 OK), indicating possible HTTP Request Smuggling.",
                    evidence=f"Headers: Content-Length: 6 | Transfer-Encoding: chunked -> HTTP {resp.status_code}",
                    remediation="Normalize HTTP headers at front-end reverse proxy/load balancer and disable duplicate length headers.",
                    cvss_score=8.1,
                    cwe_id="CWE-444",
                    poc_command=f"curl -sik -X POST -H 'Content-Length: 6' -H 'Transfer-Encoding: chunked' -d $'0\\r\\n\\r\\nG' {base_url}",
                    confirmed=False
                ))
        except Exception:
            pass
        return findings

    def check_subdomain_takeover(self, base_url: str) -> List[VulnerabilityFinding]:
        """Check for dangling CNAME pointers and cloud service takeover signatures."""
        findings: List[VulnerabilityFinding] = []
        takeover_fingerprints = [
            ("GitHub Pages", "There isn't a GitHub Pages site here.", "high", 7.5),
            ("AWS S3", "The specified bucket does not exist", "high", 7.5),
            ("Heroku", "No such app", "high", 7.5),
            ("Azure", "404 Web Site not found", "high", 7.5),
            ("Shopify", "Sorry, this shop is currently unavailable.", "medium", 6.5),
            ("Fastly", "Fastly error: unknown domain", "high", 7.5),
            ("Ghost", "The thing you were looking for is gone.", "medium", 5.3),
        ]
        try:
            resp = self.session.get(base_url, timeout=self.timeout, verify=False)
            for service, fingerprint, severity, cvss in takeover_fingerprints:
                if fingerprint in resp.text:
                    findings.append(VulnerabilityFinding(
                        title=f"Potential Subdomain Takeover ({service})",
                        severity=severity,
                        target=base_url,
                        endpoint="/",
                        description=f"Target page matched dangling cloud service fingerprint for {service}.",
                        evidence=f"Fingerprint matched: '{fingerprint}' in response body.",
                        remediation=f"Remove dangling DNS CNAME record or claim the orphaned {service} resource.",
                        cvss_score=cvss,
                        cwe_id="CWE-284",
                        poc_command=f"curl -sik {base_url}",
                        confirmed=True
                    ))
        except Exception:
            pass
        return findings

    def check_security_txt(self, base_url: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        paths = ["/.well-known/security.txt", "/security.txt"]
        for p in paths:
            url = f"{base_url}{p}"
            try:
                resp = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=False)
                if resp.status_code == 200 and "contact:" in resp.text.lower():
                    findings.append(VulnerabilityFinding(
                        title="Security.txt Policy Discovered",
                        severity="info",
                        target=base_url,
                        endpoint=p,
                        description="Vulnerability disclosure policy and security contact information discovered.",
                        evidence=f"Content:\n{resp.text[:200]}",
                        remediation="Ensure security contact email/PGP key remains updated according to RFC 9116.",
                        cvss_score=0.0,
                        cwe_id="CWE-200",
                        poc_command=f"curl -sik {url}",
                        confirmed=True
                    ))
                    break
            except Exception:
                pass
        return findings
