"""Code-level remediation.

The report used to emit a single nginx rule for every finding — including a
GraphQL config, which is not nginx at all. This module returns a fix in the
language and layer the finding actually lives in, plus a short reason.

Snippets are defensive patterns, not drop-in patches: they show the shape of the
correct code so the owning team can apply it to their own stack.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Sequence

from reporting.compliance import VULN_CLASS, classify_finding, map_finding

__all__ = ["Remediation", "remediation_for", "remediation_summary", "LANGUAGE_LABELS"]


LANGUAGE_LABELS = {
    "nginx": "nginx",
    "python": "Python",
    "javascript": "JavaScript / Node",
    "java": "Java",
    "go": "Go",
    "yaml": "YAML",
    "bash": "shell",
    "generic": "configuration",
}


@dataclass
class Remediation:
    """A concrete fix for one vulnerability class."""

    vuln_class: str
    language: str
    snippet: str
    explanation: str
    verify: str = ""
    references: List[str] = None

    def __post_init__(self):
        if self.references is None:
            self.references = []

    @property
    def language_label(self) -> str:
        return LANGUAGE_LABELS.get(self.language, self.language)

    def to_dict(self) -> Dict[str, Any]:
        mapping = map_finding(_ClassProbe(self.vuln_class))
        return {
            "vuln_class": self.vuln_class,
            "language": self.language,
            "language_label": self.language_label,
            "snippet": self.snippet,
            "explanation": self.explanation,
            "verify": self.verify,
            "references": list(self.references),
            "cwe": mapping.cwe,
            "owasp_web": mapping.owasp_web,
        }


class _ClassProbe:
    """Lets ``map_finding`` work from a class name rather than a finding."""

    def __init__(self, vuln_class: str):
        self.title = vuln_class
        self.evidence = ""


_FIXES: Dict[str, Remediation] = {
    VULN_CLASS.SQLI: Remediation(
        VULN_CLASS.SQLI, "python",
        '''# Never interpolate user input into SQL. Bind it.
# BEFORE
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# AFTER (parameterised — the driver escapes and quotes for you)
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))''',
        "Parameter binding keeps data separate from the statement, so input can "
        "never change the query's structure. ORMs do this by default — the bug "
        "usually comes from a raw() or text() escape hatch.",
        "Re-run the payload that produced the anomaly; it must be treated as a "
        "literal value and return no rows.",
        ["CWE-89", "OWASP A03:2021"],
    ),
    VULN_CLASS.BROKEN_ACCESS: Remediation(
        VULN_CLASS.BROKEN_ACCESS, "python",
        '''# Authorise the OBJECT, not just the route.
# BEFORE
@app.get("/api/v1/orders/{order_id}")
def get_order(order_id: int, user=Depends(authenticated)):
    return db.orders.get(order_id)

# AFTER
@app.get("/api/v1/orders/{order_id}")
def get_order(order_id: int, user=Depends(authenticated)):
    order = db.orders.get(order_id)
    if order is None or order.owner_id != user.id:
        raise HTTPException(404)   # 404, not 403: do not confirm the ID exists
    return order''',
        "Deny by default and check ownership on every object read. Returning 404 "
        "rather than 403 avoids an ID-enumeration oracle.",
        "Request another tenant's object ID with a valid low-privilege session; "
        "it must not return the record.",
        ["CWE-639", "OWASP API1:2023"],
    ),
    VULN_CLASS.SSRF: Remediation(
        VULN_CLASS.SSRF, "python",
        '''import ipaddress, socket
from urllib.parse import urlparse

DENIED = (ipaddress.ip_address("169.254.169.254"),)

def assert_safe_url(url: str) -> None:
    host = urlparse(url).hostname or ""
    if host in {"localhost", "metadata.google.internal"}:
        raise ValueError("host not allowed")
    for info in socket.getaddrinfo(host, None):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip in DENIED:
            raise ValueError("resolves to a non-public address")
    # Re-resolve at request time, or pin the validated IP, to avoid DNS rebinding.''',
        "Validate the *resolved* address, not just the hostname, and re-check "
        "after resolution — otherwise a rebinding DNS record defeats the filter.",
        "Request a URL pointing at 169.254.169.254 and at 127.0.0.1; both must "
        "be refused before any request is sent.",
        ["CWE-918", "OWASP A10:2021"],
    ),
    VULN_CLASS.SSTI: Remediation(
        VULN_CLASS.SSTI, "python",
        '''# BEFORE — the template source itself comes from user input
Template(user_supplied).render()

# AFTER — the template is fixed; only the data is user-controlled
env = jinja2.Environment(autoescape=True)
template = env.get_template("greeting.html")   # trusted, on disk
template.render(name=user_supplied)''',
        "User input must be template *data*, never template *source*. If the "
        "product genuinely needs user-authored templates, use a sandboxed engine "
        "(Jinja2 SandboxedEnvironment) and disable attribute access to dunder names.",
        "Submit {{7*7}} and ${7*7}; the response must contain the literal text, "
        "not 49.",
        ["CWE-1336", "OWASP A03:2021"],
    ),
    VULN_CLASS.EXPOSED_FILE: Remediation(
        VULN_CLASS.EXPOSED_FILE, "nginx",
        '''# Block dotfiles and VCS metadata explicitly — the default config serves them.
location ~ /\\.(git|svn|env|htaccess|aws|docker) { deny all; return 404; }
location ~* \\.(bak|old|sql|swp|zip|tar\\.gz)$ { deny all; return 404; }

# And keep secrets out of the web root entirely:
#   secrets belong in the environment or a vault, never in a served file''',
        "A 404 rather than a 403 avoids confirming the file exists. The real fix "
        "is to stop deploying secrets into the served tree at all.",
        "Re-request each disclosed path; every one must return 404.",
        ["CWE-538", "OWASP A01:2021"],
    ),
    VULN_CLASS.CREDENTIAL_LEAK: Remediation(
        VULN_CLASS.CREDENTIAL_LEAK, "bash",
        '''# 1. Rotate first — the exposed secret must be assumed compromised already.
# 2. Remove it from the code and from history.
git filter-repo --path config/secrets.yml --invert-paths   # or BFG Repo-Cleaner
# 3. Load it at runtime instead.
export DB_PASSWORD="$(vault kv get -field=password secret/prod/db)"
# 4. Add a pre-commit gate so it cannot come back.
pre-commit install   # with gitleaks or detect-secrets configured''',
        "Removing the string from HEAD does not revoke it — anyone who pulled the "
        "repo still has it. Rotation is the only step that actually closes the hole.",
        "Re-scan the repository history and the served paths; no live secret "
        "should be retrievable.",
        ["CWE-798", "OWASP A07:2021"],
    ),
    VULN_CLASS.CORS: Remediation(
        VULN_CLASS.CORS, "nginx",
        '''# BEFORE (the misconfiguration)
#   add_header Access-Control-Allow-Origin $http_origin always;
#   add_header Access-Control-Allow-Credentials true always;

# AFTER — reflect only an explicit allowlist, never the request's Origin
map $http_origin $cors_origin {
    default "";
    "https://app.example.com"    $http_origin;
    "https://admin.example.com"  $http_origin;
}
add_header Access-Control-Allow-Origin      $cors_origin always;
add_header Access-Control-Allow-Credentials true always;
add_header Vary                             Origin always;''',
        "Wildcard-with-credentials and Origin-reflection both let any site read "
        "an authenticated user's responses. Echo only origins you control, and "
        "send Vary: Origin so caches do not serve the wrong header.",
        "Send Origin: https://evil.example; the response must contain no "
        "Access-Control-Allow-Origin header.",
        ["CWE-942", "OWASP A05:2021"],
    ),
    VULN_CLASS.MISSING_HEADERS: Remediation(
        VULN_CLASS.MISSING_HEADERS, "nginx",
        '''add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Content-Type-Options    "nosniff" always;
add_header X-Frame-Options           "DENY" always;
add_header Referrer-Policy           "strict-origin-when-cross-origin" always;
add_header Permissions-Policy        "geolocation=(), camera=(), microphone=()" always;
# Start CSP in report-only mode, then enforce once violations stop.
add_header Content-Security-Policy   "default-src 'self'; object-src 'none'; frame-ancestors 'none'" always;''',
        "These are cheap compensating controls. CSP is the one that matters most "
        "and the one most likely to break the app, so ship it as "
        "Content-Security-Policy-Report-Only first.",
        "Re-fetch any page and confirm each header is present on the 200 response.",
        ["CWE-693", "OWASP A05:2021"],
    ),
    VULN_CLASS.COOKIE: Remediation(
        VULN_CLASS.COOKIE, "python",
        '''response.set_cookie(
    "session",
    token,
    httponly=True,   # not readable by JavaScript — blocks XSS-based theft
    secure=True,     # HTTPS only
    samesite="Lax",  # not sent on cross-site POST — blocks CSRF
    path="/",
    max_age=3600,
)''',
        "HttpOnly stops script from reading the cookie, Secure stops it being "
        "sent in cleartext, and SameSite removes most CSRF surface without a "
        "separate token.",
        "Fetch any page and confirm Set-Cookie carries all three attributes.",
        ["CWE-614", "OWASP A07:2021"],
    ),
    VULN_CLASS.OPEN_REDIRECT: Remediation(
        VULN_CLASS.OPEN_REDIRECT, "python",
        '''ALLOWED = {"https://app.example.com", "https://admin.example.com"}

def safe_redirect(request, default="/"):
    target = request.args.get("next", default)
    parsed = urlparse(target)
    # Reject absolute URLs to other hosts; allow only relative paths.
    if parsed.netloc and target not in ALLOWED:
        target = default
    return redirect(target)''',
        "The safest rule is to accept only relative paths. If absolute URLs are "
        "required, compare against an allowlist — never against a substring, "
        "which `//evil.example` and `https://app.example.com.evil.example` defeat.",
        "Request ?next=https://evil.example; the response must stay on your host.",
        ["CWE-601", "OWASP A01:2021"],
    ),
    VULN_CLASS.DIR_LISTING: Remediation(
        VULN_CLASS.DIR_LISTING, "nginx",
        '''autoindex off;                 # nginx
# Apache:  Options -Indexes
# S3:     remove the ListBucket permission from the bucket policy''',
        "Directory indexes let an attacker enumerate files that are not linked "
        "anywhere, which is how unreferenced backups and configs get found.",
        "Request a directory URL; it must return 403 or an index page, not a "
        "file listing.",
        ["CWE-548", "OWASP A01:2021"],
    ),
    VULN_CLASS.GRAPHQL_INTROSPECTION: Remediation(
        VULN_CLASS.GRAPHQL_INTROSPECTION, "javascript",
        '''// Apollo Server
const server = new ApolloServer({
  typeDefs, resolvers,
  introspection: process.env.NODE_ENV !== "production",
});

// graphql-yoga
const server = createServer({ schema, maskedErrors: true });''',
        "Introspection hands an attacker the complete schema — every type, field "
        "and argument to fuzz. Disable it in production and mask errors so stack "
        "traces are not returned either.",
        "POST {__schema{types{name}}}; it must be rejected.",
        ["CWE-200", "OWASP API3:2023"],
    ),
    VULN_CLASS.JWT_WEAK: Remediation(
        VULN_CLASS.JWT_WEAK, "python",
        '''import jwt

# BEFORE — algorithms=None lets the token pick its own, including "none"
payload = jwt.decode(token, key, options={"verify_signature": False})

# AFTER — pin the algorithm and require the signature
payload = jwt.decode(
    token, key,
    algorithms=["RS256"],          # never ["none"], never a list including HS256+RS256
    options={"require": ["exp", "iat", "iss", "aud"]},
    issuer="https://auth.example.com",
    audience="api.example.com",
)''',
        "Accepting `alg: none` means an attacker can mint any identity. Mixing "
        "HS256 and RS256 is the classic confusion attack — the public key "
        "becomes the HMAC secret. Pin exactly one algorithm.",
        "Submit a token with alg set to none; it must be rejected.",
        ["CWE-347", "OWASP A02:2021"],
    ),
    VULN_CLASS.JWT_EXPOSED: Remediation(
        VULN_CLASS.JWT_EXPOSED, "generic",
        '''# Do not return tokens in a response body or a URL.
# Store the session token in an HttpOnly cookie, or return it once at login and
# keep it in memory — never in localStorage, where any XSS can read it.
Set-Cookie: session=<token>; HttpOnly; Secure; SameSite=Lax

# And scope it down: short expiry, minimal claims, no PII in the payload.
# A JWT payload is base64, not encryption — treat it as public.''',
        "Anything in a JWT payload is readable by anyone who holds the token. "
        "Treat it as public data and keep bearer tokens out of URLs, which end up "
        "in logs, referers and browser history.",
        "Inspect a normal response body and the URL; no token should appear in "
        "either.",
        ["CWE-522", "OWASP A07:2021"],
    ),
    VULN_CLASS.REQUEST_SMUGGLING: Remediation(
        VULN_CLASS.REQUEST_SMUGGLING, "nginx",
        '''# Reject ambiguous framing at the edge rather than passing it upstream.
# Reject requests carrying both Content-Length and Transfer-Encoding.
if ($http_transfer_encoding) { set $flag "${flag}T"; }
if ($content_length)         { set $flag "${flag}C"; }
if ($flag = "TC")            { return 400; }

# Then align the tiers: same HTTP version, no connection reuse mismatch,
# and a single authoritative parser (prefer HTTP/2 end to end).''',
        "Smuggling needs the proxy and the origin to disagree about where one "
        "request ends. Refusing ambiguous framing removes the disagreement.",
        "Send a request with both Content-Length and Transfer-Encoding; it must "
        "be rejected with 400.",
        ["CWE-444", "OWASP A04:2021"],
    ),
    VULN_CLASS.HOST_HEADER: Remediation(
        VULN_CLASS.HOST_HEADER, "nginx",
        '''server {
    server_name app.example.com;
    # Default server refuses any Host that is not explicitly configured.
}
server {
    listen 80 default_server;
    listen 443 ssl default_server;
    return 444;                       # close the connection, no response
}''',
        "Build absolute URLs from a configured base URL, never from the request's "
        "Host header — otherwise password-reset links can be pointed at an "
        "attacker's domain.",
        "Send a request with Host: evil.example; it must not be served by the "
        "application vhost.",
        ["CWE-644", "OWASP A05:2021"],
    ),
    VULN_CLASS.SUBDOMAIN_TAKEOVER: Remediation(
        VULN_CLASS.SUBDOMAIN_TAKEOVER, "generic",
        '''# Either claim the resource or remove the record — a dangling CNAME is a
# takeover waiting to happen.
# 1. Re-point the CNAME at a resource you control, or
# 2. Delete the DNS record entirely:
dig legacy.example.com CNAME +short     # confirm what it points at
# then remove that record in your DNS provider

# 3. Add dangling-record detection to CI so this cannot recur.''',
        "A CNAME pointing at a deprovisioned third-party service lets anyone "
        "register that resource and serve content under your domain — including "
        "cookies scoped to it.",
        "Resolve the hostname; it must not point at an unclaimed third-party "
        "service.",
        ["CWE-1392", "OWASP A05:2021"],
    ),
    VULN_CLASS.XSS: Remediation(
        VULN_CLASS.XSS, "javascript",
        '''// Escape on output, in the context you are writing to.
element.textContent = userInput;          // safe: text node, never parsed

// Avoid these — they parse the string as HTML:
//   element.innerHTML = userInput;
//   document.write(userInput);

// And ship a CSP as defence in depth (no unsafe-inline):
//   Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
''',
        "Contextual output encoding is the fix. A CSP without unsafe-inline is "
        "the backstop for when encoding is missed somewhere.",
        "Submit <img src=x onerror=alert(1)> into the affected parameter; it must "
        "render as inert text.",
        ["CWE-79", "OWASP A03:2021"],
    ),
    VULN_CLASS.RCE: Remediation(
        VULN_CLASS.RCE, "python",
        '''import shlex, subprocess

# BEFORE — the shell parses the string
subprocess.run(f"convert {filename}", shell=True)

# AFTER — argument vector, no shell involved
subprocess.run(["convert", filename], shell=False, check=True, timeout=30)''',
        "Pass an argument vector and never shell=True with user input. Add a "
        "timeout, and drop privileges for the process — command execution should "
        "not also mean root.",
        "Re-run the payload that produced execution; it must be passed as a "
        "literal argument.",
        ["CWE-94", "OWASP A03:2021"],
    ),
}

_GENERIC = Remediation(
    VULN_CLASS.INFO, "generic",
    "# Informational observation — no code change required.\n"
    "# Record it, and re-check on the next assessment.",
    "This finding did not indicate a control failure. It is reported for "
    "completeness and asset-inventory purposes.",
)


def remediation_for(finding: Any) -> Remediation:
    """The concrete fix for one finding."""
    return _FIXES.get(classify_finding(finding), _GENERIC)


def remediation_summary(findings: Sequence[Any]) -> Dict[str, Any]:
    """Distinct fixes needed, grouped, so a team sees a work list not a wall."""
    by_class: Dict[str, int] = {}
    for finding in findings:
        vuln_class = classify_finding(finding)
        by_class[vuln_class] = by_class.get(vuln_class, 0) + 1

    fixes = []
    for vuln_class, count in sorted(by_class.items(), key=lambda kv: -kv[1]):
        fix = _FIXES.get(vuln_class, _GENERIC)
        fixes.append({
            "vuln_class": vuln_class,
            "language_label": fix.language_label,
            "findings": count,
            "explanation": fix.explanation,
        })
    return {
        "distinct_fixes": len(fixes),
        "findings_total": len(findings),
        "actionable": sum(1 for f in fixes if f["vuln_class"] != VULN_CLASS.INFO),
        "fixes": fixes,
    }
