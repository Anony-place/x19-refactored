"""Standards mapping for X19 findings.

Every finding class X19 can emit is mapped to the standards a security team is
actually audited against: CWE, OWASP Top 10 (2021), OWASP API Top 10 (2023),
PCI-DSS 4.0 and SOC 2 Trust Services Criteria.

Classification is by keyword against the finding title rather than exact-string
matching, so a reworded title still lands on the right control set.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence

__all__ = [
    "VULN_CLASS",
    "ComplianceMapping",
    "STANDARDS",
    "classify_finding",
    "map_finding",
    "compliance_summary",
    "control_gaps",
]


class VULN_CLASS:
    SSRF = "ssrf"
    SSTI = "ssti"
    SQLI = "sqli"
    BROKEN_ACCESS = "broken_access_control"
    CORS = "cors"
    MISSING_HEADERS = "missing_security_headers"
    COOKIE = "cookie_flags"
    DIR_LISTING = "directory_listing"
    EXPOSED_FILE = "exposed_file"
    CREDENTIAL_LEAK = "credential_leak"
    OPEN_REDIRECT = "open_redirect"
    GRAPHQL_INTROSPECTION = "graphql_introspection"
    JWT_WEAK = "jwt_weak_signing"
    JWT_EXPOSED = "jwt_exposed"
    REQUEST_SMUGGLING = "request_smuggling"
    HOST_HEADER = "host_header_injection"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    XSS = "xss"
    RCE = "remote_code_execution"
    INFO = "informational"


#: Standards this module maps to, in report order.
STANDARDS = ("cwe", "owasp_web", "owasp_api", "pci_dss", "soc2")

STANDARD_LABELS = {
    "cwe": "CWE",
    "owasp_web": "OWASP Top 10 2021",
    "owasp_api": "OWASP API Top 10 2023",
    "pci_dss": "PCI-DSS 4.0",
    "soc2": "SOC 2 TSC",
}


@dataclass(frozen=True)
class ComplianceMapping:
    """The standards footprint of one vulnerability class."""

    vuln_class: str
    cwe: str
    owasp_web: str
    owasp_api: str
    pci_dss: List[str] = field(default_factory=list)
    soc2: List[str] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_class": self.vuln_class,
            "cwe": self.cwe,
            "owasp_web": self.owasp_web,
            "owasp_api": self.owasp_api,
            "pci_dss": list(self.pci_dss),
            "soc2": list(self.soc2),
            "note": self.note,
        }

    def controls(self) -> Dict[str, Any]:
        """Flat ``standard -> reference`` view for report tables."""
        return {
            "cwe": self.cwe,
            "owasp_web": self.owasp_web,
            "owasp_api": self.owasp_api,
            "pci_dss": ", ".join(self.pci_dss),
            "soc2": ", ".join(self.soc2),
        }


# ---------------------------------------------------------------------------
# The mapping table
# ---------------------------------------------------------------------------
MAPPINGS: Dict[str, ComplianceMapping] = {
    VULN_CLASS.SSRF: ComplianceMapping(
        VULN_CLASS.SSRF, "CWE-918", "A10:2021 Server-Side Request Forgery", "",
        ["6.2.4", "11.3.1"], ["CC6.6", "CC7.1"],
        "Egress filtering is the compensating control auditors ask for.",
    ),
    VULN_CLASS.SSTI: ComplianceMapping(
        VULN_CLASS.SSTI, "CWE-1336", "A03:2021 Injection", "",
        ["6.2.4", "6.4.3"], ["CC6.6"],
        "Template injection is routinely treated as remote code execution.",
    ),
    VULN_CLASS.SQLI: ComplianceMapping(
        VULN_CLASS.SQLI, "CWE-89", "A03:2021 Injection", "API8:2023 Security Misconfiguration",
        ["6.2.4", "6.4.3", "3.2.1"], ["CC6.6", "CC6.1"],
        "If cardholder data is reachable, requirement 3 applies as well.",
    ),
    VULN_CLASS.BROKEN_ACCESS: ComplianceMapping(
        VULN_CLASS.BROKEN_ACCESS, "CWE-639", "A01:2021 Broken Access Control",
        "API1:2023 Broken Object Level Authorization",
        ["6.2.4", "7.2.1"], ["CC6.1", "CC6.3"],
        "Server-side authorization checks, not client-side hiding.",
    ),
    VULN_CLASS.CORS: ComplianceMapping(
        VULN_CLASS.CORS, "CWE-942", "A05:2021 Security Misconfiguration",
        "API8:2023 Security Misconfiguration",
        ["6.2.4"], ["CC6.6"],
        "Origin reflection with credentials is cross-origin data theft.",
    ),
    VULN_CLASS.MISSING_HEADERS: ComplianceMapping(
        VULN_CLASS.MISSING_HEADERS, "CWE-693", "A05:2021 Security Misconfiguration", "",
        ["6.2.4", "6.4.3"], ["CC6.6"],
        "Absent CSP/HSTS removes the browser-side compensating controls that "
        "6.2.4 and 6.4.3 expect to be present.",
    ),
    VULN_CLASS.COOKIE: ComplianceMapping(
        VULN_CLASS.COOKIE, "CWE-614", "A07:2021 Identification and Authentication Failures",
        "API2:2023 Broken Authentication",
        ["6.2.4", "8.2.1"], ["CC6.1"],
        "Session cookies without Secure/HttpOnly/SameSite can be read or replayed, "
        "defeating the access controls CC6.1 relies on.",
    ),
    VULN_CLASS.DIR_LISTING: ComplianceMapping(
        VULN_CLASS.DIR_LISTING, "CWE-548", "A01:2021 Broken Access Control", "",
        ["6.2.4"], ["CC6.1"],
        "Directory indexes publish paths that were never meant to be reachable, "
        "so unauthorised reads become trivial to discover.",
    ),
    VULN_CLASS.EXPOSED_FILE: ComplianceMapping(
        VULN_CLASS.EXPOSED_FILE, "CWE-538", "A01:2021 Broken Access Control", "",
        ["6.2.4", "3.2.1", "12.5.1"], ["CC6.1"],
        "Exposed source or config can disclose stored secrets (requirement 3).",
    ),
    VULN_CLASS.CREDENTIAL_LEAK: ComplianceMapping(
        VULN_CLASS.CREDENTIAL_LEAK, "CWE-798", "A07:2021 Identification and Authentication Failures",
        "API2:2023 Broken Authentication",
        ["8.2.1", "8.3.1", "3.2.1"], ["CC6.1", "CC6.2"],
        "Rotate first, then remove. Auditors treat leaked keys as a breach event.",
    ),
    VULN_CLASS.OPEN_REDIRECT: ComplianceMapping(
        VULN_CLASS.OPEN_REDIRECT, "CWE-601", "A01:2021 Broken Access Control", "",
        ["6.2.4"], ["CC6.6"],
        "An attacker-controlled redirect target is the delivery step in most "
        "credential-phishing chains against the application's own users.",
    ),
    VULN_CLASS.GRAPHQL_INTROSPECTION: ComplianceMapping(
        VULN_CLASS.GRAPHQL_INTROSPECTION, "CWE-200", "A01:2021 Broken Access Control",
        "API3:2023 Broken Object Property Level Authorization",
        ["6.2.4"], ["CC6.1"],
        "Introspection hands an attacker the full schema, including internal "
        "fields that were assumed to be undiscoverable.",
    ),
    VULN_CLASS.JWT_WEAK: ComplianceMapping(
        VULN_CLASS.JWT_WEAK, "CWE-347", "A02:2021 Cryptographic Failures",
        "API2:2023 Broken Authentication",
        ["8.2.1", "8.3.2"], ["CC6.1"],
        "An unsigned or alg:none token can be forged by anyone, so every "
        "authorisation decision downstream of it is unauthenticated.",
    ),
    VULN_CLASS.JWT_EXPOSED: ComplianceMapping(
        VULN_CLASS.JWT_EXPOSED, "CWE-522", "A07:2021 Identification and Authentication Failures",
        "API2:2023 Broken Authentication",
        ["8.3.1"], ["CC6.1"],
        "A token reachable from client-side code is readable by any injected "
        "script and by anyone who obtains the response.",
    ),
    VULN_CLASS.REQUEST_SMUGGLING: ComplianceMapping(
        VULN_CLASS.REQUEST_SMUGGLING, "CWE-444", "A04:2021 Insecure Design", "",
        ["6.2.4", "6.4.3"], ["CC6.6"],
        "Desync between proxy tiers defeats network segmentation claims.",
    ),
    VULN_CLASS.HOST_HEADER: ComplianceMapping(
        VULN_CLASS.HOST_HEADER, "CWE-644", "A05:2021 Security Misconfiguration", "",
        ["6.2.4"], ["CC6.6"],
        "Trusting the Host header lets an attacker poison generated URLs and "
        "password-reset links served to other users.",
    ),
    VULN_CLASS.SUBDOMAIN_TAKEOVER: ComplianceMapping(
        VULN_CLASS.SUBDOMAIN_TAKEOVER, "CWE-1392", "A05:2021 Security Misconfiguration", "",
        ["6.2.4", "12.5.1"], ["CC6.1"],
        "Dangling DNS is an asset-inventory failure (requirement 12.5.1).",
    ),
    VULN_CLASS.XSS: ComplianceMapping(
        VULN_CLASS.XSS, "CWE-79", "A03:2021 Injection", "",
        ["6.2.4", "6.4.3"], ["CC6.6"],
        "Script execution in a user's session is both an injection failure "
        "(6.2.4) and a missing public-facing control (6.4.3).",
    ),
    VULN_CLASS.RCE: ComplianceMapping(
        VULN_CLASS.RCE, "CWE-94", "A03:2021 Injection", "",
        ["6.2.4", "6.4.3", "11.3.1"], ["CC6.6", "CC7.1"],
        "Code execution on the host defeats every application-layer control at "
        "once and is the highest-priority remediation in any report.",
    ),
    VULN_CLASS.INFO: ComplianceMapping(
        VULN_CLASS.INFO, "", "", "", [], ["CC7.1"],
        "Informational — no control failure on its own.",
    ),
}


#: Ordered ``(vuln_class, keywords)`` — first match wins, so put the specific
#: classes ahead of the generic ones.
_RULES = (
    (VULN_CLASS.REQUEST_SMUGGLING, ("smuggl", "cl.te", "te.cl", "desync")),
    (VULN_CLASS.SSTI, ("template injection", "ssti")),
    (VULN_CLASS.SQLI, ("sql injection", "sqli")),
    (VULN_CLASS.SSRF, ("ssrf", "request forgery", "metadata leak")),
    (VULN_CLASS.BROKEN_ACCESS, ("idor", "bola", "authorization bypass", "access control")),
    # CORS must precede credential-leak: "Wildcard with Credentials" contains the
    # word "credential" but is a CORS misconfiguration, not a leaked secret.
    # "access-control-allow-origin" is included because verified CORS findings
    # usually carry the response header in their evidence rather than the word.
    (VULN_CLASS.CORS, ("cors", "access-control-allow-origin", "acao")),
    # Likewise exposed-JWT must precede weak-JWT, or the bare "jwt" keyword wins.
    (VULN_CLASS.JWT_EXPOSED, ("exposed jwt", "jwt in client", "jwt token in")),
    (VULN_CLASS.JWT_WEAK, ("alg: none", "unsigned token", "jwt")),
    # Deliberately narrow: a bare "credential"/"secret" keyword steals titles
    # from the CORS and cookie classes.
    # Must precede exposed-file: every leaked-secret title starts with
    # "Exposed", so a bare "exposed" keyword would claim all of them.
    (VULN_CLASS.CREDENTIAL_LEAK, (
        "api key", "leaked", "hardcoded", "private key", "credential exposure",
        "exposed credential", "secret exposure", "exposed secret",
        "access key", "access token", "secret key",
    )),
    (VULN_CLASS.GRAPHQL_INTROSPECTION, ("graphql", "introspection")),
    (VULN_CLASS.OPEN_REDIRECT, ("open redirect",)),
    (VULN_CLASS.DIR_LISTING, ("directory listing",)),
    (VULN_CLASS.HOST_HEADER, ("host header",)),
    (VULN_CLASS.SUBDOMAIN_TAKEOVER, ("subdomain takeover", "dangling")),
    (VULN_CLASS.MISSING_HEADERS, ("security header", "missing header", "hsts", "csp")),
    (VULN_CLASS.COOKIE, ("cookie",)),
    (VULN_CLASS.XSS, ("xss", "cross-site scripting")),
    (VULN_CLASS.RCE, ("remote code execution", "command injection", "rce")),
    # robots.txt is public by design, so it is not an access-control failure.
    (VULN_CLASS.INFO, ("robots.txt",)),
    (VULN_CLASS.EXPOSED_FILE, ("exposed", "disclos", "backup", ".env", ".git", "config")),
)


def classify_finding(finding: Any) -> str:
    """Return the ``VULN_CLASS`` a finding belongs to.

    Accepts a finding object, or a bare string — either a vulnerability class
    (``"ssrf"``) or a finding title (``"SQL Injection Anomaly"``) — so callers
    that only hold the class or the title need not build a stub finding.
    """
    if isinstance(finding, str):
        text = finding.strip().lower()
        known = {v for k, v in vars(VULN_CLASS).items() if not k.startswith("_")}
        if text in known:
            return text
        title, evidence = text, ""
    else:
        title = str(getattr(finding, "title", "") or "").lower()
        evidence = str(getattr(finding, "evidence", "") or "").lower()
    haystack = f"{title} {evidence}"
    for vuln_class, keywords in _RULES:
        if any(keyword in haystack for keyword in keywords):
            return vuln_class
    return VULN_CLASS.INFO


def map_finding(finding: Any) -> ComplianceMapping:
    """Standards footprint for one finding."""
    return MAPPINGS[classify_finding(finding)]


def compliance_summary(findings: Sequence[Any]) -> Dict[str, Any]:
    """Aggregate the standards footprint across a set of findings."""
    by_class: Dict[str, int] = {}
    cwe: Dict[str, int] = {}
    owasp_web: Dict[str, int] = {}
    owasp_api: Dict[str, int] = {}
    pci: Dict[str, int] = {}
    soc2: Dict[str, int] = {}

    for finding in findings:
        mapping = map_finding(finding)
        by_class[mapping.vuln_class] = by_class.get(mapping.vuln_class, 0) + 1
        if mapping.cwe:
            cwe[mapping.cwe] = cwe.get(mapping.cwe, 0) + 1
        if mapping.owasp_web:
            owasp_web[mapping.owasp_web] = owasp_web.get(mapping.owasp_web, 0) + 1
        if mapping.owasp_api:
            owasp_api[mapping.owasp_api] = owasp_api.get(mapping.owasp_api, 0) + 1
        for req in mapping.pci_dss:
            pci[req] = pci.get(req, 0) + 1
        for criterion in mapping.soc2:
            soc2[criterion] = soc2.get(criterion, 0) + 1

    return {
        "total": len(findings),
        "by_class": dict(sorted(by_class.items(), key=lambda kv: -kv[1])),
        "cwe": dict(sorted(cwe.items(), key=lambda kv: -kv[1])),
        "owasp_web": dict(sorted(owasp_web.items())),
        "owasp_api": dict(sorted(owasp_api.items())),
        "pci_dss": dict(sorted(pci.items())),
        "soc2": dict(sorted(soc2.items())),
        "unmapped": by_class.get(VULN_CLASS.INFO, 0),
    }


def control_gaps(findings: Sequence[Any], standard: str = "soc2") -> List[str]:
    """Which controls of ``standard`` are implicated by these findings."""
    if standard not in STANDARDS:
        raise ValueError(f"unknown standard {standard!r} — expected one of {STANDARDS}")
    implicated: Dict[str, int] = {}
    for finding in findings:
        mapping = map_finding(finding)
        if standard in ("pci_dss", "soc2"):
            for control in getattr(mapping, standard):
                implicated[control] = implicated.get(control, 0) + 1
        else:
            value = getattr(mapping, standard)
            if value:
                implicated[value] = implicated.get(value, 0) + 1
    return [
        f"{control} ({count} finding{'s' if count != 1 else ''})"
        for control, count in sorted(implicated.items())
    ]
