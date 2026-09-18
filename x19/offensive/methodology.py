"""
X19 Offensive Methodology — bug bounty methodology, attack surface modeling, hypothesis generation.

Uses knowledge base and datasets to provide offensive team capabilities:
- Recon methodology
- Attack surface modeling
- Hypothesis generation from observations
- Testing methodology per vuln class
- Verification strategies
- Fully autonomous decision making
"""

from __future__ import annotations

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from x19.knowledge import get_knowledge_base
from x19.datasets import get_datasets
from x19.offensive.payloads import PayloadGenerator


@dataclass
class Hypothesis:
    """Testable hypothesis from recon observations."""

    id: str
    vuln_class: str
    endpoint: str
    param: Optional[str] = None
    rationale: str = ""  # Why this might be vulnerable, from observation
    observation: str = ""  # What tool saw
    test_method: str = ""  # How to test
    expected_evidence: str = ""  # What evidence expected if vulnerable
    severity: str = "medium"
    confidence: str = "low"
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    payloads: List[str] = field(default_factory=list)
    status: str = "pending"  # pending, tested, failed, verified


class OffensiveMethodology:
    """Offensive methodology engine — uses knowledge base and datasets."""

    def __init__(self):
        self.kb = get_knowledge_base()
        self.ds = get_datasets()
        self.payload_gen = PayloadGenerator()

    def generate_hypotheses_from_recon(self, discoveries: Dict[str, List[str]], attack_surface: Optional[Dict[str, Any]] = None) -> List[Hypothesis]:
        """Generate testable hypotheses from recon observations."""
        hypotheses = []

        # Get recon data
        endpoints = discoveries.get("endpoints", [])
        tech = discoveries.get("tech", [])
        subdomains = discoveries.get("subdomains", [])
        auth_flows = discoveries.get("auth", [])

        # For each endpoint, generate hypotheses based on vuln classes
        vuln_classes = self.kb.list_vuln_classes()
        if not vuln_classes:
            vuln_classes = ["xss", "sqli", "ssrf", "idor", "bola", "open_redirect"]

        for endpoint in endpoints:
            # XSS hypothesis: if endpoint has params that are reflected
            if any(x in endpoint.lower() for x in ["search", "q=", "query", "name", "comment", "profile"]):
                hypotheses.append(
                    Hypothesis(
                        id=f"H-XSS-{len(hypotheses)+1}",
                        vuln_class="xss",
                        endpoint=endpoint,
                        param="q" if "search" in endpoint else "input",
                        rationale=f"Endpoint {endpoint} has search or input param that might be reflected without encoding",
                        observation=f"Discovered endpoint {endpoint} with potential input reflection",
                        test_method="Test with witness payload <script>alert(1)</script> or <img src=x onerror=alert(1)>, check if reflected unescaped",
                        expected_evidence="Response contains payload unescaped, executes in browser, tool output",
                        severity="high",
                        confidence="low",
                        cwe="CWE-79",
                        owasp="A03:2021",
                        payloads=self.payload_gen.get_witness_payloads("xss")[:3],
                    )
                )

            # SQLi hypothesis: if endpoint has ID param that might go to DB
            if any(x in endpoint.lower() for x in ["id=", "user", "users", "product", "order", "api"]):
                hypotheses.append(
                    Hypothesis(
                        id=f"H-SQLI-{len(hypotheses)+1}",
                        vuln_class="sqli",
                        endpoint=endpoint,
                        param="id",
                        rationale=f"Endpoint {endpoint} has ID param that might go to SQL without sanitization",
                        observation=f"Discovered endpoint {endpoint} with ID param",
                        test_method="Test with single quote ' for error, boolean AND 1=1 vs AND 1=2 for difference, time SLEEP(2) for delay (minimal)",
                        expected_evidence="SQL error or time delay or data, tool output",
                        severity="critical",
                        confidence="low",
                        cwe="CWE-89",
                        owasp="A03:2021",
                        payloads=self.payload_gen.get_witness_payloads("sqli")[:3],
                    )
                )

            # BOLA/IDOR hypothesis: if endpoint has object ID
            if any(x in endpoint.lower() for x in ["/api/users/", "/api/documents/", "/api/orders/", "{id}", "/users/", "/documents/"]):
                hypotheses.append(
                    Hypothesis(
                        id=f"H-BOLA-{len(hypotheses)+1}",
                        vuln_class="bola",
                        endpoint=endpoint,
                        param="id",
                        rationale=f"Endpoint {endpoint} uses object ID, might not check ownership",
                        observation=f"Discovered API endpoint {endpoint} with object ID",
                        test_method="Auth as user A, try to access user B's object by changing ID, minimal proof, redact PII",
                        expected_evidence="Request as user A to other user ID returns 200 with other user data (redact PII), tool output",
                        severity="critical",
                        confidence="low",
                        cwe="CWE-862",
                        owasp="API1:2023",
                        payloads=["Change ID 123 to 124"],
                    )
                )

            # SSRF hypothesis: if endpoint fetches URL
            if any(x in endpoint.lower() for x in ["url=", "fetch", "import", "image", "webhook", "callback"]):
                hypotheses.append(
                    Hypothesis(
                        id=f"H-SSRF-{len(hypotheses)+1}",
                        vuln_class="ssrf",
                        endpoint=endpoint,
                        param="url",
                        rationale=f"Endpoint {endpoint} fetches URL, might not validate, possible SSRF",
                        observation=f"Discovered endpoint {endpoint} with URL param",
                        test_method="Test with http://127.0.0.1, http://localhost for internal, http://169.254.169.254 requires approval for cloud metadata",
                        expected_evidence="Request to internal URL returns internal data, tool output",
                        severity="high",
                        confidence="low",
                        cwe="CWE-918",
                        owasp="A10:2021",
                        payloads=self.payload_gen.get_witness_payloads("ssrf")[:3],
                    )
                )

            # Open redirect hypothesis
            if any(x in endpoint.lower() for x in ["redirect", "return", "next", "url=", "continue"]):
                hypotheses.append(
                    Hypothesis(
                        id=f"H-REDIRECT-{len(hypotheses)+1}",
                        vuln_class="open_redirect",
                        endpoint=endpoint,
                        param="url" if "url" in endpoint else "redirect",
                        rationale=f"Endpoint {endpoint} has redirect param, might allow open redirect",
                        observation=f"Discovered endpoint {endpoint} with redirect param",
                        test_method="Test with https://evil.com, //evil.com, check if redirects to evil.com",
                        expected_evidence="Response redirects to evil.com, Location header contains evil.com, tool output",
                        severity="medium",
                        confidence="low",
                        cwe="CWE-601",
                        owasp="A01:2021",
                        payloads=["https://evil.com", "//evil.com"],
                    )
                )

        # Deduplicate hypotheses by endpoint+vuln_class
        seen = set()
        deduped = []
        for h in hypotheses:
            key = f"{h.endpoint}:{h.vuln_class}:{h.param}"
            if key not in seen:
                seen.add(key)
                deduped.append(h)

        return deduped

    def get_testing_methodology(self, vuln_class: str) -> Optional[Dict[str, Any]]:
        """Get testing methodology for vuln class from knowledge base."""
        return self.kb.get_vuln_class(vuln_class)

    def get_verification_strategy(self, vuln_class: str) -> Optional[Dict[str, Any]]:
        """Get verification strategy for vuln class."""
        return self.kb.get_verification(vuln_class)

    def get_remediation(self, vuln_class: str) -> Optional[str]:
        """Get remediation guidance."""
        return self.kb.get_remediation(vuln_class)

    def get_false_positive_indicators(self, vuln_class: str) -> Optional[Dict[str, Any]]:
        """Get false positive indicators."""
        return self.kb.get_false_positives(vuln_class)

    def build_attack_surface_model(self, discoveries: Dict[str, List[str]]) -> Dict[str, Any]:
        """Build attack surface model from discoveries."""
        endpoints = discoveries.get("endpoints", [])
        tech = discoveries.get("tech", [])
        subdomains = discoveries.get("subdomains", [])
        auth = discoveries.get("auth", [])

        # Map inputs, sinks, trust boundaries, auth flows
        inputs = []
        for endpoint in endpoints:
            # Extract params from endpoint
            if "?" in endpoint:
                query = endpoint.split("?", 1)[1]
                params = [p.split("=")[0] for p in query.split("&") if "=" in p]
                inputs.extend(params)
            # Assume common params
            inputs.extend(["id", "q", "search", "url", "redirect"])

        # Deduplicate
        inputs = list(set(inputs))

        sinks = []
        for t in tech:
            if "react" in t.lower() or "angular" in t.lower() or "vue" in t.lower():
                sinks.append("DOM XSS sinks: innerHTML, document.write, eval")
            if "php" in t.lower() or "java" in t.lower() or "python" in t.lower():
                sinks.append("Server-side sinks: SQL query, template, file path, URL fetch")

        trust_boundaries = ["Internet → Web App", "Web App → Database", "Web App → Internal Services", "User A → User B data"]

        auth_flows = auth if auth else ["login", "registration", "password reset", "session", "JWT"]

        return {
            "inputs": inputs,
            "sinks": sinks,
            "trust_boundaries": trust_boundaries,
            "auth_flows": auth_flows,
            "endpoints": endpoints,
            "tech": tech,
            "subdomains": subdomains,
            "model_summary": f"Attack surface: {len(endpoints)} endpoints, {len(inputs)} inputs, {len(tech)} tech, {len(auth_flows)} auth flows",
        }

    def prioritize_hypotheses(self, hypotheses: List[Hypothesis]) -> List[Hypothesis]:
        """Prioritize hypotheses by likelihood, impact, severity."""
        # Simple prioritization: critical/high severity first, then by vuln class likelihood
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        def sort_key(h: Hypothesis):
            return (severity_order.get(h.severity.lower(), 5), h.vuln_class)

        return sorted(hypotheses, key=sort_key)

    def get_methodology_for_phase(self, phase: str) -> Optional[Dict[str, Any]]:
        """Get methodology for phase (recon, testing, etc.)."""
        return self.kb.get_methodology(phase)
