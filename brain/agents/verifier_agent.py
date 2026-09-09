"""X19 Proof-of-Concept (PoC) & False-Positive Verification Agent.

This is the gate that decides whether a candidate finding is allowed to become
a reportable one. XBOW's whole product claim rests on the equivalent step —
"proof, not a flood of maybes" — so the rule here is **default deny**: a
finding is confirmed only when a deterministic check reproduces it, and when
the engagement supplied canaries, only when a canary value actually comes back.

Anything without a verification rule is rejected with a reason rather than
waved through, which is what the previous implementation did.
"""

from __future__ import annotations

import re
from typing import Any, List, Optional, Tuple

import requests
import urllib3

from brain.agents.base_agent import BaseSwarmAgent
from execution.native_vuln import VulnerabilityFinding
from execution.scope_guard import ScopeGuard

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#: Finding-title fragments and the check that adjudicates them.
_PASSIVE_TITLE_HINTS = ("missing security header", "header")
_EXPOSED_TITLE_HINTS = ("exposed", "disclos", "directory listing", "backup", ".env", "config")

#: A real HTTP header name is dashed (X-Foo, Strict-Transport-Security).
_HEADER_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+\b")


class VerifierAgent(BaseSwarmAgent):
    """Verifies candidate findings with deterministic replay and canary proofs."""

    def __init__(self, coordinator: Optional[Any] = None, scope_guard: Optional[ScopeGuard] = None):
        super().__init__(name="VerifierAgent", role="PoC & Zero False-Positive Verifier", coordinator=coordinator)
        self.scope_guard = scope_guard or ScopeGuard(enforce=False)
        self.verified_findings: List[VulnerabilityFinding] = []
        self.rejections: List[dict] = []

    def run(self, target: str, **kwargs) -> None:
        self.current_task = f"Verifying findings for {target}"
        self.progress_pct = 20
        self.log(f"Starting independent verification pipeline for findings on {target}...")

        pending_findings: List[VulnerabilityFinding] = list(kwargs.get("findings") or [])
        if self.coordinator and hasattr(self.coordinator, "get_unverified_findings"):
            pending_findings = self.coordinator.get_unverified_findings() or pending_findings
        canaries: List[str] = [str(c) for c in (kwargs.get("canaries") or []) if str(c).strip()]

        if not pending_findings:
            self.log("No pending findings to verify.")
            self.progress_pct = 100
            return

        if canaries:
            self.log(f"Canary validation active — {len(canaries)} canary value(s) must be reproduced.")

        total = len(pending_findings)
        for index, finding in enumerate(pending_findings):
            if self.is_stopped():
                break

            self.log(f"Verifying finding [{index + 1}/{total}]: {finding.title}...")
            confirmed, reason = self._verify_finding(finding, canaries)

            if confirmed:
                finding.confirmed = True
                if not finding.evidence:
                    finding.evidence = reason
                self.verified_findings.append(finding)
                self.discovered_count += 1
                self.log(f" [✓] CONFIRMED: {finding.title} at {finding.endpoint} — {reason}")
                if self.coordinator and hasattr(self.coordinator, "mark_finding_verified"):
                    self.coordinator.mark_finding_verified(finding)
            else:
                self.rejections.append({"title": finding.title, "endpoint": finding.endpoint, "reason": reason})
                self.log(f" [✗] REJECTED: {finding.title} — {reason}")

            self.progress_pct = int(((index + 1) / total) * 100)

        self.current_task = "Verification completed"

    # ------------------------------------------------------------------
    def _verify_finding(self, finding: VulnerabilityFinding, canaries: List[str]) -> Tuple[bool, str]:
        """Reproduce a finding. Returns ``(confirmed, reason)``. Default: deny."""
        url = self._finding_url(finding)
        if not url:
            return False, "finding has no target/endpoint to replay"

        try:
            self.scope_guard.assert_allowed(url)
        except Exception as exc:
            return False, f"replay blocked by scope guard ({exc})"

        try:
            response = requests.get(url, timeout=4.0, verify=False, allow_redirects=False)
        except Exception as exc:
            return False, f"replay request failed ({type(exc).__name__})"

        title = str(finding.title or "").lower()
        evidence = str(finding.evidence or "")
        body = response.text or ""
        headers = {k.lower(): v for k, v in response.headers.items()}

        # 1. Canary proof is the strongest signal available: if the engagement
        #    planted canaries, one of them must actually come back.
        if canaries:
            for canary in canaries:
                if canary and (canary in body or any(canary in v for v in headers.values())):
                    return True, f"canary reproduced in response ({canary[:8]}…)"
            return False, "no canary value reproduced — exploitation not proven"

        # 2. CORS misconfiguration: the attacker origin must be reflected.
        if "cors" in title:
            try:
                probe = requests.get(
                    url, headers={"Origin": "https://evil-attacker.example"},
                    timeout=4.0, verify=False, allow_redirects=False,
                )
                acao = probe.headers.get("Access-Control-Allow-Origin", "")
                if "evil-attacker.example" in acao or acao == "*":
                    return True, f"Access-Control-Allow-Origin: {acao}"
                return False, f"attacker origin not reflected (got {acao or 'no ACAO header'})"
            except Exception as exc:
                return False, f"CORS replay failed ({type(exc).__name__})"

        # 3. Exposed file / information disclosure: the disclosed content must
        #    actually be in the body, not merely a 200 status.
        if any(hint in title for hint in _EXPOSED_TITLE_HINTS):
            if response.status_code != 200:
                return False, f"replay returned HTTP {response.status_code}, expected 200"
            if evidence and evidence.strip() and evidence.strip() in body:
                return True, "disclosed content reproduced verbatim in response body"
            if not evidence.strip():
                return False, "no evidence snippet recorded to match against the response"
            return False, "recorded evidence not present in the replayed response"

        # 4. Passive header findings: the claimed header must really be there
        #    (or really be absent, for "missing header" findings).
        if any(hint in title for hint in _PASSIVE_TITLE_HINTS):
            header_name = self._header_name_from(finding)
            if not header_name:
                return False, "could not determine which header the finding refers to"
            present = header_name in headers
            if title.startswith("missing") or "missing" in title:
                if not present:
                    return True, f"header '{header_name}' is absent as reported"
                return False, f"header '{header_name}' is present, finding no longer holds"
            if present:
                return True, f"header '{header_name}: {headers[header_name][:60]}' observed"
            return False, f"header '{header_name}' not present in the replayed response"

        # 5. Everything else: default deny. A finding class with no
        #    deterministic rule is not proof of anything.
        return False, f"no deterministic verification rule for this finding class ({response.status_code} on replay)"

    # ------------------------------------------------------------------
    @staticmethod
    def _finding_url(finding: VulnerabilityFinding) -> str:
        target = str(getattr(finding, "target", "") or "").strip()
        endpoint = str(getattr(finding, "endpoint", "") or "").strip()
        if not target:
            return ""
        if endpoint and not endpoint.startswith("/"):
            endpoint = "/" + endpoint
        return target.rstrip("/") + endpoint

    @staticmethod
    def _header_name_from(finding: VulnerabilityFinding) -> str:
        """Best-effort extraction of the header a header-finding refers to.

        The title is checked first because that is where the header is named
        (``Missing security header: X-Foo``). Evidence is only trusted when the
        token is genuinely header-shaped — an unrelated ``root:toor`` snippet
        must not be read as a header called ``root``, which would make the
        gate confirm a finding about a header that was never claimed.
        """
        title = str(getattr(finding, "title", "") or "")
        description = str(getattr(finding, "description", "") or "")
        evidence = str(getattr(finding, "evidence", "") or "")

        if ":" in title:
            candidate = title.split(":", 1)[1].strip().lower().rstrip(".,;:")
            if candidate and " " not in candidate:
                return candidate

        for source in (title, description):
            match = _HEADER_RE.search(source)
            if match:
                return match.group(0).lower()

        if ":" in evidence:
            candidate = evidence.split(":", 1)[0].strip().lower()
            if (
                candidate
                and " " not in candidate
                and "-" in candidate
                and len(candidate) <= 40
            ):
                return candidate
        return ""
