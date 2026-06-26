"""Context builder helpers extracted from agent.py.

These originally lived as X19 methods that assembled LLM context blocks
from inner state. During Phase 5 they become standalone functions so
future modules can build AI prompts without importing the monolith.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def cve_context_block(model: Any) -> str:
    """Generate CVE-to-test mapping for identified services."""
    cve_map = {
        "tomcat": ["CVE-2020-1938 (Ghostcat AJP RCE)", "CVE-2017-12617 (PUT JSP RCE)", "CVE-2017-12615 (PUT RCE)", "Default creds: tomcat:tomcat, admin:admin"],
        "apache": ["CVE-2021-41773 (Path Traversal 2.4.49)", "CVE-2021-42013 (RCE 2.4.50)", "CVE-2023-25690 (mod_proxy SSRF)"],
        "nginx": ["CVE-2023-44487 (HTTP/2 RST flood)", "CVE-2021-23017 (DNS resolver)", "Alias traversal, merge_slashes bypass"],
        "openssh": ["CVE-2024-6387 (regreSSHion RCE)", "CVE-2023-38408 (RCE via ssh-agent)", "CVE-2023-28531 (pfx bypass)"],
        "mysql": ["CVE-2023-22102 (RCE)", "CVE-2022-21367 (DoS)", "Empty root password check"],
        "redis": ["CVE-2022-0543 (Lua sandbox RCE)", "Unauthenticated access → SSH key/cron RCE"],
        "docker": ["CVE-2024-21626 (runc RCE)", "Docker API unauth on :2375", "Privileged container escape"],
        "kubernetes": ["CVE-2023-3676 (kubelet volume)", "Anonymous auth on :10250", "Dashboard unauth"],
        "gitlab": ["CVE-2023-7028 (Password reset)", "CVE-2023-5009 (Pipeline RCE)", "CVE-2023-3932 (Public project)"],
        "jenkins": ["CVE-2024-23897 (Arbitrary file read)", "CVE-2023-27898 (XSS)", "Default creds: admin:admin"],
    }
    parts: List[str] = []
    ports = getattr(model, "ports", []) or []
    tech = getattr(model, "tech_stack", {}) or {}

    port_text = " ".join(f"{p.get('service','')} {p.get('product','')}".lower() for p in ports)
    tech_text = " ".join(f"{k} {v}".lower() for k, v in tech.items())

    for name, cves in cve_map.items():
        if name in port_text:
            parts.append(f"  {name}: {'; '.join(cves)}")
        elif name in tech_text:
            parts.append(f"  {name} (tech): {'; '.join(cves)}")
    if parts:
        return "KNOWN CVEs BY SERVICE:\n" + "\n".join(parts) + "\n"
    return ""


def tool_failure_context(broken_tools: List[str], failure_counts: Dict[str, Any]) -> str:
    """Show tools that keep failing so AI stops using them."""
    if not broken_tools:
        return ""
    lines = ["BROKEN TOOLS (3+ failures — do NOT use until fixed):"]
    for t in sorted(broken_tools):
        fails = {k.split(":", 1)[1]: v for k, v in failure_counts.items() if k.startswith(t)}
        errors = "; ".join(f"{e}({c}x)" for e, c in fails.items())
        lines.append(f"  - {t}: {errors}")
    return "\n".join(lines) + "\n"


def session_outcomes_context(outcomes: List[Dict[str, Any]]) -> str:
    """Recall what worked/didn't from the current session."""
    if not outcomes:
        return ""
    lines = ["SESSION OUTCOMES:"]
    for o in outcomes[-8:]:
        lines.append(
            f"  [{o.get('status','')}] {o.get('technique','')} on {o.get('service','')} "
            f"({o.get('target','')}) — {o.get('note','')[:80]}"
        )
    return "\n".join(lines) + "\n"


def false_claim_context(false_claim_urls: List[str]) -> str:
    """Anti-hallucination: surface URLs that returned 404/410 in this session."""
    if not false_claim_urls:
        return ""
    sample = sorted(false_claim_urls)[:8]
    extra = len(false_claim_urls) - len(sample)
    tail = f" (+{extra} more)" if extra > 0 else ""
    return (
        "=== REPEATED FALSE CLAIMS (URLs that returned 404/410 — DO NOT claim they exist) ===\n"
        + "\n".join(f"  ✗ {u}  ← returned 404/410, NOT deployed" for u in sample)
        + (f"\n  {tail}" if tail else "")
        + "\nINSTRUCTION: if you say 'X is deployed' or 'X is accessible' in your "
          "reasoning, X must have returned HTTP 200/2xx in this session. Anything "
          "in the list above is the OPPOSITE of what you should claim.\n"
    )
