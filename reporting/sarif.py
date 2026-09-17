"""
SARIF 2.1.0 Generator — Strix + Shannon + RedAMon CI/CD pattern.

Produces SARIF JSON that ingests into GitHub Code Scanning, GitLab SAST, etc.
Converts X19 VulnerabilityFinding list -> SARIF runs[0].results with:

 - ruleId = vuln_class / title slug
 - level = error|warning|note per severity
 - partialFingerprints for deduplication (Strix pattern)
 - physicalLocation (endpoint URL -> artifactLocation)
 - codeFlows for chain steps if available
 - properties.tags (owasp, cwe, cvss)

Usage:
  from reporting.sarif import to_sarif
  sarif_json = to_sarif(findings, target="example.com")
  # or via report_generator
  gen = SecurityReportGenerator(target, findings)
  print(gen.sarif())
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")

SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

def _slug(title: str) -> str:
    import re
    s = re.sub(r"[^a-z0-9]+","-", title.lower()).strip("-")
    return s[:64] or "finding"

def to_sarif(findings: List[Any], target: str = "", tool_name: str = "X19", tool_version: str = "5.0") -> Dict[str, Any]:
    """
    Convert VulnerabilityFinding list to SARIF 2.1.0 dict.
    Accepts both VulnerabilityFinding objects and plain dicts.
    """
    from reporting.compliance import map_finding
    from reporting.remediation import remediation_for

    results: List[Dict[str, Any]] = []
    rules: List[Dict[str, Any]] = []
    seen_rules: Dict[str, Any] = {}

    for f in findings:
        # normalize
        if isinstance(f, dict):
            title = f.get("title","Finding")
            severity = f.get("severity","medium")
            endpoint = f.get("endpoint","")
            description = f.get("description","")
            evidence = f.get("evidence","")
            cwe = f.get("cwe_id","") or f.get("cwe","")
            cvss = f.get("cvss_score","")
            vuln_class = f.get("vuln_class","")
            owasp = f.get("owasp","")
        else:
            title = getattr(f, "title", "Finding")
            severity = getattr(f, "severity", "medium") or "medium"
            endpoint = getattr(f, "endpoint", "") or ""
            description = getattr(f, "description", "") or ""
            evidence = getattr(f, "evidence", "") or ""
            cwe = getattr(f, "cwe_id", "") or ""
            cvss = getattr(f, "cvss_score", "") or ""
            try:
                mapping = map_finding(f)
                vuln_class = mapping.vuln_class
                owasp = mapping.owasp_web or mapping.owasp_api or ""
                cwe = mapping.cwe or cwe
            except Exception:
                vuln_class = "unknown"
                owasp = ""

        rule_id = _slug(vuln_class or title) if vuln_class else _slug(title)
        level = SEVERITY_TO_SARIF_LEVEL.get(severity.lower(), "warning")
        fingerprint = hashlib.sha256(f"{rule_id}|{endpoint}|{title}".encode()).hexdigest()[:16]

        if rule_id not in seen_rules:
            rule = {
                "id": rule_id,
                "name": title[:120],
                "shortDescription": {"text": title[:200]},
                "fullDescription": {"text": description[:800] or title},
                "help": {"text": (remediation_for(f).explanation[:800] if not isinstance(f, dict) else description[:500]) or "See remediation guide."},
                "properties": {"tags": [t for t in [cwe, owasp, f"severity:{severity}", f"cvss:{cvss}"] if t], "severity": severity},
            }
            if cwe:
                rule["properties"]["cwe"] = cwe
            rules.append(rule)
            seen_rules[rule_id] = rule

        # artifact location: endpoint URL -> uri
        uri = endpoint if endpoint.startswith("http") else (f"https://{target}{endpoint}" if endpoint.startswith("/") else endpoint or target)
        location: Dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": uri or target or "unknown", "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": 1, "startColumn": 1}
            },
            "logicalLocations": [{"fullyQualifiedName": endpoint or target}]
        }

        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f"{title} at {endpoint or target}: {description[:400]}"},
            "locations": [location],
            "partialFingerprints": {"primaryLocationLineHash": fingerprint},
            "properties": {
                "tags": [t for t in [cwe, owasp, vuln_class] if t],
                "severity": severity,
                "endpoint": endpoint,
                "evidence": evidence[:1000],
            }
        }
        # attach fix snippet as fixes array (SARIF autofix draft)
        try:
            if not isinstance(f, dict):
                fix = remediation_for(f)
                if fix and fix.snippet:
                    result["fixes"] = [{
                        "description": {"text": fix.explanation[:300]},
                        "artifactChanges": [{
                            "artifactLocation": {"uri": uri},
                            "replacements": [{"deletedRegion": {"startLine": 1, "startColumn": 1, "endLine": 1, "endColumn": 1}, "insertedContent": {"text": fix.snippet[:2000]}}]
                        }]
                    }]
        except Exception:
            pass

        results.append(result)

    sarif: Dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": "https://github.com/Anony-place/x19-refactored",
                    "rules": rules,
                    "properties": {"target": target}
                }
            },
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": _utc_now(),
                "properties": {"target": target, "findings": len(findings)}
            }],
            "results": results,
            "artifacts": [{"location": {"uri": target or "target"}}] if target else [],
            "properties": {"x19:sarif": True}
        }]
    }
    return sarif

def sarif_to_json(findings: List[Any], target: str = "", pretty: bool = True) -> str:
    return json.dumps(to_sarif(findings, target=target), indent=2 if pretty else None)
