"""
AutoFix — CypherFix / Strix Autofix pattern: Triage → Grouping → CodeFix → Draft PR + Verify-after-fix

Groups findings by vuln_class / CWE / tech stack, generates per-group fix patch snippet
(via remediation.py), writes a draft PR markdown + .patch stub, and re-runs proof
to verify the fix (PoV re-validation).

Mirrors RedAMon CypherFix pipeline but without requiring Neo4j or GitHub token for
draft generation — drafts are written to x19_workspace/autofix/<target_slug>/.

Stages:
  triage(findings) -> groups: List[Group]
  codefix(group)   -> FixProposal (snippet + verify command)
  draft_pr(groups, target) -> path to markdown
  verify_after_fix(group, verify_fn) -> bool (re-runs PoV via provided callable)

If a GitHub token is present (GITHUB_TOKEN), can optionally open a real PR via `gh`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")

@dataclass
class FixProposal:
    vuln_class: str
    cwe: str
    count: int
    title: str
    endpoints: List[str]
    snippet: str
    language: str
    explanation: str
    verify: str
    group_hash: str

@dataclass
class Group:
    key: str  # vuln_class|cwe|language
    findings: List[Any]
    cwe: str = ""
    vuln_class: str = ""
    language: str = ""

def triage(findings: List[Any]) -> List[Group]:
    from reporting.compliance import map_finding
    from reporting.remediation import remediation_for
    buckets: Dict[str, Group] = {}
    for f in findings:
        try:
            mapping = map_finding(f)
            vc = mapping.vuln_class or "unknown"
            cwe = mapping.cwe or getattr(f, "cwe_id", "") or "unknown"
            fix = remediation_for(f)
            lang = getattr(fix, "language", "generic") or "generic"
        except Exception:
            vc = getattr(f, "vuln_class", "unknown") or "unknown"
            cwe = getattr(f, "cwe_id", "unknown") or "unknown"
            lang = "generic"
        key = f"{vc}|{cwe}|{lang}"
        if key not in buckets:
            buckets[key] = Group(key=key, findings=[], cwe=cwe, vuln_class=vc, language=lang)
        buckets[key].findings.append(f)
    # sort by severity weight
    sev_weight = {"critical":4,"high":3,"medium":2,"low":1,"info":0}
    def _w(g: Group) -> int:
        return max(sev_weight.get(getattr(f, "severity","info").lower(),0) for f in g.findings)
    return sorted(buckets.values(), key=_w, reverse=True)

def codefix(group: Group) -> FixProposal:
    from reporting.remediation import remediation_for
    # pick representative finding for snippet
    rep = group.findings[0]
    try:
        fix = remediation_for(rep)
        snippet = fix.snippet
        language = fix.language
        explanation = fix.explanation
        verify = fix.verify or f"Re-run: curl -s {getattr(rep,'endpoint','/')}"
    except Exception:
        snippet = f"# Fix {group.vuln_class}: see remediation guide\n# Apply per finding endpoints: {', '.join(str(getattr(f,'endpoint','')) for f in group.findings[:3])}"
        language = group.language or "generic"
        explanation = f"Grouped fix for {group.vuln_class} ({group.cwe}) — {len(group.findings)} finding(s)"
        verify = "Re-run proof command for each endpoint"
    endpoints = [str(getattr(f,"endpoint","")) for f in group.findings]
    group_hash = hashlib.sha256(group.key.encode()).hexdigest()[:8]
    # craft aggregated title
    title = f"fix({group.vuln_class}): {group.cwe} — {len(group.findings)} finding(s)"
    return FixProposal(
        vuln_class=group.vuln_class, cwe=group.cwe, count=len(group.findings),
        title=title, endpoints=endpoints, snippet=snippet, language=language,
        explanation=explanation, verify=verify, group_hash=group_hash
    )

def draft_pr(groups: List[Group], target: str = "", workspace: Optional[Path] = None) -> Path:
    base = Path(workspace) if workspace else Path("x19_workspace") / "autofix"
    slug = hashlib.sha256((target or "default").encode()).hexdigest()[:10]
    out_dir = base / slug
    out_dir.mkdir(parents=True, exist_ok=True)
    proposals = [codefix(g) for g in groups]

    # markdown draft
    md_lines = [f"# 🛠️ X19 AutoFix Draft — {target}", f"_Generated: {_utc_now()}_", ""]
    md_lines.append(f"**Target:** `{target}`  ")
    md_lines.append(f"**Groups:** {len(groups)}  ")
    md_lines.append(f"**Total findings:** {sum(len(g.findings) for g in groups)}  ")
    md_lines.append("")
    md_lines.append("## Grouped Fixes")
    for p in proposals:
        md_lines.append(f"\n### {p.title}")
        md_lines.append(f"- **CWE:** `{p.cwe}`  ")
        md_lines.append(f"- **Language:** `{p.language}`  ")
        md_lines.append(f"- **Endpoints:** " + ", ".join(f"`{e}`" for e in p.endpoints[:5]) + (f" (+{len(p.endpoints)-5} more)" if len(p.endpoints)>5 else ""))
        md_lines.append(f"\n**Fix:** {p.explanation}\n")
        md_lines.append(f"```{p.language}\n{p.snippet}\n```")
        md_lines.append(f"\n**Verify after fix:** `{p.verify}`\n")
        md_lines.append("---")

    md_lines.append("\n## How to Apply")
    md_lines.append("1. Review each snippet in the context of your codebase (branch `x19/autofix-<hash>`).")
    md_lines.append("2. Apply the `*.patch` stubs in this directory or cherry-pick snippets.")
    md_lines.append("3. Run `python run.py --verify-fix x19_workspace/autofix/<slug>` or re-run the PoC commands noted above.")
    md_lines.append("4. Re-scan with `python run.py -t <target>` — findings should be gone (SARIF diff).")
    md_path = out_dir / "DRAFT_PR.md"
    md_path.write_text("\n".join(md_lines))

    # per-group patch stubs
    for p in proposals:
        patch = out_dir / f"fix-{p.group_hash}-{p.vuln_class}.patch"
        patch.write_text(
            f"--- a/{p.vuln_class}\n+++ b/{p.vuln_class}\n@@ AutoFix stub for {p.title} @@\n"
            f"# Language: {p.language}\n# CWE: {p.cwe}\n# Endpoints: {', '.join(p.endpoints)}\n\n{p.snippet}\n"
        )
    # manifest for tooling
    manifest = {
        "target": target,
        "generated_at": _utc_now(),
        "groups": len(groups),
        "findings": sum(len(g.findings) for g in groups),
        "proposals": [asdict(p) for p in proposals],
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return md_path

def verify_after_fix(group: Group, verify_fn: Optional[Callable[[Any], bool]] = None) -> Dict[str, Any]:
    """
    Re-run verification for each finding in group via verify_fn(finding)->bool.
    If verify_fn is None, returns advisory (no re-run).
    Returns {"verified": int, "remaining": int, "details": [...]}
    """
    if verify_fn is None:
        return {"verified": 0, "remaining": len(group.findings), "mode": "advisory", "note": "No verify_fn provided — attach PoV re-run callable to enable."}
    results = []
    for f in group.findings:
        try:
            ok = bool(verify_fn(f))
            results.append({"endpoint": str(getattr(f,"endpoint","")), "title": str(getattr(f,"title","")), "fixed": ok})
        except Exception as e:
            results.append({"endpoint": str(getattr(f,"endpoint","")), "title": str(getattr(f,"title","")), "fixed": False, "error": str(e)})
    verified = sum(1 for r in results if r.get("fixed"))
    return {"verified": verified, "remaining": len(results)-verified, "details": results, "mode": "active"}
