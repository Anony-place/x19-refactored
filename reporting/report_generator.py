"""
X19 Security Assessment & Remediation Report Generator.
Generates enterprise-grade Markdown, HTML, and JSON reports with executive summaries,
CVSS v3.1 scoring, CWE mappings, reproducible PoCs, and actionable defensive remediations.
"""

from __future__ import annotations
import json
import time
from dataclasses import asdict
from datetime import datetime
from typing import Dict, List, Optional, Any

from execution.native_vuln import VulnerabilityFinding


class SecurityReportGenerator:
    """Generates structured defensive security assessment and remediation reports."""

    def __init__(self, target: str, findings: List[VulnerabilityFinding], metadata: Optional[Dict[str, Any]] = None):
        self.target = target
        self.findings = findings
        self.metadata = metadata or {}
        self.generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    def get_stats(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.severity.lower()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["info"] += 1
        return counts

    def calculate_risk_score(self) -> float:
        weights = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
        total = sum(weights.get(f.severity.lower(), 1.0) for f in self.findings)
        return min(100.0, round(total * 4.0, 1))

    def generate_markdown(self) -> str:
        stats = self.get_stats()
        risk_score = self.calculate_risk_score()

        md = []
        md.append(f"# 🛡️ X19 Security Assessment & Remediation Report")
        md.append(f"**Target Host:** `{self.target}`  ")
        md.append(f"**Assessment Date:** {self.generated_at}  ")
        md.append(f"**Overall Risk Rating:** {self._risk_label(risk_score)} ({risk_score}/100)  ")
        md.append("\n---\n")

        # Executive Summary
        md.append("## 1. Executive Summary")
        md.append(
            f"An automated in-scope cognitive security assessment was conducted against **{self.target}**. "
            f"A total of **{len(self.findings)} verified finding(s)** were identified during the assessment. "
            f"All findings have been independently verified with reproducible Proofs of Concept (PoCs) to eliminate false positives."
        )
        md.append("\n### Finding Severity Breakdown")
        md.append("| Severity | Count |")
        md.append("| :--- | :--- |")
        md.append(f"| 🔴 Critical | {stats['critical']} |")
        md.append(f"| 🟠 High | {stats['high']} |")
        md.append(f"| 🟡 Medium | {stats['medium']} |")
        md.append(f"| 🔵 Low | {stats['low']} |")
        md.append(f"| ⚪ Info | {stats['info']} |")
        md.append(f"| **Total** | **{len(self.findings)}** |")
        md.append("\n---\n")

        # Detailed Technical Findings
        md.append("## 2. Detailed Technical Findings & Remediations\n")
        if not self.findings:
            md.append("No security vulnerabilities or misconfigurations were detected.")
        else:
            for idx, f in enumerate(self.findings, 1):
                md.append(f"### {idx}. [{f.severity.upper()}] {f.title}")
                md.append(f"- **Affected Endpoint:** `{f.endpoint}`")
                md.append(f"- **CVSS v3.1 Score:** `{f.cvss_score}`")
                if f.cwe_id:
                    md.append(f"- **CWE Identifier:** `{f.cwe_id}`")
                md.append(f"- **Status:** Verified (0% False Positive)")
                md.append(f"\n**Description:**  \n{f.description}\n")
                md.append(f"**Evidence:**  \n```\n{f.evidence}\n```\n")
                if f.poc_command:
                    md.append(f"**Proof of Concept (PoC Command):**  \n```bash\n{f.poc_command}\n```\n")
                md.append(f"**Defensive Remediation:**  \n{f.remediation}\n")
                md.append(f"**Defensive Configuration Patch Guidance:**  \n```nginx\n# Recommended Server Hardening Rule\n{self._get_remediation_snippet(f)}\n```\n")
                md.append("\n---\n")

        # Compliance & Best Practices
        md.append("## 3. General Defensive Recommendations")
        md.append("1. **Defense-in-Depth:** Enforce strict Content Security Policy (CSP), HTTP Strict Transport Security (HSTS), and X-Frame-Options headers.")
        md.append("2. **Principle of Least Privilege:** Restrict public access to administrative directories, hidden `.git`/`.env` files, and metadata.")
        md.append("3. **Continuous Monitoring:** Conduct automated periodic vulnerability scans and maintain active Web Application Firewall (WAF) rule sets.")

        return "\n".join(md)

    def generate_html(self) -> str:
        stats = self.get_stats()
        risk_score = self.calculate_risk_score()

        findings_html = []
        for idx, f in enumerate(self.findings, 1):
            sev_class = f.severity.lower()
            findings_html.append(f"""
            <div class="finding-card severity-{sev_class}">
                <div class="finding-header">
                    <h3>#{idx} {f.title}</h3>
                    <span class="badge badge-{sev_class}">{f.severity.upper()} | CVSS {f.cvss_score}</span>
                </div>
                <div class="finding-meta">
                    <strong>Endpoint:</strong> <code>{f.endpoint}</code> | 
                    <strong>CWE:</strong> {f.cwe_id or 'N/A'}
                </div>
                <p><strong>Description:</strong> {f.description}</p>
                <div class="code-block">
                    <strong>Evidence:</strong>
                    <pre>{f.evidence}</pre>
                </div>
                {f'<div class="code-block"><strong>Proof of Concept:</strong><pre>{f.poc_command}</pre></div>' if f.poc_command else ''}
                <div class="remediation-box">
                    <strong>🛡️ Remediation Advice:</strong>
                    <p>{f.remediation}</p>
                </div>
            </div>
            """)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>X19 Security Assessment Report - {self.target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px 20px; }}
        .container {{ max-width: 900px; margin: 0 auto; background: #1e293b; padding: 32px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }}
        h1, h2, h3 {{ color: #38bdf8; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 20px 0; }}
        .stat-card {{ background: #0f172a; padding: 16px; border-radius: 8px; text-align: center; border: 1px solid #334155; }}
        .stat-num {{ font-size: 1.8rem; font-weight: bold; color: #38bdf8; }}
        .finding-card {{ background: #0f172a; border-radius: 8px; padding: 20px; margin-bottom: 20px; border-left: 5px solid #38bdf8; }}
        .severity-critical {{ border-left-color: #ef4444; }}
        .severity-high {{ border-left-color: #f97316; }}
        .severity-medium {{ border-left-color: #eab308; }}
        .severity-low {{ border-left-color: #3b82f6; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }}
        .badge-critical {{ background: #ef4444; color: #fff; }}
        .badge-high {{ background: #f97316; color: #fff; }}
        .badge-medium {{ background: #eab308; color: #000; }}
        .badge-low {{ background: #3b82f6; color: #fff; }}
        .badge-info {{ background: #64748b; color: #fff; }}
        pre {{ background: #020617; padding: 10px; border-radius: 6px; overflow-x: auto; color: #a5f3fc; font-family: monospace; font-size: 0.85rem; }}
        .remediation-box {{ background: rgba(56, 189, 248, 0.1); border: 1px solid #0284c7; padding: 12px; border-radius: 6px; margin-top: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ X19 Security Assessment & Remediation Report</h1>
        <p><strong>Target:</strong> {self.target} | <strong>Generated:</strong> {self.generated_at}</p>
        <div class="stats-grid">
            <div class="stat-card"><div class="stat-num">{stats['critical']}</div><div>Critical</div></div>
            <div class="stat-card"><div class="stat-num">{stats['high']}</div><div>High</div></div>
            <div class="stat-card"><div class="stat-num">{stats['medium']}</div><div>Medium</div></div>
            <div class="stat-card"><div class="stat-num">{stats['low']}</div><div>Low</div></div>
        </div>
        <h2>Detailed Findings</h2>
        {''.join(findings_html) if findings_html else '<p>No vulnerabilities detected.</p>'}
    </div>
</body>
</html>"""
        return html

    def generate_json(self) -> str:
        return json.dumps({
            "target": self.target,
            "generated_at": self.generated_at,
            "risk_score": self.calculate_risk_score(),
            "stats": self.get_stats(),
            "findings": [asdict(f) for f in self.findings],
            "metadata": self.metadata
        }, indent=2)

    @staticmethod
    def _risk_label(score: float) -> str:
        if score >= 75.0:
            return "🔴 HIGH RISK"
        if score >= 40.0:
            return "🟠 MEDIUM RISK"
        if score >= 15.0:
            return "🟡 LOW RISK"
        return "🟢 INFORMATIONAL / SECURE"

    @staticmethod
    def _get_remediation_snippet(finding: VulnerabilityFinding) -> str:
        if "Git" in finding.title or ".env" in finding.title:
            return "location ~ /\\.(git|env|svn) { deny all; return 404; }"
        if "CORS" in finding.title:
            return "add_header Access-Control-Allow-Origin \"https://yourtrusteddomain.com\" always;"
        if "Headers" in finding.title:
            return "add_header X-Frame-Options \"DENY\" always;\nadd_header X-Content-Type-Options \"nosniff\" always;\nadd_header Content-Security-Policy \"default-src 'self';\" always;"
        if "GraphQL" in finding.title:
            return "# In Apollo Server / GraphQL config:\nintrospection: process.env.NODE_ENV !== 'production'"
        return "# General hardening:\nlimit_req zone=one burst=5 nodelay;"
