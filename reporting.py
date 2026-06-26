import json
import os
import re
import requests
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass, field, asdict

from constants import C, ICO
from config import CONFIG, load_config
from logging_utils import log


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


class ReportWriter:
    """Write per-session reports: Markdown (always) and HTML (with collapsible sections).

    Each finding gets:
      - title + severity badge
      - endpoint / method
      - request/response (from evidence)
      - generated curl reproduction command
      - CVSS score (estimated from severity)
      - remediation hints (where we can suggest them)
    """

    SEVERITY_COLORS = {
        "critical": "#7c1d3f", "high": "#b91c1c", "medium": "#b45309",
        "low": "#1d4ed8", "info": "#374151",
    }
    SEVERITY_EMOJI = {
        "critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED]",
        "low": "[LOW]", "info": "[INFO]",
    }

    def __init__(self, target: str, findings: List[dict], session_meta: dict = None,
                 workspace: str = ""):
        self.target = target
        self.findings = findings or []
        self.session_meta = session_meta or {}
        self.workspace = Path(workspace or os.path.expanduser("~/x19_workspace"))
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _safe_fname(self) -> str:
        return re.sub(r'[^a-zA-Z0-9._-]+', '_', self.target)[:60] or "report"

    def _generated_curl(self, f: dict) -> str:
        """Best-effort: extract a curl PoC from finding's evidence / request / endpoint."""
        ep = f.get("endpoint") or f.get("url") or f.get("target") or self.target
        method = (f.get("method") or "GET").upper()
        body = f.get("body") or f.get("request") or ""
        headers = f.get("headers") or {}
        # If a command field has curl in it, use it directly
        cmd = f.get("command") or f.get("exploit") or ""
        if "curl" in cmd:
            # Strip newlines
            return " ".join(cmd.split())
        # Otherwise build a generic one
        parts = [f"curl -i -X {method}"]
        for k, v in (headers.items() if isinstance(headers, dict) else []):
            parts.append(f"-H '{k}: {v}'")
        if body:
            parts.append(f"--data-raw '{body[:300]}'")
        parts.append(f"'{ep}'")
        return " ".join(parts)

    def write_markdown(self) -> str:
        path = self.workspace / f"report_{self._safe_fname()}_{int(time.time())}.md"
        L: List[str] = []
        L.append(f"# X19 Pentest Report — {self.target}\n")
        L.append(f"**Generated:** {self.ts}  ")
        L.append(f"**Target:** `{self.target}`  ")
        L.append(f"**Findings:** {len(self.findings)}  ")
        # Severity histogram
        sev_counts: dict = {}
        for f in self.findings:
            s = (f.get("severity") or "info").lower()
            sev_counts[s] = sev_counts.get(s, 0) + 1
        L.append("**By severity:** " + " | ".join(
            f"{k}={v}" for k, v in sorted(sev_counts.items(), key=lambda x: -x[1])))
        L.append("")
        if self.session_meta:
            L.append("## Session info")
            for k, v in self.session_meta.items():
                L.append(f"- **{k}**: {v}")
            L.append("")
        L.append("## Summary")
        L.append("| # | Severity | Title | Endpoint | CVSS |")
        L.append("|---|----------|-------|----------|------|")
        for i, f in enumerate(self.findings, 1):
            sev = (f.get("severity") or "info").lower()
            score, _ = _cvss_from_severity(sev)
            L.append(f"| {i} | {self.SEVERITY_EMOJI.get(sev, '[?]')} {sev} | "
                     f"{f.get('title','(no title)')} | "
                     f"`{f.get('endpoint') or f.get('url') or '-'}` | {score:.1f} |")
        L.append("")
        L.append("## Detailed findings")
        for i, f in enumerate(self.findings, 1):
            sev = (f.get("severity") or "info").lower()
            score, vector = _cvss_from_severity(sev)
            L.append(f"### {i}. {f.get('title', '(untitled)')}")
            L.append(f"- **Severity:** {sev}  ")
            L.append(f"- **CVSS:** {score:.1f} ({vector})  ")
            if f.get("endpoint") or f.get("url"):
                L.append(f"- **Endpoint:** `{f.get('endpoint') or f.get('url')}`  ")
            if f.get("kind"):
                L.append(f"- **Class:** {f['kind']}  ")
            if f.get("cve"):
                L.append(f"- **CVE:** {f['cve']}  ")
            if f.get("detail"):
                L.append(f"\n{f['detail']}\n")
            if f.get("evidence"):
                ev = f["evidence"]
                if isinstance(ev, (list, tuple)):
                    ev = "\n".join(str(x) for x in ev)
                L.append(f"**Evidence:**\n```\n{str(ev)[:1500]}\n```\n")
            L.append("**Reproduction:**")
            L.append("```bash")
            L.append(self._generated_curl(f))
            L.append("```\n")
            if f.get("remediation"):
                L.append(f"**Remediation:** {f['remediation']}\n")
            L.append("---\n")
        try:
            path.write_text("\n".join(L), encoding="utf-8")
            log(f"[Report] markdown -> {path}")
        except Exception as e:
            log(f"[Report] markdown write failed: {e}")
            return ""
        return str(path)

    def write_html(self) -> str:
        path = self.workspace / f"report_{self._safe_fname()}_{int(time.time())}.html"
        css = """
        body { font-family: -apple-system, system-ui, sans-serif; max-width: 1100px; margin: 24px auto; padding: 0 16px; color: #1f2937; }
        h1 { border-bottom: 3px solid #1f2937; padding-bottom: 8px; }
        .meta { color: #6b7280; margin-bottom: 24px; }
        .finding { border: 1px solid #e5e7eb; border-left: 6px solid #999; border-radius: 6px;
                   margin: 16px 0; padding: 14px 18px; background: #fafafa; }
        .finding.critical { border-left-color: #7c1d3f; }
        .finding.high     { border-left-color: #b91c1c; }
        .finding.medium   { border-left-color: #b45309; }
        .finding.low      { border-left-color: #1d4ed8; }
        .finding.info     { border-left-color: #374151; }
        .sev { display: inline-block; padding: 2px 10px; border-radius: 12px;
               color: #fff; font-size: 12px; font-weight: 700; text-transform: uppercase; }
        .sev.critical { background: #7c1d3f; }
        .sev.high     { background: #b91c1c; }
        .sev.medium   { background: #b45309; }
        .sev.low      { background: #1d4ed8; }
        .sev.info     { background: #374151; }
        details { margin-top: 8px; }
        summary { cursor: pointer; font-weight: 600; color: #4b5563; padding: 4px 0; }
        pre { background: #1f2937; color: #f3f4f6; padding: 10px 14px; border-radius: 4px;
              overflow-x: auto; font-size: 13px; }
        table { border-collapse: collapse; width: 100%; margin: 16px 0; }
        th, td { border: 1px solid #e5e7eb; padding: 8px 12px; text-align: left; }
        th { background: #f3f4f6; }
        code { background: #e5e7eb; padding: 2px 5px; border-radius: 3px; font-size: 13px; }
        """
        sev_counts: dict = {}
        for f in self.findings:
            s = (f.get("severity") or "info").lower()
            sev_counts[s] = sev_counts.get(s, 0) + 1

        html = [f"""<!doctype html><html><head><meta charset="utf-8">
<title>X19 Report — {self.target}</title><style>{css}</style></head><body>
<h1>X19 Pentest Report</h1>
<div class="meta">
<strong>Target:</strong> <code>{self.target}</code><br>
<strong>Generated:</strong> {self.ts}<br>
<strong>Total findings:</strong> {len(self.findings)} &middot;
<strong>By severity:</strong> """ + " ".join(
    f'<span class="sev {k}">{k}: {v}</span>' for k, v in sorted(sev_counts.items(), key=lambda x: -x[1]))
+ "</div>"]

        html.append("<h2>Summary</h2>")
        html.append("<table><tr><th>#</th><th>Severity</th><th>Title</th><th>Endpoint</th><th>CVSS</th></tr>")
        for i, f in enumerate(self.findings, 1):
            sev = (f.get("severity") or "info").lower()
            score, _ = _cvss_from_severity(sev)
            html.append(f'<tr><td>{i}</td><td><span class="sev {sev}">{sev}</span></td>'
                        f'<td>{(f.get("title") or "(untitled)").replace("<","&lt;")}</td>'
                        f'<td><code>{(f.get("endpoint") or f.get("url") or "-").replace("<","&lt;")}</code></td>'
                        f'<td>{score:.1f}</td></tr>')
        html.append("</table>")

        html.append("<h2>Detailed findings</h2>")
        for i, f in enumerate(self.findings, 1):
            sev = (f.get("severity") or "info").lower()
            score, vector = _cvss_from_severity(sev)
            html.append(f'<div class="finding {sev}">')
            html.append(f'<h3>{i}. {(f.get("title") or "(untitled)").replace("<","&lt;")} '
                        f'<span class="sev {sev}">{sev}</span></h3>')
            html.append(f'<p><strong>CVSS:</strong> {score:.1f} '
                        f'<code>{vector}</code></p>')
            if f.get("endpoint") or f.get("url"):
                html.append(f'<p><strong>Endpoint:</strong> <code>{(f.get("endpoint") or f.get("url")).replace("<","&lt;")}</code></p>')
            if f.get("kind"):
                html.append(f'<p><strong>Class:</strong> {f["kind"]}</p>')
            if f.get("cve"):
                html.append(f'<p><strong>CVE:</strong> {f["cve"]}</p>')
            if f.get("detail"):
                html.append(f'<p>{(f["detail"] or "").replace("<","&lt;")}</p>')
            if f.get("evidence"):
                ev = f["evidence"]
                if isinstance(ev, (list, tuple)):
                    ev = "\n".join(str(x) for x in ev)
                html.append('<details><summary>Evidence</summary>'
                            f'<pre>{(str(ev)[:2000]).replace("<","&lt;")}</pre></details>')
            curl_cmd = self._generated_curl(f)
            html.append('<details open><summary>Reproduction (curl)</summary>'
                        f'<pre>{(curl_cmd).replace("<","&lt;")}</pre></details>')
            if f.get("remediation"):
                html.append(f'<p><strong>Remediation:</strong> {f["remediation"]}</p>')
            html.append("</div>")
        html.append("</body></html>")
        try:
            path.write_text("\n".join(html), encoding="utf-8")
            log(f"[Report] html -> {path}")
        except Exception as e:
            log(f"[Report] html write failed: {e}")
            return ""
        return str(path)

    def write_both(self) -> Tuple[str, str]:
        return self.write_markdown(), self.write_html()


CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.I)

REMEDIATION = {
    "sql injection": "Use parameterized queries/prepared statements; validate input; apply least-privilege DB accounts.",
    "sqli": "Use parameterized queries/prepared statements; validate input; apply least-privilege DB accounts.",
    "xss": "Context-encode output, set a strict CSP, sanitize HTML input, rely on framework auto-escaping.",
    "rce": "Patch/remove the vulnerable component now; never pass user input to shell/eval; add a WAF virtual patch as interim.",
    "command injection": "Avoid shell calls with user input; use argument arrays/allow-lists; patch affected software.",
    "lfi": "Validate file paths against an allow-list; block directory traversal; run with least privilege.",
    "ssrf": "Allow-list outbound URLs; block link-local/metadata IPs (169.254.169.254); route via a fetch proxy.",
    "exposed .env": "Remove secret files from the web root; rotate leaked credentials; restrict access via server config.",
    "default credential": "Change default passwords; enforce strong unique credentials; disable unused accounts.",
    "open port": "Restrict exposure via firewall/security group; disable unused services; require authentication.",
    "outdated": "Upgrade to a fixed version; subscribe to vendor advisories; enable automatic security updates.",
    "ssl": "Disable weak ciphers/protocols (SSLv3/TLS1.0); deploy a valid certificate; enable HSTS.",
    "subdomain takeover": "Remove dangling DNS records pointing to unclaimed services; reclaim or delete the CNAME.",
}


def remediation_for(title: str, detail: str = "") -> str:
    t = f"{title} {detail}".lower()
    for k, v in REMEDIATION.items():
        if k in t:
            return v
    return "Validate the issue, apply vendor patches, restrict exposure, and re-test."


class ThreatIntel:
    """Exploit-availability signals from CISA KEV, FIRST EPSS, and ExploitDB (searchsploit)."""
    _kev: Optional[set] = None

    @classmethod
    def kev_set(cls) -> set:
        """CISA Known Exploited Vulnerabilities catalog, cached for the process."""
        if cls._kev is None:
            cls._kev = set()
            try:
                r = requests.get(
                    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                    timeout=20)
                for v in r.json().get("vulnerabilities", []):
                    if v.get("cveID"):
                        cls._kev.add(v["cveID"].upper())
            except Exception as e:
                log(f"[ThreatIntel] KEV fetch failed: {e}")
        return cls._kev

    @classmethod
    def is_kev(cls, cve: str) -> bool:
        return bool(cve) and cve.upper() in cls.kev_set()

    @staticmethod
    def epss(cve: str) -> float:
        """FIRST EPSS exploit-probability 0..1 (0.0 if unknown)."""
        if not cve:
            return 0.0
        try:
            r = requests.get("https://api.first.org/data/v1/epss",
                             params={"cve": cve.upper()}, timeout=15)
            data = r.json().get("data", [])
            return float(data[0]["epss"]) if data else 0.0
        except Exception:
            return 0.0

    @staticmethod
    def exploits(query: str) -> list:
        """Existing PUBLIC exploits/PoCs via ExploitDB (searchsploit). Discovery only —
        does not author exploit code. Returns [] if searchsploit is not installed."""
        try:
            p = subprocess.run(["searchsploit", "--json", query],
                               capture_output=True, text=False, timeout=30)
            so = (p.stdout or b"").decode("utf-8", errors="replace")
            return [e.get("Title", "") for e in json.loads(so or "{}").get("RESULTS_EXPLOIT", [])][:10]
        except Exception:
            return []


class OTX:
    """AlienVault OTX (Open Threat Exchange) threat intel. Reads OTX_API_KEY from env.
    Degrades to empty/neutral on any error — never fabricates."""
    BASE = "https://otx.alienvault.com/api/v1"

    @staticmethod
    def _headers() -> dict:
        k = os.environ.get("OTX_API_KEY", "") or load_config().get("OTX_API_KEY", "")
        return {"X-OTX-API-KEY": k} if k else {}

    @classmethod
    def passive_dns(cls, domain: str) -> list:
        """Related hostnames from OTX passive DNS (extra recon source). [] on error."""
        hosts = set()
        try:
            r = requests.get(f"{cls.BASE}/indicators/domain/{domain}/passive_dns",
                             headers=cls._headers(), timeout=20)
            for rec in r.json().get("passive_dns", []):
                h = str(rec.get("hostname", "")).strip().lower()
                if h.endswith(domain) and " " not in h:
                    hosts.add(h)
        except Exception as e:
            log(f"[OTX] passive_dns failed for {domain}: {e}")
        return sorted(hosts)

    @classmethod
    def threat_context(cls, indicator: str, kind: str = "domain") -> dict:
        """Threat reputation: pulse count, tags, malware families. kind: 'domain' or 'IPv4'."""
        try:
            r = requests.get(f"{cls.BASE}/indicators/{kind}/{indicator}/general",
                             headers=cls._headers(), timeout=20)
            pi = r.json().get("pulse_info", {}) or {}
            tags, malware = set(), set()
            for p in (pi.get("pulses", []) or [])[:50]:
                tags.update(t for t in (p.get("tags") or []) if t)
                for m in (p.get("malware_families") or []):
                    malware.add(m.get("display_name", "") if isinstance(m, dict) else m)
            return {"pulses": int(pi.get("count", 0)),
                    "tags": sorted(tags)[:15], "malware": sorted(m for m in malware if m)[:10]}
        except Exception as e:
            log(f"[OTX] threat_context failed for {indicator}: {e}")
            return {"pulses": 0, "tags": [], "malware": []}


def prioritize_findings(findings: list) -> list:
    """Rank findings by real-time exploit availability then severity. Adds cve/kev/epss keys.
    Sort key: KEV (actively exploited) > EPSS probability > severity."""
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    out = []
    for f in findings:
        text = f"{f.get('title','')} {f.get('detail','')} {f.get('evidence','')}"
        m = CVE_RE.search(text)
        cve = m.group(0).upper() if m else ""
        g = dict(f)
        g["cve"] = cve
        g["kev"] = ThreatIntel.is_kev(cve)
        g["epss"] = ThreatIntel.epss(cve) if cve else 0.0
        g["_rank"] = (1 if g["kev"] else 0, round(g["epss"], 4), sev_rank.get(f.get("severity", "info"), 0))
        out.append(g)
    out.sort(key=lambda x: x["_rank"], reverse=True)
    return out


def build_report(target: str, findings: list, tool_failures: dict = None, tool_effectiveness: dict = None) -> str:
    """Automated markdown report: prioritized findings + remediation. No findings -> says so."""
    ranked = prioritize_findings(findings)
    lines = [f"# X19 Security Assessment — {target}",
             f"_Generated {datetime.now().isoformat(timespec='seconds')}_",
             "", f"**Verified findings: {len(ranked)}**", ""]
    if not ranked:
        lines.append("No verified findings.")
    else:
        for i, f in enumerate(ranked, 1):
            tags = [t for t in (f["cve"], "KEV/actively-exploited" if f["kev"] else "",
                                f"EPSS={f['epss']:.1%}" if f["epss"] else "") if t]
            tag = f" ({', '.join(tags)})" if tags else ""
            lines.append(f"## {i}. [{f.get('severity','info').upper()}] {f.get('title','')}{tag}")
            if f.get("detail"):
                lines.append(f"\n{f['detail'][:600]}")
            if f.get("evidence"):
                lines.append(f"\n**Evidence:**\n```\n{f['evidence'][:400]}\n```")
            lines.append(f"\n**Remediation:** {remediation_for(f.get('title',''), f.get('detail',''))}\n")

    # Add execution metrics and tool performance summaries
    if tool_failures or tool_effectiveness:
        lines.append("\n---")
        lines.append("## Tool Execution Metrics")
        
        if tool_failures:
            lines.append("\n### Tool Failures")
            has_failures = False
            for cmd, info in sorted(tool_failures.items(), key=lambda x: x[1].get("count", 0), reverse=True)[:5]:
                count = info.get("count", 0)
                err = info.get("error", "").strip()
                lines.append(f"- **`{cmd}`**: failed {count} times (Last error: `{err[:100]}`)")
                has_failures = True
            if not has_failures:
                lines.append("No tool failures recorded during this session.")
                
        if tool_effectiveness:
            lines.append("\n### Tool Effectiveness & Yield")
            effective = []
            avoid = []
            for t, r in sorted(tool_effectiveness.items(), key=lambda x: x[1]["wins"]/x[1]["runs"] if x[1]["runs"] else 0, reverse=True):
                runs = r.get("runs", 0)
                wins = r.get("wins", 0)
                if runs > 0:
                    rate = wins / runs
                    if rate >= 0.34:
                        effective.append(f"- **`{t}`**: {wins}/{runs} productive ({rate:.1%})")
                    else:
                        avoid.append(f"- **`{t}`**: {wins}/{runs} productive ({rate:.1%}) - *consider avoiding*")
            if effective:
                lines.append("\n**Top Productive Tools:**")
                lines.extend(effective)
            if avoid:
                lines.append("\n**Low-Yield/Avoid Tools:**")
                lines.extend(avoid)
            if not effective and not avoid:
                lines.append("No tool execution effectiveness metrics available.")

    return "\n".join(lines)


def crtsh_subdomains(domain: str) -> list:
    """Passive subdomain intel from crt.sh certificate-transparency logs. [] on error."""
    subs = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=25)
        for row in r.json():
            for name in str(row.get("name_value", "")).split("\n"):
                name = name.strip().lstrip("*.").lower()
                if name.endswith(domain) and " " not in name:
                    subs.add(name)
    except Exception as e:
        log(f"[Recon] crt.sh failed for {domain}: {e}")
    return sorted(subs)


def nessus_scan(target: str) -> str:
    """Launch a real Nessus scan via its REST API. Requires NESSUS_URL, NESSUS_ACCESS_KEY,
    NESSUS_SECRET_KEY, NESSUS_TEMPLATE (install-specific UUID). Honest error if unconfigured —
    never fabricated results."""
    url = os.environ.get("NESSUS_URL")
    ak = os.environ.get("NESSUS_ACCESS_KEY")
    sk = os.environ.get("NESSUS_SECRET_KEY")
    tmpl = os.environ.get("NESSUS_TEMPLATE")
    if not (url and ak and sk and tmpl):
        return "[nessus] not configured (set NESSUS_URL/NESSUS_ACCESS_KEY/NESSUS_SECRET_KEY/NESSUS_TEMPLATE)"
    try:
        import urllib3
        urllib3.disable_warnings()
        h = {"X-ApiKeys": f"accessKey={ak}; secretKey={sk}", "Content-Type": "application/json"}
        base = url.rstrip("/")
        r = requests.post(f"{base}/scans", headers=h, verify=False, timeout=30,
                          json={"uuid": tmpl, "settings": {"name": f"x19-{target}", "text_targets": target}})
        sid = r.json().get("scan", {}).get("id")
        if not sid:
            return f"[nessus] create failed: {r.text[:200]}"
        requests.post(f"{base}/scans/{sid}/launch", headers=h, verify=False, timeout=30)
        return f"[nessus] launched scan id={sid} for {target}"
    except Exception as e:
        return f"[nessus] error: {e}"


class Finding:
    severity: str
    title: str
    description: str
    source: str = ""
    evidence: str = ""


@dataclass
class TargetModel:
    """Persistent structured knowledge about the target, built incrementally."""
    hostname: str = ""
    ip_addresses: list = field(default_factory=list)
    ports: list = field(default_factory=list)  # [{port, proto, service, version, state}]
    os_info: str = ""
    subdomains: set = field(default_factory=set)
    endpoints: list = field(default_factory=list)  # [{url, method, params, tech, status}]
    credentials: list = field(default_factory=list)  # [{service, username, password, source}]
    tech_stack: dict = field(default_factory=dict)  # {tech_name: version_or_info}
    findings: list = field(default_factory=list)
    attack_paths: list = field(default_factory=list)  # [{technique, service, rationale, attempted}]
    notes: list = field(default_factory=list)
    command_outputs: dict = field(default_factory=dict)  # {cmd_id: {command, stdout, stderr, returncode, timestamp}}

    def add_port(self, port: int, proto: str, service: str, version: str = "", state: str = "open"):
        key = f"{port}/{proto}"
        if not any(p.get("key") == key for p in self.ports):
            self.ports.append({"key": key, "port": port, "proto": proto, "service": service, "version": version, "state": state})

    def add_subdomain(self, sub: str):
        self.subdomains.add(sub)

    def add_credential(self, service: str, username: str, password: str, source: str = ""):
        self.credentials.append({"service": service, "username": username, "password": password, "source": source})

    def add_endpoint(self, url: str, method: str = "GET", params: str = "", tech: str = "", status: int = 0):
        for e in self.endpoints:
            if e["url"] == url and e["method"] == method:
                if status and not e.get("status"):
                    e["status"] = status
                if params and not e.get("params"):
                    e["params"] = params
                return
        self.endpoints.append({"url": url, "method": method, "params": params, "tech": tech, "status": status})

    def set_endpoint_status(self, url: str, status: int):
        for e in self.endpoints:
            if e["url"].rstrip('/') == url.rstrip('/'):
                e["status"] = status
                return
        self.endpoints.append({"url": url, "method": "GET", "params": "", "tech": "", "status": status})

    def add_tech(self, name: str, version: str = ""):
        self.tech_stack[name] = version

    def add_attack_path(self, technique: str, service: str, rationale: str):
        self.attack_paths.append({"technique": technique, "service": service, "rationale": rationale, "attempted": False})

    def add_finding(self, finding):
        self.findings.append(finding)

    def store_output(self, cmd_id: str, command: str, stdout: str, stderr: str, returncode: int):
        self.command_outputs[cmd_id] = {
            "command": command, "stdout": stdout, "stderr": stderr,
            "returncode": returncode, "timestamp": datetime.now().isoformat(),
        }

    def get_output(self, cmd_id: str) -> Optional[str]:
        entry = self.command_outputs.get(cmd_id)
        if entry:
            out = entry.get("stdout", "")
            err = entry.get("stderr", "")
            combined = out + ("\n[STDERR]\n" + err if err else "")
            return combined
        return None

    def service_summary(self) -> str:
        if not self.ports:
            return "No ports discovered yet"
        lines = []
        for p in self.ports[:15]:
            ver = f" {p['version']}" if p.get('version') else ""
            lines.append(f"  {p['key']:10} {p['service']}{ver}")
        if len(self.ports) > 15:
            lines.append(f"  ... and {len(self.ports)-15} more")
        return "\n".join(lines)

    def summary(self) -> str:
        parts = [f"Target: {self.hostname}"]
        if self.ip_addresses:
            parts.append(f"IPs: {', '.join(self.ip_addresses[:3])}")
        if self.os_info:
            parts.append(f"OS: {self.os_info[:100]}")
        if self.subdomains:
            parts.append(f"Subdomains: {len(self.subdomains)}")
        if self.ports:
            parts.append(f"Open ports: {len(self.ports)}")
        if self.tech_stack:
            parts.append(f"Tech: {', '.join(f'{k}={v}' if v else k for k, v in list(self.tech_stack.items())[:8])}")
        if self.credentials:
            parts.append(f"Credentials: {len(self.credentials)}")
        if self.endpoints:
            parts.append(f"Endpoints: {len(self.endpoints)}")
        if self.attack_paths:
            n_attempted = sum(1 for a in self.attack_paths if a["attempted"])
            parts.append(f"Attack paths: {len(self.attack_paths)} ({n_attempted} attempted)")
        if self.findings:
            sev: Dict[str, int] = {}
            for f in self.findings:
                s = f.severity if isinstance(f, Finding) else f.get("severity", "info")
                sev[s] = sev.get(s, 0) + 1
            parts.append(f"Findings: {', '.join(f'{k.upper()}:{v}' for k, v in sorted(sev.items()))}")
        return " | ".join(parts)

    def to_dict(self) -> dict:
        """Serialize recon state so it survives crashes/restarts (findings persist via Session)."""
        return {
            "hostname": self.hostname, "ip_addresses": self.ip_addresses, "ports": self.ports,
            "os_info": self.os_info, "subdomains": sorted(self.subdomains), "endpoints": self.endpoints,
            "credentials": self.credentials, "tech_stack": self.tech_stack,
            "attack_paths": self.attack_paths, "notes": self.notes,
        }

    def load_dict(self, d: dict):
        self.ip_addresses = d.get("ip_addresses", []); self.ports = d.get("ports", [])
        self.os_info = d.get("os_info", ""); self.subdomains = set(d.get("subdomains", []))
        self.endpoints = d.get("endpoints", []); self.credentials = d.get("credentials", [])
        self.tech_stack = d.get("tech_stack", {}); self.attack_paths = d.get("attack_paths", [])
        self.notes = d.get("notes", [])
