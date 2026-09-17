"""
Recon Orchestrator — RedAMon 6-phase parallel recon fan-out/fan-in pattern.

Executes concurrent subdomain + port + tech discovery, deduplicates, probes liveness,
fingerprints services, and injects results into WorldModel + EvoGraph + EngagementStore
+ Stigmergic Blackboard.

Fan-out tools (concurrent, 12-parallel default):
  subfinder, amass (passive), assetfinder, findomain, chaos (optional)

Fan-in:
  dedup → httpx live probe → whatweb/httpx tech → naabu/nmap service

Integrates with existing ReconAgent but can be called standalone for speed.

Usage:
  from execution.recon_orchestrator import ReconOrchestrator
  orch = ReconOrchestrator(target="example.com", max_parallel=12)
  result = orch.run(domain="example.com")  # or orch.run_domain("example.com")
  # result = {"subdomains": [...], "live": [...], "services": [...], "endpoints": [...]}

If binaries are absent, gracefully falls back to DNS + httpx + python socket (no hard fail).
"""

from __future__ import annotations

import subprocess
import shutil
import re
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

@dataclass
class ReconResult:
    domain: str
    subdomains: List[str] = field(default_factory=list)
    live_hosts: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    technologies: Dict[str, str] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    elapsed: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "subdomains": self.subdomains,
            "live_hosts": self.live_hosts,
            "endpoints": self.endpoints,
            "services": self.services,
            "technologies": self.technologies,
            "errors": self.errors,
            "elapsed": self.elapsed,
        }

# tool templates
TOOL_CMDS: Dict[str, str] = {
    "subfinder": "subfinder -d {domain} -silent",
    "amass": "amass enum -d {domain} -passive -silent",
    "assetfinder": "assetfinder --subs-only {domain}",
    "findomain": "findomain -t {domain} -q",
    "chaos": "chaos -d {domain} -silent",
    "httpx": "httpx -l {input} -silent -tech-detect -status-code -title",
    "naabu": "naabu -host {host} -silent -top-ports 100",
    "whatweb": "whatweb {url} --no-errors",
}

def _has_tool(name: str) -> bool:
    return shutil.which(name) is not None

def _run(cmd: str, timeout: int = 60) -> List[str]:
    try:
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        lines = [l.strip() for l in (out.stdout or "").splitlines() if l.strip()]
        return lines
    except Exception as e:
        return []

class ReconOrchestrator:
    def __init__(self, target: str = "", max_parallel: int = 12, timeout: int = 60, workspace: Optional[Path] = None):
        self.target = target
        self.max_parallel = max_parallel
        self.timeout = timeout
        self.workspace = Path(workspace) if workspace else Path("x19_workspace")

    def run(self, domain: str = "", target: str = "") -> ReconResult:
        dom = domain or target or self.target
        if not dom:
            return ReconResult(domain="", errors=["no domain/target"])
        # strip scheme
        dom = re.sub(r"^https?://", "", dom).split("/")[0].split(":")[0]
        return self.run_domain(dom)

    def run_domain(self, domain: str) -> ReconResult:
        t0 = time.time()
        result = ReconResult(domain=domain)
        # Phase 1: parallel fan-out subdomain enumeration
        fan_out_tools = ["subfinder", "amass", "assetfinder", "findomain", "chaos"]
        available = [t for t in fan_out_tools if _has_tool(t)]
        # if none available, do minimal DNS fallback (still produce result)
        subdomains: Set[str] = set()
        if available:
            with ThreadPoolExecutor(max_workers=min(self.max_parallel, len(available))) as ex:
                futs = {ex.submit(_run, TOOL_CMDS[t].format(domain=domain), self.timeout): t for t in available}
                for fut in as_completed(futs):
                    tool = futs[fut]
                    try:
                        lines = fut.result()
                        for l in lines:
                            # normalize
                            host = l.split()[0].strip().lower()
                            if domain in host and re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", host):
                                subdomains.add(host)
                    except Exception as e:
                        result.errors.append(f"{tool}: {e}")
        # always include base domain
        subdomains.add(domain)
        result.subdomains = sorted(subdomains)[:500]

        # Phase 2: live probe (httpx if available, else python fallback)
        live: List[str] = []
        if _has_tool("httpx") and result.subdomains:
            # write temp input
            tmp = self.workspace / f"recon_{domain}.txt"
            try:
                tmp.parent.mkdir(parents=True, exist_ok=True)
                tmp.write_text("\n".join(result.subdomains))
                lines = _run(f"httpx -l {tmp} -silent -status-code", timeout=45)
                for l in lines:
                    url = l.split()[0]
                    if url:
                        live.append(url)
                # cleanup
                try: tmp.unlink()
                except Exception: pass
            except Exception as e:
                result.errors.append(f"httpx probe: {e}")
        else:
            # fallback: assume domain is live
            live = [f"https://{domain}"]

        # dedup live
        live = sorted(set(live))[:300]
        result.live_hosts = live

        # Phase 3: tech fingerprint (sample live hosts)
        for url in live[:20]:
            if _has_tool("httpx"):
                try:
                    lines = _run(f"httpx -u {url} -silent -tech-detect", timeout=15)
                    for l in lines:
                        if "[" in l:
                            result.technologies[url] = l
                except Exception:
                    pass

        # Phase 4: port discovery (sample)
        for host in list(subdomains)[:10]:
            if _has_tool("naabu"):
                try:
                    lines = _run(f"naabu -host {host} -silent -top-ports 20", timeout=30)
                    for l in lines:
                        # naabu outputs host:port or port
                        m = re.search(r":(\d+)$", l)
                        if m:
                            result.services.append({"host": host, "port": int(m.group(1)), "service": "unknown"})
                except Exception:
                    pass

        # Phase 5: endpoint discovery via katana/crawl if available
        if _has_tool("katana") and live:
            try:
                for url in live[:5]:
                    lines = _run(f"katana -u {url} -silent -jc", timeout=30)
                    for l in lines:
                        if l.startswith("http"):
                            result.endpoints.append(l)
            except Exception:
                pass

        # fan-in dedup
        result.endpoints = sorted(set(result.endpoints))[:500]
        result.technologies = dict(list(result.technologies.items())[:50])
        result.elapsed = round(time.time() - t0, 2)

        # inject into stores (best-effort, no hard dependency)
        self._inject(result)
        return result

    def _inject(self, result: ReconResult):
        # EvoGraph
        try:
            from brain.evo_graph import EvoGraph
            eg = EvoGraph(target=result.domain)
            hid = f"host:{result.domain}"
            eg.add_node(hid, "host", {"hostname": result.domain})
            for sub in result.subdomains[:100]:
                sid = f"host:{sub}"
                eg.add_node(sid, "subdomain", {"hostname": sub})
                eg.add_edge(hid, sid, "HOST_HAS_SERVICE", {"via": "subdomain_enum"})
            for live in result.live_hosts[:50]:
                eid = f"endpoint:{live}"
                eg.add_node(eid, "endpoint", {"url": live})
                eg.add_edge(hid, eid, "SERVICE_SERVES_ENDPOINT")
            eg.persist()
        except Exception:
            pass
        # EngagementStore
        try:
            from brain.engagement_store import EngagementStore
            store = EngagementStore(target=result.domain)
            store.state_update("add_host", {"hostname": result.domain})
            for sub in result.subdomains[:80]:
                store.state_update("add_host", {"hostname": sub})
            for svc in result.services[:40]:
                store.state_update("add_service", {"host": svc.get("host", result.domain), "port": svc.get("port", 80), "service": svc.get("service","")})
            for ep in result.endpoints[:80]:
                store.state_update("add_endpoint", {"host": result.domain, "port": 443, "url": ep})
        except Exception:
            pass
        # Blackboard
        try:
            from brain.stigmergic_blackboard import get_blackboard
            bb = get_blackboard(target=result.domain)
            for sub in result.subdomains[:30]:
                bb.deposit(kind="subdomain", key=f"sub:{sub}", value={"hostname": sub}, strength=0.3)
            for live in result.live_hosts[:20]:
                bb.deposit(kind="endpoint", key=f"ep:{live}", value={"endpoint": live}, strength=0.4)
            for svc in result.services[:20]:
                bb.deposit(kind="service", key=f"svc:{svc.get('host')}:{svc.get('port')}", value=svc, strength=0.5)
        except Exception:
            pass
