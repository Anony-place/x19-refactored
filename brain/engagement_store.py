"""
EngagementStore — Persistent Hosts/Services/Vulns/Creds/Access graph (PentestCode HPTSA pattern).

Mirrors PentestCode's SQLite EngagementStore:
 - 4 entities + access: host, service, endpoint, vulnerability, credential, access
 - relationships: HostHasService, ServiceServesEndpoint, EndpointVulnerableTo, CredentialAuthenticatesTo, AccessRequires, VulnerabilityEnables
 - `state_update` / `state_query` mandatory parser tools (like PentestCode's 18 parsers)
 - persistent per-target SQLite (x19_workspace/engagement/<slug>.db)
 - attack path suggester (cost = risk × depth, cheapest high-impact chain)

Diff vs PentestCode: X19 also links to WorldModel + EvoGraph, so this store is a
view, not a fork. No TS/Bun required; pure Python SQLite.

Usage:
  store = EngagementStore(target="example.com")
  store.state_update("add_host", {"hostname":"example.com","ip":"93.184.216.34"})
  store.state_update("add_service", {"host":"example.com","port":443,"service":"https"})
  paths = store.suggest_attack_paths(limit=3)
  store.state_query("hosts") -> [...]
"""

from __future__ import annotations

import json
import hashlib
import sqlite3
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")

def _slug(target: str) -> str:
    return hashlib.sha256((target or "default").encode()).hexdigest()[:12]

class EngagementStore:
    def __init__(self, target: str = "default", workspace: Optional[Path] = None):
        self.target = target or "default"
        self.slug = _slug(self.target)
        base = Path(workspace) if workspace else Path("x19_workspace") / "engagement"
        base.mkdir(parents=True, exist_ok=True)
        self.db_path = base / f"{self.slug}.db"
        self._init_db()

    def _init_db(self):
        con = sqlite3.connect(str(self.db_path))
        con.execute("CREATE TABLE IF NOT EXISTS hosts (id TEXT PRIMARY KEY, hostname TEXT, ip TEXT, os_info TEXT, attrs TEXT, updated_at TEXT)")
        con.execute("CREATE TABLE IF NOT EXISTS services (id TEXT PRIMARY KEY, host_id TEXT, port INT, proto TEXT, service TEXT, version TEXT, state TEXT, attrs TEXT)")
        con.execute("CREATE TABLE IF NOT EXISTS endpoints (id TEXT PRIMARY KEY, service_id TEXT, url TEXT, method TEXT, status INT, params TEXT, tech TEXT, attrs TEXT)")
        con.execute("CREATE TABLE IF NOT EXISTS credentials (id TEXT PRIMARY KEY, service TEXT, username TEXT, secret_ref TEXT, source TEXT, confidence REAL, attrs TEXT)")
        con.execute("CREATE TABLE IF NOT EXISTS vulnerabilities (id TEXT PRIMARY KEY, title TEXT, severity TEXT, endpoint TEXT, description TEXT, evidence TEXT, confidence REAL, attrs TEXT)")
        con.execute("CREATE TABLE IF NOT EXISTS access (id TEXT PRIMARY KEY, credential_id TEXT, host_id TEXT, service_id TEXT, via TEXT, attrs TEXT)")
        con.execute("CREATE TABLE IF NOT EXISTS edges (src TEXT, dst TEXT, kind TEXT, attrs TEXT)")
        con.commit()
        con.close()

    # -- state_update (PentestCode mandatory tool) --
    def state_update(self, op: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Canonical mutator. Ops:
          add_host {hostname, ip, os_info}
          add_service {host, port, proto?, service, version?}
          add_endpoint {host, port, url, method?, status?, params?, tech?}
          add_credential {service, username, secret_ref?, source?}
          add_vulnerability {title, severity, endpoint?, evidence?}
          add_access {credential_id, host_id, via?}
        Returns {"ok":bool, "id":str}
        """
        con = sqlite3.connect(str(self.db_path))
        op = op.lower()
        try:
            if op == "add_host":
                hid = data.get("id") or f"host:{data.get('hostname', data.get('ip','unknown'))}"
                con.execute("INSERT OR REPLACE INTO hosts VALUES (?,?,?,?,?,?)",
                            (hid, data.get("hostname",""), data.get("ip",""), data.get("os_info",""), json.dumps(data), _utc_now()))
                con.commit()
                return {"ok": True, "id": hid}
            elif op == "add_service":
                host_id = data.get("host_id") or f"host:{data.get('host','unknown')}"
                port = int(data.get("port",0))
                sid = data.get("id") or f"service:{host_id}:{port}"
                con.execute("INSERT OR REPLACE INTO services VALUES (?,?,?,?,?,?,?,?)",
                            (sid, host_id, port, data.get("proto","tcp"), data.get("service",""), data.get("version",""), data.get("state","open"), json.dumps(data)))
                con.execute("INSERT OR IGNORE INTO edges VALUES (?,?,?,?)", (host_id, sid, "HOST_HAS_SERVICE", "{}"))
                con.commit()
                return {"ok": True, "id": sid}
            elif op == "add_endpoint":
                host_id = data.get("host_id") or f"host:{data.get('host','unknown')}"
                port = int(data.get("port", 80))
                sid = data.get("service_id") or f"service:{host_id}:{port}"
                url = data.get("url","")
                eid = data.get("id") or f"endpoint:{sid}:{hashlib.sha256(url.encode()).hexdigest()[:8]}"
                con.execute("INSERT OR REPLACE INTO endpoints VALUES (?,?,?,?,?,?,?,?)",
                            (eid, sid, url, data.get("method","GET"), int(data.get("status",0)), data.get("params",""), data.get("tech",""), json.dumps(data)))
                con.execute("INSERT OR IGNORE INTO edges VALUES (?,?,?,?)", (sid, eid, "SERVICE_SERVES_ENDPOINT", "{}"))
                con.commit()
                return {"ok": True, "id": eid}
            elif op == "add_credential":
                cid = data.get("id") or f"cred:{data.get('service','')}:{data.get('username','')}"
                con.execute("INSERT OR REPLACE INTO credentials VALUES (?,?,?,?,?,?,?)",
                            (cid, data.get("service",""), data.get("username",""), data.get("secret_ref",""), data.get("source",""), float(data.get("confidence",0.5)), json.dumps(data)))
                con.commit()
                return {"ok": True, "id": cid}
            elif op == "add_vulnerability":
                vid = data.get("id") or f"vuln:{hashlib.sha256(data.get('title','').encode()).hexdigest()[:10]}"
                con.execute("INSERT OR REPLACE INTO vulnerabilities VALUES (?,?,?,?,?,?,?,?)",
                            (vid, data.get("title",""), data.get("severity","medium"), data.get("endpoint",""), data.get("description",""), data.get("evidence",""), float(data.get("confidence",0.5)), json.dumps(data)))
                # link endpoint→vuln if endpoint supplied
                if data.get("endpoint"):
                    # best-effort edge
                    con.execute("INSERT INTO edges VALUES (?,?,?,?)", (data.get("endpoint"), vid, "ENDPOINT_VULNERABLE_TO", "{}"))
                con.commit()
                return {"ok": True, "id": vid}
            elif op == "add_access":
                aid = data.get("id") or f"access:{hashlib.sha256(str(data).encode()).hexdigest()[:10]}"
                con.execute("INSERT OR REPLACE INTO access VALUES (?,?,?,?,?,?)",
                            (aid, data.get("credential_id",""), data.get("host_id",""), data.get("service_id",""), data.get("via",""), json.dumps(data)))
                con.commit()
                return {"ok": True, "id": aid}
            else:
                return {"ok": False, "error": f"unknown op {op}"}
        finally:
            con.close()

    # -- state_query --
    def state_query(self, entity: str = "hosts", where: Optional[Dict[str, Any]] = None, limit: int = 100) -> List[Dict[str, Any]]:
        entity = entity.lower()
        table_map = {"hosts":"hosts","host":"hosts","services":"services","service":"services","endpoints":"endpoints","endpoint":"endpoints","credentials":"credentials","credential":"credentials","vulnerabilities":"vulnerabilities","vuln":"vulnerabilities","access":"access"}
        table = table_map.get(entity, "hosts")
        con = sqlite3.connect(str(self.db_path))
        con.row_factory = sqlite3.Row
        q = f"SELECT * FROM {table} LIMIT ?"
        params: List[Any] = [limit]
        if where:
            # very minimal where support
            clauses = " AND ".join(f"{k}=?" for k in where.keys())
            q = f"SELECT * FROM {table} WHERE {clauses} LIMIT ?"
            params = list(where.values()) + [limit]
        rows = con.execute(q, params).fetchall()
        con.close()
        return [dict(r) for r in rows]

    def snapshot(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "hosts": len(self.state_query("hosts", limit=1000)),
            "services": len(self.state_query("services", limit=1000)),
            "endpoints": len(self.state_query("endpoints", limit=1000)),
            "vulns": len(self.state_query("vulnerabilities", limit=1000)),
            "creds": len(self.state_query("credentials", limit=1000)),
            "access": len(self.state_query("access", limit=1000)),
        }

    def suggest_attack_paths(self, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Cost-based attack path suggester. Cost = risk(weight) × depth.
        Groups low-cost High/Critical vulns that share endpoints/hosts.
        """
        sev_weight = {"critical": 0.1, "high": 0.3, "medium": 0.6, "low": 0.85, "info": 1.0}
        vulns = self.state_query("vulnerabilities", limit=200)
        if not vulns:
            return []
        # score each
        scored = []
        for v in vulns:
            sev = (v.get("severity") or "medium").lower()
            w = sev_weight.get(sev, 0.6)
            # depth proxy: endpoint present => shorter chain (lower depth)
            depth = 1 if v.get("endpoint") else 2
            cost = w * depth
            scored.append((cost, v))
        scored.sort(key=lambda x: x[0])
        paths: List[Dict[str, Any]] = []
        for cost, v in scored[:limit]:
            # try to enrich with host
            paths.append({
                "cost": round(cost, 3),
                "title": v.get("title",""),
                "severity": v.get("severity",""),
                "endpoint": v.get("endpoint",""),
                "impact": "direct" if cost < 0.4 else "lateral",
                "steps": [{"role": "exploit", "title": v.get("title",""), "endpoint": v.get("endpoint","")}],
            })
        return paths

    def export_json(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "snapshot": self.snapshot(),
            "hosts": self.state_query("hosts"),
            "services": self.state_query("services"),
            "endpoints": self.state_query("endpoints"),
            "vulnerabilities": self.state_query("vulnerabilities"),
            "credentials": self.state_query("credentials"),
            "attack_paths": self.suggest_attack_paths(),
        }
