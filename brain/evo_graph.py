"""
EvoGraph — Persistent Evolutionary Knowledge Graph (RedAMon EvoGraph + PentAGI Graphiti pattern).

File-backed hybrid that mimics Neo4j's 17-node/20-rel model without requiring Neo4j.
Temporal revisioning (Graphiti): every mutation is versioned, queryable by revision.
Cross-session persistence: stored as JSON + SQLite fallback in x19_workspace/evo_graph/.

RedAMon node types (17) aliased:
 host, domain, subdomain, ip, service, endpoint, parameter, technology,
 credential, user, vulnerability, finding, hypothesis, experiment, evidence,
 repository, cloud_resource

Edges (20 core):
 HOST_HAS_SERVICE, SERVICE_SERVES_ENDPOINT, ENDPOINT_HAS_PARAMETER, ENDPOINT_EXPOSES,
 ENDPOINT_VULNERABLE_TO, SERVICE_AFFECTED_BY, TECHNOLOGY_AFFECTED_BY,
 CREDENTIAL_AUTHENTICATES_TO, VULNERABILITY_REQUIRES, VULNERABILITY_ENABLES,
 FINDING_CONFIRMS, FINDING_REJECTS, HYPOTHESIS_TESTS, EXPERIMENT_PRODUCES_EVIDENCE,
 plus legacy access/auth/depends/exploits/owns/contains/runs/vulnerable_to + domain aliases.

No external dep needed. If neo4j driver is present, can sync (optional).
"""

from __future__ import annotations

import json
import hashlib
import sqlite3
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

# Re-export canonical node/edge constants from attack_graph for compatibility
try:
    from brain.attack_graph import (
        ALL_NODE_TYPES, ALL_EDGE_TYPES,
        NODE_HOST, NODE_SERVICE, NODE_ENDPOINT, NODE_VULNERABILITY,
        NODE_FUNDING, NODE_CREDENTIAL, NODE_TECHNOLOGY, NODE_PARAMETER,
        NODE_HYPOTHESIS, NODE_EXPERIMENT, NODE_EVIDENCE, NODE_USER, NODE_REPOSITORY,
    )
except Exception:
    ALL_NODE_TYPES = frozenset({"host","service","endpoint","vulnerability","finding","credential","technology","parameter","hypothesis","experiment","evidence","user","repository","domain","subdomain","ip","cloud_resource"})
    ALL_EDGE_TYPES = frozenset({"HOST_HAS_SERVICE","SERVICE_SERVES_ENDPOINT","ENDPOINT_HAS_PARAMETER","ENDPOINT_EXPOSES","ENDPOINT_VULNERABLE_TO","SERVICE_AFFECTED_BY","TECHNOLOGY_AFFECTED_BY","CREDENTIAL_AUTHENTICATES_TO","VULNERABILITY_REQUIRES","VULNERABILITY_ENABLES","FINDING_CONFIRMS","FINDING_REJECTS","HYPOTHESIS_TESTS","EXPERIMENT_PRODUCES_EVIDENCE"})

# RedAMon 17 types mapping (superset)
REDAMON_NODE_TYPES = frozenset({
    "host","domain","subdomain","ip","service","endpoint","parameter","technology",
    "credential","user","vulnerability","finding","hypothesis","experiment","evidence",
    "repository","cloud_resource",
})

@dataclass
class EvoNode:
    id: str
    type: str
    attrs: Dict[str, Any] = field(default_factory=dict)
    state: str = "observed"
    revision: int = 0
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)

@dataclass
class EvoEdge:
    src: str
    dst: str
    kind: str
    attrs: Dict[str, Any] = field(default_factory=dict)
    revision: int = 0
    created_at: str = field(default_factory=_utc_now)

class EvoGraph:
    """
    Persistent, temporal, cross-session graph.
    
    Storage: x19_workspace/evo_graph/<target_slug>.json  (primary)
             x19_workspace/evo_graph.db SQLite (index)
    Each mutation bumps `revision` and appends to `history`.
    """

    def __init__(self, target: str = "default", workspace: Optional[Path] = None):
        self.target = target or "default"
        self.slug = hashlib.sha256(self.target.encode()).hexdigest()[:12]
        base = Path(workspace) if workspace else Path("x19_workspace") / "evo_graph"
        base.mkdir(parents=True, exist_ok=True)
        self.file_path = base / f"{self.slug}.json"
        self.db_path = base.parent / "evo_graph.db" if base.name != "evo_graph.db" else base
        # fallback if base is evo_graph dir
        if self.file_path.parent.name == "evo_graph":
            self.db_path = self.file_path.parent.parent / "evo_graph.db"
        else:
            self.db_path = Path("x19_workspace") / "evo_graph.db"
        self.nodes: Dict[str, EvoNode] = {}
        self.edges: List[EvoEdge] = []
        self.history: List[Dict[str, Any]] = []
        self.revision: int = 0
        self._load()

    # -- persistence --
    def _load(self):
        if self.file_path.exists():
            try:
                data = json.loads(self.file_path.read_text())
                self.revision = data.get("revision", 0)
                for nid, nd in data.get("nodes", {}).items():
                    self.nodes[nid] = EvoNode(**nd)
                for ed in data.get("edges", []):
                    self.edges.append(EvoEdge(**ed))
                self.history = data.get("history", [])
            except Exception:
                pass
        # ensure db exists (optional index)
        try:
            self._ensure_db()
        except Exception:
            pass

    def _ensure_db(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(str(self.db_path))
        con.execute("CREATE TABLE IF NOT EXISTS evo_nodes (target TEXT, node_id TEXT, type TEXT, attrs TEXT, revision INT, PRIMARY KEY(target, node_id))")
        con.execute("CREATE TABLE IF NOT EXISTS evo_edges (target TEXT, src TEXT, dst TEXT, kind TEXT, attrs TEXT, revision INT)")
        con.commit()
        con.close()

    def persist(self):
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "target": self.target,
            "revision": self.revision,
            "nodes": {nid: asdict(n) for nid, n in self.nodes.items()},
            "edges": [asdict(e) for e in self.edges],
            "history": self.history[-200:],  # keep last 200 mutations
            "updated_at": _utc_now(),
        }
        self.file_path.write_text(json.dumps(payload, indent=2))
        try:
            con = sqlite3.connect(str(self.db_path))
            for nid, node in self.nodes.items():
                con.execute("INSERT OR REPLACE INTO evo_nodes VALUES (?,?,?,?,?)",
                            (self.target, nid, node.type, json.dumps(node.attrs), node.revision))
            # edges: append only newest
            if self.edges:
                e = self.edges[-1]
                con.execute("INSERT INTO evo_edges VALUES (?,?,?,?,?,?)",
                            (self.target, e.src, e.dst, e.kind, json.dumps(e.attrs), e.revision))
            con.commit()
            con.close()
        except Exception:
            pass

    # -- mutations --
    def add_node(self, node_id: str, node_type: str, attrs: Optional[Dict[str, Any]] = None, state: str = "observed") -> EvoNode:
        attrs = attrs or {}
        self.revision += 1
        if node_id in self.nodes:
            n = self.nodes[node_id]
            n.attrs.update(attrs)
            n.state = state
            n.revision = self.revision
            n.updated_at = _utc_now()
        else:
            n = EvoNode(id=node_id, type=node_type, attrs=dict(attrs), state=state, revision=self.revision)
            self.nodes[node_id] = n
        self.history.append({"op": "add_node", "id": node_id, "type": node_type, "rev": self.revision, "ts": _utc_now()})
        return n

    def add_edge(self, src: str, dst: str, kind: str, attrs: Optional[Dict[str, Any]] = None) -> EvoEdge:
        self.revision += 1
        e = EvoEdge(src=src, dst=dst, kind=kind, attrs=dict(attrs or {}), revision=self.revision)
        self.edges.append(e)
        self.history.append({"op": "add_edge", "src": src, "dst": dst, "kind": kind, "rev": self.revision, "ts": _utc_now()})
        return e

    def evolve(self, note: str = ""):
        """Explicit temporal checkpoint (Graphiti pattern) — bumps revision without mutation."""
        self.revision += 1
        self.history.append({"op": "evolve", "note": note, "rev": self.revision, "ts": _utc_now()})
        self.persist()

    # -- queries (Cypher-like minimal) --
    def query(self, cypher_like: str = "", node_type: str = "", edge_kind: str = "") -> Dict[str, List[Any]]:
        """
        Minimal Cypher-like query. Supports:
          query(node_type="host") -> hosts
          query(edge_kind="HOST_HAS_SERVICE")
          query("MATCH (h:host)-[r:HOST_HAS_SERVICE]->(s:service) RETURN h,s")
        Fallback is filter by type/kind.
        """
        # try to parse MATCH syntax for compat
        nt = node_type
        ek = edge_kind
        if cypher_like and "MATCH" in cypher_like:
            # very small parser
            import re
            m = re.search(r"\(\w+:(\w+)\)", cypher_like)
            if m and not nt:
                nt = m.group(1).lower()
            m2 = re.search(r"\[\w*:(\w+)\]", cypher_like)
            if m2 and not ek:
                ek = m2.group(1)
        nodes = [n for n in self.nodes.values() if not nt or n.type.lower() == nt.lower() or (nt == "finding" and n.type == "finding")]
        edges = [e for e in self.edges if not ek or e.kind == ek]
        return {"nodes": nodes, "edges": edges}

    def get_node(self, node_id: str) -> Optional[EvoNode]:
        return self.nodes.get(node_id)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "revision": self.revision,
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "types": {t: sum(1 for n in self.nodes.values() if n.type == t) for t in set(n.type for n in self.nodes.values())},
        }

    # -- integration helpers --
    def ingest_world_model(self, world_model: Any):
        """Ingest X19 WorldModel snapshot into EvoGraph (cross-session evolve)."""
        try:
            target = getattr(world_model, "target", self.target)
            if target and target != self.target:
                self.target = target
            for host_key, host in getattr(world_model, "hosts", {}).items():
                hid = f"host:{host_key}"
                self.add_node(hid, "host", {"hostname": getattr(host, "hostname", host_key), "ip_addresses": getattr(host, "ip_addresses", [])})
                for svc_key, svc in getattr(host, "services", {}).items():
                    sid = f"service:{host_key}:{svc_key}"
                    self.add_node(sid, "service", {"port": getattr(svc, "port", 0), "service": getattr(svc, "service", ""), "version": getattr(svc, "version", "")})
                    self.add_edge(hid, sid, "HOST_HAS_SERVICE")
                    for ep_key, ep in getattr(host, "endpoints", {}).items():
                        eid = f"endpoint:{host_key}:{ep_key}"
                        self.add_node(eid, "endpoint", {"url": getattr(ep, "url", ep_key), "method": getattr(ep, "method", "GET"), "status": getattr(ep, "status", 0)})
                        self.add_edge(sid, eid, "SERVICE_SERVES_ENDPOINT")
                for vuln in getattr(host, "vulnerabilities", []):
                    vid = f"vuln:{host_key}:{getattr(vuln, 'title', 'vuln')}"
                    self.add_node(vid, "vulnerability", {"title": getattr(vuln, "title", ""), "severity": getattr(vuln, "severity", "info")})
                    self.add_edge(hid, vid, "SERVICE_AFFECTED_BY")
            self.evolve("ingest world_model")
        except Exception:
            pass

    def to_attack_graph_dict(self) -> Dict[str, Any]:
        """Export in attack_graph-compatible dict for X19 adapters."""
        return {
            "nodes": [{"id": n.id, "type": n.type, "state": n.state, "attrs": n.attrs} for n in self.nodes.values()],
            "edges": [{"src": e.src, "dst": e.dst, "kind": e.kind, "attrs": e.attrs} for e in self.edges],
            "revision": self.revision,
        }
