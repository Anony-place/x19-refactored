"""
Stigmergic Blackboard — Pentest-Swarm-AI true swarm pattern.

Blackboard with pheromone decay vs pipeline dispatch.

Concepts from Armur-Ai/Pentest-Swarm-AI:
 - stigmergic: agents don't call each other; they read/write a shared blackboard
 - pheromone: finding kinds deposit strength that decays exponentially (τ configurable)
 - predicates: reactor agents wake when `pheromone[kind] > threshold` AND blackboard has fields they need
 - emergence: chains form via mutual reinforcement, not orchestrator sequence

X19 retains deterministic coordinator as well — this module is an optional parallel
layer that the coordinator consults for emergent dispatch.

Storage: in-memory + optional SQLite persistence (x19_workspace/blackboard.db) for
cross-run pheromone memory (like pgvector+pheromone hybrid but lightweight).

Usage:
  bb = get_blackboard(target="example.com")
  bb.deposit(kind="sqli", endpoint="/search?q=1", strength=1.0, evidence="order by 4 --")
  bb.decay()  # called per-loop or on timer
  woke = bb.predicates_to_wake()  # -> ["vuln_agent:sqli", "web_agent:crawl"]
  chain = bb.emergent_chains()    # -> inferred chains from co-occurring pheromones
"""

from __future__ import annotations

import json
import math
import sqlite3
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Set

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")

DEFAULT_DECAY_TAU = 3600.0  # seconds to decay to e^-1
DEFAULT_DB = Path("x19_workspace") / "blackboard.db"

@dataclass
class BlackboardField:
    kind: str  # recon|vuln|exploit|creds|endpoint|technology
    key: str   # endpoint or finding id
    value: Dict[str, Any]
    pheromone: float = 1.0
    last_update: float = field(default_factory=time.time)
    deposits: int = 1

@dataclass
class PheromoneRecord:
    kind: str
    strength: float
    last_bump: float
    deposits: int = 1

# Predicate registry: kind -> (required_fields, wake_agent)
PREDICATES: Dict[str, Dict[str, Any]] = {
    "sqli": {"fields": {"endpoint"}, "wake": "vuln_agent", "threshold": 0.6},
    "xss": {"fields": {"endpoint"}, "wake": "web_agent", "threshold": 0.5},
    "ssrf": {"fields": {"endpoint"}, "wake": "vuln_agent", "threshold": 0.6},
    "creds": {"fields": {"credential"}, "wake": "recon_agent", "threshold": 0.4},
    "service": {"fields": {"host"}, "wake": "recon_agent", "threshold": 0.3},
    "technology": {"fields": {"endpoint"}, "wake": "web_agent", "threshold": 0.35},
}

class StigmergicBlackboard:
    def __init__(self, target: str = "default", db_path: Optional[Path] = None, decay_tau: float = DEFAULT_DECAY_TAU):
        self.target = target or "default"
        self.decay_tau = decay_tau
        self.db_path = Path(db_path) if db_path else DEFAULT_DB
        self.fields: Dict[str, BlackboardField] = {}  # key -> field
        self.pheromones: Dict[str, PheromoneRecord] = {}
        self._load()

    def _load(self):
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            con = sqlite3.connect(str(self.db_path))
            con.execute("CREATE TABLE IF NOT EXISTS blackboard (target TEXT, key TEXT, kind TEXT, value TEXT, pheromone REAL, last_update REAL, PRIMARY KEY(target,key))")
            con.execute("CREATE TABLE IF NOT EXISTS pheromones (target TEXT, kind TEXT, strength REAL, last_bump REAL, deposits INT, PRIMARY KEY(target,kind))")
            cur = con.execute("SELECT key, kind, value, pheromone, last_update FROM blackboard WHERE target=?", (self.target,))
            for key, kind, value, pher, ts in cur.fetchall():
                try:
                    val = json.loads(value)
                except Exception:
                    val = {}
                self.fields[key] = BlackboardField(kind=kind, key=key, value=val, pheromone=pher, last_update=ts, deposits=1)
            cur2 = con.execute("SELECT kind, strength, last_bump, deposits FROM pheromones WHERE target=?", (self.target,))
            for kind, strength, bump, dep in cur2.fetchall():
                self.pheromones[kind] = PheromoneRecord(kind=kind, strength=strength, last_bump=bump, deposits=dep)
            con.close()
        except Exception:
            pass

    def _persist(self):
        try:
            con = sqlite3.connect(str(self.db_path))
            for key, f in self.fields.items():
                con.execute("INSERT OR REPLACE INTO blackboard VALUES (?,?,?,?,?,?)",
                            (self.target, key, f.kind, json.dumps(f.value), f.pheromone, f.last_update))
            for kind, p in self.pheromones.items():
                con.execute("INSERT OR REPLACE INTO pheromones VALUES (?,?,?,?,?)",
                            (self.target, kind, p.strength, p.last_bump, p.deposits))
            con.commit()
            con.close()
        except Exception:
            pass

    def deposit(self, kind: str, key: str = "", value: Optional[Dict[str, Any]] = None, strength: float = 1.0, evidence: str = "", endpoint: str = "") -> BlackboardField:
        """
        Deposit finding/observation onto blackboard. Kind is normalized (e.g., 'sqli', 'xss', 'creds', 'endpoint').
        Pheromone for kind is bumped.
        """
        kind = kind.lower().strip() or "generic"
        field_key = key or f"{kind}:{endpoint or evidence[:30] or str(time.time())}"
        val = dict(value or {})
        if endpoint: val["endpoint"] = endpoint
        if evidence: val["evidence"] = evidence[:1000]
        val["kind"] = kind

        now = time.time()
        if field_key in self.fields:
            bf = self.fields[field_key]
            bf.value.update(val)
            bf.pheromone = min(5.0, bf.pheromone + strength * 0.6)
            bf.last_update = now
            bf.deposits += 1
        else:
            bf = BlackboardField(kind=kind, key=field_key, value=val, pheromone=strength, last_update=now, deposits=1)
            self.fields[field_key] = bf

        # pheromone bump
        if kind in self.pheromones:
            p = self.pheromones[kind]
            # decay before bump
            elapsed = now - p.last_bump
            decayed = p.strength * math.exp(-elapsed / self.decay_tau) if self.decay_tau > 0 else p.strength
            p.strength = min(10.0, decayed + strength)
            p.last_bump = now
            p.deposits += 1
        else:
            self.pheromones[kind] = PheromoneRecord(kind=kind, strength=strength, last_bump=now, deposits=1)

        self._persist()
        return bf

    def decay(self, now: Optional[float] = None):
        """Apply exponential decay to all pheromones/fields."""
        now = now or time.time()
        for p in self.pheromones.values():
            elapsed = now - p.last_bump
            p.strength = p.strength * math.exp(-elapsed / self.decay_tau) if self.decay_tau > 0 else p.strength
            p.last_bump = now
        for f in self.fields.values():
            elapsed = now - f.last_update
            f.pheromone = f.pheromone * math.exp(-elapsed / self.decay_tau) if self.decay_tau > 0 else f.pheromone
        # prune near-zero
        self.fields = {k: v for k, v in self.fields.items() if v.pheromone > 0.02}
        self.pheromones = {k: v for k, v in self.pheromones.items() if v.strength > 0.02}
        self._persist()

    def snapshot(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "fields": len(self.fields),
            "pheromones": {k: round(v.strength, 3) for k, v in self.pheromones.items()},
            "strongest": max(self.pheromones.items(), key=lambda kv: kv[1].strength)[0] if self.pheromones else None,
        }

    def predicates_to_wake(self) -> List[str]:
        """Which reactor predicates are satisfied given current pheromones + fields?"""
        field_kinds = {f.kind for f in self.fields.values()}
        woke: List[str] = []
        for kind, rule in PREDICATES.items():
            p = self.pheromones.get(kind)
            if not p or p.strength < rule["threshold"]:
                continue
            # field requirement
            req = rule["fields"]
            if req and not (req & field_kinds or kind in field_kinds):
                # allow if same kind field exists
                continue
            woke.append(f"{rule['wake']}:{kind}")
        # also emergent: if two vuln pheromones both high, wake chain coordinator
        highs = [k for k, v in self.pheromones.items() if v.strength > 0.7]
        if len(highs) >= 2:
            woke.append(f"coordinator:chain:{'+'.join(sorted(highs)[:3])}")
        return sorted(set(woke))

    def emergent_chains(self) -> List[Dict[str, Any]]:
        """
        Infer emergent chains from co-occurring high pheromones + shared endpoints.
        Returns chain proposals sorted by strength product.
        """
        # group by endpoint
        by_endpoint: Dict[str, List[str]] = {}
        for f in self.fields.values():
            ep = f.value.get("endpoint") or f.key
            by_endpoint.setdefault(ep, []).append(f.kind)
        chains: List[Dict[str, Any]] = []
        for ep, kinds in by_endpoint.items():
            if len(set(kinds)) >= 2:
                strength = sum(self.pheromones.get(k, PheromoneRecord(k,0,time.time())).strength for k in set(kinds))
                chains.append({"endpoint": ep, "kinds": sorted(set(kinds)), "strength": round(strength, 3), "fields": kinds})
        # cross-kind reinforcement even across endpoints
        if len(self.pheromones) >= 2:
            sorted_pher = sorted(self.pheromones.items(), key=lambda kv: kv[1].strength, reverse=True)
            top2 = [k for k,_ in sorted_pher[:2]]
            if len(top2)==2:
                chains.append({"endpoint": "*", "kinds": top2, "strength": round(sum(v.strength for _,v in sorted_pher[:2]),3), "cross_endpoint": True})
        return sorted(chains, key=lambda c: c["strength"], reverse=True)

    def query(self, kind: str = "", limit: int = 50) -> List[BlackboardField]:
        items = list(self.fields.values())
        if kind:
            items = [f for f in items if f.kind == kind.lower()]
        return sorted(items, key=lambda f: f.pheromone, reverse=True)[:limit]

    def clear(self):
        self.fields.clear()
        self.pheromones.clear()
        try:
            con = sqlite3.connect(str(self.db_path))
            con.execute("DELETE FROM blackboard WHERE target=?", (self.target,))
            con.execute("DELETE FROM pheromones WHERE target=?", (self.target,))
            con.commit()
            con.close()
        except Exception:
            pass

# singleton per target
_BOARDS: Dict[str, StigmergicBlackboard] = {}

def get_blackboard(target: str = "default", decay_tau: float = DEFAULT_DECAY_TAU) -> StigmergicBlackboard:
    key = target or "default"
    if key not in _BOARDS:
        _BOARDS[key] = StigmergicBlackboard(target=key, decay_tau=decay_tau)
    return _BOARDS[key]
