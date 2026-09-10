from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class SecurityMemorySnapshot:
    target: str
    facts: List[Dict[str, Any]]
    hypotheses: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]
    dead_ends: List[Dict[str, Any]]
    lessons: List[Dict[str, Any]]
    priorities: List[Dict[str, Any]]
    relations: List[Dict[str, Any]]
    recent_attempts: List[Dict[str, Any]]
    checkpoint: Optional[Dict[str, Any]] = None

    def to_prompt(self, max_chars: int = 12000) -> str:
        if max_chars < len(json.dumps({"target": self.target}, separators=(",", ":"))):
            raise ValueError("max_chars is too small for a valid memory snapshot")
        payload: Dict[str, Any] = {"target": self.target}
        sections = (
            ("facts", self.facts), ("hypotheses", self.hypotheses),
            ("evidence", self.evidence), ("dead_ends", self.dead_ends),
            ("lessons", self.lessons), ("priorities", self.priorities),
            ("relations", self.relations), ("recent_attempts", self.recent_attempts),
        )
        for name, records in sections:
            payload[name] = []
            for record in records:
                candidate = dict(payload)
                candidate[name] = payload[name] + [record]
                if self.checkpoint is not None:
                    candidate["checkpoint"] = self.checkpoint
                if len(json.dumps(candidate, ensure_ascii=False, separators=(",", ":"))) > max_chars:
                    continue
                payload[name].append(record)
        if self.checkpoint is not None:
            candidate = dict(payload)
            candidate["checkpoint"] = self.checkpoint
            if len(json.dumps(candidate, ensure_ascii=False, separators=(",", ":"))) <= max_chars:
                payload["checkpoint"] = self.checkpoint
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


class SecurityMemory:
    """Deterministic, provenance-aware canonical memory for X19 security runs.

    SQLite is authoritative. Every persistent item has origin metadata, an
    authority level and a monotonic revision. Quarantined items are excluded
    from normal retrieval unless explicitly requested.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS memory_items (
                    item_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    item_key TEXT NOT NULL,
                    value_json TEXT NOT NULL,
                    confidence REAL NOT NULL DEFAULT 1.0,
                    status TEXT NOT NULL DEFAULT 'active',
                    source TEXT NOT NULL DEFAULT 'agent',
                    authority INTEGER NOT NULL DEFAULT 1,
                    provenance_json TEXT NOT NULL DEFAULT '{}',
                    revision INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(target, kind, item_key)
                );
                CREATE INDEX IF NOT EXISTS idx_memory_target_kind
                    ON memory_items(target, kind, status, authority);
                CREATE TABLE IF NOT EXISTS memory_events (
                    event_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    item_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    event TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_memory_events_target
                    ON memory_events(target, created_at);
                CREATE TABLE IF NOT EXISTS memory_relations (
                    relation_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    from_id TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    to_id TEXT NOT NULL,
                    confidence REAL NOT NULL DEFAULT 1.0,
                    created_at TEXT NOT NULL,
                    UNIQUE(target, from_id, relation, to_id)
                );
                CREATE INDEX IF NOT EXISTS idx_memory_relations_target
                    ON memory_relations(target, from_id, relation);
                CREATE TABLE IF NOT EXISTS memory_attempts (
                    attempt_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    action_key TEXT NOT NULL,
                    hypothesis_id TEXT,
                    outcome TEXT NOT NULL,
                    status TEXT NOT NULL,
                    failure_level TEXT,
                    evidence_ids_json TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_memory_attempts_target
                    ON memory_attempts(target, created_at);
                CREATE TABLE IF NOT EXISTS memory_checkpoints (
                    target TEXT PRIMARY KEY,
                    state_json TEXT NOT NULL,
                    cursor TEXT,
                    updated_at TEXT NOT NULL
                );
            """)
            self._migrate_columns()
            self._conn.commit()

    def _migrate_columns(self) -> None:
        cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(memory_items)")}
        migrations = {
            "authority": "ALTER TABLE memory_items ADD COLUMN authority INTEGER NOT NULL DEFAULT 1",
            "provenance_json": "ALTER TABLE memory_items ADD COLUMN provenance_json TEXT NOT NULL DEFAULT '{}'",
            "revision": "ALTER TABLE memory_items ADD COLUMN revision INTEGER NOT NULL DEFAULT 1",
        }
        for name, sql in migrations.items():
            if name not in cols:
                self._conn.execute(sql)

    def upsert(self, target: str, kind: str, key: str, value: Dict[str, Any], *,
               confidence: float = 1.0, status: str = "active", source: str = "agent",
               authority: int = 1, provenance: Optional[Dict[str, Any]] = None) -> str:
        if not target or not kind or not key:
            raise ValueError("target, kind and key are required")
        authority = max(0, min(3, int(authority)))
        provenance = dict(provenance or {})
        now = _now()
        with self._lock:
            row = self._conn.execute(
                "SELECT item_id, created_at, revision FROM memory_items WHERE target=? AND kind=? AND item_key=?",
                (target, kind, key)).fetchone()
            item_id = row["item_id"] if row else str(uuid.uuid4())
            created_at = row["created_at"] if row else now
            revision = (row["revision"] + 1) if row else 1
            payload = json.dumps(value, ensure_ascii=False)
            provenance_json = json.dumps(provenance, ensure_ascii=False)
            self._conn.execute("""INSERT INTO memory_items
                (item_id,target,kind,item_key,value_json,confidence,status,source,authority,provenance_json,revision,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(target,kind,item_key) DO UPDATE SET
                value_json=excluded.value_json, confidence=excluded.confidence,
                status=excluded.status, source=excluded.source, authority=excluded.authority,
                provenance_json=excluded.provenance_json, revision=excluded.revision,
                updated_at=excluded.updated_at""",
                (item_id, target, kind, key, payload, max(0.0, min(1.0, confidence)),
                 status, source, authority, provenance_json, revision, created_at, now))
            self._conn.execute("INSERT INTO memory_events VALUES (?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), target, item_id, revision, "upsert", payload, now))
            self._conn.commit()
            return item_id

    def get(self, target: str, kind: str, key: str, *, include_quarantined: bool = False) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM memory_items WHERE target=? AND kind=? AND item_key=?",
                (target, kind, key)).fetchone()
        if not row or (row["status"] == "quarantined" and not include_quarantined):
            return None
        return self._row(row)

    def list(self, target: str, kind: str, *, status: str = "active", limit: int = 100,
             min_authority: int = 0) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM memory_items WHERE target=? AND kind=? AND status=? AND authority>=? "
                "ORDER BY updated_at DESC LIMIT ?",
                (target, kind, status, max(0, min_authority), limit)).fetchall()
        return [self._row(r) for r in rows]

    def relate(self, target: str, from_id: str, relation: str, to_id: str, *, confidence: float = 1.0) -> str:
        if not from_id or not to_id or not relation:
            raise ValueError("relation endpoints and relation name are required")
        rid = str(uuid.uuid4())
        with self._lock:
            self._conn.execute("INSERT OR IGNORE INTO memory_relations VALUES (?,?,?,?,?,?,?)",
                (rid, target, from_id, relation, to_id, max(0.0, min(1.0, confidence)), _now()))
            self._conn.commit()
            row = self._conn.execute(
                "SELECT relation_id FROM memory_relations WHERE target=? AND from_id=? AND relation=? AND to_id=?",
                (target, from_id, relation, to_id)).fetchone()
        return row["relation_id"] if row else rid

    def relations(self, target: str, *, from_id: str = "", limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            if from_id:
                rows = self._conn.execute("SELECT * FROM memory_relations WHERE target=? AND from_id=? ORDER BY created_at DESC LIMIT ?",
                                          (target, from_id, limit)).fetchall()
            else:
                rows = self._conn.execute("SELECT * FROM memory_relations WHERE target=? ORDER BY created_at DESC LIMIT ?",
                                          (target, limit)).fetchall()
        return [dict(row) for row in rows]

    def record_fact(self, target: str, key: str, value: Dict[str, Any], *, confidence: float = 1.0,
                    source: str = "tool", provenance: Optional[Dict[str, Any]] = None,
                    authority: int = 1) -> str:
        return self.upsert(target, "fact", key, value, confidence=confidence, source=source,
                           authority=authority, provenance=provenance)

    def record_evidence(self, target: str, key: str, *, observation: str, source: str,
                        hypothesis_id: str = "", strength: str = "observed",
                        receipt: Optional[Dict[str, Any]] = None,
                        provenance: Optional[Dict[str, Any]] = None) -> str:
        eid = self.upsert(target, "evidence", key,
                          {"observation": observation[:12000], "source": source,
                           "hypothesis_id": hypothesis_id, "strength": strength,
                           "receipt": receipt or {}},
                          confidence=1.0 if strength in {"observed", "verified"} else 0.5,
                          source=source, authority=1, provenance=provenance)
        if hypothesis_id:
            self.relate(target, eid, "supports", hypothesis_id)
        return eid

    def record_hypothesis(self, target: str, hypothesis_id: str, hypothesis: str, *,
                          state: str = "new", confidence: float = 0.5,
                          basis: Optional[List[str]] = None, next_test: str = "",
                          provenance: Optional[Dict[str, Any]] = None) -> str:
        hid = self.upsert(target, "hypothesis", hypothesis_id,
                          {"hypothesis": hypothesis, "state": state,
                           "basis": basis or [], "next_test": next_test}, confidence=confidence,
                          authority=2, provenance=provenance)
        for eid in basis or []:
            self.relate(target, eid, "supports", hid, confidence=confidence)
        return hid

    def record_attempt(self, target: str, action_key: str, *, outcome: str,
                       status: str = "completed", hypothesis_id: str = "",
                       failure_level: str = "", evidence_ids: Optional[List[str]] = None,
                       details: Optional[Dict[str, Any]] = None) -> str:
        aid = str(uuid.uuid4())
        evidence_ids = list(evidence_ids or [])
        with self._lock:
            self._conn.execute("INSERT INTO memory_attempts VALUES (?,?,?,?,?,?,?,?,?,?)",
                (aid, target, action_key, hypothesis_id, outcome, status,
                 failure_level or None, json.dumps(evidence_ids),
                 json.dumps(details or {}, ensure_ascii=False), _now()))
            self._conn.commit()
        if hypothesis_id:
            self.relate(target, aid, "tests", hypothesis_id)
        for eid in evidence_ids:
            self.relate(target, aid, "produced", eid)
        return aid

    def record_dead_end(self, target: str, key: str, reason: str, *, evidence_id: str = "",
                        failure_level: str = "L2") -> str:
        did = self.upsert(target, "dead_end", key,
                          {"reason": reason, "evidence_id": evidence_id, "failure_level": failure_level},
                          status="closed", authority=1)
        if evidence_id:
            self.relate(target, evidence_id, "explains", did)
        return did

    def record_failure_lesson(self, target: str, action_key: str, *, level: str,
                              reason: str, lesson: str) -> str:
        aid = self.record_attempt(target, action_key, outcome=reason, status="failed", failure_level=level)
        self.upsert(target, "lesson", f"failure:{action_key}:{level}",
                    {"lesson": lesson, "category": f"failure:{level}"}, confidence=0.8, authority=2)
        return aid

    def set_priority(self, target: str, key: str, priority: int, reason: str) -> str:
        return self.upsert(target, "priority", key, {"priority": priority, "reason": reason}, authority=2)

    def save_checkpoint(self, target: str, state: Dict[str, Any], cursor: str = "") -> None:
        with self._lock:
            self._conn.execute("""INSERT INTO memory_checkpoints(target,state_json,cursor,updated_at)
                VALUES (?,?,?,?) ON CONFLICT(target) DO UPDATE SET
                state_json=excluded.state_json,cursor=excluded.cursor,updated_at=excluded.updated_at""",
                (target, json.dumps(state, ensure_ascii=False), cursor, _now()))
            self._conn.commit()

    def checkpoint(self, target: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute("SELECT state_json,cursor,updated_at FROM memory_checkpoints WHERE target=?",
                                     (target,)).fetchone()
        if not row:
            return None
        return {"state": json.loads(row["state_json"]), "cursor": row["cursor"], "updated_at": row["updated_at"]}

    def snapshot(self, target: str, *, limits: Optional[Dict[str, int]] = None,
                 min_authority: int = 0) -> SecurityMemorySnapshot:
        limits = limits or {}
        with self._lock:
            attempts = self._conn.execute(
                "SELECT * FROM memory_attempts WHERE target=? ORDER BY created_at DESC LIMIT ?",
                (target, limits.get("attempts", 20))).fetchall()
        return SecurityMemorySnapshot(
            target=target,
            facts=self.list(target, "fact", limit=limits.get("facts", 40), min_authority=min_authority),
            hypotheses=self.list(target, "hypothesis", limit=limits.get("hypotheses", 20), min_authority=min_authority),
            evidence=self.list(target, "evidence", limit=limits.get("evidence", 30), min_authority=min_authority),
            dead_ends=self.list(target, "dead_end", status="closed", limit=limits.get("dead_ends", 20), min_authority=min_authority),
            lessons=self.list(target, "lesson", limit=limits.get("lessons", 20), min_authority=min_authority),
            priorities=self.list(target, "priority", limit=limits.get("priorities", 20), min_authority=min_authority),
            relations=self.relations(target, limit=limits.get("relations", 40)),
            recent_attempts=[dict(row) for row in attempts],
            checkpoint=self.checkpoint(target),
        )

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return {"id": row["item_id"], "kind": row["kind"], "key": row["item_key"],
                "value": json.loads(row["value_json"]), "confidence": row["confidence"],
                "status": row["status"], "source": row["source"],
                "authority": row["authority"], "provenance": json.loads(row["provenance_json"]),
                "revision": row["revision"], "created_at": row["created_at"],
                "updated_at": row["updated_at"]}

    def close(self) -> None:
        with self._lock:
            self._conn.close()
