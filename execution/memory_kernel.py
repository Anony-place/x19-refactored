from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional



def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class MemoryItem:
    kind: str
    key: str
    value: Dict[str, Any]
    confidence: float = 1.0
    status: str = "active"
    source: str = "agent"
    item_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)


@dataclass(frozen=True)
class MemorySnapshot:
    target: str
    facts: List[Dict[str, Any]]
    hypotheses: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]
    dead_ends: List[Dict[str, Any]]
    lessons: List[Dict[str, Any]]
    priorities: List[Dict[str, Any]]

    def to_prompt(self, max_chars: int = 12000) -> str:
        payload = {
            "target": self.target,
            "facts": self.facts,
            "hypotheses": self.hypotheses,
            "evidence": self.evidence,
            "dead_ends": self.dead_ends,
            "lessons": self.lessons,
            "priorities": self.priorities,
        }
        text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        return text[:max_chars]


class MemoryKernel:
    """Small deterministic mission-memory layer.

    SQLite is authoritative for structured state. Vector memory remains optional
    secondary retrieval; it must never become the source of truth for facts or
    evidence.
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
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS memory_items (
                    item_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    item_key TEXT NOT NULL,
                    value_json TEXT NOT NULL,
                    confidence REAL NOT NULL DEFAULT 1.0,
                    status TEXT NOT NULL DEFAULT 'active',
                    source TEXT NOT NULL DEFAULT 'agent',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(target, kind, item_key)
                );
                CREATE INDEX IF NOT EXISTS idx_memory_target_kind
                    ON memory_items(target, kind, status);
                CREATE TABLE IF NOT EXISTS memory_events (
                    event_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    item_id TEXT NOT NULL,
                    event TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_memory_events_target
                    ON memory_events(target, created_at);
                """
            )
            self._conn.commit()

    def upsert(self, target: str, kind: str, key: str, value: Dict[str, Any], *,
               confidence: float = 1.0, status: str = "active", source: str = "agent") -> str:
        now = _now()
        with self._lock:
            row = self._conn.execute(
                "SELECT item_id FROM memory_items WHERE target=? AND kind=? AND item_key=?",
                (target, kind, key),
            ).fetchone()
            item_id = row["item_id"] if row else str(uuid.uuid4())
            self._conn.execute(
                """INSERT INTO memory_items
                   (item_id,target,kind,item_key,value_json,confidence,status,source,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(target,kind,item_key) DO UPDATE SET
                     value_json=excluded.value_json,
                     confidence=excluded.confidence,
                     status=excluded.status,
                     source=excluded.source,
                     updated_at=excluded.updated_at""",
                (item_id, target, kind, key, json.dumps(value, ensure_ascii=False),
                 max(0.0, min(1.0, confidence)), status, source, now, now),
            )
            self._conn.execute(
                "INSERT INTO memory_events VALUES (?,?,?,?,?,?)",
                (str(uuid.uuid4()), target, item_id, "upsert", json.dumps(value, ensure_ascii=False), now),
            )
            self._conn.commit()
            return item_id

    def get(self, target: str, kind: str, key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM memory_items WHERE target=? AND kind=? AND item_key=?",
                (target, kind, key),
            ).fetchone()
        if not row:
            return None
        return self._row(row)

    def list(self, target: str, kind: str, *, status: str = "active", limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM memory_items WHERE target=? AND kind=? AND status=? "
                "ORDER BY updated_at DESC LIMIT ?",
                (target, kind, status, limit),
            ).fetchall()
        return [self._row(r) for r in rows]

    def record_evidence(self, target: str, key: str, *, observation: str, source: str,
                        hypothesis_id: str = "", strength: str = "observed") -> str:
        return self.upsert(
            target, "evidence", key,
            {"observation": observation[:12000], "source": source,
             "hypothesis_id": hypothesis_id, "strength": strength},
            confidence=1.0 if strength in {"observed", "verified"} else 0.5,
            source=source,
        )

    def record_hypothesis(self, target: str, hypothesis_id: str, hypothesis: str, *,
                          state: str = "new", confidence: float = 0.5,
                          basis: Optional[List[str]] = None, next_test: str = "") -> str:
        return self.upsert(
            target, "hypothesis", hypothesis_id,
            {"hypothesis": hypothesis, "state": state, "basis": basis or [], "next_test": next_test},
            confidence=confidence,
        )

    def record_dead_end(self, target: str, key: str, reason: str, *, evidence_id: str = "") -> str:
        return self.upsert(
            target, "dead_end", key,
            {"reason": reason, "evidence_id": evidence_id},
            confidence=1.0,
            status="closed",
        )

    def record_lesson(self, target: str, key: str, lesson: str, *, category: str = "general") -> str:
        return self.upsert(target, "lesson", key, {"lesson": lesson, "category": category})

    def set_priority(self, target: str, key: str, priority: int, reason: str) -> str:
        return self.upsert(target, "priority", key, {"priority": priority, "reason": reason})

    def snapshot(self, target: str, *, limits: Optional[Dict[str, int]] = None) -> MemorySnapshot:
        limits = limits or {}
        return MemorySnapshot(
            target=target,
            facts=self.list(target, "fact", limit=limits.get("fact", 40)),
            hypotheses=self.list(target, "hypothesis", limit=limits.get("hypothesis", 20)),
            evidence=self.list(target, "evidence", limit=limits.get("evidence", 30)),
            dead_ends=self.list(target, "dead_end", status="closed", limit=limits.get("dead_end", 20)),
            lessons=self.list(target, "lesson", limit=limits.get("lesson", 20)),
            priorities=self.list(target, "priority", limit=limits.get("priority", 20)),
        )

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["item_id"], "kind": row["kind"], "key": row["item_key"],
            "value": json.loads(row["value_json"]), "confidence": row["confidence"],
            "status": row["status"], "source": row["source"],
            "created_at": row["created_at"], "updated_at": row["updated_at"],
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()
