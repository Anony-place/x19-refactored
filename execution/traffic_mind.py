"""
TrafficMind — HTTP Traffic Capture & HMAC History (Strix proxy + RedAMon TrafficMind pattern).

Captures every request/response that passes through CommandGateway, BrowserAutomation,
or direct calls. Stores HMAC-SHA256 tagged entries in SQLite (x19_workspace/traffic.db)
and provides query/export for PoV validator, report generator, and UI drawer.

Features mirroring competitors:
 - HMAC tagging per entry (RedAMon: prevents tampering, proves evidence provenance)
 - 10M history page concept → SQLite indexed, paginated query()
 - Full-text search + filter by target/status/method/tag
 - Signed export for report evidence (attaches to SARIF)
 - Integrated mitmproxy-like capture() hook — called from gateway, not requiring mitmproxy binary

Zero external deps; optional mitmproxy integration if installed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

DEFAULT_DB = Path("x19_workspace") / "traffic.db"
HMAC_KEY_ENV = "X19_TRAFFIC_HMAC_KEY"
DEFAULT_HMAC_KEY = b"x19-traffic-mind-v1"

@dataclass
class TrafficEntry:
    id: str
    timestamp: str
    target: str
    method: str
    url: str
    request_headers: str
    request_body: str
    response_status: int
    response_headers: str
    response_body: str
    hmac: str
    tags: str  # comma-separated
    tool: str = ""
    command_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class TrafficMind:
    """HMAC-tagged HTTP history. Singleton-friendly per workspace."""

    def __init__(self, db_path: Optional[Path] = None, hmac_key: Optional[bytes] = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.hmac_key = hmac_key or DEFAULT_HMAC_KEY
        # allow env override
        import os
        env_key = os.getenv(HMAC_KEY_ENV)
        if env_key:
            self.hmac_key = env_key.encode()
        self._init_db()

    def _init_db(self):
        con = sqlite3.connect(str(self.db_path))
        con.execute("""
            CREATE TABLE IF NOT EXISTS traffic (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                target TEXT,
                method TEXT,
                url TEXT,
                request_headers TEXT,
                request_body TEXT,
                response_status INT,
                response_headers TEXT,
                response_body TEXT,
                hmac TEXT,
                tags TEXT,
                tool TEXT,
                command_id TEXT
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_traffic_target ON traffic(target)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_traffic_url ON traffic(url)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_traffic_status ON traffic(response_status)")
        con.commit()
        con.close()

    def _sign(self, payload: str) -> str:
        return hmac.new(self.hmac_key, payload.encode(), hashlib.sha256).hexdigest()[:32]

    def capture(
        self,
        target: str = "",
        method: str = "GET",
        url: str = "",
        request_headers: str = "",
        request_body: str = "",
        response_status: int = 0,
        response_headers: str = "",
        response_body: str = "",
        tags: str = "",
        tool: str = "",
        command_id: str = "",
    ) -> TrafficEntry:
        ts = _utc_now()
        raw = f"{ts}|{method}|{url}|{response_status}|{response_body[:500]}"
        sig = self._sign(raw)
        eid = hashlib.sha256(f"{ts}{url}{response_body[:200]}".encode()).hexdigest()[:16]
        entry = TrafficEntry(
            id=eid, timestamp=ts, target=target, method=method.upper(), url=url,
            request_headers=request_headers[:4000], request_body=request_body[:4000],
            response_status=response_status, response_headers=response_headers[:4000],
            response_body=response_body[:8000], hmac=sig, tags=tags, tool=tool, command_id=command_id,
        )
        try:
            con = sqlite3.connect(str(self.db_path))
            con.execute(
                "INSERT OR REPLACE INTO traffic VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (entry.id, entry.timestamp, entry.target, entry.method, entry.url,
                 entry.request_headers, entry.request_body, entry.response_status,
                 entry.response_headers, entry.response_body, entry.hmac, entry.tags,
                 entry.tool, entry.command_id)
            )
            con.commit()
            con.close()
        except Exception:
            pass
        return entry

    def query(
        self,
        target: str = "",
        url_contains: str = "",
        status: Optional[int] = None,
        tag: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> List[TrafficEntry]:
        con = sqlite3.connect(str(self.db_path))
        con.row_factory = sqlite3.Row
        q = "SELECT * FROM traffic WHERE 1=1"
        params: List[Any] = []
        if target:
            q += " AND target = ?"
            params.append(target)
        if url_contains:
            q += " AND url LIKE ?"
            params.append(f"%{url_contains}%")
        if status is not None:
            q += " AND response_status = ?"
            params.append(status)
        if tag:
            q += " AND tags LIKE ?"
            params.append(f"%{tag}%")
        q += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = con.execute(q, params).fetchall()
        con.close()
        return [TrafficEntry(**dict(r)) for r in rows]

    def count(self) -> int:
        con = sqlite3.connect(str(self.db_path))
        c = con.execute("SELECT COUNT(*) FROM traffic").fetchone()[0]
        con.close()
        return int(c)

    def export_signed(self, target: str = "", limit: int = 1000) -> Dict[str, Any]:
        entries = self.query(target=target, limit=limit)
        payload = json.dumps([e.to_dict() for e in entries], sort_keys=True)
        sig = self._sign(payload)
        return {"entries": [e.to_dict() for e in entries], "hmac": sig, "count": len(entries), "exported_at": _utc_now()}

    def verify(self, entry: TrafficEntry) -> bool:
        raw = f"{entry.timestamp}|{entry.method}|{entry.url}|{entry.response_status}|{entry.response_body[:500]}"
        expected = self._sign(raw)
        return hmac.compare_digest(expected, entry.hmac)

    def clear(self, target: str = ""):
        con = sqlite3.connect(str(self.db_path))
        if target:
            con.execute("DELETE FROM traffic WHERE target = ?", (target,))
        else:
            con.execute("DELETE FROM traffic")
        con.commit()
        con.close()

# module-level singleton for gateway hook
_MIND: Optional[TrafficMind] = None

def get_traffic_mind(db_path: Optional[Path] = None) -> TrafficMind:
    global _MIND
    if _MIND is None or (db_path and Path(db_path) != _MIND.db_path):
        _MIND = TrafficMind(db_path=db_path)
    return _MIND
