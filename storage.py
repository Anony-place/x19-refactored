import json
import os
import re
import sqlite3
import subprocess
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass, field, asdict

from constants import C, ICO, PROVIDERS
from config import CONFIG, CONFIG_DIR, CONFIG_FILE, load_config, save_config, SCRIPTS_DIR, PAYLOADS_DIR, WORDLISTS_DIR
from logging_utils import log, swallow as _swallow




# ===================== DATA MANAGER =====================

class DataManager:
    """Manages scripts, payloads, wordlists, and local datasets."""

    SCRIPTS_DIR = SCRIPTS_DIR
    PAYLOADS_DIR = PAYLOADS_DIR
    WORDLISTS_DIR = WORDLISTS_DIR
    DATASETS_DIR = Path(__file__).resolve().parent.parent / "datasets"
    DATASET_EXTS = {".pdf", ".txt", ".md", ".json", ".csv", ".html", ".htm"}

    @classmethod
    def list_files(cls, directory: Path, ext: str = "") -> List[Path]:
        if not directory.exists():
            return []
        return sorted([f for f in directory.rglob("*") if f.is_file() and (not ext or f.suffix == ext)])

    @classmethod
    def list_scripts(cls) -> List[Path]:
        return cls.list_files(cls.SCRIPTS_DIR, ".py") + cls.list_files(cls.SCRIPTS_DIR, ".sh")

    @classmethod
    def list_payloads(cls) -> List[Path]:
        return cls.list_files(cls.PAYLOADS_DIR)

    @classmethod
    def list_wordlists(cls) -> List[Path]:
        return cls.list_files(cls.WORDLISTS_DIR)

    @classmethod
    def _configured_dataset_dirs(cls) -> List[Path]:
        dirs: List[Path] = []
        raw = os.getenv("X19_DATASETS_DIR") or load_config().get("DATASETS_DIR", "")
        if raw:
            for part in str(raw).split(os.pathsep):
                part = part.strip()
                if part:
                    dirs.append(Path(part).expanduser())
        dirs.append(cls.DATASETS_DIR)
        return dirs

    @classmethod
    def list_datasets(cls) -> List[Path]:
        """List local knowledge datasets, defaulting to ./datasets in the project root."""
        seen = set()
        files: List[Path] = []
        for directory in cls._configured_dataset_dirs():
            if not directory.exists():
                continue
            for p in sorted(directory.rglob("*")):
                if not p.is_file() or p.suffix.lower() not in cls.DATASET_EXTS:
                    continue
                key = str(p.resolve())
                if key in seen:
                    continue
                seen.add(key)
                files.append(p)
        return files

    @classmethod
    def get_script(cls, name: str) -> Optional[str]:
        for p in [cls.SCRIPTS_DIR / name, cls.SCRIPTS_DIR / f"{name}.py", cls.SCRIPTS_DIR / f"{name}.sh"]:
            if p.exists():
                return p.read_text()
        return None

    @classmethod
    def get_payload(cls, name: str) -> Optional[str]:
        p = cls.PAYLOADS_DIR / name
        return p.read_text() if p.exists() else None

    @classmethod
    def write_script(cls, name: str, content: str) -> Path:
        path = cls.SCRIPTS_DIR / name
        path.write_text(content)
        path.chmod(0o755)
        return path

    @classmethod
    def write_payload(cls, name: str, content: str) -> Path:
        path = cls.PAYLOADS_DIR / name
        path.write_text(content)
        return path

    @classmethod
    def summary(cls) -> str:
        parts = []
        scripts = cls.list_scripts()
        payloads = cls.list_payloads()
        wordlists = cls.list_wordlists()
        datasets = cls.list_datasets()
        if scripts:
            parts.append(f"Scripts ({len(scripts)}): " + ", ".join(s.name for s in scripts))
        if payloads:
            parts.append(f"Payloads ({len(payloads)}): " + ", ".join(p.name for p in payloads))
        if wordlists:
            parts.append(f"Wordlists ({len(wordlists)}): " + ", ".join(w.name for w in wordlists))
        if datasets:
            parts.append(f"Datasets ({len(datasets)}): " + ", ".join(p.name for p in datasets))
        return "\n".join(parts) if parts else "No custom datasets installed."

    @classmethod
    def context_block(cls) -> str:
        """Returns a formatted block for AI context showing available datasets."""
        lines = ["AVAILABLE DATASETS:"]
        scripts = cls.list_scripts()
        payloads = cls.list_payloads()
        wordlists = cls.list_wordlists()
        datasets = cls.list_datasets()

        if scripts:
            lines.append(f"  Scripts:")
            for s in scripts:
                rel = s.relative_to(SCRIPTS_DIR.parent.parent)
                first = s.read_text().split('\n')[0].replace('#', '').strip()[:80]
                lines.append(f"    {rel} — {first}")
        if payloads:
            lines.append(f"  Payloads:")
            for p in payloads:
                rel = p.relative_to(PAYLOADS_DIR.parent.parent)
                size = len(p.read_bytes())
                lines.append(f"    {rel} ({size} bytes)")
        if wordlists:
            lines.append(f"  Wordlists:")
            for w in wordlists:
                rel = w.relative_to(WORDLISTS_DIR.parent.parent)
                size = len(w.read_bytes())
                lines.append(f"    {rel} ({size} bytes)")
        if datasets:
            lines.append(f"  Local knowledge datasets ({len(datasets)}):")
            for d in datasets:
                try:
                    rel = d.relative_to(cls.DATASETS_DIR.parent)
                except Exception:
                    rel = d
                size = d.stat().st_size
                lines.append(f"    {rel} ({size} bytes)")
            lines.append("    Note: PDF/text datasets are indexed into Chroma memory on learner startup.")
        if len(lines) == 1:
            return ""
        return "\n".join(lines)

    @classmethod
    def register_tool(cls, name: str, command: str, description: str, timeout: int = 120) -> str:
        """Register a new tool in the global TOOLS dict at runtime.
        Returns the code line to add to x19.py for persistence."""
        from tools import TOOLS
        TOOLS[name] = f"{command} | {description} | {timeout}"
        return f'    "{name}": "{command} | {description} | {timeout}",\n'


class SQLDatabase:
    """Unified relational database layer supporting SQLite (default) and PostgreSQL.

    Tables:
      - sessions:     session_id, target, target_type, status, started, ended, findings_count
      - commands:     id, session_id, cmd, result, category, returncode, timestamp
      - findings:     id, session_id, severity, title, detail, evidence, timestamp
      - ports:        id, session_id, port, proto, service, version, timestamp
      - techniques:   id, technique, category, target, success, timestamp
      - lessons:      id, lesson, severity, target, timestamp
      - profiles:     id, profile_text, target_type, timestamp
    """

    _instance: Optional["SQLDatabase"] = None
    _lock = threading.RLock()  # reentrant: __new__ holds it while _ensure_tables re-acquires

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._init_db()
        return cls._instance

    def _init_db(self):
        self.db_type = CONFIG.DB_TYPE.lower()
        self._conn: Optional[Any] = None
        self._pg_pool: Optional[Any] = None
        if self.db_type == "postgres":
            self._init_postgres()
        else:
            self._init_sqlite()
        self._ensure_tables()

    def _init_sqlite(self):
        db_path = Path(CONFIG.DB_SQLITE_PATH)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

    def _init_postgres(self):
        try:
            import psycopg2
            self._conn = psycopg2.connect(
                host=CONFIG.DB_HOST,
                port=CONFIG.DB_PORT,
                dbname=CONFIG.DB_NAME,
                user=CONFIG.DB_USER,
                password=CONFIG.DB_PASSWORD,
                connect_timeout=5,
            )
        except ImportError:
            print(f"{C.R}[!] psycopg2 not installed, falling back to SQLite{C.N}")
            self.db_type = "sqlite"
            self._init_sqlite()
        except Exception as e:
            print(f"{C.R}[!] PostgreSQL connection failed: {e}. Falling back to SQLite.{C.N}")
            self.db_type = "sqlite"
            self._init_sqlite()

    def _cursor(self):
        if self.db_type == "postgres":
            import psycopg2.extras
            return self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        return self._conn.cursor()

    def _ensure_tables(self):
        """Create tables if they don't exist."""
        ddl = [
            """CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY {},
                session_id TEXT NOT NULL UNIQUE,
                target TEXT NOT NULL,
                target_type TEXT,
                status TEXT DEFAULT 'active',
                started TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ended TIMESTAMP,
                findings_count INTEGER DEFAULT 0,
                commands_count INTEGER DEFAULT 0
            )""",
            """CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY {},
                session_id TEXT NOT NULL,
                cmd TEXT,
                result TEXT,
                category TEXT,
                returncode INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT fk_cmd_session FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )""",
            """CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY {},
                session_id TEXT NOT NULL,
                severity TEXT,
                title TEXT,
                detail TEXT,
                evidence TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT fk_find_session FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )""",
            """CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY {},
                session_id TEXT NOT NULL,
                port INTEGER,
                proto TEXT,
                service TEXT,
                version TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT fk_port_session FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )""",
            """CREATE TABLE IF NOT EXISTS techniques (
                id INTEGER PRIMARY KEY {},
                technique TEXT,
                category TEXT,
                target TEXT,
                success BOOLEAN,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS lessons (
                id INTEGER PRIMARY KEY {},
                lesson TEXT,
                severity TEXT,
                target TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",
            """CREATE TABLE IF NOT EXISTS profiles (
                id INTEGER PRIMARY KEY {},
                profile_text TEXT,
                target_type TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",
        ]
        pk_sqlite = "AUTOINCREMENT"
        pk_postgres = "GENERATED ALWAYS AS IDENTITY"
        pk = pk_postgres if self.db_type == "postgres" else pk_sqlite
        for sql in ddl:
            try:
                with self._lock:
                    cur = self._cursor()
                    cur.execute(sql.replace("{}", pk))
                    self._conn.commit()
            except Exception as e:
                _swallow(e)

    def save_session(self, session_data: dict):
        """Insert or update session record."""
        sess_id = session_data.get("session_id", "")
        if not sess_id:
            return
        try:
            with self._lock:
                cur = self._cursor()
                if self.db_type == "postgres":
                    cur.execute(
                        """INSERT INTO sessions (session_id, target, target_type, status, started, findings_count, commands_count)
                           VALUES (%s, %s, %s, %s, %s, %s, %s)
                           ON CONFLICT (session_id) DO UPDATE SET
                           status=EXCLUDED.status, ended=EXCLUDED.ended, findings_count=EXCLUDED.findings_count,
                           commands_count=EXCLUDED.commands_count""",
                        (sess_id, session_data.get("target", ""), session_data.get("type", ""),
                         session_data.get("status", "active"), session_data.get("started", datetime.now()),
                         len(session_data.get("findings", [])), len(session_data.get("commands", [])))
                    )
                else:
                    cur.execute(
                        """INSERT OR REPLACE INTO sessions
                           (session_id, target, target_type, status, started, findings_count, commands_count)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (sess_id, session_data.get("target", ""), session_data.get("type", ""),
                         session_data.get("status", "active"), session_data.get("started", datetime.now()),
                         len(session_data.get("findings", [])), len(session_data.get("commands", [])))
                    )
                self._conn.commit()
        except Exception as e:
            _swallow(e)

    def save_command(self, session_id: str, cmd: str, result: str, category: str, returncode: int):
        if not session_id:
            return
        try:
            with self._lock:
                cur = self._cursor()
                if self.db_type == "postgres":
                    cur.execute(
                        "INSERT INTO commands (session_id, cmd, result, category, returncode) VALUES (%s, %s, %s, %s, %s)",
                        (session_id, cmd[:500], result[:1000], category, returncode)
                    )
                else:
                    cur.execute(
                        "INSERT INTO commands (session_id, cmd, result, category, returncode) VALUES (?, ?, ?, ?, ?)",
                        (session_id, cmd[:500], result[:1000], category, returncode)
                    )
                self._conn.commit()
        except Exception as e:
            _swallow(e)

    def save_finding(self, session_id: str, severity: str, title: str, detail: str, evidence: str):
        if not session_id:
            return
        try:
            with self._lock:
                cur = self._cursor()
                if self.db_type == "postgres":
                    cur.execute(
                        "INSERT INTO findings (session_id, severity, title, detail, evidence) VALUES (%s, %s, %s, %s, %s)",
                        (session_id, severity, title[:200], detail[:1000], evidence[:1000])
                    )
                else:
                    cur.execute(
                        "INSERT INTO findings (session_id, severity, title, detail, evidence) VALUES (?, ?, ?, ?, ?)",
                        (session_id, severity, title[:200], detail[:1000], evidence[:1000])
                    )
                self._conn.commit()
        except Exception as e:
            _swallow(e)

    def save_technique(self, technique: str, category: str, target: str, success: bool):
        try:
            with self._lock:
                cur = self._cursor()
                if self.db_type == "postgres":
                    cur.execute(
                        "INSERT INTO techniques (technique, category, target, success) VALUES (%s, %s, %s, %s)",
                        (technique[:500], category, target[:200], success)
                    )
                else:
                    cur.execute(
                        "INSERT INTO techniques (technique, category, target, success) VALUES (?, ?, ?, ?)",
                        (technique[:500], category, target[:200], success)
                    )
                self._conn.commit()
        except Exception as e:
            _swallow(e)

    def get_recent_techniques(self, target: str = "", category: str = "", n: int = 10) -> List[Dict]:
        """Query recent techniques with optional filtering."""
        try:
            with self._lock:
                cur = self._cursor()
                if target and category:
                    sql = "SELECT * FROM techniques WHERE target LIKE ? AND category = ? ORDER BY timestamp DESC LIMIT ?"
                    params = (f"%{target}%", category, n)
                elif target:
                    sql = "SELECT * FROM techniques WHERE target LIKE ? ORDER BY timestamp DESC LIMIT ?"
                    params = (f"%{target}%", n)
                elif category:
                    sql = "SELECT * FROM techniques WHERE category = ? ORDER BY timestamp DESC LIMIT ?"
                    params = (category, n)
                else:
                    sql = "SELECT * FROM techniques ORDER BY timestamp DESC LIMIT ?"
                    params = (n,)
                if self.db_type == "postgres":
                    sql = sql.replace("LIKE ?", "LIKE %s").replace("= ?", "= %s").replace("LIMIT ?", "LIMIT %s")
                    cur.execute(sql, params)
                else:
                    cur.execute(sql, params)
                rows = cur.fetchall()
                return [dict(r) for r in rows] if rows else []
        except Exception:
            return []

    def get_session_stats(self, session_id: str) -> Dict:
        """Get all stats for a session."""
        try:
            with self._lock:
                cur = self._cursor()
                if self.db_type == "postgres":
                    cur.execute("SELECT * FROM sessions WHERE session_id = %s", (session_id,))
                else:
                    cur.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
                row = cur.fetchone()
                return dict(row) if row else {}
        except Exception:
            return {}

    def get_top_categories(self, n: int = 5) -> List[Tuple[str, int]]:
        """Return most frequently used categories from commands."""
        try:
            with self._lock:
                cur = self._cursor()
                cur.execute(
                    "SELECT category, COUNT(*) as cnt FROM commands WHERE category != 'other' GROUP BY category ORDER BY cnt DESC LIMIT ?",
                    (n,)
                )
                rows = cur.fetchall()
                return [(r["category"], r["cnt"]) for r in rows] if rows else []
        except Exception:
            return []

    def save_profile(self, text: str, target_type: str):
        try:
            with self._lock:
                cur = self._cursor()
                if self.db_type == "postgres":
                    cur.execute(
                        "INSERT INTO profiles (profile_text, target_type) VALUES (%s, %s)",
                        (text[:500], target_type)
                    )
                else:
                    cur.execute(
                        "INSERT INTO profiles (profile_text, target_type) VALUES (?, ?)",
                        (text[:500], target_type)
                    )
                self._conn.commit()
        except Exception as e:
            _swallow(e)

    def get_recent_profiles(self, n: int = 5) -> List[Dict]:
        try:
            with self._lock:
                cur = self._cursor()
                cur.execute("SELECT * FROM profiles ORDER BY timestamp DESC LIMIT ?", (n,))
                rows = cur.fetchall()
                return [dict(r) for r in rows] if rows else []
        except Exception:
            return []

    def summary(self) -> str:
        try:
            with self._lock:
                cur = self._cursor()
                tables = ["sessions", "commands", "findings", "techniques", "lessons", "profiles"]
                parts = [f"SQL DB ({self.db_type}):"]
                for t in tables:
                    cur.execute(f"SELECT COUNT(*) as cnt FROM {t}")
                    row = cur.fetchone()
                    cnt = row["cnt"] if row else 0
                    parts.append(f"  {t}: {cnt} rows")
                return "\n".join(parts)
        except Exception:
            return f"SQL DB ({self.db_type}): unavailable"


class Session:
    def __init__(self):
        self.dir = Path(CONFIG.SESSIONS_DIR)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.id: Optional[str] = None
        self.data: Dict = {}

    def create(self, target: str) -> str:
        self.id = f"x19_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.data = {
            "session_id": self.id,
            "target": target,
            "started": datetime.now().isoformat(),
            "status": "active",
            "iterations": 0,
            "commands": [],
            "findings": [],
            "ports_discovered": [],
            "os_info": "",
        }
        self.save()
        return self.id

    def save(self):
        if self.id:
            (self.dir / f"{self.id}.json").write_text(json.dumps(self.data, indent=2, default=str))

    def add_cmd(self, cmd: str, result: str, category: str = "other", returncode: int = 0):
        self.data["commands"].append({"cmd": cmd[:200], "result": result[:500], "rc": returncode, "ts": datetime.now().isoformat()})
        self.data["iterations"] = len(self.data["commands"])
        self.save()
        try:
            SQLDatabase().save_command(self.id, cmd, result, category, returncode)
        except Exception as e:
            log(f"[Session] SQL save_command failed: {e}")

    def add_finding(self, severity: str, title: str, detail: str, evidence: str = ""):
        self.data["findings"].append({"severity": severity, "title": title, "detail": detail[:500], "evidence": evidence[:500], "ts": datetime.now().isoformat()})
        self.save()

    def set_ports(self, ports: str):
        self.data["ports_discovered"] = ports
        self.save()

    def set_os(self, os_info: str):
        self.data["os_info"] = os_info
        self.save()

    def report(self) -> str:
        d = self.data
        lines = [
            "=" * 72,
            f"X19 Assessment Report",
            f"Session: {d.get('session_id','?')}",
            f"Target: {d.get('target','?')}",
            f"Started: {d.get('started','?')}",
            f"Status: {d.get('status','?')}",
            f"Iterations: {d.get('iterations',0)}",
            "=" * 72,
        ]
        finds = d.get("findings", [])
        lines.append(f"\nFindings ({len(finds)}):")
        for f in finds:
            lines.append(f"  [{f['severity'].upper():8}] {f['title']}")
            lines.append(f"           {f['detail'][:200]}")
        cmds = d.get("commands", [])
        lines.append(f"\nCommands ({len(cmds)}):")
        for c in cmds[-30:]:
            lines.append(f"  - {c['cmd'][:120]}")
        lines.append(f"\n{'=' * 72}")

        # Phase 3: emit professional Markdown + HTML report (with curl PoCs and CVSS).
        # Fail-soft — never break the basic report() return if file writing fails.
        try:
            session_meta = {
                "session_id": d.get("session_id", "?"),
                "target": d.get("target", "?"),
                "started": d.get("started", "?"),
                "status": d.get("status", "?"),
                "iterations": d.get("iterations", 0),
                "domain": d.get("target", "?").replace("https://", "").replace("http://", "").split("/")[0],
            }
            report_dir = os.path.join(os.path.dirname(self.path) if hasattr(self, "path") and self.path else ".", "reports")
            from reporting import ReportWriter
            rw = ReportWriter(target=d.get("target", "?"), findings=finds, session_meta=session_meta, out_dir=report_dir)
            md_path, html_path = rw.write_both()
            lines.append(f"\n[REPORT] Markdown: {md_path}")
            lines.append(f"[REPORT] HTML:     {html_path}")
        except Exception as e:
            log(f"[report] ReportWriter failed (basic report still returned): {e}")

        return "\n".join(lines)

    def findings_summary(self) -> str:
        f = self.data.get("findings", [])
        if not f:
            return "No findings"
        sev: Dict[str, int] = {}
        for x in f:
            s = x.get("severity", "info")
            sev[s] = sev.get(s, 0) + 1
        parts = [f"{k.upper()}:{v}" for k, v in sorted(sev.items())]
        return f"{len(f)} findings [{', '.join(parts)}]"


@dataclass
class LoopSignal:
    state: str = "none"  # none|soft|hard
    category: str = ""   # derived/stagnant category
    reason: str = ""


class JsonFileStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as e:
            log(f"[StateDB] corrupt/unreadable state at {self.path}: {e}")
            return {}

    def save(self, data: dict):
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        tmp.replace(self.path)


class StateDatabase:
    """State database for autonomy internals. Lightweight JSON persistence."""
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.state_file = base_dir / "state.json"
        self.store = JsonFileStore(self.state_file)
        self._data = self.store.load()
        if not self._data:
            self._data = {
                "current_goal": {"node": "assessment", "updated_ts": 0},
                "transitions": [],
                "counters": {},
            }

    def update_goal(self, node: str):
        self._data["current_goal"] = {"node": node, "updated_ts": time.time()}
        self._append_transition({"type": "goal_update", "node": node})
        self.store.save(self._data)

    def update_transition(self, payload: dict):
        self._append_transition(payload)
        self.store.save(self._data)

    def _append_transition(self, payload: dict):
        ts = time.time()
        entry = {"ts": ts, **payload}
        self._data.setdefault("transitions", [])
        self._data["transitions"].append(entry)
        # cap history
        self._data["transitions"] = self._data["transitions"][-200:]

    def bump_counter(self, key: str, inc: int = 1):
        c = self._data.setdefault("counters", {})
        c[key] = c.get(key, 0) + inc
        self._append_transition({"type": "counter_bump", "key": key, "inc": inc})
        self.store.save(self._data)


class FailureMemory:
    """Failure memory prevents re-trying the same failing command signatures.
    Also tracks structured lessons for cross-session learning."""
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.fail_file = base_dir / "failures.json"
        self.store = JsonFileStore(self.fail_file)
        self._data = self.store.load()
        if not self._data:
            self._data = {
                "failures": {},  # sig -> {count,last_ts,last_output_snippet,blocked_until}
                "categories": {},  # category -> {count,last_ts}
                "lessons": [],  # list of structured lessons
            }

    @staticmethod
    def signature(command: str) -> str:
        # normalize by stripping temp paths and collapse whitespace
        s = command.strip()
        s = re.sub(r'/tmp/[a-zA-Z0-9_\.\-]+', '/tmp/_', s)
        s = re.sub(r'\s+', ' ', s)
        # short hash to keep file small
        import hashlib
        return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()[:16]

    def record_failure(self, command: str, category: str, output: str, blocked_for_sec: int = 3600):
        sig = self.signature(command)
        now = time.time()
        failures = self._data.setdefault("failures", {})
        f = failures.get(sig, {"count": 0, "first_ts": now})
        f["count"] = int(f.get("count", 0)) + 1
        f["last_ts"] = now
        f["last_output_snippet"] = (output or "")[:300]
        # Exponential backoff blocking
        cnt = f["count"]
        backoff = min(blocked_for_sec * (2 ** max(0, cnt - 1)), blocked_for_sec * 16)
        f["blocked_until"] = now + backoff
        failures[sig] = f

        cats = self._data.setdefault("categories", {})
        c = cats.get(category, {"count": 0, "last_ts": now})
        c["count"] = int(c.get("count", 0)) + 1
        c["last_ts"] = now
        cats[category] = c

        self.store.save(self._data)
        return sig

    def record_lesson(self, lesson: str, category: str = "", context: str = ""):
        """Record a structured lesson from a mistake or failure pattern."""
        lessons = self._data.setdefault("lessons", [])
        lessons.append({
            "lesson": lesson,
            "category": category,
            "context": (context or "")[:200],
            "ts": time.time(),
        })
        # Keep only last 50 lessons
        if len(lessons) > 50:
            self._data["lessons"] = lessons[-50:]
        self.store.save(self._data)

    def recent_lessons(self, limit: int = 5) -> List[Dict]:
        """Return most recent lessons."""
        lessons = self._data.get("lessons", [])
        return lessons[-limit:]

    def top_failures(self, limit: int = 3) -> List[Dict]:
        """Return most repeated failures."""
        failures = self._data.get("failures", {})
        if not failures:
            return []
        sorted_fails = sorted(
            failures.items(),
            key=lambda x: int(x[1].get("count", 0)),
            reverse=True,
        )[:limit]
        result = []
        for sig, info in sorted_fails:
            cnt = info.get("count", 0)
            snippet = (info.get("last_output_snippet", "") or "")[:80]
            result.append({"sig": sig, "count": cnt, "snippet": snippet})
        return result

    def is_blocked(self, command: str) -> Tuple[bool, str]:
        sig = self.signature(command)
        f = self._data.get("failures", {}).get(sig)
        if not f:
            return False, ""
        now = time.time()
        until = float(f.get("blocked_until", 0) or 0)
        if until > now:
            return True, f.get("last_output_snippet", "")[:120]
        return False, ""

    def stats(self) -> str:
        fails = self._data.get("failures", {})
        total = sum(int(v.get("count", 0)) for v in fails.values())
        unique = len(fails)
        return f"FailureMemory: {unique} signatures, {total} total failures"


class GoalNode:
    def __init__(self, node: str, parent: Optional[str], kind: str, description: str):
        self.node = node
        self.parent = parent
        self.kind = kind  # recon|web|exploit|validate|report
        self.description = description
        self.active = True


class GoalTree:
    """Goal tree drives what we ask next (structured autonomy)."""
    def __init__(self):
        # Minimal but extensible tree
        self.nodes: Dict[str, GoalNode] = {}
        self._build()

    def _build(self):
        def add(node, parent, kind, desc):
            self.nodes[node] = GoalNode(node=node, parent=parent, kind=kind, description=desc)

        add("assessment", None, "root", "Decide best path based on target model + evidence")
        add("recon_ports", "assessment", "recon", "Discover services/ports and infer likely attack surface")
        add("recon_web", "assessment", "recon", "Discover endpoints/tech stack for web/API targets")
        add("recon_ad", "assessment", "recon", "Enumerate AD surface if applicable")
        add("exploit_web", "assessment", "exploit", "Exploit discovered web/API weaknesses (auth, injection, RCE)")
        add("exploit_smb", "assessment", "exploit", "Exploit SMB/windows weaknesses if exposed")
        add("validate", "assessment", "validate", "Verify exploit impact and capture evidence")
        add("report", "assessment", "report", "Produce final verified PoC/report")
        add("self_debug", "assessment", "diagnose", "Run self-diagnostic and recovery procedures when stuck in a loop")

    def select_active_node(
        self,
        model: "TargetModel",
        target_type: str,
        forced_exploit: bool,
        loop_sig: LoopSignal,
        autonomy_profile: Optional["AutonomyProfile"] = None,
    ) -> str:
        # Hard pivot if we are stuck/looping
        if loop_sig.state == "hard":
            return "self_debug"

        if autonomy_profile:
            suggestion = autonomy_profile.recommend_goal(model, target_type, forced_exploit, loop_sig)
            if suggestion:
                return suggestion

        # If forced exploit mode, bias towards exploit nodes
        if forced_exploit:
            if any(p.get("port") in (80, 443, 8080, 8443) for p in model.ports):
                return "exploit_web"
            if any(p.get("port") == 445 for p in model.ports):
                return "exploit_smb"
            return "validate"

        # Choose based on observed ports/services
        open_ports = {p.get("port") for p in model.ports}
        if any(pt in open_ports for pt in (80, 443, 8080, 8443)) and (target_type != "public_real_world"):
            return "recon_web" if not model.endpoints else "exploit_web"
        if any(pt in open_ports for pt in (389, 445, 3389)):
            # heuristic: AD-ish ports -> recon_ad, windows exploit if evidence
            if any(pt == 389 for pt in open_ports):
                return "recon_ad"
            return "exploit_smb" if any(f.severity in ("medium", "high", "critical") for f in model.findings) else "validate"
        # Default: recon ports
        if not model.ports:
            return "recon_ports"
        # If we have ports but no endpoints/findings -> decide web/ad based on endpoints
        if model.endpoints:
            return "exploit_web"
        return "recon_ports"
