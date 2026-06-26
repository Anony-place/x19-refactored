import hashlib
import json
import os
import re
import requests
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any
from collections import Counter

from constants import C, ICO
from storage import DataManager
from config import CONFIG, load_config, CONFIG_DIR
from logging_utils import log, swallow as _swallow


def _memory_disabled() -> bool:
    return os.getenv("X19_DISABLE_MEMORY", "").strip().lower() in ("1", "true", "yes")


_TECH_JUNK = ("dictionary.cambridge", "merriam-webster", "thesaurus", "vocabulary.com", "dictionary.com",
              "britannica.com", "collinsdictionary", "yourdictionary", "wordnik", "pinterest.",
              "/wiki/special:", "definition of", "meaning of", "pronunciation", "synonyms", "antonyms",
              "rhymes with", "in a sentence", "crossword", "translate to")
# Word-boundary match so e.g. "rce" does NOT match "source:". Whole-word security signals only.
_TECH_SEC_RE = re.compile(r'\b(' + '|'.join([
    "cve", "ghsa", "exploits?", "payloads?", "injection", "xss", "sqli", "ssrf", "rce", "lfi", "rfi",
    "xxe", "csrf", "idor", "bola", "bypass", "vulnerabilit\\w+", "attacks?", "fuzzing", "traversal",
    "deserializ\\w+", "privilege", "takeover", "misconfig\\w*", "jwt", "oauth", "smuggling", "ssti",
    "overflow", "poc", "nuclei", "metasploit", "burpsuite", "burp", "waf", "shells?", "enumeration",
    "subdomains?", "pollution", "disclosure", "exposure", "weaponize", "exfiltration", "malware",
    "backdoor", "credentials?", "webshell", "lolbin\\w*", "osint", "social.?engineer\\w*", "pretext\\w*",
    "persuasion", "deception", "phishing", "physical.?security",
]) + r')\b', re.I)


def is_actionable_technique(text: str) -> bool:
    """True only for actionable security content; rejects dictionary/marketing/generic pages."""
    t = (text or "").lower()
    if len(t.strip()) < 40:
        return False
    if any(j in t for j in _TECH_JUNK):
        return False
    return bool(_TECH_SEC_RE.search(t))


def technique_metadata(name: str, category: str, source: str, base: dict = None) -> dict:
    """Schema fields every technique record must carry (req 3)."""
    md = dict(base or {})
    md.update({
        "technique_name": (name or "")[:160] or "unnamed",
        "category": category or "web",
        "source": source or md.get("source", "unknown"),
        "testing_steps": md.get("testing_steps", "see technique text"),
        "evidence_required": md.get("evidence_required", "reproduce request/response or tool output proving impact"),
    })
    return md


def is_bug_bounty_mode() -> bool:
    return CONFIG.BUG_BOUNTY_MODE or os.getenv("X19_BUG_BOUNTY_MODE", "").strip().lower() in ("1", "true", "yes")


def is_ctf_mode() -> bool:
    """CTF mode: aggressive exploitation, flag hunting, full testing."""
    return CONFIG.CTF_MODE or os.getenv("X19_CTF_MODE", "").strip().lower() in ("1", "true", "yes")


def is_fast_mode() -> bool:
    """Faster planning/decisions: compact prompt, smaller context, no extra LLM verify."""
    if CONFIG.FAST_MODE or os.getenv("X19_FAST_MODE", "").strip().lower() in ("1", "true", "yes"):
        return True
    return is_bug_bounty_mode() or is_ctf_mode()


class ChromaMemory:
    """Persistent vector memory using ChromaDB. Stores conversations, techniques, lessons."""

    MEMORY_DIR = CONFIG_DIR / "memory"

    def __init__(self):
        self.ready = False
        self.client = None
        self._collections = {}
        self._init_lock = threading.Lock()
        self._init_thread: Optional[threading.Thread] = None
        self.MEMORY_DIR.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> bool:
        """Connect to ChromaDB with a timeout so startup cannot hang indefinitely."""
        if self.ready or _memory_disabled():
            return self.ready
        with self._init_lock:
            if self.ready:
                return True

        timeout = float(os.getenv("X19_CHROMA_TIMEOUT", "60"))
        result: Dict[str, Any] = {"client": None, "err": None}

        def _run():
            try:
                import chromadb
                from chromadb.config import Settings
                client = chromadb.PersistentClient(
                    path=str(self.MEMORY_DIR),
                    settings=Settings(anonymized_telemetry=False),
                )
                # Set state here too: if the outer join already timed out, this late-arriving
                # client must still enable memory instead of being discarded.
                with self._init_lock:
                    self.client = client
                    self.ready = True
                result["client"] = client
            except ImportError:
                result["err"] = ImportError("chromadb not installed")
            except Exception as e:
                result["err"] = e

        t = threading.Thread(target=_run, daemon=True, name="x19-chroma-connect")
        t.start()
        t.join(timeout=timeout)

        with self._init_lock:
            if self.ready:
                return True
            if t.is_alive():
                print(
                    f"{C.Y}[!] ChromaDB still initializing after {timeout:.0f}s — continuing in "
                    f"background; memory enables automatically when ready "
                    f"(raise X19_CHROMA_TIMEOUT, or X19_DISABLE_MEMORY=1 to skip){C.N}",
                    flush=True,
                )
                return False
            if result["err"]:
                if isinstance(result["err"], ImportError):
                    return False
                print(f"{C.Y}[!] ChromaDB unavailable: {result['err']}{C.N}", flush=True)
                return False
            self.client = result["client"]
            self.ready = True
            return True

    def start_async_init(self):
        """Initialize ChromaDB in the background so the UI is not blocked."""
        if self.ready or _memory_disabled() or (self._init_thread and self._init_thread.is_alive()):
            return
        self._init_thread = threading.Thread(target=self._connect, daemon=True, name="x19-chroma-init")
        self._init_thread.start()

    def _ensure(self, wait: bool = False) -> bool:
        if self.ready:
            return True
        if _memory_disabled():
            return False
        if self._init_thread and self._init_thread.is_alive():
            if wait:
                self._init_thread.join(timeout=float(os.getenv("X19_CHROMA_TIMEOUT", "60")))
            return self.ready
        return self._connect()

    def _coll(self, name: str):
        if not self._ensure(wait=True):
            return None
        if name not in self._collections:
            try:
                self._collections[name] = self.client.get_or_create_collection(
                    name=name, metadata={"hnsw:space": "cosine"}
                )
            except Exception:
                return None
        return self._collections[name]

    def add(self, collection: str, text: str, metadata: dict = None, doc_id: str = None) -> bool:
        """Returns True only if the document was actually persisted. Callers must not count fetched-but-unstored items."""
        if not self._ensure():
            log(f"[MEMORY_WRITE_DROP] {collection}: memory not ready (async init) — write discarded")
            return False
        coll = self._coll(collection)
        if not coll:
            log(f"[MEMORY_WRITE_DROP] {collection}: collection unavailable — write discarded")
            return False
        import uuid
        doc_id = doc_id or str(uuid.uuid4())
        metadata = metadata or {}
        try:
            coll.add(documents=[text], metadatas=[metadata], ids=[doc_id])
            log(f"[MEMORY_WRITE] {collection} id={doc_id[:8]} date={metadata.get('date','?')} len={len(text)}")
            return True
        except Exception as e:
            log(f"[MEMORY_WRITE_FAIL] {collection}: {type(e).__name__}: {e}")
            return False

    def query(self, collection: str, query: str, n: int = 5, where: dict = None) -> list:
        if not self._ensure():
            return []
        coll = self._coll(collection)
        if not coll:
            return []
        try:
            kw = {"query_texts": [query], "n_results": n}
            if where:
                kw["where"] = where
            res = coll.query(**kw)
            items = []
            if res.get("documents") and res["documents"][0]:
                for i, doc in enumerate(res["documents"][0]):
                    items.append({
                        "text": doc,
                        "metadata": res["metadatas"][0][i] if res.get("metadatas") else {},
                        "distance": res["distances"][0][i] if res.get("distances") else 0,
                    })
            log(f"[MEMORY_READ] query {collection} q={query[:50]!r} n={len(items)}")
            return items
        except Exception:
            return []

    def count(self, collection: str) -> int:
        if not self._ensure():
            return 0
        coll = self._coll(collection)
        return coll.count() if coll else 0

    def get_by_date(self, collection: str, date: str, limit: int = 50) -> list:
        """Return stored docs whose metadata date matches — REAL records only, no LLM. [] if none."""
        if not self._ensure(wait=True):
            return []
        coll = self._coll(collection)
        if not coll:
            return []
        try:
            res = coll.get(where={"date": date}, limit=limit)
            docs = res.get("documents", []) or []
            metas = res.get("metadatas", []) or []
            ids = res.get("ids", []) or []
            log(f"[MEMORY_READ] get_by_date {collection} date={date} n={len(docs)}")
            return [{"id": i, "text": d, "metadata": m} for i, d, m in zip(ids, docs, metas)]
        except Exception:
            return []

    def get_all(self, collection: str, limit: int = 5000) -> list:
        if not self._ensure(wait=True):
            return []
        coll = self._coll(collection)
        if not coll:
            return []
        try:
            res = coll.get(limit=limit)
            return [{"id": i, "text": d, "metadata": m} for i, d, m in zip(
                res.get("ids", []) or [], res.get("documents", []) or [], res.get("metadatas", []) or [])]
        except Exception:
            return []

    def delete_ids(self, collection: str, ids: list) -> int:
        if not ids or not self._ensure(wait=True):
            return 0
        coll = self._coll(collection)
        if not coll:
            return 0
        try:
            coll.delete(ids=ids)
            return len(ids)
        except Exception:
            return 0

    def rebuild_techniques(self) -> dict:
        """Re-validate the techniques collection; delete junk; return valid/invalid/percent (req 4,6)."""
        recs = self.get_all("techniques")
        bad = [r["id"] for r in recs if not self._tech_valid(r)]
        deleted = self.delete_ids("techniques", bad)
        total = len(recs)
        valid = total - deleted
        pct = (valid / total * 100.0) if total else 0.0
        log(f"[MEMORY_REBUILD] techniques: {valid}/{total} valid ({pct:.1f}%), deleted {deleted} junk")
        return {"total": total, "valid": valid, "invalid": deleted, "valid_pct": pct}

    def technique_validity(self) -> dict:
        """Validity stats without deleting (for /memory display)."""
        recs = self.get_all("techniques")
        total = len(recs)
        valid = sum(1 for r in recs if self._tech_valid(r))
        pct = (valid / total * 100.0) if total else 0.0
        return {"total": total, "valid": valid, "invalid": total - valid, "valid_pct": pct}

    @staticmethod
    def _tech_valid(r: dict) -> bool:
        # Command-derived (pentest) techniques are kept; learner/search snippets must be actionable.
        if (r.get("metadata") or {}).get("command"):
            return True
        return is_actionable_technique(r.get("text", ""))

    def delete_old(self, collection: str, older_than_days: int = 90):
        if not self._ensure():
            return
        coll = self._coll(collection)
        if not coll:
            return
        try:
            cutoff = time.time() - (older_than_days * 86400)
            coll.delete(where={"timestamp": {"$lt": cutoff}})
        except Exception as e:
            _swallow(e)

    def summary(self) -> str:
        if not self.ready:
            return "Memory: chromadb not installed (pip install chromadb)"
        try:
            cols = self.client.list_collections()
            parts = [f"Memory ({len(cols)} collections):"]
            for c in cols:
                parts.append(f"  {c.name}: {c.count()} entries")
            return "\n".join(parts)
        except Exception:
            return "Memory: unknown status"

    def similar_techniques(self, target: str, n: int = 5) -> list:
        """Semantic search for techniques similar to target context."""
        return self.query("techniques", f"pentesting {target} techniques", n=n)

    def similar_findings(self, target: str, n: int = 5) -> list:
        """Semantic search for findings similar to target context."""
        return self.query("lessons", f"vulnerability findings {target}", n=n)

    def similar_lessons(self, target: str, n: int = 5) -> list:
        """Semantic search for past-session lessons relevant to this target context.
        Used to inject cross-session 'what worked / what didn't' into the AI prompt
        so it doesn't repeat past mistakes and can lean on past wins."""
        return self.query("lessons", f"pentest lessons learned {target}", n=n)

    def get_user_profile(self, n: int = 5) -> list:
        """Get user preference patterns."""
        return self.query("profile", "user preferences pentesting", n=n)

    def export_to_sqlite(self, sqlite_db: "SQLDatabase"):
        """Export all ChromaDB vectors to SQL for unified querying."""
        if not self.ready:
            return
        for coll_name in ["techniques", "lessons", "conversations", "profile"]:
            try:
                coll = self._coll(coll_name)
                if coll:
                    all_docs = coll.get()
                    if all_docs and all_docs.get("documents"):
                        for doc, meta in zip(all_docs["documents"], all_docs.get("metadatas", [{}])):
                            if coll_name == "techniques":
                                sqlite_db.save_technique(
                                    doc[:500], meta.get("category", "other"),
                                    meta.get("target", ""), meta.get("success", False)
                                )
                            elif coll_name == "lessons":
                                sqlite_db.save_finding(
                                    meta.get("target", ""), meta.get("severity", "info"),
                                    meta.get("title", "Unknown"), doc[:200], ""
                                )
            except Exception as e:
                _swallow(e)


class PGVectorMemory:
    """PostgreSQL with pgvector extension for vector similarity search.

    Requires: CREATE EXTENSION IF NOT EXISTS vector;
    Tables use vector(1536) for OpenAI embeddings or vector(384) for smaller models.
    """

    def __init__(self):
        self.ready = False
        self._conn: Optional[Any] = None
        self._embedding_dim = 384  # Default for sentence-transformers/all-MiniLM-L6-v2
        self._init_pgvector()

    def _init_pgvector(self):
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
            cur = self._conn.cursor()
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
            self._conn.commit()
            self.ready = True
        except ImportError:
            pass
        except Exception as e:
            print(f"{C.R}[!] PGVector init failed: {e}{C.N}")

    def _get_embedding(self, text: str) -> List[float]:
        """Generate embedding using sentence-transformers if available, else simple hash."""
        try:
            from sentence_transformers import SentenceTransformer
            model = SentenceTransformer('all-MiniLM-L6-v2')
            return model.encode(text).tolist()
        except ImportError:
            # Fallback: simple hash-based embedding
            import hashlib
            h = int(hashlib.md5(text.encode()).hexdigest()[:8], 16)
            return [float((h >> (i % 32)) & 1) for i in range(self._embedding_dim)]

    def add(self, collection: str, text: str, metadata: dict = None, doc_id: str = None):
        """Add document with embedding to pgvector table."""
        if not self.ready or not self._conn:
            return
        metadata = metadata or {}
        embedding = self._get_embedding(text)
        try:
            cur = self._conn.cursor()
            table = f"x19_{collection}"
            cur.execute(f"""
                INSERT INTO {table} (id, text, embedding, metadata, timestamp)
                VALUES (%s, %s, %s, %s, NOW())
            """, (doc_id or str(time.time()), text[:2000], embedding, json.dumps(metadata)))
            self._conn.commit()
        except Exception as e:
            print(f"{C.R}[!] PGVector add failed: {e}{C.N}")

    def query(self, collection: str, query: str, n: int = 5, where: dict = None) -> list:
        """Semantic similarity search using pgvector."""
        if not self.ready or not self._conn:
            return []
        query_emb = self._get_embedding(query)
        try:
            cur = self._conn.cursor()
            table = f"x19_{collection}"
            # Using cosine similarity (1 - distance)
            cur.execute(f"""
                SELECT text, metadata, 1 - (embedding <=> %s) as similarity
                FROM {table}
                ORDER BY embedding <=> %s
                LIMIT %s
            """, (query_emb, query_emb, n))
            rows = cur.fetchall()
            return [{"text": r[0], "metadata": r[1], "distance": 1 - r[2]} for r in rows]
        except Exception:
            return []

    def count(self, collection: str) -> int:
        if not self.ready or not self._conn:
            return 0
        try:
            cur = self._conn.cursor()
            cur.execute(f"SELECT COUNT(*) FROM x19_{collection}")
            return cur.fetchone()[0]
        except Exception:
            return 0

    def summary(self) -> str:
        if not self.ready:
            return "PGVector: postgres/pgvector not available"
        try:
            cur = self._conn.cursor()
            cur.execute("SELECT tablename FROM pg_tables WHERE tablename LIKE 'x19_%'")
            tables = cur.fetchall()
            parts = ["PGVector Memory:"]
            for t in tables:
                cur.execute(f"SELECT COUNT(*) FROM {t[0]}")
                cnt = cur.fetchone()[0]
                parts.append(f"  {t[0]}: {cnt} entries")
            return "\n".join(parts)
        except Exception:
            return "PGVector: error"


class BackgroundLearner:
    """Proactive daily learning thread. Searches DuckDuckGo for CVEs, techniques, news."""

    def __init__(self, memory: ChromaMemory):
        self.memory = memory
        self.running = False
        self.thread = None
        self._last_file = CONFIG_DIR / "last_learn.txt"
        self._dataset_index_file = CONFIG_DIR / "dataset_index.json"
        self._stats = {"cycles": 0, "articles": 0}

    def _dataset_dirs(self) -> List[Path]:
        """Return configured/project local dataset directories."""
        dirs: List[Path] = []
        raw = os.getenv("X19_DATASETS_DIR") or load_config().get("DATASETS_DIR", "")
        if raw:
            for part in str(raw).split(os.pathsep):
                part = part.strip()
                if part:
                    dirs.append(Path(part).expanduser())
        dirs.append(Path(__file__).resolve().parent.parent / "datasets")
        dirs.append(Path.cwd() / "datasets")
        seen = set()
        out = []
        for d in dirs:
            key = str(d.resolve()) if d.exists() else str(d)
            if key not in seen:
                seen.add(key)
                out.append(d)
        return out

    def _dataset_files(self) -> List[Path]:
        """List local dataset files that can be indexed into memory."""
        exts = {".pdf", ".txt", ".md", ".json", ".csv", ".html", ".htm"}
        files: List[Path] = []
        seen = set()
        for directory in self._dataset_dirs():
            if not directory.exists():
                continue
            for p in sorted(directory.rglob("*")):
                if not p.is_file() or p.suffix.lower() not in exts:
                    continue
                if "__pycache__" in p.parts or p.name.startswith("."):
                    continue
                key = str(p.resolve())
                if key not in seen:
                    seen.add(key)
                    files.append(p)
        return files

    @staticmethod
    def _file_signature(path: Path) -> str:
        h = hashlib.sha256()
        try:
            with path.open("rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
        except Exception:
            return f"{path.stat().st_size}:{path.stat().st_mtime}"
        return h.hexdigest()

    def _load_dataset_index(self) -> dict:
        try:
            return json.loads(self._dataset_index_file.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_dataset_index(self, index: dict):
        try:
            self._dataset_index_file.write_text(json.dumps(index, indent=2), encoding="utf-8")
        except Exception as e:
            _swallow(e)

    def _read_pdf_text(self, path: Path) -> str:
        """Extract text from PDFs using pypdf/PyPDF2 or pdftotext when available."""
        texts = []
        try:
            try:
                from pypdf import PdfReader
            except ImportError:
                from PyPDF2 import PdfReader
            reader = PdfReader(str(path))
            for page in reader.pages:
                try:
                    text = page.extract_text() or ""
                except Exception:
                    text = ""
                if text.strip():
                    texts.append(text)
        except Exception:
            try:
                proc = subprocess.run(
                    ["pdftotext", str(path), "-"],
                    capture_output=True,
                    text=False,
                    timeout=60,
                    check=False,
                )
                proc.stdout = (proc.stdout or b"").decode("utf-8", errors="replace")
                proc.stderr = (proc.stderr or b"").decode("utf-8", errors="replace")
                if proc.returncode == 0 and proc.stdout.strip():
                    texts.append(proc.stdout)
            except Exception as e:
                log(f"[Dataset] PDF extraction failed for {path.name}: install pypdf/PyPDF2 or poppler-utils ({e})")
                return ""
        max_chars = int(os.getenv("X19_DATASET_MAX_TEXT_CHARS", "160000"))
        return "\n".join(texts)[:max_chars]

    def _read_dataset_text(self, path: Path) -> str:
        suffix = path.suffix.lower()
        if suffix == ".pdf":
            return self._read_pdf_text(path)
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            try:
                return path.read_text(encoding="latin-1", errors="ignore")
            except Exception:
                return ""

    @staticmethod
    def _split_text(text: str, chunk_chars: int = 1800, overlap: int = 250, min_chunk: int = 250) -> List[str]:
        text = re.sub(r"\s+", " ", text or "").strip()
        if not text:
            return []
        chunks: List[str] = []
        start = 0
        while start < len(text):
            end = min(start + chunk_chars, len(text))
            if end < len(text):
                sentence_cut = text.rfind(". ", start, end)
                newline_cut = text.rfind("\n", start, end)
                cut = sentence_cut if sentence_cut > newline_cut else newline_cut
                if cut > start + chunk_chars // 2:
                    end = cut + 1
            chunk = text[start:end].strip()
            if len(chunk) >= min_chunk:
                chunks.append(chunk)
            start = max(start + 1, end - overlap)
        return chunks

    @staticmethod
    def _dataset_category(path: Path) -> str:
        name = path.name.lower()
        if any(k in name for k in ("social", "deception", "persuasion", "body")):
            return "social_engineering"
        if "osint" in name:
            return "osint"
        if any(k in name for k in ("python", "black", "hat")):
            return "tooling"
        if any(k in name for k in ("exploit", "exploitation")):
            return "exploitation"
        if any(k in name for k in ("pentest", "penetration")):
            return "methodology"
        return "dataset"

    def learn_datasets_once(self) -> int:
        """Index local PDF/text datasets into Chroma memory once per file signature."""
        if _memory_disabled():
            return 0
        files = self._dataset_files()
        if not files:
            return 0
        index = self._load_dataset_index()
        chunk_chars = int(os.getenv("X19_DATASET_CHUNK_CHARS", "1800"))
        overlap = int(os.getenv("X19_DATASET_OVERLAP_CHARS", "250"))
        today = datetime.now().strftime("%Y-%m-%d")
        stored_total = 0
        files_seen = 0
        for path in files:
            files_seen += 1
            try:
                sig = self._file_signature(path)
                cached = index.get(str(path.resolve()), {})
                if cached.get("signature") == sig and cached.get("chunks", 0) > 0:
                    continue
                text = self._read_dataset_text(path)
                if not text:
                    continue
                chunks = self._split_text(text, chunk_chars=chunk_chars, overlap=overlap)
                if not chunks:
                    continue
                category = self._dataset_category(path)
                stored = 0
                for i, chunk in enumerate(chunks):
                    title = f"{path.name} — section {i + 1}/{len(chunks)}"
                    md = technique_metadata(
                        title,
                        category,
                        str(path),
                        {
                            "source": "local_dataset",
                            "dataset_file": str(path),
                            "dataset_name": path.name,
                            "chunk": i + 1,
                            "total_chunks": len(chunks),
                            "date": today,
                            "timestamp": time.time(),
                            "testing_steps": "Use as background methodology; verify against real target output before claiming a finding.",
                            "evidence_required": "Actual target output, request/response, or tool evidence proving impact.",
                        },
                    )
                    doc_id = f"dataset-{hashlib.sha256((str(path.resolve()) + ':' + str(i) + ':' + chunk[:120]).encode()).hexdigest()}"
                    if self.memory.add("techniques", chunk, md, doc_id=doc_id):
                        stored += 1
                if stored:
                    index[str(path.resolve())] = {
                        "signature": sig,
                        "size": path.stat().st_size,
                        "mtime": path.stat().st_mtime,
                        "chunks": stored,
                        "updated": datetime.now().isoformat(timespec="seconds"),
                    }
                    stored_total += stored
                    print(f"{C.G}[+] Datasets: indexed {stored}/{len(chunks)} chunks from {path.name}{C.N}")
            except Exception as e:
                log(f"[Dataset] failed to index {path}: {type(e).__name__}: {e}")
        self._save_dataset_index(index)
        if stored_total:
            print(f"{C.G}[+] Datasets: indexed {stored_total} chunks from {files_seen} local dataset file(s){C.N}")
        return stored_total

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True, name="x19-learner")
        self.thread.start()

    def stop(self):
        self.running = False

    def learn_now(self):
        """Force a learn cycle immediately."""
        return self.learn_datasets_once() + self._learn_cycle()

    def _loop(self):
        # Force an immediate learn on start
        try:
            self.learn_datasets_once()
            self._learn_cycle()
            self._save_ts()
        except Exception as e:
            _swallow(e)
        while self.running:
            try:
                if self._should_learn():
                    self._learn_cycle()
                    self._save_ts()
            except Exception as e:
                _swallow(e)
            time.sleep(3600)

    def _should_learn(self) -> bool:
        if not self._last_file.exists():
            return True
        try:
            last = float(self._last_file.read_text().strip())
            return (time.time() - last) > 3600
        except Exception:
            return True

    def _save_ts(self):
        try:
            self._last_file.write_text(str(time.time()))
        except Exception as e:
            _swallow(e)

    def _search(self, query: str, max_results: int = 5) -> list:
        results = []
        # Try DuckDuckGo first
        try:
            from ddgs import DDGS
            with DDGS() as ddgs:
                for r in ddgs.text(query, max_results=max_results):
                    href = r.get('href', '')
                    title = r.get('title', '')
                    snippet = f"Title: {title}\nBody: {r.get('body','')}\nSource: {href}"
                    results.append(snippet)
        except ImportError:
            try:
                from duckduckgo_search import DDGS
                with DDGS() as ddgs:
                    for r in ddgs.text(query, max_results=max_results):
                        href = r.get('href', '')
                        title = r.get('title', '')
                        snippet = f"Title: {title}\nBody: {r.get('body','')}\nSource: {href}"
                        results.append(snippet)
            except ImportError:
                pass
        except Exception as e:
            _swallow(e)
        # If DuckDuckGo returned nothing, try web search via requests
        if not results:
            try:
                import requests
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                url = f"https://html.duckduckgo.com/html/?q={requests.utils.quote(query)}"
                r = requests.get(url, headers=headers, timeout=10)
                if r.status_code == 200:
                    titles = re.findall(r'class="result__a"[^>]*>(.*?)</a>', r.text, re.DOTALL)
                    bodies = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', r.text, re.DOTALL)
                    sources = re.findall(r'class="result__url"[^>]*>(.*?)</a>', r.text, re.DOTALL)
                    for i in range(min(len(titles), max_results)):
                        t = re.sub(r'<[^>]+>', '', titles[i]).strip()
                        b = re.sub(r'<[^>]+>', '', bodies[i]).strip() if i < len(bodies) else ''
                        s = re.sub(r'<[^>]+>', '', sources[i]).strip() if i < len(sources) else ''
                        results.append(f"Title: {t}\nBody: {b}\nSource: {s}")
            except Exception as e:
                _swallow(e)
        return results

    def _note(self, msg: str):
        try:
            log(f"[Learner] {msg}")
        except Exception as e:
            _swallow(e)

    def _learn_cycle(self) -> int:
        """Run one learning cycle. Returns articles learned."""
        self._stats["cycles"] += 1
        cycle = self._stats["cycles"]
        today = datetime.now().strftime("%Y-%m-%d")
        year = datetime.now().year
        queries = [
            # Critical CVEs and exploits
            f"critical CVE {year} proof of concept exploit",
            f"remote code execution CVE {year}",
            f"actively exploited vulnerabilities {year}",
            f"CVE {year} exploit github",
            # Web security - expanded (bug bounty / offensive appsec topics)
            f"web vulnerability new technique {year}",
            "bug bounty writeup critical severity",
            "subdomain enumeration advanced technique",
            "API security vulnerability exploit",
            f"XSS bypass WAF {year}",
            f"SQL injection bypass filter {year}",
            f"SSRF cloud metadata {year}",
            f"GraphQL introspection {year}",
            f"JWT attack authentication bypass {year}",
            # OAuth/OIDC + authz/authn logic bugs
            f"oauth misconfiguration account takeover {year}",
            f"oidc id token validation bypass {year}",
            f"open redirect account takeover {year}",
            f"SSRF + cloud metadata chain exploit {year}",
            # IDOR/BOLA, business logic, privilege issues
            f"idor graphql authorization bypass {year}",
            f"broken object level authorization exploit {year}",
            f"horizontal privilege escalation business logic {year}",
            # Injection classes
            f"template injection exploit {year}",
            f"prototype pollution vulnerability exploit {year}",
            f"cache poisoning vulnerability exploit {year}",
            f"http request smuggling exploit {year}",
            f"cors misconfiguration token leakage {year}",
            f"deserialization vulnerability remote code execution {year}",
            f"insecure file upload bypass extension spoof {year}",
            # Web framework-specific
            f"laravel jwt auth bypass vulnerability {year}",
            f"fastapi dependency injection bypass vulnerability {year}",
            f"spring boot actuator exposure exploit {year}",
            f"nextjs server actions exploit {year}",
            # DB/exposure classes
            f".env secrets exposure exploit {year}",
            f"database dump misconfiguration exploit {year}",
            f"backup file disclosure exploit {year}",
            # Rate-limit / WAF evasion related
            f"rate limit bypass techniques {year}",
            f"waf bypass technique payload encoding {year}",
            # Token / session attacks
            f"session fixation vulnerability exploit {year}",
            f"jwt alg none attack {year}",
            # Automation/tooling
            f"nuclei template bypass ideas {year}",
            "best recon methodology bug bounty",
            f"web vuln to rce chain {year}",
            # Infrastructure - expanded
            f"Active Directory attack technique {year}",
            f"cloud security exploit AWS Azure GCP {year}",
            "Kubernetes container escape exploit",
            "LDAP injection attack",
            "SMB relay attack",
            "SSH key reuse attack",
            # Tools & methodology - expanded
            "new pentesting tool 2025 2026",
            "best recon methodology bug bounty",
            "red team technique adversary simulation",
            f"nuclei templates new {year}",
            f"subfinder amass recon {year}",
            "ffuf payload bypass",
            # Evasion & post-exploitation
            f"EDR bypass technique {year}",
            f"AMSI bypass powershell {year}",
            "living off the land binaries lolbins",
            f"proxy tunnel chisel ligolo {year}",
            "SSH tunneling pivoting",
            # Mobile & exploit dev
            "Android pentesting bypass root detection",
            "iOS pentesting keychain dump",
            "buffer overflow exploit development",
            # Cloud-specific
            "AWS IAM privilege escalation",
            "Azure AD Connect attack",
            "GCP metadata SSRF",
            # Internal tools
            "open source security tools github",
            "network scanning recon tools",
        ]
        total = 0
        for q in queries:
            results = self._search(q, max_results=5)
            for r in results:
                if not is_actionable_technique(r):
                    continue  # reject dictionary/marketing/generic pages (req 1,2)
                name = (re.search(r'Title:\s*(.+)', r) or [None, q]).__getitem__(1).strip()[:160] \
                    if re.search(r'Title:\s*(.+)', r) else q
                src = (re.search(r'Source:\s*(\S+)', r).group(1) if re.search(r'Source:\s*(\S+)', r) else "ddg-search")
                if self.memory.add("techniques", r, technique_metadata(name, "web", src, {
                    "query": q, "date": today, "cycle": cycle, "timestamp": time.time(),
                    "testing_steps": q,
                })):
                    total += 1
        # Independent open-source feeds (structured JSON, no API key) — keep learning even when DuckDuckGo is down.
        total += self._learn_github_advisories()
        if total == 0:
            log("[Learner] 0 techniques stored — DuckDuckGo down and GitHub advisories empty")
        cve_count = self._learn_cve_updates() + self._learn_cisa_kev()
        self._stats["articles"] += total + cve_count
        log(f"[Learner] Cycle {cycle}: {total} techniques + {cve_count} CVEs ({self._stats['articles']} total)")
        return total + cve_count

    def _learn_cve_updates(self) -> int:
        """Fetch the last 24h of high/critical CVEs from the NVD API into memory."""
        from datetime import timedelta
        learned = 0
        try:
            now = datetime.now()
            resp = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={
                    "resultsPerPage": 100,
                    "startIndex": 0,
                    "pubStartDate": (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
                },
                timeout=30,
            )
            for cve in resp.json().get("vulnerabilities", []):
                c = cve.get("cve", {})
                cve_id = c.get("id", "")
                descs = c.get("descriptions", [])
                description = descs[0].get("value", "") if descs else ""
                metrics = c.get("metrics", {}).get("cvssMetricV31") or []
                severity = metrics[0]["cvssData"]["baseScore"] if metrics else 0
                if severity >= 7.0:
                    if self.memory.add("cves", f"CVE: {cve_id} - {description}", {
                        "severity": severity,
                        "date": now.strftime("%Y-%m-%d"),
                        "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        "source": "nvd",
                    }):
                        learned += 1
        except Exception as e:
            log(f"[!] CVE update failed: {e}")
        return learned

    def _learn_cisa_kev(self) -> int:
        """CISA Known Exploited Vulnerabilities — actively-exploited CVEs (JSON, no API key)."""
        from datetime import timedelta
        learned = 0
        today = datetime.now().strftime("%Y-%m-%d")
        cutoff = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")  # ISO dates compare lexicographically
        try:
            resp = requests.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                timeout=30,
            )
            for v in resp.json().get("vulnerabilities", []):
                if (v.get("dateAdded") or "") < cutoff:
                    continue
                cid = v.get("cveID", "")
                text = f"CVE: {cid} - [KEV/actively-exploited] {v.get('vulnerabilityName','')}: {v.get('shortDescription','')}"
                if self.memory.add("cves", text, {
                    "severity": "kev", "date": today, "source": "cisa_kev",
                    "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                }, doc_id=f"kev-{cid}"):
                    learned += 1
        except Exception as e:
            log(f"[!] CISA KEV update failed: {e}")
        return learned

    def _learn_github_advisories(self) -> int:
        """GitHub Advisory Database — recent security advisories with sources (JSON, no API key)."""
        learned = 0
        today = datetime.now().strftime("%Y-%m-%d")
        try:
            resp = requests.get(
                "https://api.github.com/advisories",
                params={"per_page": 100, "sort": "published", "direction": "desc"},
                headers={"Accept": "application/vnd.github+json", "User-Agent": "x19-learner"},
                timeout=30,
            )
            data = resp.json()
            for a in data if isinstance(data, list) else []:
                if (a.get("published_at") or "")[:10] != today:
                    continue
                gid = a.get("ghsa_id", "")
                text = f"[{gid}] {a.get('summary','')} — severity={a.get('severity','')} cve={a.get('cve_id','')}"
                if not is_actionable_technique(text):
                    continue
                if self.memory.add("techniques", text, technique_metadata(
                    a.get("summary", gid), a.get("type", "web"),
                    a.get("html_url") or "https://github.com/advisories",
                    {"date": today, "testing_steps": "review advisory, reproduce against affected version",
                     "evidence_required": f"confirm affected version + PoC for {a.get('cve_id','')}"},
                ), doc_id=f"ghsa-{gid}"):
                    learned += 1
        except Exception as e:
            log(f"[!] GitHub advisory update failed: {e}")
        return learned
