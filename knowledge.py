"""Dynamic cybersecurity knowledge layer for X19.

Design constraints (from the autonomy audits):
- **Not hardcoded**: facts come from live feeds at runtime — CISA KEV, NVD
  API 2.0, FIRST EPSS, local searchsploit — plus an optional user-owned
  corpus. Shipping a CVE list in code is exactly what this module replaces.
- **Focused, not a prompt dump**: knowledge is retrieved by what the target
  actually runs (world-model tech stack), version-matched where possible,
  sorted by exploitation signal, and hard-capped in size.
- **Real-time but resilient**: every source is disk-cached with a TTL under
  ``CONFIG_DIR/cache/intel``; on network failure the cached copy (even a
  stale one, clearly labelled) keeps the agent informed. No source error ever
  propagates — worst case is an empty intel block.
- **Custom layer**: users drop markdown/txt notes into ``CONFIG_DIR/knowledge``
  (or ``X19_KNOWLEDGE_DIR``); they are chunked and embedded into the vector
  store's ``intel`` collection for semantic recall — the agent's private,
  engagement-specific brain.

Sources are pluggable via ``X19_INTEL_SOURCES`` (comma list of source names,
default "kev,nvd"); ``X19_INTEL_DISABLE=1`` turns the layer off entirely.
An optional ``NVD_API_KEY`` env raises NVD rate limits.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from config import CONFIG_DIR
from logging_utils import log

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"

# Fleet mode runs several X19 loops per process; ingestion touches the
# SHARED corpus_state.json and the shared vector store, so serialize it.
_INGEST_LOCK = threading.Lock()

CACHE_DIR = CONFIG_DIR / "cache" / "intel"
KNOWLEDGE_DIR = Path(os.getenv("X19_KNOWLEDGE_DIR") or (CONFIG_DIR / "knowledge"))

KEV_TTL = 12 * 3600        # KEV catalog updates daily
NVD_TTL = 24 * 3600        # product lookups are stable within a day
EPSS_TTL = 6 * 3600

CHAR_CAP = 2800            # hard cap on the rendered intel block
MAX_ITEMS = 6
ITEM_CAP = 230             # per-item text cap


def _intel_disabled() -> bool:
    return (os.getenv("X19_INTEL_DISABLE", "") or "").strip().lower() in ("1", "true", "yes", "on")


def _enabled_sources() -> set:
    raw = (os.getenv("X19_INTEL_SOURCES", "") or "").strip().lower()
    return {s.strip() for s in raw.split(",") if s.strip()} if raw else {"kev", "nvd"}


def _cache_read(name: str, ttl: int) -> Optional[dict]:
    """Return cached payload dict if present and fresh, else None (path kept)."""
    try:
        path = CACHE_DIR / f"{name}.json"
        if not path.exists():
            return None
        blob = json.loads(path.read_text())
        fetched = float(blob.get("fetched_at", 0) or 0)
        if time.time() - fetched > ttl:
            return None
        return blob
    except Exception as e:
        log(f"[INTEL] cache read {name}: {e}")
        return None


def _cache_write(name: str, data: Any) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        (CACHE_DIR / f"{name}.json").write_text(
            json.dumps({"fetched_at": time.time(), "data": data}))
    except Exception as e:
        log(f"[INTEL] cache write {name}: {e}")


def _cache_age(name: str) -> float:
    try:
        blob = json.loads((CACHE_DIR / f"{name}.json").read_text())
        return max(0.0, time.time() - float(blob.get("fetched_at", 0) or 0))
    except Exception:
        return float("inf")


@dataclass
class IntelItem:
    """One knowledge item relevant to something the target runs."""
    product: str = ""
    cve: str = ""
    title: str = ""
    cvss: float = 0.0
    known_exploited: bool = False
    ransomware: bool = False
    public_exploit: bool = False
    epss: float = -1.0          # -1 = unknown/not fetched
    version_matched: bool = False
    source: str = ""
    detail: str = ""

    def sort_key(self) -> tuple:
        return (
            0 if self.known_exploited else 1,
            0 if self.version_matched else 1,
            -self.epss if self.epss >= 0 else -self.cvss / 10.0,
            -self.cvss,
        )

    def render(self) -> str:
        flags = []
        if self.known_exploited:
            flags.append("KEV: actively exploited")
        if self.ransomware:
            flags.append("ransomware-linked")
        if self.public_exploit:
            flags.append("public PoC")
        if self.epss >= 0:
            flags.append(f"EPSS {self.epss:.2f}")
        if self.cvss:
            flags.append(f"CVSS {self.cvss:.1f}")
        head = f"{self.cve}: {self.title}" if self.cve else self.title
        text = f"[{self.product or self.source}] {head}"
        if flags:
            text += " (" + ", ".join(flags) + ")"
        if self.detail:
            text += f" — {self.detail}"
        if not self.version_matched and self.product:
            text += " [verify version applies]"
        return text[:ITEM_CAP]


class KnowledgeLayer:
    """Facade the agent talks to. All methods are failure-tolerant."""

    def __init__(self, memory=None):
        self._memory = memory            # ChromaMemory-like; may be None
        self._ingest_state_file = CACHE_DIR / "corpus_state.json"
        self._sploit_cache: Dict[str, List[str]] = {}
        self._epss_cache: Dict[str, float] = {}

    # ------------------------------------------------------------------
    # Source: CISA KEV (product-level "actively exploited" signal)
    # ------------------------------------------------------------------
    def kev_entries(self) -> List[dict]:
        if _intel_disabled() or "kev" not in _enabled_sources():
            return []
        blob = _cache_read("kev", KEV_TTL)
        if blob is None:
            data: List[dict] = []
            try:
                r = requests.get(KEV_URL, timeout=20)
                r.raise_for_status()
                data = [
                    {
                        "cve": str(v.get("cveID") or "").upper(),
                        "vendor": str(v.get("vendorProject") or ""),
                        "product": str(v.get("product") or ""),
                        "title": str(v.get("vulnerabilityName") or ""),
                        "ransomware": str(v.get("knownRansomwareCampaignUse") or "").lower()
                                      == "known",
                    }
                    for v in r.json().get("vulnerabilities", [])
                    if v.get("cveID")
                ]
                _cache_write("kev", data)
            except Exception as e:
                log(f"[INTEL] KEV fetch failed: {e}")
                stale = _cache_read("kev", 10 * 365 * 24 * 3600)  # any age
                if stale:
                    blob = stale
            else:
                blob = {"data": data}
        return list(blob.get("data") or []) if blob else []

    # ------------------------------------------------------------------
    # Source: NVD 2.0 keyword search (version-aware CVE facts)
    # ------------------------------------------------------------------
    def nvd_lookup(self, product: str) -> List[dict]:
        if _intel_disabled() or "nvd" not in _enabled_sources():
            return []
        key = "nvd_" + hashlib.md5(product.lower().encode()).hexdigest()[:10]
        blob = _cache_read(key, NVD_TTL)
        if blob is None:
            items: List[dict] = []
            try:
                headers = {"apiKey": os.getenv("NVD_API_KEY")} if os.getenv("NVD_API_KEY") else {}
                r = requests.get(
                    NVD_URL,
                    params={"keywordSearch": product, "resultsPerPage": 12},
                    headers=headers, timeout=20)
                r.raise_for_status()
                for wrapper in r.json().get("vulnerabilities", []):
                    cve = wrapper.get("cve") or {}
                    cid = str(cve.get("id") or "")
                    if not cid.startswith("CVE-"):
                        continue
                    desc = ""
                    for d in cve.get("descriptions", []):
                        if d.get("lang") == "en":
                            desc = str(d.get("value") or "")
                            break
                    score, severity = 0.0, ""
                    metrics = cve.get("metrics") or {}
                    for metric_name in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        if metric_name in metrics:
                            cd = metrics[metric_name][0].get("cvssData") or {}
                            score = float(cd.get("baseScore") or 0)
                            severity = str(cd.get("baseSeverity") or "")
                            break
                    refs = cve.get("references") or []
                    has_poc = any(
                        "exploit" in str(tag).lower()
                        for ref in refs for tag in (ref.get("tags") or []))
                    items.append({
                        "cve": cid,
                        "title": (severity or "vulnerability") + f" {cid}",
                        "detail": desc,
                        "cvss": score,
                        "public_exploit": has_poc,
                        "published": str(cve.get("published") or "")[:10],
                    })
                _cache_write(key, items)
            except Exception as e:
                log(f"[INTEL] NVD lookup '{product}': {e}")
                stale = _cache_read(key, 10 * 365 * 24 * 3600)
                if stale:
                    blob = stale
            else:
                blob = {"data": items}
        return list(blob.get("data") or []) if blob else []

    # ------------------------------------------------------------------
    # Source: FIRST EPSS (per-CVE exploitation probability)
    # ------------------------------------------------------------------
    def epss(self, cve: str) -> float:
        if not cve or _intel_disabled():
            return -1.0
        cve = cve.upper()
        if cve in self._epss_cache:
            return self._epss_cache[cve]
        val = -1.0
        blob = _cache_read(f"epss_{cve}", EPSS_TTL)
        if blob is None:
            try:
                r = requests.get(EPSS_URL, params={"cve": cve}, timeout=10)
                data = r.json().get("data", [])
                if data:
                    val = float(data[0].get("epss") or 0.0)
                _cache_write(f"epss_{cve}", val)
            except Exception as e:
                log(f"[INTEL] EPSS {cve}: {e}")
                stale = _cache_read(f"epss_{cve}", 10 * 365 * 24 * 3600)
                if stale is not None:
                    val = float(stale.get("data") or 0.0)
        else:
            val = float(blob.get("data") or 0.0)
        self._epss_cache[cve] = val
        return val

    # ------------------------------------------------------------------
    # Source: local searchsploit (public PoC titles, if installed)
    # ------------------------------------------------------------------
    def public_exploits(self, product: str) -> List[str]:
        if product in self._sploit_cache:
            return self._sploit_cache[product]
        titles: List[str] = []
        try:
            import subprocess
            p = subprocess.run(["searchsploit", "--json", product],
                               capture_output=True, text=False, timeout=30)
            so = (p.stdout or b"").decode("utf-8", errors="replace")
            titles = [str(e.get("Title") or "")
                      for e in json.loads(so or "{}").get("RESULTS_EXPLOIT", [])][:8]
        except FileNotFoundError:
            pass
        except Exception as e:
            log(f"[INTEL] searchsploit '{product}': {e}")
        self._sploit_cache[product] = titles
        return titles

    # ------------------------------------------------------------------
    # Correlation: target tech stack → focused intel items
    # ------------------------------------------------------------------
    def product_intel(self, tech_stack: Dict[str, str]) -> List[IntelItem]:
        """Match the live feeds against what the target actually runs."""
        if not tech_stack:
            return []
        kev = self.kev_entries()
        kev_l = [
            (k, f"{k.get('vendor','')} {k.get('product','')}".lower())
            for k in kev
        ]
        out: List[IntelItem] = []
        for name, version in list(tech_stack.items())[:8]:
            name_l = str(name or "").lower().strip()
            if not name_l:
                continue
            # KEV is product-level (no versions) — match by name overlap.
            for k, hay in kev_l:
                if name_l in hay or any(part and part in hay
                                        for part in name_l.split()[:2]):
                    out.append(IntelItem(
                        product=str(name), cve=k["cve"], title=k["title"] or "exploited in the wild",
                        known_exploited=True, ransomware=k["ransomware"],
                        source="cisa-kev"))
                    break  # one KEV hit per product keeps the block focused
            # NVD gives version-aware facts; enrich the best matches.
            for item in self.nvd_lookup(str(name)):
                detail = item.get("detail") or ""
                matched = bool(version) and str(version) in detail
                if item.get("cvss", 0) >= 7.0 or matched or item.get("public_exploit"):
                    out.append(IntelItem(
                        product=str(name), cve=item.get("cve", ""),
                        title="version-matched vulnerability" if matched
                              else f"candidate {item.get('cve','')}",
                        cvss=float(item.get("cvss") or 0),
                        public_exploit=bool(item.get("public_exploit")),
                        version_matched=matched, source="nvd",
                        detail=detail[:140]))
            if out and out[-1].source == "nvd" and out[-1].cve:
                out[-1].epss = self.epss(out[-1].cve)
        out.sort(key=lambda i: i.sort_key())
        return out[:MAX_ITEMS]

    # ------------------------------------------------------------------
    # Custom corpus: user-owned knowledge dir → vector store
    # ------------------------------------------------------------------
    def ingest_custom(self) -> int:
        """Ingest new/changed files from the knowledge dir. Returns chunks added.

        Files are chunked on paragraph boundaries; per-file content hashes make
        re-ingestion idempotent. Memory unavailable → 0, never raises.
        """
        memory = self._memory
        if memory is None:
            try:
                from memory import ChromaMemory, _memory_disabled
                if _memory_disabled():
                    return 0
                memory = ChromaMemory()
            except Exception as e:
                log(f"[INTEL] corpus ingestion unavailable: {e}")
                return 0
        with _INGEST_LOCK:   # fleet units share state + store — serialize
            return self._ingest_locked(memory)

    def _ingest_locked(self, memory) -> int:
        try:
            KNOWLEDGE_DIR.mkdir(parents=True, exist_ok=True)
            state: Dict[str, str] = {}
            try:
                state = json.loads(self._ingest_state_file.read_text())
            except Exception:
                state = {}
            added = 0
            for path in sorted(KNOWLEDGE_DIR.rglob("*")):
                if not path.is_file() or path.suffix.lower() not in (".md", ".txt", ".json"):
                    continue
                text = path.read_text(errors="replace")
                if not text.strip():
                    continue
                fhash = hashlib.sha1(text.encode()).hexdigest()[:12]
                rel = str(path.relative_to(KNOWLEDGE_DIR))
                if state.get(rel) == fhash:
                    continue
                for idx, chunk in enumerate(_chunks(text)):
                    cid = f"{fhash}{idx:03d}"
                    if memory.add("intel", chunk,
                                  metadata={"source": rel, "kind": "custom",
                                            "date": time.strftime("%Y-%m-%d")},
                                  doc_id=cid):
                        added += 1
                state[rel] = fhash
            self._ingest_state_file.parent.mkdir(parents=True, exist_ok=True)
            _tmp = self._ingest_state_file.with_suffix(".json.tmp")
            _tmp.write_text(json.dumps(state))
            os.replace(_tmp, self._ingest_state_file)   # atomic — no torn state
            return added
        except Exception as e:
            log(f"[INTEL] corpus ingestion failed: {e}")
            return 0

    def recall(self, query: str, n: int = 4) -> List[str]:
        """Semantic recall from the custom corpus."""
        memory = self._memory
        if memory is None:
            try:
                from memory import ChromaMemory, _memory_disabled
                if _memory_disabled():
                    return []
                memory = ChromaMemory()
            except Exception:
                return []
        try:
            if not getattr(memory, "ready", False):
                return []
            return [str(rec.get("text") or "")
                    for rec in memory.query("intel", query, n=n) if rec.get("text")]
        except Exception as e:
            log(f"[INTEL] recall: {e}")
            return []

    # ------------------------------------------------------------------
    # Rendering: the focused block injected into the decision context
    # ------------------------------------------------------------------
    def render_context(self, tech_stack: Dict[str, str], query: str = "") -> str:
        if _intel_disabled() or not (tech_stack or query):
            return ""
        sections: List[str] = []
        if tech_stack:
            items = self.product_intel(tech_stack)
            if items:
                lines = ["LIVE INTEL (real-time feeds, sorted by exploitation signal):"]
                for it in items:
                    lines.append(f"  - {it.render()}")
                kev_age = _cache_age("kev")
                if kev_age and kev_age != float("inf") and kev_age > KEV_TTL:
                    lines.append(f"  (feeds offline — intel cache is {int(kev_age // 3600)}h old)")
                lines.append(
                    "FOCUS: prioritize probes matching the intel above; intel marked "
                    "'verify version applies' may not affect this exact target version.")
                sections.append("\n".join(lines))
        if query:
            recalled = self.recall(query)
            if recalled:
                lines = ["CUSTOM KNOWLEDGE (your corpus):"]
                for rec in recalled[:3]:
                    lines.append(f"  - {rec[:200]}")
                sections.append("\n".join(lines))
        if not sections:
            return ""
        block = "\n\n".join(sections)
        if len(block) > CHAR_CAP:
            block = block[:CHAR_CAP - 3].rstrip() + "..."
        return block


def _chunks(text: str, size: int = 1100, overlap: int = 120) -> List[str]:
    """Paragraph-aware chunking for corpus ingestion."""
    paras = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    out: List[str] = []
    buf = ""
    for para in paras:
        if len(buf) + len(para) + 2 <= size:
            buf = f"{buf}\n{para}" if buf else para
            continue
        if buf:
            out.append(buf)
        if len(para) > size:
            for i in range(0, len(para), size - overlap):
                out.append(para[i:i + size])
            buf = ""
        else:
            buf = para
    if buf:
        out.append(buf)
    return out[:200]
