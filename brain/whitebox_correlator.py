"""White-box correlator — Shannon 96.15% pattern.

Shannon's edge over black-box agents is source↔dynamic correlation: static
analysis proposes a vector, live exploitation proves it, and the report ties
them to an exact source location + working exploit.

X19 is black-box by default. When the operator optionally shares repo/API
artifacts, this module correlates them to dynamic findings without making
white-box mandatory. It never trusts LLM-supplied source claims — it only
links artifacts the operator actually provided.

Usage:
  correlator = WhiteboxCorrelator(artifacts_dir="/path/to/repo")
  correlator.ingest_artifacts()  # index files
  edge = correlator.correlate(finding)  # returns source location hint or None
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class SourceLocation:
    file: str
    line: int
    snippet: str
    confidence: float = 0.6


@dataclass
class Correlation:
    finding_title: str
    source_loc: Optional[SourceLocation] = None
    evidence: str = ""
    confidence: float = 0.0
    reason: str = ""


# Light static heuristics — no hardcoded exploit payloads, just structural patterns
# that the correlator can flag as *candidate* vectors the dynamic engine already proved.


_PATTERNS: List[tuple[str, re.Pattern, str]] = [
    ("sql_concat", re.compile(r"(SELECT|INSERT|UPDATE).*?\$\{.*?\}|query\s*\+.*request\.", re.I), "string-concatenated query"),
    ("xss_sink", re.compile(r"innerHTML\s*=|dangerouslySetInnerHTML|document\.write\(.*location\.", re.I), "DOM sink"),
    ("ssrf_sink", re.compile(r"requests\.(get|post)\(.*request\.(args|form|json)|fetch\(.*req\.", re.I), "request-controlled fetch"),
    ("idor_param", re.compile(r"@PathParam.*id|get.*ById\(.*id|findById\(.*\)", re.I), "IDOR-prone param"),
    ("jwt_none", re.compile(r"alg.*none|verify.*false|JWT.*no.*verify", re.I), "JWT none/unsigned"),
    ("env_exposure", re.compile(r"process\.env|dotenv|DB_PASSWORD|SECRET_KEY", re.I), "env/secret exposure"),
]


class WhiteboxCorrelator:
    """Optional correlation engine. Safe to instantiate with no artifacts — it simply
    reports no correlation (black-box mode)."""

    def __init__(self, artifacts_dir: Optional[str | Path] = None, max_files: int = 400):
        self.artifacts_dir: Optional[Path] = Path(artifacts_dir).expanduser().resolve() if artifacts_dir else None
        self.max_files = max_files
        self._index: List[tuple[Path, str]] = []  # (path, content preview)
        self._indexed = False

    def ingest_artifacts(self) -> str:
        if self.artifacts_dir is None or not self.artifacts_dir.exists():
            return "whitebox: no artifacts dir — black-box mode (no correlation)"
        count = 0
        for p in self.artifacts_dir.rglob("*"):
            if count >= self.max_files:
                break
            if not p.is_file():
                continue
            if p.suffix.lower() not in {".py", ".js", ".ts", ".java", ".go", ".php", ".rb", ".cs", ".html", ".json", ".xml", ".yaml", ".yml"}:
                continue
            # skip vendored deps
            if any(seg in {"node_modules", ".git", "vendor", "dist", "build", "__pycache__"} for seg in p.parts):
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")[:8000]
            except Exception:
                continue
            self._index.append((p, text))
            count += 1
        self._indexed = True
        return f"whitebox: indexed {len(self._index)} files from {self.artifacts_dir}"

    def correlate(self, finding: Any) -> Correlation:
        title = str(getattr(finding, "title", "") or getattr(finding, "get", lambda k,d: d)("title","") or "finding")
        evidence = str(getattr(finding, "evidence", "") or getattr(finding, "get", lambda k,d: d)("evidence","") or "")[:500]
        # heuristic: map finding family to pattern
        fam = title.lower() + " " + evidence.lower()
        best: Optional[tuple[str, re.Pattern, str]] = None
        for name, pat, desc in _PATTERNS:
            if name in fam or pat.search(fam):
                best = (name, pat, desc)
                break
        if best is None:
            # fallback by title keyword
            for name, pat, desc in _PATTERNS:
                if name.split("_")[0] in fam:
                    best = (name, pat, desc)
                    break
        if best is None or not self._indexed or not self._index:
            return Correlation(finding_title=title, evidence=evidence, reason="no white-box correlation (black-box mode or no matching pattern)")

        name, pat, desc = best
        # search indexed files for pattern hits
        for path, content in self._index:
            m = pat.search(content)
            if m:
                idx = m.start()
                line_no = content[:idx].count("\n") + 1
                snippet = content[max(0, idx-60): idx+120].replace("\n", " ")[:180]
                # confidence based on finding severity + pattern match
                conf = 0.65
                if "critical" in fam or "high" in fam:
                    conf = 0.75
                return Correlation(
                    finding_title=title,
                    source_loc=SourceLocation(file=str(path), line=line_no, snippet=snippet, confidence=conf),
                    evidence=evidence,
                    confidence=conf,
                    reason=f"static pattern '{name}' ({desc}) matches dynamic finding",
                )
        return Correlation(finding_title=title, evidence=evidence, reason=f"pattern '{name}' matched but no source file hit in indexed artifacts")

    def context_block(self) -> str:
        if not self._indexed:
            return ""
        return f"WHITE-BOX: indexed {len(self._index)} files; correlator ready — findings may include source location when matched"
