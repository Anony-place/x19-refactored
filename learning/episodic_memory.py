"""Episodic memory — PentAGI layered memory pattern.

PentAGI's 15.5k★ design has 3 layers: vector (pgvector long-term) + working
context + episodic history. X19 has Chroma vector + session + failure-memory,
but episodic (per-target run history → semantic recall) is thin. This module
closes that gap: every run's hypotheses/findings/failures become episodes that
future runs can semantically recall and correlate.

It is additive and storage-light: JSON file per target + optional Chroma
bridge when available. No Neo4j required; Graphiti bridge is optional.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Episode:
    target: str
    ts: float = field(default_factory=time.time)
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    failures: List[Dict[str, Any]] = field(default_factory=list)
    tech_stack: Dict[str, str] = field(default_factory=dict)
    ports: List[Dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    id: str = ""

    def __post_init__(self):
        if not self.id:
            h = hashlib.sha1(f"{self.target}{self.ts}{self.summary[:80]}".encode()).hexdigest()[:12]
            self.id = f"ep-{h}"


class EpisodicMemory:
    """Per-workspace episodic store. One JSONL file, plus optional Chroma semantic index."""

    def __init__(self, workspace: str | Path = "episodic"):
        self.workspace = Path(workspace).expanduser().resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.file = self.workspace / "episodes.jsonl"
        self._episodes: Optional[List[Episode]] = None

    def _load(self) -> List[Episode]:
        if self._episodes is not None:
            return self._episodes
        out: List[Episode] = []
        if self.file.exists():
            try:
                for line in self.file.read_text(encoding="utf-8").splitlines():
                    line=line.strip()
                    if not line:
                        continue
                    d = json.loads(line)
                    out.append(Episode(**{k: d.get(k, getattr(Episode, k, None)) for k in Episode.__dataclass_fields__}))
            except Exception:
                pass
        self._episodes = out
        return out

    def record(self, episode: Episode) -> str:
        eps = self._load()
        eps.append(episode)
        try:
            with self.file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(episode), ensure_ascii=False) + "\n")
        except Exception:
            pass
        # also try Chroma if available
        self._upsert_chroma(episode)
        return episode.id

    def _upsert_chroma(self, episode: Episode) -> None:
        try:
            from memory import get_memory  # X19 existing Chroma bridge
            mem = get_memory()
            if mem is None:
                return
            text = f"target {episode.target} tech {','.join(episode.tech_stack.keys())} findings {[f.get('title','') for f in episode.findings][:3]} summary {episode.summary[:300]}"
            mem.add(text, metadata={"episode_id": episode.id, "target": episode.target, "kind": "episodic"})
        except Exception:
            pass

    def recall(self, target: str, tech_stack: Dict[str,str] | None = None, top_k: int = 3) -> List[Episode]:
        """Deterministic recall: same-target first, then same-stack, then recent."""
        eps = self._load()
        if not eps:
            return []
        scored: List[tuple[float, Episode]] = []
        tech = set((tech_stack or {}).keys())
        for ep in eps:
            if ep.target == target:
                # don't recall self
                continue
            score = 0.0
            if ep.target and target and ep.target.split(":")[0] == target.split(":")[0]:
                score += 2.0  # same host
            ep_tech = set(ep.tech_stack.keys())
            if tech and ep_tech:
                jacc = len(tech & ep_tech) / max(1, len(tech | ep_tech))
                score += jacc * 1.5
                # shared stack bonus (NodeZero/HPTSA shared-stack pattern)
                if len(tech & ep_tech) >= 2:
                    score += 0.5
            # recency decay (last 30 days)
            age_days = (time.time() - ep.ts) / 86400
            if age_days < 30:
                score += (30 - age_days) / 60  # up to 0.5
            # findings quality
            if ep.findings:
                score += 0.3
            scored.append((score, ep))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [ep for s, ep in scored[:top_k] if s > 0.1]

    def correlate_failure(self, failure: Dict[str, Any], target: str) -> str:
        """Link a failure to past episodes that saw the same failure class."""
        eps = self.recall(target, top_k=5)
        klass = str(failure.get("class") or failure.get("kind") or "").lower()
        hits = []
        for ep in eps:
            for f in ep.failures:
                fk = str(f.get("class") or f.get("kind") or "").lower()
                if klass and fk == klass:
                    hits.append(ep.id)
        if hits:
            return f"episodic: failure class '{klass}' seen in {len(hits)} prior episodes ({', '.join(hits[:2])}) — consider strategy pivot (failure-memory correlated)"
        return ""

    def context_block(self, target: str, tech_stack: Dict[str,str]|None=None) -> str:
        recs = self.recall(target, tech_stack, top_k=3)
        if not recs:
            return ""
        lines = ["EPISODIC MEMORY (past runs you can learn from — not proof):"]
        for ep in recs:
            age = int((time.time() - ep.ts)/3600)
            findings = ", ".join(str(f.get("title",""))[:40] for f in ep.findings[:2]) or "no findings"
            lines.append(f"  {ep.id} {ep.target} {age}h ago tech={list(ep.tech_stack.keys())[:3]} → {findings}")
        return "\n".join(lines)

    def stats(self) -> Dict[str, Any]:
        eps = self._load()
        return {"episodes": len(eps), "file": str(self.file), "targets": len(set(e.target for e in eps))}
