"""Lightweight MITRE ATLAS tagging for AI-security evidence.

ATLAS is a threat knowledge base for adversarial AI systems. X19 stores tags
as provenance metadata only; a tag never upgrades severity or proves impact.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass(frozen=True)
class AtlasTechnique:
    technique_id: str
    name: str
    tactic: str = ""
    source: str = "MITRE ATLAS"


# Stable high-signal entries used by the telemetry layer. Keep this registry
# intentionally small and evidence-oriented; unknown techniques are allowed.
TECHNIQUES: Dict[str, AtlasTechnique] = {
    "AML.T0051": AtlasTechnique("AML.T0051", "Prompt Injection"),
    "AML.T0052": AtlasTechnique("AML.T0052", "Phishing"),
}


def tags_for_metadata(metadata: Dict[str, Any] | None) -> List[Dict[str, str]]:
    metadata = metadata or {}
    raw = metadata.get("atlas_techniques", metadata.get("atlas", []))
    if isinstance(raw, str):
        raw = [raw]
    tags: List[Dict[str, str]] = []
    for value in raw if isinstance(raw, (list, tuple)) else []:
        key = str(value).strip().upper()
        item = TECHNIQUES.get(key)
        if item:
            tags.append({"id": item.technique_id, "name": item.name, "source": item.source})
        else:
            tags.append({"id": key, "name": "Unresolved ATLAS technique", "source": item.source if item else "MITRE ATLAS"})
    return tags


def attach_atlas(metadata: Dict[str, Any] | None) -> Dict[str, Any]:
    result = dict(metadata or {})
    tags = tags_for_metadata(result)
    if tags:
        result["atlas_tags"] = tags
    return result
