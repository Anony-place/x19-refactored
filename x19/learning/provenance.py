"""
X19 Learning Loop with Provenance — FACT, OBSERVATION, LESSON, SKILL, HYPOTHESIS.

Reuses Hermes learning architecture (background_review, curator, learning_graph),
but adds separation with provenance to prevent unverified claims becoming permanent knowledge.

Provenance types:
- FACT: Verified fact from tool output or trusted source
- OBSERVATION: What tool saw, factual observation
- LESSON: Learned from success/failure, with evidence
- SKILL: Procedural knowledge, methodology that worked
- HYPOTHESIS: Unverified idea, needs testing

Never allow unverified model-generated claims to become permanent knowledge automatically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
import uuid


class ProvenanceType(str, Enum):
    """Provenance types for learning."""

    FACT = "FACT"  # Verified fact from tool output or trusted source
    OBSERVATION = "OBSERVATION"  # What tool saw
    LESSON = "LESSON"  # Learned from success/failure
    SKILL = "SKILL"  # Procedural knowledge
    HYPOTHESIS = "HYPOTHESIS"  # Unverified idea


class Confidence(str, Enum):
    """Confidence in learned info."""

    HIGH = "high"  # Verified, strong evidence
    MEDIUM = "medium"  # Likely, moderate evidence
    LOW = "low"  # Possible, weak evidence


@dataclass
class LearnedItem:
    """Single learned item with provenance."""

    id: str = field(default_factory=lambda: f"LEARN-{uuid.uuid4().hex[:6].upper()}")
    type: ProvenanceType = ProvenanceType.OBSERVATION
    content: str = ""
    provenance: str = ""  # How it was learned: tool output, mission result, etc.
    confidence: Confidence = Confidence.MEDIUM
    evidence: List[str] = field(default_factory=list)  # Evidence supporting this
    source: str = ""  # Source: mission ID, tool, etc.
    created_at: datetime = field(default_factory=datetime.utcnow)
    tags: List[str] = field(default_factory=list)
    applicable_to: List[str] = field(default_factory=list)  # Applicable vuln classes, tech, etc.
    verified: bool = False  # Whether verified

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "content": self.content,
            "provenance": self.provenance,
            "confidence": self.confidence.value,
            "evidence": self.evidence,
            "source": self.source,
            "created_at": self.created_at.isoformat(),
            "tags": self.tags,
            "applicable_to": self.applicable_to,
            "verified": self.verified,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LearnedItem":
        def parse_dt(val):
            if isinstance(val, str):
                try:
                    return datetime.fromisoformat(val)
                except Exception:
                    return datetime.utcnow()
            return val if isinstance(val, datetime) else datetime.utcnow()

        try:
            ptype = ProvenanceType(data.get("type", "OBSERVATION"))
        except ValueError:
            ptype = ProvenanceType.OBSERVATION

        try:
            conf = Confidence(data.get("confidence", "medium"))
        except ValueError:
            conf = Confidence.MEDIUM

        return cls(
            id=data.get("id", f"LEARN-{uuid.uuid4().hex[:6].upper()}"),
            type=ptype,
            content=data.get("content", ""),
            provenance=data.get("provenance", ""),
            confidence=conf,
            evidence=data.get("evidence", []),
            source=data.get("source", ""),
            created_at=parse_dt(data.get("created_at")),
            tags=data.get("tags", []),
            applicable_to=data.get("applicable_to", []),
            verified=data.get("verified", False),
        )

    def can_become_permanent(self) -> bool:
        """Check if learned item can become permanent knowledge — requires verification and high confidence."""
        # FACT with high confidence and verified can become permanent
        if self.type == ProvenanceType.FACT and self.confidence == Confidence.HIGH and self.verified:
            return True

        # SKILL with high confidence and verified can become permanent
        if self.type == ProvenanceType.SKILL and self.confidence == Confidence.HIGH and self.verified:
            return True

        # LESSON with high confidence and evidence can become permanent
        if self.type == ProvenanceType.LESSON and self.confidence == Confidence.HIGH and len(self.evidence) > 0:
            return True

        # OBSERVATION and HYPOTHESIS should not become permanent automatically
        # They need to be promoted to FACT or LESSON first
        return False


class LearningStore:
    """Store for learned items with provenance separation."""

    def __init__(self):
        self.items: Dict[str, LearnedItem] = {}

    def add(self, item: LearnedItem) -> str:
        """Add learned item."""
        self.items[item.id] = item
        return item.id

    def get(self, item_id: str) -> Optional[LearnedItem]:
        return self.items.get(item_id)

    def list_by_type(self, ptype: ProvenanceType) -> List[LearnedItem]:
        return [item for item in self.items.values() if item.type == ptype]

    def list_by_confidence(self, confidence: Confidence) -> List[LearnedItem]:
        return [item for item in self.items.values() if item.confidence == confidence]

    def list_verified(self) -> List[LearnedItem]:
        return [item for item in self.items.values() if item.verified]

    def list_permanent_candidates(self) -> List[LearnedItem]:
        """List items that can become permanent knowledge."""
        return [item for item in self.items.values() if item.can_become_permanent()]

    def get_stats(self) -> Dict[str, Any]:
        by_type = {}
        for item in self.items.values():
            t = item.type.value
            by_type[t] = by_type.get(t, 0) + 1

        by_conf = {}
        for item in self.items.values():
            c = item.confidence.value
            by_conf[c] = by_conf.get(c, 0) + 1

        return {
            "total": len(self.items),
            "by_type": by_type,
            "by_confidence": by_conf,
            "verified": len(self.list_verified()),
            "permanent_candidates": len(self.list_permanent_candidates()),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {iid: item.to_dict() for iid, item in self.items.items()}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LearningStore":
        store = cls()
        for iid, idata in data.items():
            try:
                item = LearnedItem.from_dict(idata)
                store.items[iid] = item
            except Exception:
                continue
        return store


def create_fact(content: str, provenance: str, evidence: List[str], source: str, confidence: Confidence = Confidence.HIGH) -> LearnedItem:
    """Create FACT with high confidence, requires verification."""
    return LearnedItem(
        type=ProvenanceType.FACT,
        content=content,
        provenance=provenance,
        confidence=confidence,
        evidence=evidence,
        source=source,
        verified=True,  # FACT must be verified
    )


def create_observation(content: str, provenance: str, source: str, confidence: Confidence = Confidence.MEDIUM) -> LearnedItem:
    """Create OBSERVATION from tool output."""
    return LearnedItem(
        type=ProvenanceType.OBSERVATION,
        content=content,
        provenance=provenance,
        confidence=confidence,
        source=source,
        verified=False,
    )


def create_lesson(content: str, provenance: str, evidence: List[str], source: str, confidence: Confidence = Confidence.MEDIUM) -> LearnedItem:
    """Create LESSON from success/failure."""
    return LearnedItem(
        type=ProvenanceType.LESSON,
        content=content,
        provenance=provenance,
        confidence=confidence,
        evidence=evidence,
        source=source,
        verified=False,
    )


def create_skill(content: str, provenance: str, evidence: List[str], source: str, applicable_to: List[str]) -> LearnedItem:
    """Create SKILL — procedural knowledge that worked."""
    return LearnedItem(
        type=ProvenanceType.SKILL,
        content=content,
        provenance=provenance,
        confidence=Confidence.HIGH,
        evidence=evidence,
        source=source,
        applicable_to=applicable_to,
        verified=True,
    )


def create_hypothesis(content: str, provenance: str, source: str) -> LearnedItem:
    """Create HYPOTHESIS — unverified idea."""
    return LearnedItem(
        type=ProvenanceType.HYPOTHESIS,
        content=content,
        provenance=provenance,
        confidence=Confidence.LOW,
        source=source,
        verified=False,
    )
