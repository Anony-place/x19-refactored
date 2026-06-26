"""
X19 Cognitive Core - Milestone 1: The Memory

This module defines the core data structures for the Cognitive Core.
These types are used by all subsequent modules (Context, Reflector, Valuator, Selector).

Architecture: Frozen (Sprint 1)
"""

from dataclasses import dataclass, field
from typing import Any, Optional, List, Dict
from enum import Enum
import time
import json


class EntityType(Enum):
    """Types of entities that can exist in the Context Graph."""
    HOST = "host"
    SERVICE = "service"
    PORT = "port"
    USER = "user"
    CREDENTIAL = "credential"
    FILE = "file"
    VULNERABILITY = "vulnerability"
    NETWORK = "network"
    PROCESS = "process"
    UNKNOWN = "unknown"


class RelationshipType(Enum):
    """Types of relationships between entities."""
    RUNS_ON = "runs_on"
    LISTENS_ON = "listens_on"
    CONNECTS_TO = "connects_to"
    OWNED_BY = "owned_by"
    LOCATED_AT = "located_at"
    EXPLOITS = "exploits"
    AFFECTS = "affects"
    CONTAINS = "contains"
    AUTHENTICATES_AS = "authenticates_as"
    DERIVED_FROM = "derived_from"
    UNKNOWN = "unknown"


@dataclass
class Fact:
    """
    A single fact in the Context Graph.
    
    Represents a triple: (subject, predicate, object) with confidence and provenance.
    
    Attributes:
        subject_id: Unique identifier for the subject entity
        predicate: The relationship type or attribute name
        object_value: The value of the relationship/attribute
        confidence: Probability score [0.0, 1.0]
        source: Origin of this fact (e.g., "nmap_scan_001", "manual_input")
        timestamp: Unix timestamp when this fact was asserted
        raw_evidence: Truncated raw evidence (max 256 chars for memory safety)
    """
    subject_id: str
    predicate: str
    object_value: Any
    confidence: float = 1.0
    source: str = "unknown"
    timestamp: float = field(default_factory=time.time)
    raw_evidence: str = ""
    
    def __post_init__(self):
        """Validate and normalize the fact."""
        # Critical Fix #3: Strict confidence validation (clamping)
        self.confidence = max(0.0, min(1.0, self.confidence))
        
        # High Fix #4: Ensure JSON safety for object_value
        # Convert non-serializable types to string representation
        try:
            json.dumps(self.object_value)
        except (TypeError, ValueError):
            self.object_value = str(self.object_value)
        
        # Truncate raw evidence to prevent memory bloat (Critical Fix #1)
        if self.raw_evidence and len(self.raw_evidence) > 256:
            self.raw_evidence = self.raw_evidence[:253] + "..."
        
        # Validate timestamp
        if self.timestamp <= 0:
            self.timestamp = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert fact to dictionary for serialization."""
        return {
            "subject_id": self.subject_id,
            "predicate": self.predicate,
            "object_value": self.object_value,
            "confidence": self.confidence,
            "source": self.source,
            "timestamp": self.timestamp,
            "raw_evidence": self.raw_evidence
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Fact':
        """Create a Fact from a dictionary."""
        return cls(
            subject_id=data["subject_id"],
            predicate=data["predicate"],
            object_value=data["object_value"],
            confidence=data.get("confidence", 1.0),
            source=data.get("source", "unknown"),
            timestamp=data.get("timestamp", time.time()),
            raw_evidence=data.get("raw_evidence", "")
        )


@dataclass
class Entity:
    """
    An entity in the Context Graph.
    
    Represents a node (Host, Service, User, etc.) with properties.
    
    Attributes:
        id: Unique identifier for this entity
        entity_type: Type of entity (HOST, SERVICE, etc.)
        properties: Dictionary of attribute names to values
        confidence: Overall confidence in this entity's existence [0.0, 1.0]
        created_at: Unix timestamp when entity was first created
        updated_at: Unix timestamp when entity was last modified
    """
    id: str
    entity_type: EntityType = EntityType.UNKNOWN
    properties: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    
    def __post_init__(self):
        """Validate and normalize the entity."""
        self.confidence = max(0.0, min(1.0, self.confidence))
    
    def update(self, properties: Dict[str, Any], confidence: Optional[float] = None):
        """Update entity properties and timestamp."""
        self.properties.update(properties)
        if confidence is not None:
            self.confidence = max(0.0, min(1.0, confidence))
        self.updated_at = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert entity to dictionary for serialization."""
        return {
            "id": self.id,
            "entity_type": self.entity_type.value,
            "properties": self.properties,
            "confidence": self.confidence,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Entity':
        """Create an Entity from a dictionary."""
        return cls(
            id=data["id"],
            entity_type=EntityType(data.get("entity_type", "unknown")),
            properties=data.get("properties", {}),
            confidence=data.get("confidence", 1.0),
            created_at=data.get("created_at", time.time()),
            updated_at=data.get("updated_at", time.time())
        )


@dataclass
class ActionSchema:
    """
    Schema for an action that can be taken by the agent.
    
    Attributes:
        action_id: Unique identifier for this action
        action_type: Type of action (SCAN, EXPLOIT, ENUMERATE, etc.)
        target_entity_id: ID of the entity this action targets
        parameters: Action-specific parameters
        preconditions: List of facts that must be true for this action
        expected_effects: List of facts expected to be true after execution
        cost_estimate: Estimated cost (time, resources) [0.0, 1.0]
        risk_estimate: Estimated risk of detection/failure [0.0, 1.0]
    """
    action_id: str
    action_type: str
    target_entity_id: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    preconditions: List[Dict[str, Any]] = field(default_factory=list)
    expected_effects: List[Dict[str, Any]] = field(default_factory=list)
    cost_estimate: float = 0.5
    risk_estimate: float = 0.5
    
    def __post_init__(self):
        """Validate and normalize the action schema."""
        self.cost_estimate = max(0.0, min(1.0, self.cost_estimate))
        self.risk_estimate = max(0.0, min(1.0, self.risk_estimate))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert action schema to dictionary."""
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "target_entity_id": self.target_entity_id,
            "parameters": self.parameters,
            "preconditions": self.preconditions,
            "expected_effects": self.expected_effects,
            "cost_estimate": self.cost_estimate,
            "risk_estimate": self.risk_estimate
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ActionSchema':
        """Create an ActionSchema from a dictionary."""
        return cls(
            action_id=data["action_id"],
            action_type=data["action_type"],
            target_entity_id=data["target_entity_id"],
            parameters=data.get("parameters", {}),
            preconditions=data.get("preconditions", []),
            expected_effects=data.get("expected_effects", []),
            cost_estimate=data.get("cost_estimate", 0.5),
            risk_estimate=data.get("risk_estimate", 0.5)
        )


@dataclass
class ContextSnapshot:
    """
    Immutable snapshot of the Context Graph at a point in time.
    
    Used for "what-if" simulations without modifying the main graph.
    
    Attributes:
        entities: Dictionary of entity IDs to Entities
        facts: List of Facts
        timestamp: When this snapshot was taken
        snapshot_id: Unique identifier for this snapshot
    """
    entities: Dict[str, Entity]
    facts: List[Fact]
    timestamp: float = field(default_factory=time.time)
    snapshot_id: str = ""
    
    def __post_init__(self):
        """Generate snapshot ID if not provided."""
        if not self.snapshot_id:
            self.snapshot_id = f"snapshot_{int(self.timestamp * 1000)}"
    
    def query_entities(self, entity_type: Optional[EntityType] = None, 
                       min_confidence: float = 0.0) -> List[Entity]:
        """Query entities from the snapshot."""
        results = []
        for entity in self.entities.values():
            if entity.confidence < min_confidence:
                continue
            if entity_type is not None and entity.entity_type != entity_type:
                continue
            results.append(entity)
        return results
    
    def query_facts(self, subject_id: Optional[str] = None,
                    predicate: Optional[str] = None,
                    min_confidence: float = 0.0) -> List[Fact]:
        """Query facts from the snapshot."""
        results = []
        for fact in self.facts:
            if fact.confidence < min_confidence:
                continue
            if subject_id is not None and fact.subject_id != subject_id:
                continue
            if predicate is not None and fact.predicate != predicate:
                continue
            results.append(fact)
        return results
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert snapshot to dictionary."""
        return {
            "snapshot_id": self.snapshot_id,
            "timestamp": self.timestamp,
            "entities": {k: v.to_dict() for k, v in self.entities.items()},
            "facts": [f.to_dict() for f in self.facts]
        }
