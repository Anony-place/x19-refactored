"""
X19 Cognitive Core - Milestone 1: The Memory

Implementation of the Context Graph (IContext interface).

This module provides a lightweight property graph with confidence scoring.
It replaces the need for complex Bayesian Networks while maintaining
probabilistic reasoning capabilities.

Architecture: Frozen (Sprint 1)
Risk Mitigations Applied:
- Thread safety via Lock (Risk #1)
- Hard cap on graph size (Risk #3)
- Evidence truncation in types.py (Risk #4)
"""

import threading
import time
from typing import Optional, List, Dict, Any, Set
from collections import defaultdict

from .types import (
    Entity, 
    Fact, 
    EntityType, 
    RelationshipType, 
    ContextSnapshot,
    ActionSchema
)


class ContextGraph:
    """
    Implementation of IContext interface.
    
    A thread-safe property graph that stores entities and facts with confidence scores.
    Supports fast neighborhood queries and lightweight snapshotting for simulations.
    
    Attributes:
        max_nodes: Maximum number of nodes before pruning (default: 500)
        _entities: Internal storage of entities by ID
        _facts: Internal storage of facts
        _adjacency: Adjacency list for fast relationship traversal
        _lock: Thread lock for thread safety
    """
    
    def __init__(self, max_nodes: int = 500):
        """
        Initialize the Context Graph.
        
        Args:
            max_nodes: Maximum number of entities before automatic pruning
        """
        self.max_nodes = max_nodes
        self._entities: Dict[str, Entity] = {}
        self._facts: List[Fact] = []
        self._adjacency: Dict[str, Set[str]] = defaultdict(set)
        self._lock = threading.Lock()  # Risk Mitigation #1: Thread Safety
    
    def assert_fact(self, subject_id: str, predicate: str, object_value: Any,
                    confidence: float = 1.0, source: str = "unknown",
                    raw_evidence: str = "") -> Fact:
        """
        Assert a new fact into the graph.
        
        Creates or updates entities as needed. Handles confidence averaging
        for duplicate facts.
        
        Args:
            subject_id: ID of the subject entity
            predicate: Relationship type or attribute name
            object_value: Value of the relationship/attribute
            confidence: Confidence score [0.0, 1.0]
            source: Origin of this fact
            raw_evidence: Raw evidence string (will be truncated in Fact constructor)
        
        Returns:
            The created Fact object
        
        Raises:
            ValueError: If confidence is outside [0.0, 1.0]
        """
        with self._lock:
            # Create fact (truncation happens in Fact.__post_init__)
            fact = Fact(
                subject_id=subject_id,
                predicate=predicate,
                object_value=object_value,
                confidence=confidence,
                source=source,
                raw_evidence=raw_evidence
            )
            
            # Ensure subject entity exists
            if subject_id not in self._entities:
                self._entities[subject_id] = Entity(id=subject_id)
            
            # Handle object entity if it's an entity reference
            object_id = None
            if isinstance(object_value, str) and object_value.startswith("entity:"):
                object_id = object_value[7:]  # Remove "entity:" prefix
                if object_id not in self._entities:
                    self._entities[object_id] = Entity(id=object_id)
                self._adjacency[subject_id].add(object_id)
                self._adjacency[object_id].add(subject_id)
            
            # Check for existing similar facts and average confidence
            existing_idx = None
            for i, existing_fact in enumerate(self._facts):
                if (existing_fact.subject_id == subject_id and
                    existing_fact.predicate == predicate and
                    existing_fact.object_value == object_value):
                    existing_idx = i
                    break
            
            if existing_idx is not None:
                # Average confidence with existing fact
                old_fact = self._facts[existing_idx]
                new_confidence = (old_fact.confidence + fact.confidence) / 2
                fact.confidence = new_confidence
                self._facts[existing_idx] = fact
            else:
                self._facts.append(fact)
            
            # Update entity properties based on fact
            if subject_id in self._entities:
                prop_key = predicate
                self._entities[subject_id].update(
                    properties={prop_key: object_value},
                    confidence=max(self._entities[subject_id].confidence, confidence)
                )
            
            # Prune if necessary (Risk Mitigation #3)
            self._prune_if_needed()
            
            return fact
    
    def query(self, pattern: Dict[str, Any], min_confidence: float = 0.0) -> List[Fact]:
        """
        Query facts matching a pattern.
        
        Args:
            pattern: Dictionary with optional keys:
                - subject_id: Filter by subject
                - predicate: Filter by predicate
                - object_value: Filter by object value
            min_confidence: Minimum confidence threshold
        
        Returns:
            List of matching Facts
        """
        with self._lock:
            results = []
            for fact in self._facts:
                if fact.confidence < min_confidence:
                    continue
                
                if "subject_id" in pattern and fact.subject_id != pattern["subject_id"]:
                    continue
                if "predicate" in pattern and fact.predicate != pattern["predicate"]:
                    continue
                if "object_value" in pattern and fact.object_value != pattern["object_value"]:
                    continue
                
                results.append(fact)
            
            return results
    
    def get_entity(self, entity_id: str) -> Optional[Entity]:
        """
        Get an entity by ID.
        
        Args:
            entity_id: The entity ID
        
        Returns:
            Entity if found, None otherwise
        """
        with self._lock:
            return self._entities.get(entity_id)
    
    def get_all_entities(self, entity_type: Optional[EntityType] = None,
                         min_confidence: float = 0.0) -> List[Entity]:
        """
        Get all entities, optionally filtered by type and confidence.
        
        Args:
            entity_type: Filter by entity type
            min_confidence: Minimum confidence threshold
        
        Returns:
            List of matching Entities
        """
        with self._lock:
            results = []
            for entity in self._entities.values():
                if entity.confidence < min_confidence:
                    continue
                if entity_type is not None and entity.entity_type != entity_type:
                    continue
                results.append(entity)
            return results
    
    def get_possible_actions(self, entity_id: str) -> List[ActionSchema]:
        """
        Get possible actions for an entity based on its type and properties.
        
        This is a placeholder implementation that returns generic actions.
        Will be enhanced in later milestones with TTP mappings.
        
        Args:
            entity_id: ID of the entity
        
        Returns:
            List of possible ActionSchema objects
        """
        with self._lock:
            entity = self._entities.get(entity_id)
            if not entity:
                return []
            
            actions = []
            
            # Generate actions based on entity type
            if entity.entity_type == EntityType.HOST:
                actions.append(ActionSchema(
                    action_id=f"scan_{entity_id}",
                    action_type="SCAN",
                    target_entity_id=entity_id,
                    parameters={"scan_type": "port"},
                    cost_estimate=0.3,
                    risk_estimate=0.1
                ))
                actions.append(ActionSchema(
                    action_id=f"enum_{entity_id}",
                    action_type="ENUMERATE",
                    target_entity_id=entity_id,
                    parameters={"enum_type": "services"},
                    cost_estimate=0.4,
                    risk_estimate=0.2
                ))
            
            elif entity.entity_type == EntityType.SERVICE:
                actions.append(ActionSchema(
                    action_id=f"version_scan_{entity_id}",
                    action_type="VERSION_SCAN",
                    target_entity_id=entity_id,
                    parameters={},
                    cost_estimate=0.2,
                    risk_estimate=0.1
                ))
                actions.append(ActionSchema(
                    action_id=f"vuln_scan_{entity_id}",
                    action_type="VULN_SCAN",
                    target_entity_id=entity_id,
                    parameters={},
                    cost_estimate=0.5,
                    risk_estimate=0.3
                ))
            
            elif entity.entity_type == EntityType.PORT:
                actions.append(ActionSchema(
                    action_id=f"service_detect_{entity_id}",
                    action_type="SERVICE_DETECTION",
                    target_entity_id=entity_id,
                    parameters={},
                    cost_estimate=0.2,
                    risk_estimate=0.1
                ))
            
            return actions
    
    def snapshot(self) -> ContextSnapshot:
        """
        Create an immutable snapshot of the current graph state.
        
        Uses shallow copy for performance. The snapshot is safe for
        read-only "what-if" simulations.
        
        Returns:
            ContextSnapshot object
        """
        with self._lock:
            # Create deep copies to ensure immutability
            entities_copy = {
                eid: Entity(
                    id=e.id,
                    entity_type=e.entity_type,
                    properties=dict(e.properties),
                    confidence=e.confidence,
                    created_at=e.created_at,
                    updated_at=e.updated_at
                )
                for eid, e in self._entities.items()
            }
            
            facts_copy = [
                Fact(
                    subject_id=f.subject_id,
                    predicate=f.predicate,
                    object_value=f.object_value,
                    confidence=f.confidence,
                    source=f.source,
                    timestamp=f.timestamp,
                    raw_evidence=f.raw_evidence
                )
                for f in self._facts
            ]
            
            return ContextSnapshot(entities=entities_copy, facts=facts_copy)
    
    def _prune_if_needed(self):
        """
        Prune low-confidence entities if graph exceeds max_nodes.
        
        Risk Mitigation #3: Prevents memory explosion on large scans.
        Strategy: Remove oldest entities with lowest confidence.
        """
        if len(self._entities) <= self.max_nodes:
            return
        
        # Sort entities by confidence (ascending) then by age (oldest first)
        sorted_entities = sorted(
            self._entities.items(),
            key=lambda x: (x[1].confidence, x[1].created_at)
        )
        
        # Remove lowest confidence entities until under limit
        remove_count = len(self._entities) - self.max_nodes
        for i in range(remove_count):
            entity_id = sorted_entities[i][0]
            del self._entities[entity_id]
            
            # Clean up adjacency list
            if entity_id in self._adjacency:
                del self._adjacency[entity_id]
            for neighbors in self._adjacency.values():
                neighbors.discard(entity_id)
        
        # Clean up facts related to removed entities
        removed_ids = set(e[0] for e in sorted_entities[:remove_count])
        self._facts = [f for f in self._facts if f.subject_id not in removed_ids]
    
    def clear(self):
        """Clear all data from the graph."""
        with self._lock:
            self._entities.clear()
            self._facts.clear()
            self._adjacency.clear()
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize the graph to a dictionary."""
        with self._lock:
            return {
                "entities": {k: v.to_dict() for k, v in self._entities.items()},
                "facts": [f.to_dict() for f in self._facts],
                "max_nodes": self.max_nodes,
                "current_size": len(self._entities)
            }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ContextGraph':
        """Deserialize the graph from a dictionary."""
        graph = cls(max_nodes=data.get("max_nodes", 500))
        
        # Restore entities
        for eid, edata in data.get("entities", {}).items():
            graph._entities[eid] = Entity.from_dict(edata)
        
        # Restore facts
        for fdata in data.get("facts", []):
            graph._facts.append(Fact.from_dict(fdata))
        
        # Rebuild adjacency
        for fact in graph._facts:
            if isinstance(fact.object_value, str) and fact.object_value.startswith("entity:"):
                object_id = fact.object_value[7:]
                graph._adjacency[fact.subject_id].add(object_id)
                graph._adjacency[object_id].add(fact.subject_id)
        
        return graph
