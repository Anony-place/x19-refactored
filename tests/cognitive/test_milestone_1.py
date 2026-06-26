"""
Unit Tests for X19 Cognitive Core - Milestone 1

Tests for:
- types.py: Fact, Entity, ActionSchema, ContextSnapshot
- context_graph.py: ContextGraph

Test Categories:
1. Type validation and normalization
2. Context graph operations (assert, query, snapshot)
3. Thread safety verification
4. Memory cap and pruning
5. Serialization/deserialization
"""

import pytest
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from cognitive.types import (
    EntityType,
    RelationshipType,
    Fact,
    Entity,
    ActionSchema,
    ContextSnapshot
)

from cognitive.context_graph import ContextGraph


class TestFact:
    """Tests for the Fact dataclass."""
    
    def test_fact_creation_basic(self):
        """Test basic fact creation."""
        fact = Fact(
            subject_id="host_1",
            predicate="has_port",
            object_value=80
        )
        assert fact.subject_id == "host_1"
        assert fact.predicate == "has_port"
        assert fact.object_value == 80
        assert fact.confidence == 1.0
        assert fact.source == "unknown"
    
    def test_fact_confidence_clamping_high(self):
        """Test that confidence > 1.0 is clamped to 1.0."""
        fact = Fact(
            subject_id="host_1",
            predicate="test",
            object_value="value",
            confidence=1.5
        )
        assert fact.confidence == 1.0
    
    def test_fact_confidence_clamping_low(self):
        """Test that confidence < 0.0 is clamped to 0.0."""
        fact = Fact(
            subject_id="host_1",
            predicate="test",
            object_value="value",
            confidence=-0.5
        )
        assert fact.confidence == 0.0
    
    def test_fact_evidence_truncation(self):
        """Test that raw evidence is truncated to 256 chars (Risk Mitigation #4)."""
        long_evidence = "A" * 300
        fact = Fact(
            subject_id="host_1",
            predicate="test",
            object_value="value",
            raw_evidence=long_evidence
        )
        assert len(fact.raw_evidence) <= 256
        assert fact.raw_evidence.endswith("...")
    
    def test_fact_to_dict_from_dict(self):
        """Test serialization and deserialization."""
        original = Fact(
            subject_id="host_1",
            predicate="has_service",
            object_value="nginx",
            confidence=0.9,
            source="nmap_scan",
            raw_evidence="Port 80 open"
        )
        
        data = original.to_dict()
        restored = Fact.from_dict(data)
        
        assert restored.subject_id == original.subject_id
        assert restored.predicate == original.predicate
        assert restored.object_value == original.object_value
        assert restored.confidence == original.confidence
        assert restored.source == original.source


class TestEntity:
    """Tests for the Entity dataclass."""
    
    def test_entity_creation_basic(self):
        """Test basic entity creation."""
        entity = Entity(id="host_1", entity_type=EntityType.HOST)
        assert entity.id == "host_1"
        assert entity.entity_type == EntityType.HOST
        assert entity.confidence == 1.0
        assert len(entity.properties) == 0
    
    def test_entity_update(self):
        """Test entity property updates."""
        entity = Entity(id="host_1", entity_type=EntityType.HOST)
        entity.update({"os": "linux", "ports": [22, 80]})
        
        assert entity.properties["os"] == "linux"
        assert entity.properties["ports"] == [22, 80]
        assert entity.updated_at > entity.created_at
    
    def test_entity_confidence_update(self):
        """Test entity confidence updates."""
        entity = Entity(id="host_1", entity_type=EntityType.HOST, confidence=0.5)
        entity.update({}, confidence=0.9)
        
        assert entity.confidence == 0.9
    
    def test_entity_to_dict_from_dict(self):
        """Test entity serialization."""
        original = Entity(
            id="service_1",
            entity_type=EntityType.SERVICE,
            properties={"name": "nginx", "version": "1.18"},
            confidence=0.85
        )
        
        data = original.to_dict()
        restored = Entity.from_dict(data)
        
        assert restored.id == original.id
        assert restored.entity_type == original.entity_type
        assert restored.properties == original.properties
        assert restored.confidence == original.confidence


class TestActionSchema:
    """Tests for the ActionSchema dataclass."""
    
    def test_action_creation_basic(self):
        """Test basic action schema creation."""
        action = ActionSchema(
            action_id="scan_host_1",
            action_type="SCAN",
            target_entity_id="host_1"
        )
        assert action.action_id == "scan_host_1"
        assert action.action_type == "SCAN"
        assert action.cost_estimate == 0.5
        assert action.risk_estimate == 0.5
    
    def test_action_cost_risk_clamping(self):
        """Test that cost and risk are clamped to [0.0, 1.0]."""
        action = ActionSchema(
            action_id="test",
            action_type="TEST",
            target_entity_id="target",
            cost_estimate=1.5,
            risk_estimate=-0.5
        )
        assert action.cost_estimate == 1.0
        assert action.risk_estimate == 0.0


class TestContextGraph:
    """Tests for the ContextGraph class."""
    
    def test_context_creation(self):
        """Test basic context graph creation."""
        graph = ContextGraph(max_nodes=100)
        assert graph.max_nodes == 100
        assert len(graph.get_all_entities()) == 0
    
    def test_assert_fact_creates_entity(self):
        """Test that asserting a fact creates the subject entity."""
        graph = ContextGraph()
        graph.assert_fact("host_1", "has_port", 80)
        
        entity = graph.get_entity("host_1")
        assert entity is not None
        assert entity.id == "host_1"
    
    def test_assert_fact_updates_entity_properties(self):
        """Test that facts update entity properties."""
        graph = ContextGraph()
        graph.assert_fact("host_1", "os", "linux", confidence=0.9)
        
        entity = graph.get_entity("host_1")
        assert entity.properties["os"] == "linux"
        assert entity.confidence >= 0.9
    
    def test_query_facts_by_subject(self):
        """Test querying facts by subject ID."""
        graph = ContextGraph()
        graph.assert_fact("host_1", "has_port", 80)
        graph.assert_fact("host_1", "has_port", 22)
        graph.assert_fact("host_2", "has_port", 443)
        
        results = graph.query({"subject_id": "host_1"})
        assert len(results) == 2
        assert all(f.subject_id == "host_1" for f in results)
    
    def test_query_facts_by_confidence(self):
        """Test querying facts with confidence threshold."""
        graph = ContextGraph()
        graph.assert_fact("host_1", "fact1", "value1", confidence=0.5)
        graph.assert_fact("host_1", "fact2", "value2", confidence=0.9)
        
        low_thresh = graph.query({"subject_id": "host_1"}, min_confidence=0.4)
        high_thresh = graph.query({"subject_id": "host_1"}, min_confidence=0.8)
        
        assert len(low_thresh) == 2
        assert len(high_thresh) == 1
    
    def test_snapshot_isolation(self):
        """Test that snapshots are isolated from main graph."""
        graph = ContextGraph()
        graph.assert_fact("host_1", "os", "linux")
        
        snapshot = graph.snapshot()
        
        # Modify main graph
        graph.assert_fact("host_1", "os", "windows", confidence=0.5)
        
        # Snapshot should remain unchanged
        assert len(snapshot.entities) == 1
        assert snapshot.entities["host_1"].properties["os"] == "linux"
    
    def test_get_possible_actions_host(self):
        """Test action generation for HOST entities."""
        graph = ContextGraph()
        graph.assert_fact("host_1", "entity_type", "host")
        
        # Manually set entity type for testing
        entity = graph.get_entity("host_1")
        entity.entity_type = EntityType.HOST
        
        actions = graph.get_possible_actions("host_1")
        
        assert len(actions) > 0
        assert any(a.action_type == "SCAN" for a in actions)
        assert any(a.action_type == "ENUMERATE" for a in actions)
    
    def test_thread_safety_concurrent_writes(self):
        """Test thread safety with concurrent writes (Risk Mitigation #1)."""
        graph = ContextGraph()
        errors = []
        
        def write_fact(thread_id):
            try:
                for i in range(50):
                    graph.assert_fact(
                        f"host_{thread_id}_{i}",
                        "has_port",
                        80 + i
                    )
            except Exception as e:
                errors.append(e)
        
        threads = []
        for i in range(10):
            t = threading.Thread(target=write_fact, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        # Should have 10 * 50 = 500 entities
        assert len(graph.get_all_entities()) == 500
    
    def test_pruning_on_max_nodes(self):
        """Test automatic pruning when max_nodes is exceeded (Risk Mitigation #3)."""
        graph = ContextGraph(max_nodes=10)
        
        # Add 15 entities with varying confidence
        for i in range(15):
            conf = 0.1 * (i + 1)  # 0.1, 0.2, ..., 1.5 (clamped to 1.0)
            graph.assert_fact(f"host_{i}", "test", f"value_{i}", confidence=conf)
        
        # Should be pruned to max_nodes
        assert len(graph.get_all_entities()) <= 10
        
        # Low confidence entities should be removed first
        remaining_ids = [e.id for e in graph.get_all_entities()]
        # host_0 (confidence 0.1) should be removed
        assert "host_0" not in remaining_ids
    
    def test_serialization_roundtrip(self):
        """Test full graph serialization and deserialization."""
        original = ContextGraph(max_nodes=50)
        original.assert_fact("host_1", "os", "linux", confidence=0.9, source="test")
        original.assert_fact("host_1", "has_port", 80)
        
        data = original.to_dict()
        restored = ContextGraph.from_dict(data)
        
        assert restored.max_nodes == original.max_nodes
        assert len(restored.get_all_entities()) == len(original.get_all_entities())
        
        entity = restored.get_entity("host_1")
        assert entity is not None
        assert entity.properties["os"] == "linux"
    
    def test_clear_graph(self):
        """Test clearing the graph."""
        graph = ContextGraph()
        graph.assert_fact("host_1", "os", "linux")
        graph.assert_fact("host_2", "os", "windows")
        
        graph.clear()
        
        assert len(graph.get_all_entities()) == 0
        assert len(graph.query({})) == 0


class TestGarbageInput:
    """Test handling of edge cases and garbage input (Testing Blind Spot Mitigation)."""
    
    def test_empty_string_evidence(self):
        """Test that empty evidence strings are handled."""
        fact = Fact(
            subject_id="host_1",
            predicate="test",
            object_value="value",
            raw_evidence=""
        )
        assert fact.raw_evidence == ""
    
    def test_none_object_value(self):
        """Test handling of None object values."""
        fact = Fact(
            subject_id="host_1",
            predicate="status",
            object_value=None
        )
        assert fact.object_value is None
    
    def test_unicode_in_evidence(self):
        """Test handling of unicode characters in evidence."""
        fact = Fact(
            subject_id="host_1",
            predicate="test",
            object_value="value",
            raw_evidence="测试数据🔒" * 100
        )
        assert len(fact.raw_evidence) <= 256


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
