"""
X19 Cognitive Core

Milestone 1: The Memory (Context Graph)

This package contains the Cognitive Core modules for X19.
The core provides autonomous reasoning capabilities through:
- Context Graph (Memory)
- Reflector (Observation)
- Valuator (Value System)
- Selector (Decision)

Current Status: Milestone 1 Complete (Types + Context Graph)
"""

from .types import (
    EntityType,
    RelationshipType,
    Fact,
    Entity,
    ActionSchema,
    ContextSnapshot
)

from .context_graph import ContextGraph

__all__ = [
    'EntityType',
    'RelationshipType',
    'Fact',
    'Entity',
    'ActionSchema',
    'ContextSnapshot',
    'ContextGraph'
]

__version__ = "0.1.0-milestone-1"
