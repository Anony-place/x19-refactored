"""
X19 Identity Architecture

Proper identity layer rather than scattering personality text throughout Python files.
Implements X19 identity through Hermes' actual prompt/personality architecture.

Usage:
    from x19.identity import get_x19_identity, get_x19_soul_md, is_x19_enabled

The identity is loaded via prompt_builder's SOUL mechanism when X19 mode is active,
or falls back to Hermes default when not.
"""

from .core import (
    X19_AGENT_IDENTITY,
    X19_SOUL_MD,
    X19_IDENTITY_VERSION,
    X19_PERSONALITY_TRAITS,
    X19_BEHAVIOR_RULES,
    get_x19_identity,
    get_x19_soul_md,
    is_x19_enabled,
)

from .prompts import (
    X19_SECURITY_GUIDANCE,
    X19_EVIDENCE_GUIDANCE,
    X19_TEAM_GUIDANCE,
    X19_OPERATOR_GUIDANCE,
    X19_MISSION_GUIDANCE,
    get_x19_guidance_blocks,
)

__all__ = [
    "X19_AGENT_IDENTITY",
    "X19_SOUL_MD",
    "X19_IDENTITY_VERSION",
    "X19_PERSONALITY_TRAITS",
    "X19_BEHAVIOR_RULES",
    "X19_SECURITY_GUIDANCE",
    "X19_EVIDENCE_GUIDANCE",
    "X19_TEAM_GUIDANCE",
    "X19_OPERATOR_GUIDANCE",
    "X19_MISSION_GUIDANCE",
    "get_x19_identity",
    "get_x19_soul_md",
    "get_x19_guidance_blocks",
    "is_x19_enabled",
]
