"""X19 identity layer.

Supplies the product identity the agent runtime injects.  The organization
sections are generated from the live role catalog in :mod:`x19.org.roles`, so
there is exactly one source of truth for who is in the organization.
"""

from __future__ import annotations

from .core import (
    X19_BEHAVIOR_RULES,
    X19_IDENTITY,
    X19_IDENTITY_VERSION,
    X19_PERSONALITY_TRAITS,
    X19_PRODUCT_NAME,
    X19_SOUL_MD,
    get_x19_identity,
    get_x19_organization_brief,
    get_x19_soul_md,
)
from .prompts import (
    X19_AUTHORITY_GUIDANCE,
    X19_FAILURE_GUIDANCE,
    X19_ORCHESTRATION_GUIDANCE,
    X19_STATUS_GUIDANCE,
    X19_TRUTHFULNESS_GUIDANCE,
    get_x19_guidance_blocks,
    get_x19_team_guidance,
    get_x19_tool_directives,
)

__all__ = [
    "X19_PRODUCT_NAME",
    "X19_IDENTITY_VERSION",
    "X19_IDENTITY",
    "X19_SOUL_MD",
    "X19_PERSONALITY_TRAITS",
    "X19_BEHAVIOR_RULES",
    "X19_ORCHESTRATION_GUIDANCE",
    "X19_TRUTHFULNESS_GUIDANCE",
    "X19_STATUS_GUIDANCE",
    "X19_AUTHORITY_GUIDANCE",
    "X19_FAILURE_GUIDANCE",
    "get_x19_identity",
    "get_x19_soul_md",
    "get_x19_organization_brief",
    "get_x19_guidance_blocks",
    "get_x19_team_guidance",
    "get_x19_tool_directives",
]
