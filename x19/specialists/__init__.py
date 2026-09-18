"""
X19 Specialists — 11 distinct roles with distinct prompts.

Uses Hermes delegation: Boss/Managers orchestrator, Specialists leaf.
"""

from .base import (
    SpecialistConfig,
    build_specialist_goal,
    build_specialist_context,
    get_specialist_prompt,
    get_specialist_toolsets,
    get_specialist_delegation_role,
    create_specialist_config,
)

# Import wrappers for easy access
from . import boss
from . import recon_manager
from . import web_manager
from . import api_manager
from . import web_security
from . import api_security
from . import auth
from . import cloud_infra
from . import vuln_research
from . import bugbounty_research
from . import verification
from . import evidence_reporting
from . import defensive_validation

# Role ID to module mapping
SPECIALIST_MODULES = {
    "boss": boss,
    "recon_manager": recon_manager,
    "web_manager": web_manager,
    "api_manager": api_manager,
    "web_security": web_security,
    "api_security": api_security,
    "auth": auth,
    "cloud_infra": cloud_infra,
    "vuln_research": vuln_research,
    "bugbounty_research": bugbounty_research,
    "verification": verification,
    "evidence_reporting": evidence_reporting,
    "defensive_validation": defensive_validation,
}

__all__ = [
    "SpecialistConfig",
    "build_specialist_goal",
    "build_specialist_context",
    "get_specialist_prompt",
    "get_specialist_toolsets",
    "get_specialist_delegation_role",
    "create_specialist_config",
    "SPECIALIST_MODULES",
    "boss",
    "recon_manager",
    "web_manager",
    "api_manager",
    "web_security",
    "api_security",
    "auth",
    "cloud_infra",
    "vuln_research",
    "bugbounty_research",
    "verification",
    "evidence_reporting",
    "defensive_validation",
]
