"""
X19 — Autonomous Security Operations Agent

Built on a proven upstream agent runtime. Provides hierarchical security team,
evidence-driven assessment, and autonomous bug-bounty research capabilities.

This package contains X19-specific extensions that reuse Hermes' proven
runtime, tool, skill, memory, session, delegation, terminal, provider,
and learning architecture.

Hierarchy:
    OPERATOR (human client)
      ↓
    X19 BOSS / COMMANDER (you, orchestrator)
      ↓
    SECURITY MANAGERS (Recon, Web, API — orchestrator)
      ↓
    SPECIALIST AGENTS (9 specialists — leaf)
      ↓
    TOOLS / TERMINAL / BROWSER / DATA
"""

__version__ = "0.1.0"
__identity__ = "X19 — Autonomous Security Operations Agent"

# Marker for X19 mode detection
X19_MODE_MARKER = "x19"

# Core exports
from . import identity
from . import team
from . import specialists
from . import scope
from . import findings
from . import safety
from . import orchestration
from . import mission
from . import interface
from . import loop
from . import knowledge
from . import datasets
from . import offensive
from . import autonomous
from . import learning

__all__ = [
    "identity",
    "team",
    "specialists",
    "scope",
    "findings",
    "safety",
    "orchestration",
    "mission",
    "interface",
    "loop",
    "knowledge",
    "datasets",
    "offensive",
    "autonomous",
    "learning",
]
