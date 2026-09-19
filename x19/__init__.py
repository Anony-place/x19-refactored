"""X19 — a hierarchical multi-agent system.

    USER
      ↓
    X19   BOSS      executive orchestrator: owns the objective, decomposes,
                    delegates, monitors, resolves blockers, reviews, reports
      ↓
    X22   MANAGER   project manager: turns objectives into tasks with
                    dependencies, assigns workers, tracks progress, validates
                    output, reports upward, escalates
      ↓
    WORKERS         specialized execution agents (research, coding, security,
                    testing, documentation, analysis, devops, debugging,
                    tool execution) that use the real tool surface
      ↓
    TOOLS / EXECUTION → results → manager review → X19 audit → user

The organization is real: :mod:`x19.org.runtime` holds a task graph with an
enforced lifecycle, an agent registry overlaid with live subagent state from the
delegation engine, and an append-only event stream.  Status, audits and the TUI
all read from it.  Nothing in the product fabricates agents, progress, outputs
or completions.
"""

from __future__ import annotations

__version__ = "2.0.0"
__product__ = "X19"
__identity__ = "X19 — hierarchical multi-agent system"

from . import identity, org, state

__all__ = ["identity", "org", "state", "__version__", "__product__", "__identity__"]
