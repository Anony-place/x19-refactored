#!/usr/bin/env python3
"""
X19 - Autonomous AI Pentest Agent
AI-driven decision making. No fixed phases, no prescribed tool order.
The AI independently chooses every action, tool, and command.
"""

import sys
import traceback

from windows_bootstrap import apply_windows_utf8_bootstrap
apply_windows_utf8_bootstrap()

# Native, dependency-free reconnaissance primitives. They are registered once
# at process startup and are available through the existing ToolExecutor API.
from builtin_tools import install as install_builtin_tools
from tools import TOOLS, ToolExecutor
install_builtin_tools(TOOLS, ToolExecutor)

# Runtime compatibility fixes MUST be installed before cli imports agent.py.
from runtime_bootstrap import install_runtime_fixes
install_runtime_fixes()

# First-run AI setup MUST happen before the runtime is initialized. This lets
# the user choose primary + fallback providers/models and verifies each one.
from provider_setup import setup_if_needed
from cli import main
from builtin_integration import install_phase_access
install_phase_access()
from logging_utils import log

# Event-driven runtime is attached after cli/agent imports are complete.  The
# runtime owns session lifecycle and runs the existing autonomous worker in a
# daemon thread so the interactive UI is not blocked by a long assessment.
try:
    from agent import X19
    from agent_runtime import install_runtime

    _x19_init = X19.__init__
    _x19_loop = X19.autonomous_loop

    def _runtime_init(self, *args, **kwargs):
        _x19_init(self, *args, **kwargs)
        install_runtime(self)

    def _runtime_autonomous_loop(self, target, *args, **kwargs):
        runtime = install_runtime(self)
        if runtime.running:
            return
        runtime.start(target, worker=lambda: _x19_loop(self, target, *args, **kwargs))

    X19.__init__ = _runtime_init
    X19.autonomous_loop = _runtime_autonomous_loop
except Exception as _runtime_error:
    # Runtime integration is deliberately fail-open: the legacy foreground
    # agent remains usable if the optional lifecycle wrapper cannot initialize.
    log(f"[AgentRuntime] integration skipped: {_runtime_error}")


if __name__ == "__main__":
    try:
        if not setup_if_needed():
            sys.exit(1)
        main()
    except KeyboardInterrupt:
        print("\n[!] Stopped")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] {e}")
        traceback.print_exc()
        log(f"FATAL: {e}")
        sys.exit(1)
