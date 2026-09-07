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
