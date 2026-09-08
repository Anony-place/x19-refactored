#!/usr/bin/env python3
"""X19 — autonomous AI security assessment platform.

Terminal application entry point. There is no web server: every capability is
served by the CLI in :mod:`cli` and the terminal UI in :mod:`ui`.

    python run.py --help
    python run.py run -t <target>
    python run.py dash -t <target>
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

from builtin_integration import install_phase_access
install_phase_access()

from logging_utils import log

def main() -> int:
    # Imported late so ``x19 --version`` / ``--help`` never pay for the agent
    # import graph, and never trigger the first-run provider wizard.
    from cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Stopped")
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as exc:
        print(f"\n[!] {exc}")
        traceback.print_exc()
        log(f"FATAL: {exc}")
        sys.exit(1)
