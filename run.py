#!/usr/bin/env python3
"""X19 — autonomous AI security assessment platform.

Terminal application entry point. There is no web server: every capability is
served by the CLI in :mod:`cli` and the terminal UI in :mod:`ui`.

    python run.py --help
    python run.py run -t <target>
    python run.py dash -t <target>

Hermes-inspired runtime commands are also routed here:
    python run.py runtime
    python run.py skills
    python run.py recall "previous SSRF findings"
    python run.py delegate "analyze API auth" "review web surface"
    python run.py cron list
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


_RUNTIME_COMMANDS = {"runtime", "skills", "skill", "recall", "delegate", "cron"}


def _maybe_promote_learning(argv, result: int) -> None:
    """Promote completed assessment outcomes into reviewable skills."""
    if not argv or argv[0] != "run" or result != 0:
        return
    try:
        from runtime.learning_bridge import learn_from_latest_session

        skill = learn_from_latest_session()
        if skill:
            print(f"[x19] learned skill promoted: {skill}")
    except Exception as exc:
        # Learning must never turn a successful security assessment into a
        # failed command. Diagnostics are useful, but execution wins.
        log(f"LEARNING_PROMOTION_FAILED: {type(exc).__name__}: {exc}")


def main() -> int:
    # The runtime layer is intentionally routed before cli import so lightweight
    # capability commands do not initialize the full offensive agent graph.
    argv = list(sys.argv[1:])
    if argv and argv[0] in _RUNTIME_COMMANDS:
        from runtime_cli import dispatch

        return int(dispatch(argv) or 0)

    # Imported late so ``x19 --version`` / ``--help`` never pay for the agent
    # import graph, and never trigger the first-run provider wizard.
    from cli import main as cli_main

    result = int(cli_main() or 0)
    _maybe_promote_learning(argv, result)
    return result


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
