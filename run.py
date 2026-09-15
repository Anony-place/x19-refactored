#!/usr/bin/env python3
"""X19 — autonomous AI security assessment platform.

``run.py`` is the single supported entry point. On an interactive terminal the
default surface is the terminal application: the workspace home (status, state
and every function), with first-run setup when no provider is configured yet.
Non-interactive contexts (pipes, CI, ``X19_UI=plain``) get a dependency-light
plain control plane instead, and the live dashboard stays behind ``dash``.

    python run.py                      # workspace home (or first-run setup)
    python run.py setup                # guided setup
    python run.py run -t <target>      # one-shot autonomous assessment
    python run.py dash -t <target>     # explicit live UI only
    X19_UI=plain python run.py status  # plain control plane
"""

import os
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
from runtime_bootstrap import install_runtime_fixes, install_agent_execution_policy
install_runtime_fixes()

from builtin_integration import install_phase_access
install_phase_access()

# Install the cognitive prompt contract before agent.py imports
# utils.decision_system_prompt directly.
from brain.cognitive_runtime import install as install_cognitive_runtime
install_cognitive_runtime()

from logging_utils import log

_RUNTIME_COMMANDS = {"runtime", "skills", "skill", "recall", "delegate", "cron"}
#: Commands that stay on the lightweight plain control plane in every mode.
_ALWAYS_PLAIN_COMMANDS = {"provider", "brain"}
#: Commands served by the full terminal application on an interactive TTY.
_APP_COMMANDS = {"", "workspace", "providers", "setup"}
#: Commands that explicitly asked for the plain surface.
_PLAIN_COMMANDS = {"status"}


def _wants_plain_surface() -> bool:
    """Plain output is for machines and people who explicitly asked for it."""
    if os.getenv("X19_UI", "").strip().lower() == "plain":
        return True
    try:
        return not (sys.stdin.isatty() and sys.stdout.isatty())
    except Exception:
        return True


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
    argv = list(sys.argv[1:])

    # Hermes-style runtime commands stay lightweight and never load the full
    # offensive graph.
    if argv and argv[0] in _RUNTIME_COMMANDS:
        from runtime_cli import dispatch
        return int(dispatch(argv) or 0)

    route = argv[0] if argv else ""

    if route in _ALWAYS_PLAIN_COMMANDS or route in _PLAIN_COMMANDS:
        from plain_cli import main as plain_main
        return int(plain_main(argv) or 0)

    if route in _APP_COMMANDS:
        # An explicit invocation always goes to the full CLI (which owns
        # --json/--plain handling). Only the bare `x19` default depends on
        # whether a human is actually watching: machines get the plain status.
        if not route and _wants_plain_surface():
            from plain_cli import main as plain_main
            return int(plain_main(argv or ["status"]) or 0)
        from cli import main as cli_main
        # cli imports agent.py; only now can the compatibility layer bind the
        # gateway to each X19 instance's explicit mission target.
        install_agent_execution_policy()

        routed = ["workspace"] + argv[1:] if not route else argv
        result = int(cli_main(routed) or 0)
        _maybe_promote_learning(argv, result)
        return result

    # The existing CLI remains responsible for the rest of the security
    # assessment command graph. The cognitive runtime is already installed
    # before this import.
    from cli import main as cli_main
    install_agent_execution_policy()

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
