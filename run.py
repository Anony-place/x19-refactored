#!/usr/bin/env python3
"""X19 — autonomous AI security assessment platform.

``run.py`` is the ONLY supported entry point. Run it without args on a
human terminal — X19 will guide setup if needed and then show the single-screen
workspace (no scrolling, XBOW/Hermes-class). All other entry points are
deprecated internal aliases kept for backward compatibility only.

    python run.py                      # <-- use this. Setup if needed → workspace
    python run.py --help               # all commands (including hidden aliases)

Non-interactive contexts (pipes, CI, X19_UI=plain) get the plain control plane.
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


def _activate_fullscreen_chat() -> None:
    """Swap the interactive chat renderer for the single-screen terminal UI."""
    if os.getenv("X19_UI", "").strip().lower() in {"plain", "legacy"}:
        return
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return
    try:
        from ui.app import ConsoleApp
        from ui.fullscreen_workspace import FullscreenWorkspace

        # Keep the existing ConsoleApp implementation intact as the fallback
        # renderer. The new workspace owns only presentation/input; all command
        # handlers, agent execution, policy gates and background tasks remain
        # in the existing application.
        ConsoleApp._legacy_run = ConsoleApp.run

        def _fullscreen_run(self):
            return FullscreenWorkspace(self).run()

        ConsoleApp.run = _fullscreen_run
    except Exception as exc:
        log(f"FULLSCREEN_UI_FALLBACK: {type(exc).__name__}: {exc}")


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
        # failed security assessment. Diagnostics are useful, but execution wins.
        log(f"LEARNING_PROMOTION_FAILED: {type(exc).__name__}: {exc}")


def _setup_required() -> bool:
    """True when the 4-stage AI chain setup has not been completed."""
    try:
        from cli_support import provider_configured
        return not provider_configured()
    except Exception:
        return False

def main() -> int:
    argv = list(sys.argv[1:])

    # Hermes-style runtime commands stay lightweight and never load the full
    # offensive graph.
    if argv and argv[0] in _RUNTIME_COMMANDS:
        from runtime_cli import dispatch
        return int(dispatch(argv) or 0)

    route = argv[0] if argv else ""

    # Fleet mode: many targets, one bounded supervisor. Kept out of the heavy
    # assessment CLI — it only needs the fleet supervisor + the agent graph.
    if route == "fleet":
        from brain.fleet import cli as fleet_cli
        return int(fleet_cli(argv[1:]) or 0)

    if route in _ALWAYS_PLAIN_COMMANDS or route in _PLAIN_COMMANDS:
        from plain_cli import main as plain_main
        return int(plain_main(argv) or 0)

    if route in _APP_COMMANDS:
        # Plain status stays plain even when setup is pending -- it must not
        # pretend a run is possible. But bare interactive workspace must force
        # setup; this is the "enforce mandatory setup" fix.
        if not route and _wants_plain_surface():
            from plain_cli import main as plain_main
            return int(plain_main(argv or ["status"]) or 0)

        if _setup_required():
            # `setup` itself is exempt -- let it run without recursion
            if route in {"setup", "providers"}:
                pass
            else:
                # Force through CLI's first-run wizard (it owns the 4-stage flow)
                from cli import main as cli_main
                install_agent_execution_policy()
                return int(cli_main(["setup"]) or 0)

        from cli import main as cli_main
        install_agent_execution_policy()
        routed = ["workspace"] + argv[1:] if not route else argv
        result = int(cli_main(routed) or 0)
        _maybe_promote_learning(argv, result)
        return result

    # Mandatory setup gate for authenticated assessments (run/dash/attack).
    if _setup_required():
        from cli import main as cli_main
        install_agent_execution_policy()
        # bare `python run.py run -t ...` must not run unverified -- force setup
        argv0 = argv[0] if argv else ""
        if argv0 in {"run", "dash", "attack", "swarm", "chat"}:
            if not (sys.stdin.isatty() and sys.stdout.isatty()):
                print("[x19] Setup required: no AI provider configured (non-interactive shell).")
                print("      Please set your provider API key, for example:")
                print("        export GROQ_API_KEY=\"gsk_...\"          # Free at https://console.groq.com")
                print("        export OPENAI_API_KEY=\"sk-...\"")
                print("      Or run setup interactively: python run.py setup")
                return 1
            print("[x19] Setup required before any assessment. Starting setup wizard...")
            return int(cli_main(["setup"]) or 0)

    from cli import main as cli_main
    install_agent_execution_policy()
    _activate_fullscreen_chat()

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
