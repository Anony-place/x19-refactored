"""Early runtime compatibility fixes installed before cli/agent imports."""
from __future__ import annotations

import builtins
import os
import shutil
import sys


def install_runtime_fixes() -> None:
    # mission.py historically calls this helper without importing it. Expose
    # the canonical implementation through builtins before cli imports agent.
    try:
        from memory import is_bug_bounty_mode
        builtins.is_bug_bounty_mode = is_bug_bounty_mode
    except Exception:
        pass

    # ProxyManager used to be re-defined here for two reasons:
    # `_detect_mitmproxy` raised NameError (network.py never imported `sys`) and
    # `proxy_url` preferred Burp's listener over mitm's. Both are fixed in
    # network.py itself now. Patching module behaviour in from here made the
    # same install act differently depending on the entry point — `python -c
    # "from agent import X19; X19()"` crashed while `python run.py run -t x`
    # worked — so keep network.py out of this function permanently.

    # The TUI's /model command must mutate the existing X19 runtime rather
    # than merely changing a config value. This keeps target, session, memory,
    # planner and mission identity intact while selecting a different model.
    try:
        from ui.app import ConsoleApp
        from runtime.model_control import switch_model

        def cmd_model(self, *args: str) -> None:
            from ui.console import ok, warn
            from rich.prompt import Prompt

            name = " ".join(args).strip() or Prompt.ask("model", console=self.console).strip()
            if not name:
                warn("usage: /model <name>")
                return
            try:
                active = switch_model(self.agent, name)
            except Exception as exc:
                warn(str(exc))
                return
            ok(f"X19 model switched live → {active}")

        ConsoleApp.cmd_model = cmd_model
    except Exception:
        # UI is optional on non-interactive CLI paths.
        pass


def install_agent_execution_policy() -> None:
    """Patch X19's existing gateway with the mission target after agent import.

    The legacy agent constructs ``CommandGateway`` before its target has been
    attached to a policy. Without this binding, the gateway's fail-closed empty
    allowlist rejects every network-targeted command with ``scope_required``.
    Keep the policy deterministic and target-bound instead of weakening the
    gateway globally.
    """
    try:
        from agent import X19
        from execution import PolicyEngine, policy_from_config

        if getattr(X19, "_x19_gateway_policy_installed", False):
            return
        original_init = X19.__init__

        def wrapped_init(self, target: str = "", *args, **kwargs):
            original_init(self, target, *args, **kwargs)
            policy = policy_from_config(target)
            self.command_gateway.policy_engine = PolicyEngine(policy)
            if hasattr(self, "exec") and hasattr(self.exec, "gateway"):
                self.exec.gateway = self.command_gateway

        X19.__init__ = wrapped_init
        X19._x19_gateway_policy_installed = True
    except Exception:
        # Agent may be unavailable for lightweight commands; keep setup/status usable.
        pass
