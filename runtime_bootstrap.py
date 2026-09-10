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

    # ProxyManager's mitmproxy detector references sys.executable but the
    # network module did not import sys. Patch the detector at the boundary so
    # venv/pip-installed mitmproxy binaries are still detected.
    try:
        from network import ProxyManager

        def detect_mitmproxy(self) -> bool:
            names = ("mitmdump", "mitmproxy", "mitmweb")
            if any(shutil.which(name) for name in names):
                return True
            bindir = os.path.dirname(sys.executable)
            exts = (".exe", ".cmd", "") if os.name == "nt" else ("",)
            return any(
                os.path.exists(os.path.join(bindir, name + ext))
                for name in names for ext in exts
            )

        ProxyManager._detect_mitmproxy = detect_mitmproxy

        # When Burp + mitmproxy are both running, X19's capture proxy is the
        # mitmproxy listener (8081), not Burp's upstream listener (8080).
        def proxy_url(self) -> str:
            if self.mitm_proc is not None:
                return "http://127.0.0.1:8081"
            return "http://127.0.0.1:8080"

        ProxyManager.proxy_url = proxy_url
    except Exception:
        pass

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
