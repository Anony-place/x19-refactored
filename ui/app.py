"""The default interactive X19 experience.

``x19`` with no arguments drops the operator into this app: a styled prompt,
markdown-rendered model output, and slash commands that reach every subsystem
(assessments, live mission control, findings, reports, providers, config,
diagnostics). It is the terminal equivalent of the retired web dashboard.
"""
from __future__ import annotations

import os
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional

from rich.markdown import Markdown
from rich.prompt import Prompt
from rich.text import Text

from ui import widgets
from ui.console import get_console, info, ok, rule, step, warn

SYSTEM_PROMPT = (
    "You are X19, an expert offensive-security analyst running inside a terminal "
    "application. Answer precisely, prefer concrete commands and evidence, and "
    "never invent output you did not observe."
)

COMMANDS: List[Dict[str, str]] = [
    {"name": "/target <host>", "help": "run a full autonomous assessment", "group": "assessment"},
    {"name": "/dash <host>", "help": "live swarm mission control (full screen)", "group": "assessment"},
    {"name": "/status", "help": "current session, provider and finding counts", "group": "assessment"},
    {"name": "/findings", "help": "list recorded findings by severity", "group": "assessment"},
    {"name": "/report", "help": "render the assessment report", "group": "assessment"},
    {"name": "/providers", "help": "show AI providers, keys and failover chain", "group": "runtime"},
    {"name": "/model <name>", "help": "switch the active model", "group": "runtime"},
    {"name": "/config [K=V]", "help": "show configuration, or set a value", "group": "runtime"},
    {"name": "/sessions [id]", "help": "list stored sessions, or open one", "group": "runtime"},
    {"name": "/tools", "help": "toolchain availability", "group": "runtime"},
    {"name": "/doctor", "help": "self diagnostics and health score", "group": "runtime"},
    {"name": "/test", "help": "round-trip the AI provider", "group": "runtime"},
    {"name": "/shell", "help": "drop to the system shell", "group": "runtime"},
    {"name": "/clear", "help": "clear the conversation", "group": "session"},
    {"name": "/help", "help": "this list", "group": "session"},
    {"name": "/exit", "help": "quit", "group": "session"},
]


class ConsoleApp:
    """Interactive terminal application."""

    def __init__(self, agent: Any = None, *, version: str = "", ai: Any = None):
        self.agent = agent
        self.version = version
        self.console = get_console()
        self.history: List[Dict[str, str]] = []
        self._ai = ai
        self._exit = False

    # ------------------------------------------------------------------
    @property
    def ai(self) -> Any:
        if self._ai is None and self.agent is not None:
            self._ai = getattr(self.agent, "ai", None)
        return self._ai

    def prompt_text(self) -> str:
        name = ""
        try:
            if self.ai is not None:
                name = str(self.ai.name())[:24]
        except Exception:
            name = ""
        target = getattr(self.agent, "target", "") or ""
        text = Text()
        text.append("x19", style="bold bright_cyan")
        if target:
            text.append(f" {target}", style="bold bright_white")
        if name:
            text.append(f" · {name}", style="grey50")
        text.append(" › ", style="bold magenta")
        return text.plain

    # ------------------------------------------------------------------
    def run(self) -> int:
        from version import version_line

        self.console.print()
        rule(f"[panel.title]{version_line()}[/]  ·  interactive console")
        if self.ai is not None:
            try:
                info(f"AI provider: [bold]{self.ai.name()}[/]")
            except Exception:
                pass
        info("type a message, or [app.key]/help[/] for commands")
        self.console.print()

        while not self._exit:
            try:
                line = Prompt.ask(self.prompt_text(), console=self.console, default="", show_default=False)
            except (EOFError, KeyboardInterrupt):
                self.console.print()
                break
            line = (line or "").strip()
            if not line:
                continue
            try:
                self.handle(line)
            except KeyboardInterrupt:
                warn("interrupted")
            except SystemExit:
                raise
            except Exception as exc:  # never let one bad command kill the app
                self.console.print(f"[app.err]✖ {type(exc).__name__}: {exc}[/]")
        ok("bye")
        return 0

    # ------------------------------------------------------------------
    def handle(self, line: str) -> None:
        if not line.startswith("/"):
            self.chat(line)
            return
        parts = line[1:].split()
        command = parts[0].lower()
        args = parts[1:]
        handler: Optional[Callable[..., None]] = getattr(self, f"cmd_{command}", None)
        if handler is None:
            warn(f"unknown command '/{command}' — try /help")
            return
        handler(*args)

    # -- session ---------------------------------------------------------
    def cmd_help(self, *args: str) -> None:
        from ui.screens import help_screen

        self.console.print(help_screen(COMMANDS, version=self.version))

    def cmd_exit(self, *args: str) -> None:
        self._exit = True

    def cmd_quit(self, *args: str) -> None:
        self._exit = True

    def cmd_clear(self, *args: str) -> None:
        self.history.clear()
        ok("conversation cleared")

    def cmd_shell(self, *args: str) -> None:
        step("system shell — type 'exit' to return")
        shell = ["powershell"] if os.name == "nt" else [os.getenv("SHELL", "/bin/bash")]
        try:
            subprocess.run(shell)
        except Exception as exc:
            self.console.print(f"[app.err]✖ could not start shell: {exc}[/]")

    def cmd_test(self, *args: str) -> None:
        if self.ai is None:
            warn("no AI provider configured — run: x19 setup")
            return
        started = time.time()
        reply = self.ai.chat("Reply with the single word: ready.", "ping")
        elapsed = time.time() - started
        if reply:
            ok(f"{self.ai.name()} responded in {elapsed:.2f}s — {reply.strip()[:80]}")
        else:
            self.console.print("[app.err]✖ empty response — check API key, model and network[/]")

    # -- assessment ------------------------------------------------------
    def cmd_target(self, *args: str) -> None:
        target = " ".join(args).strip()
        if not target:
            target = Prompt.ask("target", console=self.console).strip()
        if not target:
            warn("target required")
            return
        if self.agent is None:
            warn("no agent attached — run: x19 run -t " + target)
            return
        self.agent.autonomous_loop(target)

    cmd_scan = cmd_target
    cmd_pentest = cmd_target

    def cmd_dash(self, *args: str) -> None:
        from ui.dashboard import MissionDashboard

        target = " ".join(args).strip() or getattr(self.agent, "target", "") or ""
        if not target:
            target = Prompt.ask("target", console=self.console).strip()
        if not target:
            warn("target required")
            return
        from utils import validate_target

        if not validate_target(target):
            warn(f"'{target}' does not look like a valid host, IP or URL")
            return
        from brain.coordinator import SwarmCoordinator

        coordinator = SwarmCoordinator()
        dashboard = MissionDashboard(coordinator, version=self.version, console=self.console)
        dashboard.run(target=target)
        self.console.print(dashboard.report())

    def cmd_status(self, *args: str) -> None:
        rows = [("version", self.version or "—")]
        if self.agent is not None:
            session = getattr(self.agent, "session", None)
            rows += [
                ("target", getattr(self.agent, "target", "") or "—"),
                ("session", getattr(session, "id", "") or "—"),
                ("running", str(getattr(self.agent, "running", False))),
                ("iterations", str(getattr(session, "data", {}).get("iterations", 0))),
            ]
        try:
            rows.append(("ai", self.ai.name() if self.ai else "—"))
        except Exception:
            rows.append(("ai", "—"))
        self.console.print(widgets.panel("status", widgets.kv_table(rows)))
        if self.agent is not None and getattr(self.agent, "session", None):
            self.console.print(Text(self.agent.session.findings_summary(), style="grey74"))

    def cmd_findings(self, *args: str) -> None:
        from ui.screens import findings_screen

        findings = self._session_findings()
        self.console.print(findings_screen(findings, target=getattr(self.agent, "target", "") or ""))

    def cmd_report(self, *args: str) -> None:
        if self.agent is None or getattr(self.agent, "session", None) is None:
            warn("no session — run an assessment first")
            return
        self.console.print(Markdown("```\n" + self.agent.session.report() + "\n```"))

    # -- runtime ---------------------------------------------------------
    def cmd_providers(self, *args: str) -> None:
        from constants import PROVIDERS, PROVIDER_PRIORITY
        from config import load_config
        from provider_setup import configured_chain

        from ui.screens import providers_screen

        cfg = load_config()
        providers = {
            pid: dict(info, configured=bool(cfg.get(info.get("api_key_config", ""))))
            for pid, info in PROVIDERS.items()
        }
        self.console.print(
            providers_screen(
                providers,
                current=cfg.get("AI_PROVIDER", ""),
                chain=configured_chain(),
                priority=PROVIDER_PRIORITY,
            )
        )

    def cmd_model(self, *args: str) -> None:
        from config import CONFIG, save_config

        name = " ".join(args).strip()
        if not name:
            name = Prompt.ask("model", console=self.console).strip()
        if not name:
            warn("usage: /model <name>")
            return
        save_config({"AI_MODEL": name})
        CONFIG.AI_MODEL = name
        ok(f"model set to {name} — reconnect with x19 providers to apply")

    def cmd_config(self, *args: str) -> None:
        from config import CONFIG_FILE, load_config, set_data

        from ui.screens import config_screen

        if args:
            updates: Dict[str, str] = {}
            for token in args:
                if "=" not in token:
                    warn(f"expected KEY=VALUE, got '{token}'")
                    continue
                key, value = token.split("=", 1)
                updates[key.strip().upper()] = value.strip()
            if updates:
                set_data(updates)
                ok("saved " + ", ".join(updates))
        self.console.print(config_screen(load_config(), path=str(CONFIG_FILE)))

    def cmd_sessions(self, *args: str) -> None:
        import json
        from pathlib import Path

        from config import CONFIG

        from ui.screens import session_detail_screen, sessions_screen

        directory = Path(CONFIG.SESSIONS_DIR)
        if args:
            path = directory / f"{args[0]}.json"
            if not path.exists():
                warn(f"no such session: {args[0]}")
                return
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:
                warn(f"could not read session: {exc}")
                return
            self.console.print(session_detail_screen(data, args[0]))
            return

        rows = []
        for path in sorted(directory.glob("*.json"), reverse=True)[:50]:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            rows.append(
                {
                    "id": data.get("session_id", path.stem),
                    "target": data.get("target", ""),
                    "started": data.get("started", ""),
                    "iterations": data.get("iterations", 0),
                    "findings": len(data.get("findings") or []),
                    "status": data.get("status", ""),
                }
            )
        self.console.print(sessions_screen(rows))

    def cmd_tools(self, *args: str) -> None:
        from cli_support import toolchain_rows

        from ui.screens import tools_screen

        self.console.print(tools_screen(toolchain_rows()))

    def cmd_doctor(self, *args: str) -> None:
        from cli_support import run_diagnostics

        from ui.screens import doctor_screen

        result = run_diagnostics()
        self.console.print(doctor_screen(result["checks"], score=result["score"], detail=result.get("detail", "")))

    # ------------------------------------------------------------------
    def chat(self, message: str) -> None:
        if self.ai is None:
            warn("no AI provider configured — run: x19 setup")
            return
        self.history.append({"role": "user", "content": message})
        with get_console().status("[app.info]thinking[/]", spinner="dots") if get_console().is_terminal else _noop():
            reply = ""
            try:
                reply = self.ai.chat(SYSTEM_PROMPT, message) or ""
            except Exception as exc:
                self.console.print(f"[app.err]✖ {type(exc).__name__}: {exc}[/]")
                return
        self.history.append({"role": "assistant", "content": reply})
        self.console.print()
        self.console.print(Markdown(reply.strip() or "_(empty response)_"))
        self.console.print()

    # ------------------------------------------------------------------
    def _session_findings(self) -> List[Dict[str, Any]]:
        if self.agent is None:
            return []
        try:
            return [
                {
                    "severity": f.get("severity", "info"),
                    "title": f.get("title", ""),
                    "description": f.get("detail", ""),
                    "evidence": f.get("evidence", ""),
                }
                for f in self.agent.session.data.get("findings", [])
            ]
        except Exception:
            return []


class _noop:
    def __enter__(self) -> "_noop":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None
