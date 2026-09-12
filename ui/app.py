"""Terminal-native X19 chat workspace.

The terminal is a UI, not an execution log. Long-running assessments are sent
to quiet background workers; the conversation shows only concise state and
final results. Provider failover/tool chatter stays out of the main screen.
"""
from __future__ import annotations

import os
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional

from rich.console import Group
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text
from rich.layout import Layout

from ui import widgets
from ui.background import BackgroundTaskManager
from ui.console import get_console, info, ok, rule, step, warn

SYSTEM_PROMPT = (
    "You are X19, an expert offensive-security analyst running inside a terminal "
    "application. Answer precisely, prefer concrete commands and evidence, and "
    "never invent output you did not observe. Keep user-facing responses concise. "
    "Target authorization and public-program scope are resolved by deterministic "
    "X19 policy code before active assessment; never invent authorization status."
)

COMMANDS: List[Dict[str, str]] = [
    {"name": "/target <host>", "help": "scope-check then start a quiet background assessment", "group": "assessment"},
    {"name": "/scope <host>", "help": "passively check trusted public bounty scope", "group": "assessment"},
    {"name": "/dash <host>", "help": "live swarm mission control (full screen)", "group": "assessment"},
    {"name": "/status", "help": "current session, provider and task state", "group": "assessment"},
    {"name": "/findings", "help": "list recorded findings by severity", "group": "assessment"},
    {"name": "/report", "help": "render the assessment report", "group": "assessment"},
    {"name": "/providers", "help": "show AI providers and failover chain", "group": "runtime"},
    {"name": "/provider add", "help": "add a persistent custom OpenAI-compatible provider", "group": "runtime"},
    {"name": "/model <name>", "help": "switch the active model", "group": "runtime"},
    {"name": "/config [K=V]", "help": "show configuration, or set a value", "group": "runtime"},
    {"name": "/sessions [id]", "help": "list stored sessions, or open one", "group": "runtime"},
    {"name": "/tasks", "help": "show quiet background tasks", "group": "runtime"},
    {"name": "/tools", "help": "toolchain availability", "group": "runtime"},
    {"name": "/doctor", "help": "self diagnostics and health score", "group": "runtime"},
    {"name": "/test", "help": "round-trip the AI provider", "group": "runtime"},
    {"name": "/shell", "help": "drop to the system shell", "group": "runtime"},
    {"name": "/clear", "help": "clear the conversation", "group": "session"},
    {"name": "/help", "help": "this list", "group": "session"},
    {"name": "/exit", "help": "quit", "group": "session"},
]


class ConsoleApp:
    """ChatGPT-style workspace rendered entirely inside the terminal."""

    def __init__(self, agent: Any = None, *, version: str = "", ai: Any = None):
        self.agent = agent
        self.version = version
        self.console = get_console()
        self.history: List[Dict[str, str]] = []
        self._ai = ai
        self._exit = False
        self.background = BackgroundTaskManager(max_workers=2)
        self._workspace_notice = ""

    @property
    def ai(self) -> Any:
        if self._ai is None and self.agent is not None:
            self._ai = getattr(self.agent, "ai", None)
        return self._ai

    def prompt_text(self) -> str:
        return "you ›"

    def _workspace(self) -> Layout:
        target = getattr(self.agent, "target", "") or "—"
        provider = "—"
        try:
            provider = self.ai.name() if self.ai else "—"
        except Exception:
            pass
        active = self.background.active()
        tasks = self.background.recent(6)

        sidebar = Table.grid(padding=(0, 1))
        sidebar.add_column(style="bold bright_cyan", width=20)
        sidebar.add_row("X19")
        sidebar.add_row("")
        sidebar.add_row("[bold bright_white]NEW CHAT[/]")
        sidebar.add_row("[grey50]Current session[/]")
        sidebar.add_row(f"[grey70]Target: {target[:24]}[/]")
        sidebar.add_row("")
        sidebar.add_row("[bold]WORKSPACE[/]")
        sidebar.add_row("[grey70]/target[/]  assessment")
        sidebar.add_row("[grey70]/scope[/]   bounty scope")
        sidebar.add_row("[grey70]/findings[/] findings")
        sidebar.add_row("[grey70]/report[/] report")
        sidebar.add_row("[grey70]/providers[/] providers")
        sidebar.add_row("[grey70]/sessions[/] history")
        sidebar.add_row("")
        sidebar.add_row("[bold]BACKGROUND[/]")
        if active:
            for task in active:
                sidebar.add_row(f"[yellow]●[/] {task.label[:25]}")
        else:
            sidebar.add_row("[grey50]idle[/]")
        sidebar.add_row("")
        sidebar.add_row(f"[grey50]{provider[:26]}[/]")

        chat_parts: List[Any] = []
        for item in self.history[-30:]:
            role = item.get("role")
            content = item.get("content", "").strip()
            if not content:
                continue
            if role == "user":
                chat_parts.append(Panel(content, title="you", title_align="left", border_style="magenta", padding=(0, 1)))
            else:
                chat_parts.append(Panel(Markdown(content), title="X19", title_align="left", border_style="bright_cyan", padding=(0, 1)))

        if not chat_parts:
            chat_parts.append(Panel(
                "Ready. Give me a message or use /target <host> to start an assessment.\n\n"
                "X19 checks public program scope before active work. Long-running tool output stays in the background.",
                title="X19",
                border_style="bright_cyan",
                padding=(1, 2),
            ))

        if active:
            task_lines = [f"[yellow]●[/] {t.label} — [grey70]{t.status}[/]" for t in active]
            chat_parts.append(Panel("\n".join(task_lines), title="background", border_style="yellow", padding=(0, 1)))
        elif tasks and tasks[-1].status in {"completed", "failed"}:
            last = tasks[-1]
            if last.status == "completed":
                chat_parts.append(Panel(f"[green]✓[/] {last.label} completed", title="background", border_style="green"))
            else:
                chat_parts.append(Panel(f"[red]✗[/] {last.label}: {last.error[:180]}", title="background", border_style="red"))

        main = Layout(name="main")
        compact = self.console.width < 100
        target_display = widgets.truncate(target, 22 if compact else 42)
        provider_display = widgets.truncate(provider, 16 if compact else 30)
        header = (
            f"[bold bright_cyan]X19[/]   [bold]Target:[/] {target_display}   "
            f"[bold]Provider:[/] {provider_display}   [bold]Tasks:[/] {len(active)}"
        )
        if compact:
            header += "   [grey62]/help for commands[/]"
        main.split_column(
            Layout(Panel(header, border_style="grey37", padding=(0, 1)), name="header", size=3),
            Layout(Panel(Group(*chat_parts), border_style="grey23", padding=(0, 1)), name="conversation", ratio=1),
            Layout(Panel("[bold magenta]you ›[/] _", border_style="grey37", height=3, padding=(0, 1)), name="composer", size=3),
        )
        root = Layout(name="root")
        if compact:
            # Do not squeeze the conversation below a usable width.  The full
            # command index remains available through /help.
            root.split_column(main)
        else:
            root.split_row(Layout(Panel(sidebar, border_style="grey23", padding=(1, 1)), name="sidebar", size=27), main)
        return root

    def _draw(self) -> None:
        if self.console.is_terminal:
            self.console.clear()
        self.console.print(self._workspace())

    def run(self) -> int:
        from version import version_line
        self.console.print()
        rule(f"[panel.title]{version_line()}[/]  ·  terminal workspace")
        info("[grey70]Background-first mode: tools, scans and provider failover stay quiet.[/]")
        self.console.print()

        while not self._exit:
            try:
                self._draw()
                line = Prompt.ask(self.prompt_text(), console=self.console, default="", show_default=False).strip()
            except (EOFError, KeyboardInterrupt):
                self.console.print()
                break
            if not line:
                continue
            try:
                self.handle(line)
            except KeyboardInterrupt:
                warn("interrupted")
            except SystemExit:
                raise
            except Exception as exc:
                self.console.print(f"[app.err]✖ {type(exc).__name__}: {exc}[/]")
        ok("bye")
        return 0

    def handle(self, line: str) -> None:
        # Natural-language target requests are routed deterministically before
        # the LLM. This prevents the model from issuing a blanket refusal or
        # inventing authorization status before X19 has checked scope.
        if not line.startswith("/"):
            target_request = self._parse_target_request(line)
            if target_request:
                self.cmd_target(target_request)
                return
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

    @staticmethod
    def _parse_target_request(message: str) -> Optional[str]:
        """Recognize target/scan/pentest intent without asking the LLM."""
        import re
        parts = message.strip().split()
        if not parts:
            return None
        first = parts[0].lower()
        if first not in {"target", "scan", "pentest", "assess", "enumerate", "engage", "hack"}:
            return None
        host_re = re.compile(r"^(?:(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9][a-zA-Z0-9.\-]*\.[a-zA-Z]{2,})(?::\d+)?$")
        for token in parts[1:]:
            token = token.strip().rstrip(".,")
            if token.startswith("-"):
                continue
            if host_re.match(token):
                return token
        return None

    def cmd_help(self, *args: str) -> None:
        from ui.screens import help_screen
        self.console.print(help_screen(COMMANDS, version=self.version))

    def cmd_exit(self, *args: str) -> None:
        self._exit = True

    cmd_quit = cmd_exit

    def cmd_clear(self, *args: str) -> None:
        self.history.clear()
        ok("conversation cleared")

    def cmd_shell(self, *args: str) -> None:
        step("system shell — type 'exit' to return")
        shell = ["powershell"] if os.name == "nt" else [os.getenv("SHELL", "/bin/bash")]
        subprocess.run(shell)

    def cmd_test(self, *args: str) -> None:
        if self.ai is None:
            warn("no AI provider configured — run: x19 setup")
            return
        started = time.time()
        reply = self.ai.chat("Reply with the single word: ready.", "ping")
        elapsed = time.time() - started
        if reply:
            ok(f"provider responded in {elapsed:.2f}s — {reply.strip()[:80]}")
        else:
            warn("empty response — check provider configuration")

    # -- assessment ------------------------------------------------------
    def _scope_result_text(self, result: Any) -> str:
        state = getattr(result, "state", "unknown")
        target = getattr(result, "normalized_target", "") or getattr(result, "target", "")
        program = getattr(result, "program", "")
        pattern = getattr(result, "matched_pattern", "")
        source = getattr(result, "source_url", "")
        reason = getattr(result, "reason", "")
        lines = [f"**Scope check:** `{target}`", f"**Status:** `{state}`"]
        if program:
            lines.append(f"**Program:** {program}")
        if pattern:
            lines.append(f"**Matched:** `{pattern}`")
        if source:
            lines.append(f"**Source:** {source}")
        if reason:
            lines.append(f"**Why:** {reason}")
        notes = list(getattr(result, "notes", []) or [])
        if notes:
            lines.append("\n**Program constraints:**\n" + "\n".join(f"- {n}" for n in notes[:6]))
        return "\n".join(lines)

    def _resolve_scope(self, target: str) -> Any:
        from scope_guard import resolve_scope
        return resolve_scope(target)

    def cmd_scope(self, *args: str) -> None:
        target = " ".join(args).strip() or getattr(self.agent, "target", "")
        if not target:
            warn("usage: /scope <host>")
            return
        result = self._resolve_scope(target)
        self.history.append({"role": "user", "content": f"/scope {target}"})
        self.history.append({"role": "assistant", "content": self._scope_result_text(result)})
        self.console.print(Markdown(self._scope_result_text(result)))

    def cmd_target(self, *args: str) -> None:
        target = " ".join(args).strip() or Prompt.ask("target", console=self.console).strip()
        if not target:
            warn("target required")
            return
        if self.agent is None:
            warn("no agent attached — run: x19 run -t " + target)
            return
        if self.background.active():
            warn("a background assessment is already running")
            return

        # Scope is resolved before the LLM or autonomous loop gets control.
        result = self._resolve_scope(target)
        self.history.append({"role": "user", "content": f"target {target}"})
        self.history.append({"role": "assistant", "content": self._scope_result_text(result)})
        self.console.print(Markdown(self._scope_result_text(result)))

        state = getattr(result, "state", "unknown")
        if state == "verified_out_of_scope":
            warn("assessment not started: the public program was found, but this exact target is outside its declared scope")
            return
        if state == "unknown":
            warn("assessment not started: no trusted public program or explicit scope source was verified")
            warn("for an authorized engagement, provide a scope URL via X19_SCOPE_URL or create an X19 engagement profile")
            return

        # Public-program discovery is evidence about scope, not a blanket grant
        # to attack. Require an explicit confirmation of the program rules.
        program = getattr(result, "program", "public program") or "public program"
        confirm = Prompt.ask(
            f"Proceed with active assessment under {program} rules? [y/N]",
            console=self.console,
            default="N",
        ).strip().lower()
        if confirm not in {"y", "yes"}:
            info("assessment cancelled")
            return

        try:
            task = self.background.start(
                "Assessment",
                lambda: self.agent.autonomous_loop(target),
                target=target,
            )
            try:
                self.agent.target = target
            except Exception:
                pass
            ok(f"background assessment started · task {task.id}")
        except Exception as exc:
            warn(f"could not start background assessment: {exc}")

    cmd_scan = cmd_target
    cmd_pentest = cmd_target

    def cmd_tasks(self, *args: str) -> None:
        rows = [(t.id, t.label, t.target or "—", t.status) for t in self.background.recent(20)]
        if not rows:
            self.console.print(Panel("No background tasks.", title="tasks", border_style="grey37"))
            return
        table = Table(title="quiet background tasks")
        for col in ("id", "task", "target", "status"):
            table.add_column(col)
        for row in rows:
            table.add_row(*row)
        self.console.print(table)

    def cmd_dash(self, *args: str) -> None:
        from ui.dashboard import MissionDashboard
        target = " ".join(args).strip() or getattr(self.agent, "target", "") or Prompt.ask("target", console=self.console).strip()
        if not target:
            warn("target required")
            return
        from utils import validate_target
        if not validate_target(target):
            warn(f"'{target}' does not look like a valid host, IP or URL")
            return
        from brain.coordinator import SwarmCoordinator
        dashboard = MissionDashboard(SwarmCoordinator(), version=self.version, console=self.console)
        dashboard.run(target=target)
        self.console.print(dashboard.report())

    def cmd_status(self, *args: str) -> None:
        rows = [("version", self.version or "—")]
        if self.agent is not None:
            session = getattr(self.agent, "session", None)
            rows += [("target", getattr(self.agent, "target", "") or "—"), ("session", getattr(session, "id", "") or "—"), ("running", str(getattr(self.agent, "running", False))), ("iterations", str(getattr(session, "data", {}).get("iterations", 0)))]
        try:
            rows.append(("ai", self.ai.name() if self.ai else "—"))
        except Exception:
            rows.append(("ai", "—"))
        rows.append(("background", str(len(self.background.active()))))
        self.console.print(widgets.panel("status", widgets.kv_table(rows)))

    def cmd_findings(self, *args: str) -> None:
        from ui.screens import findings_screen
        self.console.print(findings_screen(self._session_findings(), target=getattr(self.agent, "target", "") or ""))

    def cmd_report(self, *args: str) -> None:
        if self.agent is None or getattr(self.agent, "session", None) is None:
            warn("no session — run an assessment first")
            return
        self.console.print(Markdown("```\n" + self.agent.session.report() + "\n```"))

    # -- providers -------------------------------------------------------
    def cmd_providers(self, *args: str) -> None:
        from constants import PROVIDERS, PROVIDER_PRIORITY
        from config import load_config
        from provider_setup import configured_chain
        try:
            from custom_providers import load_custom_providers
            load_custom_providers()
        except Exception:
            pass
        from ui.screens import providers_screen
        cfg = load_config()
        providers = {pid: dict(info, configured=bool(cfg.get(info.get("api_key_config", "")))) for pid, info in PROVIDERS.items()}
        self.console.print(providers_screen(providers, current=cfg.get("AI_PROVIDER", ""), chain=configured_chain(), priority=PROVIDER_PRIORITY))

    def cmd_provider(self, *args: str) -> None:
        if not args or args[0].lower() != "add":
            warn("usage: /provider add")
            return
        from custom_providers import add_custom_provider
        pid = Prompt.ask("provider id", console=self.console).strip()
        name = Prompt.ask("display name", console=self.console).strip()
        base = Prompt.ask("OpenAI-compatible base URL", console=self.console).strip()
        model = Prompt.ask("default model", console=self.console).strip()
        key_env = Prompt.ask("API key env var (optional)", console=self.console, default="").strip()
        try:
            entry = add_custom_provider(pid, name, base, model, api_key_env=key_env)
            ok(f"custom provider added: {entry['name']} · restart X19 to make it available to a new agent")
        except Exception as exc:
            warn(str(exc))

    def cmd_model(self, *args: str) -> None:
        from config import CONFIG, save_config
        name = " ".join(args).strip() or Prompt.ask("model", console=self.console).strip()
        if not name:
            warn("usage: /model <name>")
            return
        save_config({"AI_MODEL": name})
        CONFIG.AI_MODEL = name
        ok(f"model set to {name}")

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
            rows.append({"id": data.get("session_id", path.stem), "target": data.get("target", ""), "started": data.get("started", ""), "iterations": data.get("iterations", 0), "findings": len(data.get("findings") or []), "status": data.get("status", "")})
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

    def chat(self, message: str) -> None:
        if self.ai is None:
            warn("no AI provider configured — run: x19 setup")
            return
        self.history.append({"role": "user", "content": message})
        with get_console().status("[app.info]thinking[/]", spinner="dots") if get_console().is_terminal else _noop():
            try:
                reply = self.ai.chat(SYSTEM_PROMPT, message) or ""
            except Exception as exc:
                warn(f"provider request failed: {type(exc).__name__}")
                return
        self.history.append({"role": "assistant", "content": reply})

    def _session_findings(self) -> List[Dict[str, Any]]:
        if self.agent is None:
            return []
        try:
            return [{"severity": f.get("severity", "info"), "title": f.get("title", ""), "description": f.get("detail", ""), "evidence": f.get("evidence", "")} for f in self.agent.session.data.get("findings", [])]
        except Exception:
            return []


class _noop:
    def __enter__(self) -> "_noop":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None
