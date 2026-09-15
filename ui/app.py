"""Terminal-native X19 chat workspace.

The terminal is a UI, not an execution log. The conversation is a rolling
transcript — every message is rendered exactly once, so nothing flickers —
while long-running assessments execute on quiet background threads. A live
status ribbon above the input line keeps the operator informed (task, elapsed
time, latest agent activity) and finished work is reported as it completes.

Nothing in this file is hardcoded to a particular provider, target, model or
terminal size: state comes from the attached agent / task manager, layout
adapts to the console width, and tunables live in the environment / config.
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

from ui import widgets
from ui.background import BackgroundTask, BackgroundTaskManager
from ui.console import get_console, info, ok, step, warn
from ui.prompt import LivePrompt

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
    {"name": "/stop", "help": "ask the running assessment to wrap up", "group": "assessment"},
    {"name": "/status", "help": "current session, provider and task state", "group": "assessment"},
    {"name": "/findings", "help": "list recorded findings by severity", "group": "assessment"},
    {"name": "/report", "help": "render the assessment report", "group": "assessment"},
    {"name": "/providers", "help": "show AI providers and failover chain", "group": "runtime"},
    {"name": "/provider add", "help": "add a persistent custom OpenAI-compatible provider", "group": "runtime"},
    {"name": "/model <name>", "help": "switch the active model", "group": "runtime"},
    {"name": "/config [K=V]", "help": "show configuration, or set a value", "group": "runtime"},
    {"name": "/sessions [id]", "help": "list stored sessions, or open one", "group": "runtime"},
    {"name": "/tasks [log <id>]", "help": "background tasks, or replay a task's output", "group": "runtime"},
    {"name": "/tools", "help": "toolchain availability", "group": "runtime"},
    {"name": "/doctor", "help": "self diagnostics and health score", "group": "runtime"},
    {"name": "/test", "help": "round-trip the AI provider", "group": "runtime"},
    {"name": "/shell", "help": "drop to the system shell", "group": "runtime"},
    {"name": "/clear", "help": "clear the conversation", "group": "session"},
    {"name": "/help", "help": "this list", "group": "session"},
    {"name": "/exit", "help": "quit", "group": "session"},
]

#: Roles the transcript understands (everything else renders as plain text).
ROLE_USER = "user"
ROLE_AGENT = "assistant"


class ConsoleApp:
    """A rolling-transcript workspace with the agent working in the background."""

    def __init__(self, agent: Any = None, *, version: str = "", ai: Any = None):
        self.agent = agent
        self.version = version
        self.console = get_console()
        self.history: List[Dict[str, str]] = []
        self._ai = ai
        self._exit = False
        self.background = BackgroundTaskManager()
        #: the task currently driving the attached agent, if any
        self._assessment_task: Optional[BackgroundTask] = None
        self.prompt = LivePrompt(
            self.console,
            ribbon_fn=self._ribbon,
            poll=self._poll_interval(),
            completer=self._completions,
        )

    def _completions(self, prefix: str) -> List[str]:
        """Tab completion candidates — derived from the command registry."""
        if not prefix.startswith("/"):
            return []
        names = []
        for entry in COMMANDS:
            name = str(entry.get("name", "")).split()[0]
            if name not in names:
                names.append(name)
        return [n for n in names if n.startswith(prefix)]

    # ------------------------------------------------------------------
    # Tunables — resolved from the environment/config, never hardcoded here
    # ------------------------------------------------------------------
    @staticmethod
    def _poll_interval() -> float:
        try:
            return max(0.1, float(os.getenv("X19_UI_POLL", "0.4")))
        except ValueError:
            return 0.4

    @property
    def ai(self) -> Any:
        if self._ai is None and self.agent is not None:
            self._ai = getattr(self.agent, "ai", None)
        return self._ai

    # ------------------------------------------------------------------
    # Transcript rendering — each message is printed exactly once
    # ------------------------------------------------------------------
    def _echo_user(self, text: str) -> None:
        line = Text()
        line.append("you ", style="accent2")
        line.append("❯ ", style="border.dim")
        line.append(text, style="bold text")
        self.console.print(line)

    def _echo_agent(self, markdown: str, title: str = "X19") -> None:
        head = Text()
        head.append(f"{title} ", style="brand")
        head.append("─", style="border.dim")
        self.console.print(head)
        self.console.print(Markdown(markdown))
        self.console.print()

    def _echo_system(self, text: str, *, style: str = "muted") -> None:
        self.console.print(Text(text, style=style))

    def remember(self, role: str, content: str) -> None:
        self.history.append({"role": role, "content": content})

    # ------------------------------------------------------------------
    # Status ribbon — one live line above the prompt
    # ------------------------------------------------------------------
    def _provider_name(self) -> str:
        try:
            return self.ai.name() if self.ai else "—"
        except Exception:
            return "—"

    def _assessment_details(self) -> str:
        """Live facts about the running assessment, straight from the agent."""
        if self._assessment_task is None or not self._assessment_task.active:
            return ""
        bits: List[str] = []
        session = getattr(self.agent, "session", None)
        data = getattr(session, "data", {}) if session is not None else {}
        try:
            iterations = int(data.get("iterations", 0) or 0)
            if iterations:
                bits.append(f"iter {iterations}")
            findings = data.get("findings") or []
            if findings:
                bits.append(f"{len(findings)} findings")
        except Exception:
            pass
        note = (self._assessment_task.note or "").strip()
        if note:
            bits.append(note)
        return " · ".join(bits)

    def _ribbon(self) -> str:
        if not getattr(self.console, "is_terminal", False):
            return ""
        width = max(40, int(self.console.width))
        left = Text()
        left.append("X19", style="brand")
        left.append(" · ", style="border.dim")
        target = getattr(self.agent, "target", "") or "no target"
        left.append(widgets.truncate(target, max(10, width // 4)), style="bold text")
        left.append(" · ", style="border.dim")
        left.append(widgets.truncate(self._provider_name(), max(8, width // 5)), style="info")

        right = Text()
        active = self.background.active()
        if active:
            details = self._assessment_details()
            elapsed = widgets.human_duration(active[0].elapsed())
            right.append("● ", style="ok")
            right.append(f"{active[0].label} {elapsed}", style="bold text")
            if details:
                right.append(f" — {widgets.truncate(details, max(10, width // 3))}", style="muted")
        else:
            right.append("○ idle", style="faint")
            right.append("   /help commands", style="faint")

        # Manually padded single line — LivePrompt repaints it in place.
        pad = max(2, width - 2 - left.cell_len - right.cell_len)
        line = Text(" ")
        line.append(left)
        line.append(" " * pad)
        line.append(right)
        if getattr(self.console, "no_color", False):
            return line.plain
        return _render_ansi(line, width, self.console)

    # ------------------------------------------------------------------
    # Welcome / notifications
    # ------------------------------------------------------------------
    def _welcome(self) -> None:
        from version import version_line

        self.console.print()
        head = Text()
        head.append(" X19 ", style="bold black on brand")
        head.append(f"  {version_line()}", style="brand")
        head.append("  ·  terminal workspace", style="muted")
        self.console.print(head)
        meta = Text()
        meta.append(f"  ai {self._provider_name()}", style="info")
        target = getattr(self.agent, "target", "")
        if target:
            meta.append(f"  ·  target {target}", style="bold text")
        self.console.print(meta)
        hints = Text("  ")
        quick = [c["name"] for c in COMMANDS if c["group"] == "assessment"][:3]
        hints.append("start here: ", style="faint")
        hints.append("  ".join(quick), style="key")
        self.console.print(hints)
        self.console.print()

    def _drain_notifications(self) -> None:
        """Report background tasks that finished since the last look."""
        for task in self.background.drain_notifications():
            duration = widgets.human_duration(task.elapsed())
            if task.status == "completed":
                body = Text()
                body.append("✔ ", style="ok")
                body.append(f"{task.label} completed in {duration}", style="bold text")
                counts = self._finding_counts()
                if counts:
                    body.append(f" — {counts}", style="warn")
                self.console.print(Panel(body, title="background", border_style="border", padding=(0, 1)))
                hint_text = Text("  ")
                hint_text.append("/report", style="key")
                hint_text.append(" render the assessment · ", style="muted")
                hint_text.append("/findings", style="key")
                hint_text.append(" list what was verified", style="muted")
                self.console.print(hint_text)
            elif task.status == "cancelled":
                self._echo_system(f"■ {task.label} interrupted after {duration}", style="warn")
            else:
                self._echo_system(f"✖ {task.label} failed after {duration}: {task.error}", style="err")
                tail_hint = Text("  ")
                tail_hint.append(f"/tasks log {task.id}", style="key")
                tail_hint.append(" replay what happened", style="muted")
                self.console.print(tail_hint)

    def _finding_counts(self) -> str:
        session = getattr(self.agent, "session", None)
        data = getattr(session, "data", {}) if session is not None else {}
        findings = data.get("findings") or []
        if not findings:
            return ""
        counts: Dict[str, int] = {}
        for finding in findings:
            severity = str(finding.get("severity", "info") or "info").lower()
            counts[severity] = counts.get(severity, 0) + 1
        order = ("critical", "high", "medium", "low", "info")
        return " ".join(f"{n} {sev}" for sev in order if (n := counts.get(sev, 0)))

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------
    def prompt_text(self) -> str:
        return "you ›"

    def run(self) -> int:
        self._welcome()
        while not self._exit:
            try:
                line = self.prompt.ask(self.prompt_text()).strip()
            except (EOFError, KeyboardInterrupt):
                self.console.print()
                break
            if not line:
                self._drain_notifications()
                continue
            self._echo_user(line)
            self.remember(ROLE_USER, line)
            try:
                self.handle(line)
            except KeyboardInterrupt:
                warn("interrupted")
            except SystemExit:
                raise
            except Exception as exc:
                self.console.print(f"[err]✖ {type(exc).__name__}: {exc}[/]")
            self._drain_notifications()
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

    # ------------------------------------------------------------------
    # Session commands
    # ------------------------------------------------------------------
    def cmd_help(self, *args: str) -> None:
        from ui.screens import help_screen
        self.console.print(help_screen(COMMANDS, version=self.version))

    def cmd_exit(self, *args: str) -> None:
        if self._assessment_task and self._assessment_task.active:
            self._echo_system(
                "note: a background assessment is still running — it is a daemon "
                "thread and ends with this process",
                style="warn",
            )
        self._exit = True

    cmd_quit = cmd_exit

    def cmd_clear(self, *args: str) -> None:
        self.history.clear()
        if self.console.is_terminal:
            self.console.clear()
        self._welcome()
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

    # ------------------------------------------------------------------
    # Assessment
    # ------------------------------------------------------------------
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
        text = self._scope_result_text(result)
        self.remember(ROLE_AGENT, text)
        self._echo_agent(text, title="scope")

    def cmd_target(self, *args: str) -> None:
        target = " ".join(args).strip() or Prompt.ask("target", console=self.console).strip()
        if not target:
            warn("target required")
            return
        if self.agent is None:
            warn("no agent attached — run: x19 run -t " + target)
            return
        if self._assessment_task and self._assessment_task.active:
            warn("a background assessment is already running — /stop it first or /tasks for status")
            return

        # Scope is resolved before the LLM or autonomous loop gets control.
        result = self._resolve_scope(target)
        text = self._scope_result_text(result)
        self.remember(ROLE_AGENT, text)
        self._echo_agent(text, title="scope")

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
            try:
                self.agent.target = target
            except Exception:
                pass
            task = self.background.start(
                f"assessment {target}",
                lambda: self.agent.autonomous_loop(target),
                target=target,
            )
            self._assessment_task = task
            ok(f"assessment running in the background · task {task.id}")
            step("keep chatting — the ribbon above the prompt tracks progress; /stop wraps it up")
        except Exception as exc:
            warn(f"could not start background assessment: {exc}")

    cmd_scan = cmd_target
    cmd_pentest = cmd_target

    def cmd_stop(self, *args: str) -> None:
        task = self._assessment_task
        if task is None or not task.active:
            warn("no background assessment running")
            return
        stopped = False
        try:
            if getattr(self.agent, "running", False):
                self.agent.stop = True
                stopped = True
        except Exception:
            pass
        if stopped:
            info(f"stop requested for task {task.id} — the agent finishes its current step and wraps up")
        else:
            warn("the agent is not reporting a running loop; waiting for the task to settle")

    def cmd_tasks(self, *args: str) -> None:
        if args and args[0].lower() == "log":
            if len(args) < 2:
                warn("usage: /tasks log <task-id>")
                return
            task = self.background.get(args[1])
            if task is None:
                warn(f"no such task: {args[1]}")
                return
            self.console.print(widgets.panel(
                f"task {task.id} · {task.label}",
                Group(*(Text(line, style="evidence") for line in task.tail(30))) if task.tail(30)
                else Text("no captured output", style="muted"),
                subtitle=f"{task.status} · {len(task.output)} lines captured",
            ))
            return
        rows = [(t.id, t.label, t.target or "—", t.status, widgets.human_duration(t.elapsed()), t.note or "—")
                for t in self.background.recent(20)]
        if not rows:
            self.console.print(Panel("No background tasks yet — /target <host> starts one.",
                                     title="tasks", border_style="border"))
            return
        table = Table(title=None, expand=True, box=None)
        for col, style in (("id", "key"), ("task", "text.strong"), ("target", "info"), ("status", ""), ("elapsed", "muted"), ("latest", "muted")):
            table.add_column(col, style=style or None)
        for row in rows:
            table.add_row(*row)
        self.console.print(widgets.panel("background tasks", table, subtitle="use /tasks log <id> to replay output"))

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
        active = self.background.active()
        rows.append(("background", f"{len(active)} running" if active else "idle"))
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
        # Most recent first, by actual modification time — file names are not
        # guaranteed to sort chronologically.
        paths = sorted(directory.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:50]
        for path in paths:
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

    # ------------------------------------------------------------------
    # LLM chat
    # ------------------------------------------------------------------
    def chat(self, message: str) -> None:
        if self.ai is None:
            warn("no AI provider configured — run: x19 setup")
            return
        from contextlib import nullcontext

        con = self.console
        spinner = (
            con.status("[info]X19 is thinking[/]", spinner="dots")
            if con.is_terminal and not getattr(con, "no_color", False)
            else nullcontext()
        )
        with spinner:
            try:
                reply = self.ai.chat(SYSTEM_PROMPT, message) or ""
            except Exception as exc:
                warn(f"provider request failed: {type(exc).__name__}")
                return
        self.remember(ROLE_AGENT, reply)
        self._echo_agent(reply)

    def _session_findings(self) -> List[Dict[str, Any]]:
        if self.agent is None:
            return []
        try:
            return [{"severity": f.get("severity", "info"), "title": f.get("title", ""), "description": f.get("detail", ""), "evidence": f.get("evidence", "")} for f in self.agent.session.data.get("findings", [])]
        except Exception:
            return []


def _render_ansi(renderable: Any, width: int, source_console: Any) -> str:
    """Render one line of markup to a raw ANSI string for in-place repaints.

    Uses the same theme as the active console so the ribbon matches the rest
    of the UI. Falls back to plain text when rendering is not possible.
    """
    import io

    from rich.console import Console

    try:
        buf = Console(
            file=io.StringIO(),
            width=width,
            force_terminal=True,
            color_system=getattr(source_console, "_color_system", None) or "truecolor",
            theme=source_console.theme,
        )
        buf.print(renderable)
        text = buf.file.getvalue()
        return text.rstrip("\n")
    except Exception:
        try:
            return renderable.plain
        except Exception:
            return str(renderable)
