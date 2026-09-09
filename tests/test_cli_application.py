"""Tests for the 4.0.0 terminal application: CLI surface, UI widgets, dashboard.

These cover the code paths that replaced the removed Flask web UI, so a
regression in the terminal interface fails the suite instead of shipping.
"""
from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from rich.console import Console

import cli
import cli_support
import version as version_module
from ui import widgets
from ui.console import init_console
from ui.dashboard import MissionDashboard, severity_summary
from ui.screens import (
    config_screen,
    doctor_screen,
    env_screen,
    findings_screen,
    help_screen,
    is_secret_key,
    mask_secret,
    providers_screen,
    session_detail_screen,
    sessions_screen,
    tools_screen,
)
from ui.theme import X19_THEME, severity_rank, severity_style


def render(renderable, width: int = 118) -> str:
    """Render a rich renderable to plain text for assertions."""
    console = Console(file=io.StringIO(), width=width, force_terminal=False, theme=X19_THEME, record=True)
    console.print(renderable)
    return console.export_text(clear=True, styles=False)


SESSION = {
    "session_id": "x19_test_0001",
    "target": "scanme.nmap.org",
    "started": "2026-01-01T00:00:00",
    "status": "complete",
    "iterations": 2,
    "os_info": "Linux",
    "ports_discovered": "22,80",
    "commands": [
        {"cmd": "nmap -sV scanme.nmap.org", "result": "22/tcp open ssh", "rc": 0, "ts": "t"},
    ],
    "findings": [
        {
            "severity": "critical",
            "title": "Exposed .env with cloud credentials",
            "detail": "The web root serves .env",
            "evidence": "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE",
            "ts": "t",
        },
        {
            "severity": "low",
            "title": "Server header version disclosure",
            "detail": "Server: Apache/2.4.41",
            "evidence": "Server: Apache/2.4.41 (Ubuntu)",
            "ts": "t",
        },
    ],
}

SUMMARY = {
    "target": "scanme.nmap.org",
    "is_running": False,
    "duration_seconds": 42,
    "agents": [
        {
            "name": "ReconAgent",
            "role": "Network & Service Discovery",
            "state": "completed",
            "current_task": "port sweep",
            "progress_pct": 100.0,
            "discovered_count": 2,
            "last_log": "2 ports open",
        },
        {
            "name": "WebAgent",
            "role": "Web Surface",
            "state": "running",
            "current_task": "fuzzing",
            "progress_pct": 40.0,
            "discovered_count": 1,
            "last_log": "",
        },
    ],
    "stats": {"open_ports": 2, "endpoints": 3, "raw_findings": 2, "verified_findings": 1, "pending_tasks": 1},
    "verified_findings": [
        {
            "severity": "critical",
            "title": "Exposed .env with cloud credentials",
            "cvss_score": 9.1,
            "evidence": "AWS_SECRET_ACCESS_KEY=…",
        }
    ],
    "ports": [{"port": 22, "protocol": "tcp", "service": "ssh", "banner": "OpenSSH 8.9", "tls_info": {}}],
    "endpoints": [{"path": "/.env", "status_code": 200, "title": "", "is_interesting": True}],
    "tasks": [{"priority": 1, "task_type": "recon", "target": "scanme.nmap.org", "status": "completed"}],
}

GRAPH = {
    "nodes": [
        {"id": "n1", "label": "Target: scanme.nmap.org", "type": "host", "value_score": 1.0},
        {"id": "n2", "label": "22/tcp ssh", "type": "service", "value_score": 0.6},
        {"id": "n3", "label": "/.env", "type": "endpoint", "value_score": 0.9},
    ],
    "edges": [
        {"from": "n1", "to": "n2", "label": "exposes"},
        {"from": "n1", "to": "n3", "label": "exposes"},
    ],
}


class VersionTests(unittest.TestCase):
    def test_version_is_semver(self):
        self.assertRegex(version_module.__version__, r"^\d+\.\d+\.\d+$")
        self.assertEqual(version_module.VERSION, version_module.__version__)
        self.assertEqual((version_module.MAJOR, version_module.MINOR, version_module.PATCH),
                         tuple(int(x) for x in version_module.__version__.split(".")))

    def test_version_info_contract(self):
        info = version_module.version_info()
        self.assertEqual(info["app"], "X19")
        self.assertEqual(info["version"], version_module.__version__)
        self.assertEqual(info["interface"], "cli")
        self.assertFalse(info["web_ui"], "the web UI must stay removed")
        for key in ("python", "platform", "schema_version", "release"):
            self.assertIn(key, info)

    def test_version_line_contains_version(self):
        self.assertIn(version_module.__version__, version_module.version_line())


class WebUiRemovedTests(unittest.TestCase):
    """The 4.0.0 contract: X19 is a terminal application, nothing serves HTTP."""

    def test_no_webui_files(self):
        for name in ("webui.py", "webui_templates", "webui_err.txt"):
            self.assertFalse((ROOT / name).exists(), f"{name} should have been removed")

    def test_requirements_have_no_web_server(self):
        text = (ROOT / "requirements.txt").read_text(encoding="utf-8").lower()
        active = [line for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
        for line in active:
            self.assertNotIn("flask", line)
            self.assertNotIn("django", line)
            self.assertNotIn("fastapi", line)

    def test_no_module_imports_a_web_framework(self):
        """Parse the AST so string literals and comments cannot fool the check."""
        import ast

        banned = {"flask", "django", "fastapi", "bottle", "tornado", "aiohttp", "starlette"}
        offenders = []
        for path in sorted(ROOT.rglob("*.py")):
            if any(part in {".git", "__pycache__", ".venv"} for part in path.parts):
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError:  # pragma: no cover - syntax is checked elsewhere
                continue
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module.split(".")[0]]
                if any(name.lower() in banned for name in names):
                    offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [])


class ArgvNormalizationTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(cli.normalize_argv([]), [])

    def test_subcommand_passthrough(self):
        self.assertEqual(cli.normalize_argv(["doctor", "--json"]), ["doctor", "--json"])

    def test_legacy_target_maps_to_run(self):
        self.assertEqual(cli.normalize_argv(["-t", "10.0.0.1"]), ["run", "-t", "10.0.0.1"])

    def test_global_flag_before_command_is_rotated(self):
        self.assertEqual(cli.normalize_argv(["--json", "report"]), ["report", "--json"])

    def test_top_level_help_and_version_stay(self):
        self.assertEqual(cli.normalize_argv(["--help"]), ["--help"])
        self.assertEqual(cli.normalize_argv(["-V"]), ["-V"])

    def test_legacy_upgrade_flag(self):
        self.assertEqual(cli.normalize_argv(["--upgrade"]), ["upgrade"])


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.parser = cli.build_parser()

    def test_all_commands_registered(self):
        sub = next(
            action for action in self.parser._actions if hasattr(action, "choices") and action.choices
        )
        for command in cli.COMMANDS:
            self.assertIn(command, sub.choices)

    def test_run_flags(self):
        args = self.parser.parse_args(["run", "-t", "scanme.nmap.org", "--bug-bounty", "--fast"])
        self.assertEqual(args.command, "run")
        self.assertEqual(args.target, "scanme.nmap.org")
        self.assertTrue(args.bug_bounty)
        self.assertTrue(args.fast)

    def test_dash_flags(self):
        args = self.parser.parse_args(["dash", "-t", "10.0.0.1", "--once", "--refresh", "0.2"])
        self.assertEqual(args.target, "10.0.0.1")
        self.assertTrue(args.once)
        self.assertAlmostEqual(args.refresh, 0.2)

    def test_report_formats(self):
        for fmt in ("markdown", "html", "json", "text"):
            args = self.parser.parse_args(["report", "--format", fmt])
            self.assertEqual(args.format, fmt)

    def test_global_json_flag_on_subcommand(self):
        args = self.parser.parse_args(["doctor", "--json"])
        self.assertTrue(args.json)


class WidgetTests(unittest.TestCase):
    def test_human_duration(self):
        self.assertEqual(widgets.human_duration(None), "—")
        self.assertEqual(widgets.human_duration(0), "00:00")
        self.assertEqual(widgets.human_duration(83), "01:23")
        self.assertEqual(widgets.human_duration(3725), "1:02:05")

    def test_truncate(self):
        self.assertEqual(widgets.truncate("abcdef", 6), "abcdef")
        self.assertEqual(widgets.truncate("abcdefg", 6), "abcde…")
        self.assertEqual(widgets.truncate("a  b\n c", 20), "a b c")

    def test_severity_ranking(self):
        order = sorted(["info", "low", "critical", "medium", "high"], key=severity_rank)
        self.assertEqual(order, ["critical", "high", "medium", "low", "info"])
        self.assertEqual(severity_rank("nonsense"), 5)

    def test_severity_style_known_and_unknown(self):
        self.assertEqual(severity_style("CRITICAL"), "bold white on red")
        self.assertEqual(severity_style("wat"), severity_style("info"))

    def test_findings_by_severity(self):
        counts = widgets.findings_by_severity(
            [{"severity": "critical"}, {"severity": "critical"}, {"severity": "low"}, {}]
        )
        self.assertEqual(counts, {"critical": 2, "low": 1, "info": 1})

    def test_severity_summary(self):
        self.assertEqual(severity_summary({}), "none")
        self.assertEqual(severity_summary({"critical": 1, "low": 2}), "critical:1 low:2")

    def test_attack_graph_tree_renders_nodes(self):
        text = render(widgets.attack_graph_tree(GRAPH))
        self.assertIn("scanme.nmap.org", text)
        self.assertIn("22/tcp ssh", text)
        self.assertIn("/.env", text)

    def test_attack_graph_tree_empty(self):
        self.assertIn("no nodes yet", render(widgets.attack_graph_tree({"nodes": [], "edges": []})))

    def test_agents_table_shows_progress(self):
        text = render(widgets.agents_table(SUMMARY["agents"]))
        self.assertIn("ReconAgent", text)
        self.assertIn("100.0%", text)
        self.assertIn("40.0%", text)

    def test_event_stream_handles_both_event_shapes(self):
        events = [
            {"event_type": "port", "sender": "Recon", "data": {"message": "22/tcp open"}, "timestamp": 0},
            {"type": "log", "sender": "Coord", "data": {"message": "stage 2"}, "timestamp": 0},
        ]
        text = render(widgets.event_stream(events))
        self.assertIn("22/tcp open", text)
        self.assertIn("stage 2", text)

    def test_findings_table_sorted_by_severity(self):
        findings = [{"severity": "low", "title": "L"}, {"severity": "critical", "title": "C"}]
        text = render(widgets.findings_table(findings))
        self.assertLess(text.index("CRITICAL"), text.index("LOW"))

    def test_progress_bar_bounds(self):
        self.assertIn("0.0%", render(widgets.progress_bar(-5)))
        self.assertIn("100.0%", render(widgets.progress_bar(250)))


class ScreenTests(unittest.TestCase):
    def test_providers_screen_marks_current(self):
        from constants import PROVIDERS

        text = render(providers_screen(PROVIDERS, current="groq"))
        self.assertIn("groq", text)
        self.assertIn("OpenRouter", text)

    def test_config_screen_masks_secrets(self):
        text = render(config_screen({"GROQ_API_KEY": "gsk_abcdefghijklmnop", "AI_MODEL": "x"}))
        self.assertNotIn("gsk_abcdefghijklmnop", text)
        self.assertIn("gsk", text)
        revealed = render(config_screen({"GROQ_API_KEY": "gsk_abcdefghijklmnop"}, reveal=True))
        self.assertIn("gsk_abcdefghijklmnop", revealed)

    def test_secret_helpers(self):
        self.assertTrue(is_secret_key("OPENAI_API_KEY"))
        self.assertFalse(is_secret_key("AI_MODEL"))
        self.assertEqual(mask_secret(""), "")
        self.assertEqual(mask_secret("short"), "•" * 5)

    def test_doctor_screen(self):
        checks = [
            {"name": "python version", "status": "pass", "detail": "3.11"},
            {"name": "toolchain", "status": "warn", "detail": "2/14"},
            {"name": "broken", "status": "fail", "detail": "boom"},
        ]
        text = render(doctor_screen(checks, score=80))
        for token in ("PASS", "WARN", "FAIL", "80/100"):
            self.assertIn(token, text)

    def test_sessions_and_detail_screens(self):
        rows = [{
            "id": "x19_test_0001", "target": "scanme.nmap.org", "started": "2026-01-01T00:00:00",
            "iterations": 2, "findings": 2, "status": "complete",
        }]
        self.assertIn("x19_test_0001", render(sessions_screen(rows)))
        self.assertIn("no sessions recorded", render(sessions_screen([])))
        detail = render(session_detail_screen(SESSION, "x19_test_0001"))
        self.assertIn("Exposed .env with cloud credentials", detail)
        self.assertIn("nmap -sV scanme.nmap.org", detail)

    def test_findings_screen_counts(self):
        text = render(findings_screen(SESSION["findings"], target="scanme.nmap.org"))
        self.assertIn("CRITICAL", text)
        self.assertIn("Server header version disclosure", text)

    def test_tools_screen(self):
        text = render(tools_screen([{"binary": "nmap", "presets": ["nmap_quick"], "available": True}]))
        self.assertIn("nmap", text)
        self.assertIn("installed", text)

    def test_help_and_env_screens(self):
        self.assertIn("run", render(help_screen(cli.HELP_COMMANDS, version=version_module.__version__)))
        self.assertIn("removed", render(env_screen(version_module.version_info())))


class DashboardTests(unittest.TestCase):
    def setUp(self):
        init_console(force_terminal=False)
        self.dash = MissionDashboard(version="9.9.9")
        self.dash.load(SUMMARY, GRAPH)

    def test_frame_renders_every_web_panel(self):
        text = self.dash.capture(width=130, height=44)
        for expected in (
            "MISSION CONTROL", "scanme.nmap.org", "swarm agents", "attack graph",
            "open ports", "endpoints", "verified findings", "event stream", "task queue",
        ):
            self.assertIn(expected, text)

    def test_scrolling_frame_renders_every_panel(self):
        text = render(self.dash.scrolling_frame())
        for expected in ("swarm agents", "attack graph", "open ports", "verified findings", "event stream"):
            self.assertIn(expected, text)

    def test_metrics_reflect_summary(self):
        text = self.dash.capture(width=130, height=44)
        self.assertIn("OPEN PORTS", text)
        self.assertIn("00:42", text)
        self.assertEqual(self.dash.stats()["open_ports"], 2)
        self.assertEqual(self.dash.status(), "completed")

    def test_event_buffer_is_bounded_and_normalised(self):
        bounded = MissionDashboard(version="1.0.0", max_events=3)
        for index in range(10):
            bounded.on_event({"type": "log", "sender": "t", "data": {"message": f"m{index}"}, "timestamp": 0})
        events = bounded.events
        self.assertEqual(len(events), 3)
        self.assertEqual([e["data"]["message"] for e in events], ["m7", "m8", "m9"])

    def test_report_panel(self):
        text = render(self.dash.report())
        self.assertIn("mission complete", text)
        self.assertIn("critical:1", text)

    def test_key_handling_toggles_focus_and_quit(self):
        self.assertTrue(self.dash._handle_key("g", _FakeLive()))
        self.assertEqual(self.dash._focus, "graph")
        self.dash._handle_key("g", _FakeLive())
        self.assertEqual(self.dash._focus, "all")
        self.assertTrue(self.dash._handle_key("space", _FakeLive()))
        self.assertTrue(self.dash._paused)
        self.assertFalse(self.dash._handle_key("q", _FakeLive()))
        self.assertTrue(self.dash._handle_key("r", _FakeLive()))
        self.assertTrue(self.dash.report_requested)

    def test_run_once_without_coordinator(self):
        stream = io.StringIO()
        console = Console(file=stream, width=120, force_terminal=False, theme=X19_THEME)
        dash = MissionDashboard(version="1.0.0", console=console)
        dash.load(SUMMARY, GRAPH)
        dash.run(once=True, start=False)
        self.assertIn("swarm agents", stream.getvalue())


class _FakeLive:
    def update(self, renderable):  # pragma: no cover - trivial
        pass


class CliSupportTests(unittest.TestCase):
    def test_toolchain_rows_detects_curl(self):
        rows = {row["binary"]: row for row in cli_support.toolchain_rows()}
        self.assertIn("curl", rows)
        self.assertEqual(rows["curl"]["available"], shutil.which("curl") is not None)
        self.assertTrue(rows["curl"]["presets"])

    def test_toolchain_coverage_counts(self):
        coverage = cli_support.toolchain_coverage()
        self.assertEqual(coverage["installed"] + len(coverage["missing"]), coverage["total"])
        self.assertEqual(
            coverage["preferred_installed"] + len(coverage["preferred_missing"]),
            coverage["preferred_total"],
        )

    def test_diagnostics_runs_and_scores(self):
        result = cli_support.run_diagnostics()
        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"], 100)
        names = {check["name"] for check in result["checks"]}
        self.assertIn("cli-only contract", names)
        self.assertIn("python version", names)
        statuses = {check["status"] for check in result["checks"]}
        self.assertTrue(statuses <= {"pass", "warn", "fail", "skip"})

    def test_session_findings_conversion(self):
        findings = cli_support.session_findings(SESSION)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].title, "Exposed .env with cloud credentials")
        self.assertEqual(findings[0].severity, "critical")
        self.assertEqual(findings[0].target, "scanme.nmap.org")

    def test_usable_providers_excludes_missing_ollama(self):
        usable = cli_support.usable_providers()
        if shutil.which("ollama") is None:
            self.assertNotIn("ollama", usable)


class SessionStoreTests(unittest.TestCase):
    def setUp(self):
        from config import CONFIG

        self._saved = CONFIG.SESSIONS_DIR
        self.tmp = tempfile.mkdtemp(prefix="x19_test_sessions_")
        CONFIG.SESSIONS_DIR = self.tmp
        (Path(self.tmp) / "x19_test_0001.json").write_text(json.dumps(SESSION), encoding="utf-8")

    def tearDown(self):
        from config import CONFIG

        CONFIG.SESSIONS_DIR = self._saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_list_and_load(self):
        rows = cli_support.list_sessions()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], "x19_test_0001")
        self.assertEqual(rows[0]["findings"], 2)
        self.assertIsNotNone(cli_support.load_session("x19_test_0001"))
        self.assertIsNone(cli_support.load_session("nope"))
        self.assertEqual(cli_support.latest_session()["session_id"], "x19_test_0001")

    def test_report_command_markdown(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.cmd_report(_ns(format="markdown", session="x19_test_0001", out=""))
        self.assertEqual(code, 0)
        self.assertIn("X19 Security Assessment", buffer.getvalue())
        self.assertIn("Exposed .env with cloud credentials", buffer.getvalue())

    def test_report_command_json_is_parseable(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            cli.cmd_report(_ns(format="json", session="x19_test_0001", out=""))
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["target"], "scanme.nmap.org")
        self.assertEqual(len(payload["findings"]), 2)

    def test_report_command_writes_file(self):
        out = Path(self.tmp) / "report.html"
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            cli.cmd_report(_ns(format="html", session="x19_test_0001", out=str(out)))
        self.assertTrue(out.exists())
        self.assertIn("<html", out.read_text(encoding="utf-8").lower())

    def test_findings_command_filters_by_severity(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            cli.cmd_findings(_ns(session="x19_test_0001", severity="critical", json=True))
        payload = json.loads(buffer.getvalue())
        self.assertEqual(len(payload["findings"]), 1)
        self.assertEqual(payload["findings"][0]["severity"], "critical")

    def test_sessions_command_json(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            cli.cmd_sessions(_ns(action="list", session="", json=True))
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload[0]["id"], "x19_test_0001")

    def test_session_show_command(self):
        buffer = io.StringIO()
        init_console(force_terminal=False)
        from ui.console import get_console

        get_console().file = buffer
        code = cli.cmd_sessions(_ns(action="show", session="x19_test_0001", json=False))
        get_console().file = sys.stdout
        self.assertEqual(code, 0)
        self.assertIn("Exposed .env with cloud credentials", buffer.getvalue())


def _ns(**kwargs):
    """Minimal argparse.Namespace stand-in with every attribute defaulted."""
    import argparse

    base = dict(
        command="", json=False, no_color=True, plain=True, quiet=False, verbose=False,
        session="", severity="", format="markdown", out="", action="list", args=[],
        reveal=False, network=False, missing=False, use="", model="", test=False,
        target="", refresh=0.5, once=False, no_tui=True, timeout=0, no_start=True,
        system="", force=False, shell="bash",
    )
    base.update(kwargs)
    return argparse.Namespace(**base)


class CommandTests(unittest.TestCase):
    def setUp(self):
        init_console(force_terminal=False)

    def test_version_command_json(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.cmd_version(_ns(json=True))
        self.assertEqual(code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["version"], version_module.__version__)
        self.assertFalse(payload["web_ui"])

    def test_doctor_command_json(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.cmd_doctor(_ns(json=True))
        self.assertIn(code, (0, 1))
        payload = json.loads(buffer.getvalue())
        self.assertIn("checks", payload)
        self.assertIn("score", payload)

    def test_tools_command_json(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            cli.cmd_tools(_ns(json=True))
        rows = json.loads(buffer.getvalue())
        self.assertIsInstance(rows, list)
        self.assertIn("binary", rows[0])

    def test_providers_command_json(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            cli.cmd_providers(_ns(json=True))
        payload = json.loads(buffer.getvalue())
        self.assertIn("groq", payload["providers"])
        self.assertIn("chain", payload)

    def test_config_command_path(self):
        from config import CONFIG_FILE

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            cli.cmd_config(_ns(action="path", args=[]))
        self.assertEqual(buffer.getvalue().strip(), str(CONFIG_FILE))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class LivePathTests(unittest.TestCase):
    """Exercise the full-screen branch even without a TTY."""

    def test_run_live_renders_and_exits(self):
        stream = io.StringIO()
        console = Console(
            file=stream, width=120, height=40, force_terminal=True, theme=X19_THEME
        )
        dash = MissionDashboard(version="1.0.0", console=console)
        dash.load(SUMMARY, GRAPH)
        result = dash._run_live(timeout=1.0, wait=False)
        self.assertEqual(result["target"], "scanme.nmap.org")
        self.assertIn("swarm agents", stream.getvalue())

    def test_ctrl_c_stops_a_running_mission(self):
        class _Coordinator:
            def __init__(self):
                self.is_running = True
                self.stopped = False

            def stop_mission(self):
                self.stopped = True

            def get_summary(self):
                return dict(SUMMARY, is_running=True)

            def get_attack_graph_d3(self):
                return GRAPH

            def subscribe_events(self, callback):
                pass

        coordinator = _Coordinator()
        dash = MissionDashboard(coordinator, version="1.0.0")
        self.assertTrue(dash._handle_key("ctrl-c", _FakeLive()))
        self.assertTrue(coordinator.stopped)
        self.assertEqual(dash.status(), "running")


class DashCommandTests(unittest.TestCase):
    def setUp(self):
        init_console(force_terminal=False)

    def test_requires_a_target(self):
        buffer = io.StringIO()
        from ui.console import get_console

        get_console().file = buffer
        try:
            code = cli.cmd_dash(_ns(target="", no_start=True, once=True))
        finally:
            get_console().file = sys.stdout
        self.assertEqual(code, 1)
        self.assertIn("target required", buffer.getvalue())

    def test_once_frame_without_starting_the_mission(self):
        buffer = io.StringIO()
        from ui.console import get_console

        get_console().file = buffer
        try:
            code = cli.cmd_dash(_ns(target="127.0.0.1", no_start=True, once=True))
        finally:
            get_console().file = sys.stdout
        self.assertEqual(code, 0)
        out = buffer.getvalue()
        self.assertIn("swarm agents", out)
        self.assertIn("127.0.0.1", out)
        # A mission that was never started must not claim completion.
        self.assertNotIn("mission complete", out)


class ExtraCommandTests(unittest.TestCase):
    def setUp(self):
        init_console(force_terminal=False)

    def test_completion_scripts(self):
        for shell, expected in (("bash", "complete -F"), ("zsh", "compdef"), ("fish", "complete -c x19")):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = cli.cmd_completion(_ns(shell=shell))
            self.assertEqual(code, 0)
            self.assertIn(expected, buffer.getvalue())
            self.assertIn("run", buffer.getvalue())
            self.assertNotIn("{", buffer.getvalue().split("cmds=")[-1].split("\n")[0]
                             if shell == "bash" else "")

    def test_debug_command_runs(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.cmd_debug(_ns(action="stats"))
        self.assertEqual(code, 0)
        self.assertIn("Source Statistics", buffer.getvalue())

    def test_handlers_cover_every_command(self):
        self.assertEqual(set(cli.HANDLERS), set(cli.COMMANDS))

    def test_help_lists_every_command(self):
        documented = {entry["name"] for entry in cli.HELP_COMMANDS}
        self.assertEqual(documented, set(cli.COMMANDS))
