"""Tests for the X19 workspace landing view and the mandatory first-run setup.

`x19` with no arguments must land on the workspace, and a fresh install must be
taken through the full setup before it can do anything real.
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argparse

import cli
from ui.console import init_console
from ui.screens import function_index, next_actions_panel, workspace_screen
from ui.theme import X19_THEME


def _capture(renderable, width: int = 118) -> str:
    from rich.console import Console

    buffer = io.StringIO()
    Console(file=buffer, force_terminal=False, width=width, no_color=True,
            theme=X19_THEME).print(renderable)
    return buffer.getvalue()


def _snapshot(**overrides):
    base = dict(
        provider={"primary": "groq", "model": "llama-3.3-70b", "chain": ["groq"], "ollama": False},
        toolchain={
            "total": 14, "installed": 2, "preferred_total": 7, "preferred_installed": 2,
            "preferred_missing": ["ffuf", "gobuster"], "rows": [],
        },
        engagements=[{"name": "lab", "target": "127.0.0.1", "target_type": "lab",
                      "has_canaries": True}],
        sessions=[{"id": "s1", "target": "127.0.0.1", "started": "2026-09-09T05:19",
                   "iterations": 12, "findings": 3, "status": "completed"}],
        findings=[{"title": "Exposed .env", "severity": "high", "endpoint": "/.env",
                   "target": "127.0.0.1", "description": "creds"}],
        commands=cli.HELP_COMMANDS,
        next_actions=[("x19 dash -t 127.0.0.1 --engagement lab", "start an assessment")],
        health={"score": 95, "checks": [{"status": "pass"}, {"status": "warn"}]},
        store_dir="/tmp/engagements",
        sessions_dir="/tmp/sessions",
        version="4.0.0",
    )
    base.update(overrides)
    return base


class WorkspaceScreenTests(unittest.TestCase):
    def test_screen_renders_every_section(self):
        data = _snapshot()
        out = _capture(workspace_screen(
            version=data["version"], provider=data["provider"], toolchain=data["toolchain"],
            engagements=data["engagements"], sessions=data["sessions"],
            findings=data["findings"], commands=data["commands"],
            next_actions=data["next_actions"], health=data["health"],
            store_dir=data["store_dir"], sessions_dir=data["sessions_dir"],
        ))
        lowered = out.lower()
        for section in ("workspace", "system", "ai chain", "engagements", "toolchain",
                        "recent missions", "latest findings", "functions", "next actions"):
            self.assertIn(section, lowered, section)

    def test_screen_shows_live_state_values(self):
        data = _snapshot()
        out = _capture(workspace_screen(
            version="4.0.0", provider=data["provider"], toolchain=data["toolchain"],
            engagements=data["engagements"], sessions=data["sessions"],
            findings=data["findings"], commands=data["commands"],
            next_actions=data["next_actions"], health=data["health"],
        ))
        self.assertIn("groq", out)
        self.assertIn("llama-3.3-70b", out)
        self.assertIn("lab", out)
        self.assertIn("95/100", out)
        self.assertIn("ffuf", out)

    def test_screen_survives_a_completely_empty_install(self):
        out = _capture(workspace_screen(
            version="4.0.0",
            provider={"primary": "", "model": "", "chain": [], "ollama": False},
            toolchain={"total": 0, "installed": 0, "preferred_total": 0,
                       "preferred_installed": 0, "preferred_missing": [], "rows": []},
            engagements=[], sessions=[], findings=[], commands=cli.HELP_COMMANDS,
            next_actions=[], health={},
        ))
        self.assertIn("no provider key configured", out)
        self.assertIn("no engagement profile yet", out)
        # recent-activity blocks are omitted rather than rendered empty
        self.assertNotIn("recent missions", out.lower())
        self.assertNotIn("latest findings", out.lower())

    def test_screen_tolerates_missing_optional_arguments(self):
        out = _capture(workspace_screen())
        self.assertIn("WORKSPACE", out)

    def test_screen_fits_a_narrow_terminal(self):
        data = _snapshot()
        out = _capture(workspace_screen(
            version="4.0.0", provider=data["provider"], toolchain=data["toolchain"],
            engagements=data["engagements"], sessions=data["sessions"],
            findings=data["findings"], commands=data["commands"],
            next_actions=data["next_actions"], health=data["health"],
        ), width=80)
        self.assertTrue(out.strip())

    def test_function_index_lists_every_command_once(self):
        out = _capture(function_index(cli.HELP_COMMANDS))
        names = [row["name"] for row in cli.HELP_COMMANDS]
        self.assertEqual(len(names), len(set(names)), "HELP_COMMANDS must not repeat a name")
        for name in names:
            self.assertIn(name, out, name)

    def test_function_index_groups_commands(self):
        rows = [
            {"name": "run", "help": "h", "group": "assessment"},
            {"name": "chat", "help": "h", "group": "interactive"},
            {"name": "doctor", "help": "h", "group": "operations"},
        ]
        out = _capture(function_index(rows))
        self.assertIn("assessment", out)
        self.assertIn("interactive", out)
        self.assertIn("operations", out)
        # group label appears once, against the first row of the group
        self.assertEqual(out.count("assessment"), 1)

    def test_function_index_handles_an_unknown_group(self):
        out = _capture(function_index([{"name": "x", "help": "h", "group": "mystery"}]))
        self.assertIn("mystery", out)
        self.assertIn("x", out)

    def test_next_actions_panel_numbers_the_steps(self):
        out = _capture(next_actions_panel([("x19 setup", "why one"), ("x19 tools", "why two")]))
        self.assertIn("1", out)
        self.assertIn("2", out)
        self.assertIn("x19 setup", out)
        self.assertIn("why two", out)

    def test_next_actions_panel_reports_a_clean_system(self):
        self.assertIn("nothing outstanding", _capture(next_actions_panel([])))


class NextActionLogicTests(unittest.TestCase):
    """Guidance must follow the real state, not a fixed list."""

    def _snapshot(self, **overrides):
        base = dict(
            provider={"chain": ["groq"]},
            toolchain={"preferred_missing": []},
            engagements=[],
        )
        base.update(overrides)
        return base

    def test_no_provider_is_the_first_thing_fixed(self):
        actions = cli.workspace_next_actions(self._snapshot(provider={"chain": []}))
        self.assertEqual(actions[0][0], "x19 setup app")

    def test_missing_engagement_is_flagged(self):
        actions = cli.workspace_next_actions(self._snapshot())
        self.assertTrue(any("engagement new" in command for command, _ in actions))

    def test_missing_tools_are_flagged_with_a_count(self):
        actions = cli.workspace_next_actions(
            self._snapshot(toolchain={"preferred_missing": ["ffuf", "gobuster", "nmap"]})
        )
        tools = [why for command, why in actions if command == "x19 tools"]
        self.assertTrue(tools)
        self.assertIn("3 preferred tool(s)", tools[0])

    def test_clean_install_gets_no_repair_actions(self):
        actions = cli.workspace_next_actions(self._snapshot(
            engagements=[{"name": "lab", "target": "127.0.0.1"}],
        ))
        commands = [command for command, _ in actions]
        self.assertNotIn("x19 setup app", commands)
        self.assertNotIn("x19 tools", commands)

    def test_dash_action_uses_the_real_profile(self):
        actions = cli.workspace_next_actions(self._snapshot(
            engagements=[{"name": "acme", "target": "acme.example.com"}],
        ))
        self.assertIn(
            ("x19 dash -t acme.example.com --engagement acme", "start a live assessment"),
            actions,
        )

    def test_dash_action_is_a_placeholder_without_a_profile(self):
        actions = cli.workspace_next_actions(self._snapshot())
        self.assertTrue(any("<target>" in command for command, _ in actions))


class WorkspaceSnapshotTests(unittest.TestCase):
    def test_snapshot_has_every_key_the_screen_needs(self):
        snapshot = cli.workspace_snapshot()
        for key in ("provider", "toolchain", "engagements", "sessions", "findings",
                    "health", "store_dir", "sessions_dir", "config_file"):
            self.assertIn(key, snapshot, key)

    def test_snapshot_shapes_are_usable(self):
        snapshot = cli.workspace_snapshot()
        self.assertIn("chain", snapshot["provider"])
        self.assertIn("installed", snapshot["toolchain"])
        self.assertIsInstance(snapshot["engagements"], list)
        self.assertIsInstance(snapshot["sessions"], list)
        self.assertIsInstance(snapshot["findings"], list)

    def test_snapshot_never_raises_on_a_bare_machine(self):
        with tempfile.TemporaryDirectory() as tmp:
            saved = os.environ.get("X19_ENGAGEMENTS_DIR")
            os.environ["X19_ENGAGEMENTS_DIR"] = tmp
            try:
                snapshot = cli.workspace_snapshot()
            finally:
                if saved is None:
                    os.environ.pop("X19_ENGAGEMENTS_DIR", None)
                else:
                    os.environ["X19_ENGAGEMENTS_DIR"] = saved
        self.assertEqual(snapshot["engagements"], [])


def _ns(**kwargs):
    base = dict(command="workspace", json=False, no_color=True, plain=True,
                quiet=False, verbose=False, no_status=False)
    base.update(kwargs)
    return argparse.Namespace(**base)


class WorkspaceCommandTests(unittest.TestCase):
    def setUp(self):
        init_console(force_terminal=False)

    def test_workspace_json_emits_state_and_functions(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.cmd_workspace(_ns(json=True))
        self.assertEqual(code, 0)
        payload = json.loads(buffer.getvalue())
        for key in ("version", "provider", "toolchain", "engagements", "sessions",
                    "commands", "next_actions"):
            self.assertIn(key, payload, key)
        self.assertEqual(payload["version"], cli.__version__)

    def test_workspace_json_next_actions_are_structured(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            cli.cmd_workspace(_ns(json=True))
        payload = json.loads(buffer.getvalue())
        self.assertTrue(payload["next_actions"])
        for action in payload["next_actions"]:
            self.assertEqual(sorted(action), ["command", "why"])

    def test_workspace_renders_in_terminal_mode(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.cmd_workspace(_ns())
        self.assertEqual(code, 0)
        self.assertIn("WORKSPACE", buffer.getvalue())
        self.assertIn("functions", buffer.getvalue().lower())


class ParserAndDefaultTests(unittest.TestCase):
    def test_workspace_is_a_registered_command(self):
        self.assertIn("workspace", cli.COMMANDS)
        self.assertIn("workspace", cli.HANDLERS)

    def test_parser_accepts_workspace(self):
        args = cli.build_parser().parse_args(["workspace"])
        self.assertEqual(args.command, "workspace")

    def test_workspace_appears_in_help(self):
        self.assertIn("workspace", [row["name"] for row in cli.HELP_COMMANDS])

    def test_help_screen_lists_workspace(self):
        from ui.screens import help_screen

        self.assertIn("workspace", _capture(help_screen(cli.HELP_COMMANDS, version="4.0.0")))

    def test_no_command_defaults_to_workspace(self):
        calls = []
        # main() dispatches through HANDLERS, so that is what must be patched.
        original_handler = cli.HANDLERS["workspace"]
        original_pending = cli.first_run_pending
        cli.HANDLERS["workspace"] = lambda args: calls.append(args.command) or 0
        cli.first_run_pending = lambda: False  # isolate routing from the setup gate
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = cli.main([])
        finally:
            cli.HANDLERS["workspace"] = original_handler
            cli.first_run_pending = original_pending
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["workspace"])

    def test_no_command_on_a_fresh_install_is_gated(self):
        original_pending = cli.first_run_pending
        original_gate = cli._enforce_first_run
        seen = []
        cli.first_run_pending = lambda: True
        cli._enforce_first_run = lambda command: seen.append(command) or 1
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = cli.main([])
        finally:
            cli.first_run_pending = original_pending
            cli._enforce_first_run = original_gate
        self.assertEqual(code, 1)
        self.assertEqual(seen, ["workspace"], "the gate must see the resolved default command")

    def test_chat_is_no_longer_advertised_as_the_default(self):
        row = [r for r in cli.HELP_COMMANDS if r["name"] == "chat"][0]
        self.assertNotIn("default", row["help"].lower())


class FirstRunGateTests(unittest.TestCase):
    """A fresh install must be set up before it can do anything real."""

    def setUp(self):
        init_console(force_terminal=False)
        self._pending = cli.first_run_pending
        self._interactive = cli._interactive_terminal
        self._setup = cli.first_run_setup

    def tearDown(self):
        cli.first_run_pending = self._pending
        cli._interactive_terminal = self._interactive
        cli.first_run_setup = self._setup

    def _gate(self, command, *, pending, interactive=True, setup_result=True):
        cli.first_run_pending = lambda: pending
        cli._interactive_terminal = lambda: interactive
        cli.first_run_setup = lambda **kwargs: setup_result
        return cli._enforce_first_run(command)

    def test_exempt_commands_are_never_gated(self):
        for command in ("setup", "version", "doctor", "config", "providers",
                        "completion", "debug", "upgrade", "tools", "engagement"):
            self.assertIsNone(self._gate(command, pending=True), command)

    def test_real_commands_pass_once_setup_is_done(self):
        for command in ("workspace", "run", "dash", "chat", "findings", "report", "sessions"):
            self.assertIsNone(self._gate(command, pending=False), command)

    def test_fresh_install_without_a_tty_blocks_every_real_command(self):
        for command in ("workspace", "run", "dash", "chat", "findings", "report", "sessions"):
            self.assertEqual(
                self._gate(command, pending=True, interactive=False), 1, command,
            )

    def test_fresh_install_blocks_when_setup_cannot_complete(self):
        for command in ("workspace", "run", "dash", "chat"):
            self.assertEqual(
                self._gate(command, pending=True, setup_result=False), 1, command,
            )

    def test_gate_runs_setup_when_a_human_is_present(self):
        ran = []
        cli.first_run_pending = lambda: True
        cli._interactive_terminal = lambda: True
        cli.first_run_setup = lambda **kwargs: ran.append(1) is None
        self.assertIsNone(cli._enforce_first_run("workspace"))
        self.assertEqual(ran, [1], "setup must actually run")

    def test_gate_refuses_without_a_tty_rather_than_hanging(self):
        self.assertEqual(self._gate("run", pending=True, interactive=False), 1)

    def test_gate_stops_when_setup_fails(self):
        self.assertEqual(self._gate("run", pending=True, setup_result=False), 1)

    def test_pending_tracks_provider_configuration(self):
        import cli_support

        original = cli_support.provider_configured
        try:
            cli_support.provider_configured = lambda: True
            self.assertFalse(cli.first_run_pending())
            cli_support.provider_configured = lambda: False
            self.assertTrue(cli.first_run_pending())
        finally:
            cli_support.provider_configured = original


class FirstRunSetupTests(unittest.TestCase):
    """The four-stage flow: providers → toolchain → engagement → verify."""

    def setUp(self):
        init_console(force_terminal=False)
        self._tmp = tempfile.TemporaryDirectory()
        self._env = os.environ.get("X19_ENGAGEMENTS_DIR")
        os.environ["X19_ENGAGEMENTS_DIR"] = self._tmp.name

        import cli_support
        import provider_setup

        self._saved = {
            "provider_configured": cli_support.provider_configured,
            "resolve_provider": cli_support.resolve_provider,
            "setup_if_needed": provider_setup.setup_if_needed,
            "wizard": cli.engagement_wizard,
        }
        cli_support.provider_configured = lambda: False
        cli_support.resolve_provider = lambda: "groq"
        provider_setup.setup_if_needed = lambda force=False: True
        cli.engagement_wizard = lambda target="": None

    def tearDown(self):
        import cli_support
        import provider_setup

        cli_support.provider_configured = self._saved["provider_configured"]
        cli_support.resolve_provider = self._saved["resolve_provider"]
        provider_setup.setup_if_needed = self._saved["setup_if_needed"]
        cli.engagement_wizard = self._saved["wizard"]
        if self._env is None:
            os.environ.pop("X19_ENGAGEMENTS_DIR", None)
        else:
            os.environ["X19_ENGAGEMENTS_DIR"] = self._env
        self._tmp.cleanup()

    def _run(self, **kwargs):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            result = cli.first_run_setup(**kwargs)
        return result, buffer.getvalue()

    def test_all_four_stages_run_and_it_succeeds(self):
        result, out = self._run()
        self.assertTrue(result)
        for stage in ("1/4", "2/4", "3/4", "4/4"):
            self.assertIn(stage, out, stage)
        self.assertIn("setup complete", out)

    def test_verify_stage_reports_where_state_lives(self):
        _, out = self._run()
        self.assertIn("groq", out)
        self.assertIn("config.json", out)
        self.assertIn("engagements", out.lower())

    def test_provider_stage_is_skipped_when_already_configured(self):
        import cli_support

        cli_support.provider_configured = lambda: True
        calls = []
        import provider_setup

        provider_setup.setup_if_needed = lambda force=False: calls.append(1) or True
        result, out = self._run()
        self.assertTrue(result)
        self.assertEqual(calls, [], "must not re-run the provider wizard")
        self.assertIn("already configured", out)

    def test_force_re_runs_the_provider_stage(self):
        import cli_support
        import provider_setup

        cli_support.provider_configured = lambda: True
        calls = []
        provider_setup.setup_if_needed = lambda force=False: calls.append(force) or True
        self._run(force=True)
        self.assertEqual(calls, [True])

    def test_setup_fails_when_no_provider_can_be_saved(self):
        import provider_setup

        provider_setup.setup_if_needed = lambda force=False: False
        result, out = self._run()
        self.assertFalse(result)
        self.assertIn("cannot run an assessment", out)

    def test_setup_fails_when_no_provider_resolves_afterwards(self):
        import cli_support

        cli_support.resolve_provider = lambda: None
        result, out = self._run()
        self.assertFalse(result)
        self.assertIn("no usable provider resolved", out)

    def test_keyboard_interrupt_during_provider_setup_is_handled(self):
        import provider_setup

        def boom(force=False):
            raise KeyboardInterrupt

        provider_setup.setup_if_needed = boom
        result, out = self._run()
        self.assertFalse(result)
        self.assertIn("interrupted", out)

    def test_toolchain_stage_reports_missing_preferred_tools(self):
        import cli_support

        original = cli_support.toolchain_coverage
        cli_support.toolchain_coverage = lambda: {
            "total": 10, "installed": 3, "preferred_total": 5, "preferred_installed": 2,
            "preferred_missing": ["ffuf", "nmap"], "rows": [],
        }
        try:
            _, out = self._run()
        finally:
            cli_support.toolchain_coverage = original
        self.assertIn("ffuf", out)
        self.assertIn("missing preferred tools", out.lower())

    def test_toolchain_stage_confirms_a_full_toolchain(self):
        import cli_support

        original = cli_support.toolchain_coverage
        cli_support.toolchain_coverage = lambda: {
            "total": 10, "installed": 10, "preferred_total": 5, "preferred_installed": 5,
            "preferred_missing": [], "rows": [],
        }
        try:
            _, out = self._run()
        finally:
            cli_support.toolchain_coverage = original
        self.assertIn("full preferred toolchain present", out)

    def test_engagement_stage_is_skipped_when_profiles_exist(self):
        import engagement as eng

        eng.EngagementProfile(name="lab", target="127.0.0.1",
                              targets=["127.0.0.1"], target_type="lab").save()
        calls = []
        cli.engagement_wizard = lambda target="": calls.append(1)
        result, out = self._run()
        self.assertTrue(result)
        self.assertEqual(calls, [], "must not re-run the wizard")
        self.assertIn("already saved", out)
        self.assertIn("lab", out)

    def test_engagement_wizard_runs_when_there_is_no_profile(self):
        calls = []
        cli.engagement_wizard = lambda target="": calls.append(1)
        self._run()
        self.assertEqual(calls, [1])

    def test_wizard_cancellation_does_not_abort_setup(self):
        def interrupted(target=""):
            raise KeyboardInterrupt

        cli.engagement_wizard = interrupted
        result, out = self._run()
        self.assertTrue(result, "a skipped engagement must not fail the whole setup")
        self.assertIn("skipped", out)

    def test_force_re_runs_the_engagement_stage(self):
        import engagement as eng

        eng.EngagementProfile(name="lab", target="127.0.0.1",
                              targets=["127.0.0.1"], target_type="lab").save()
        calls = []
        cli.engagement_wizard = lambda target="": calls.append(1)
        self._run(force=True)
        self.assertEqual(calls, [1])

    def test_setup_is_resumable(self):
        """A cancelled attempt resumes without redoing finished stages."""
        import cli_support
        import provider_setup

        provider_setup.setup_if_needed = lambda force=False: False
        first, _ = self._run()
        self.assertFalse(first)

        # the operator fixes the provider out of band, then re-runs
        provider_setup.setup_if_needed = lambda force=False: True
        cli_support.provider_configured = lambda: True
        second, out = self._run()
        self.assertTrue(second)
        self.assertIn("already configured", out)


if __name__ == "__main__":
    unittest.main()
