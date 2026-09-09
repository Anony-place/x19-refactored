"""Tests for engagement profiles — the four XBOW guidance cards and their CLI.

The profile is the only supported way to give an assessment scope, priorities,
strategy and validation rules, so a silent regression here would mean agents
running without authorisation boundaries.
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
import engagement as eng
from ui.console import init_console


def _profile(**overrides) -> eng.EngagementProfile:
    """A valid, fully-populated profile; override any field per test."""
    base = dict(
        name="lab",
        target="127.0.0.1",
        targets=["127.0.0.1"],
        target_type="lab",
        attack_surface=eng.AttackSurface(endpoints=["/api/v1/login"]),
        priorities=eng.Priorities(focus=["auth"], vuln_classes=["sqli"]),
        strategy=eng.AttackStrategy(known_weaknesses=["legacy panel"]),
        validation=eng.Validation(
            canaries=[{"label": "c1", "value": "CANARY-abc123", "kind": "generic"}],
            require_poc=True,
            min_severity="low",
        ),
        budget=eng.MissionBudget(max_seconds=120, max_commands=60),
    )
    base.update(overrides)
    return eng.EngagementProfile(**base)


class EngagementStoreTests(unittest.TestCase):
    """Schema, validation and on-disk storage."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._saved_env = os.environ.get("X19_ENGAGEMENTS_DIR")
        os.environ["X19_ENGAGEMENTS_DIR"] = self._tmp.name

    def tearDown(self):
        if self._saved_env is None:
            os.environ.pop("X19_ENGAGEMENTS_DIR", None)
        else:
            os.environ["X19_ENGAGEMENTS_DIR"] = self._saved_env
        self._tmp.cleanup()

    def test_store_directory_honours_env_override(self):
        self.assertEqual(Path(eng.engagements_dir()), Path(self._tmp.name))
        self.assertTrue(Path(self._tmp.name).is_dir())

    def test_profile_path_is_named_json(self):
        self.assertEqual(eng.profile_path("lab").name, "lab.json")
        self.assertEqual(eng.profile_path("lab").parent, Path(self._tmp.name))

    def test_validate_name_accepts_safe_names(self):
        for name in ("lab", "lab-local", "client_a", "v1.2"):
            eng.validate_name(name)

    def test_validate_name_rejects_path_traversal_and_garbage(self):
        for name in ("../etc/passwd", "a/b", "", "UPPER", "-leading-dash", "x" * 80):
            with self.assertRaises(ValueError, msg=name):
                eng.validate_name(name)

    def test_valid_profile_has_no_problems(self):
        self.assertEqual(eng.validate_profile(_profile()), [])

    def test_profile_without_scope_is_rejected(self):
        problems = eng.validate_profile(_profile(target="", targets=[]))
        self.assertTrue(any("nothing is in scope" in p for p in problems), problems)

    def test_unknown_target_type_is_rejected(self):
        problems = eng.validate_profile(_profile(target_type="yolo"))
        self.assertTrue(any("target_type" in p for p in problems), problems)

    def test_unknown_min_severity_is_rejected(self):
        profile = _profile(validation=eng.Validation(min_severity="vibes"))
        problems = eng.validate_profile(profile)
        self.assertTrue(any("min_severity" in p for p in problems), problems)

    def test_auto_target_type_demands_explicit_authorisation(self):
        problems = eng.validate_profile(_profile(target_type="auto"))
        self.assertTrue(any("explicitly" in p for p in problems), problems)

    def test_negative_budget_is_rejected(self):
        profile = _profile(budget=eng.MissionBudget(max_seconds=-5))
        problems = eng.validate_profile(profile)
        self.assertTrue(any("negative" in p for p in problems), problems)

    def test_missing_attack_surface_file_is_reported(self):
        profile = _profile(attack_surface=eng.AttackSurface(api_specs=["/nope/openapi.yaml"]))
        problems = eng.validate_profile(profile)
        self.assertTrue(any("attack-surface file not found" in p for p in problems), problems)

    def test_save_and_load_round_trips_all_four_cards(self):
        original = _profile()
        path = original.save()
        self.assertTrue(path.is_file())

        loaded = eng.load_profile("lab")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.target, "127.0.0.1")
        self.assertEqual(loaded.target_type, "lab")
        self.assertEqual(loaded.attack_surface.endpoints, ["/api/v1/login"])
        self.assertEqual(loaded.priorities.focus, ["auth"])
        self.assertEqual(loaded.priorities.vuln_classes, ["sqli"])
        self.assertEqual(loaded.strategy.known_weaknesses, ["legacy panel"])
        self.assertFalse(loaded.strategy.allow_destructive)
        self.assertEqual(loaded.validation.canary_values(), ["CANARY-abc123"])
        self.assertEqual(loaded.budget.max_seconds, 120)

    def test_saved_file_is_valid_json_on_disk(self):
        _profile().save()
        data = json.loads(eng.profile_path("lab").read_text(encoding="utf-8"))
        self.assertEqual(data["name"], "lab")
        self.assertEqual(data["schema_version"], eng.PROFILE_SCHEMA_VERSION)
        self.assertIn("validation", data)

    def test_load_missing_profile_returns_none(self):
        self.assertIsNone(eng.load_profile("does-not-exist"))

    def test_list_profiles_summarises_store(self):
        _profile().save()
        rows = eng.list_profiles()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["name"], "lab")
        self.assertEqual(row["target"], "127.0.0.1")
        self.assertEqual(row["target_type"], "lab")
        self.assertTrue(row["has_canaries"])
        self.assertFalse(row["has_credentials"])

    def test_list_profiles_skips_corrupt_files(self):
        (Path(self._tmp.name) / "broken.json").write_text("{not json", encoding="utf-8")
        _profile().save()
        rows = eng.list_profiles()
        self.assertEqual([r["name"] for r in rows], ["lab"])

    def test_delete_profile(self):
        _profile().save()
        self.assertTrue(eng.delete_profile("lab"))
        self.assertFalse(eng.profile_path("lab").exists())
        self.assertFalse(eng.delete_profile("lab"))

    def test_ad_hoc_profile_is_conservative(self):
        profile = eng.ad_hoc_profile("10.0.0.5")
        self.assertEqual(profile.target, "10.0.0.5")
        self.assertEqual(profile.targets, ["10.0.0.5"])
        self.assertFalse(profile.strategy.allow_destructive, "ad-hoc runs must never be destructive")
        self.assertTrue(profile.validation.require_poc)
        self.assertEqual(profile.validation.min_severity, "low")
        self.assertIn("Ad-hoc", profile.rules_of_engagement)

    def test_ad_hoc_profile_normalises_name(self):
        profile = eng.ad_hoc_profile("HTTP://Example.COM:8080")
        eng.validate_name(profile.name)  # must not raise
        self.assertTrue(profile.name.startswith("adhoc-"))


class ScopeAndSeverityTests(unittest.TestCase):
    """Scope enforcement and severity filtering derived from the profile."""

    def test_scope_allowlist_unions_target_and_targets(self):
        profile = _profile(target="10.0.0.1", targets=["10.0.0.1", "10.0.0.2"])
        self.assertEqual(profile.scope_allowlist(), ["10.0.0.1", "10.0.0.2"])

    def test_scope_allowlist_dedupes_and_keeps_order(self):
        profile = _profile(target="10.0.0.1", targets=["10.0.0.1", "10.0.0.2", "10.0.0.1"])
        self.assertEqual(profile.scope_allowlist(), ["10.0.0.1", "10.0.0.2"])

    def test_is_in_scope(self):
        profile = _profile(target="127.0.0.1", targets=["127.0.0.1"], out_of_scope=["127.0.0.2"])
        self.assertTrue(profile.is_in_scope("127.0.0.1"))
        self.assertFalse(profile.is_in_scope("127.0.0.2"))
        self.assertFalse(profile.is_in_scope("8.8.8.8"))

    def test_out_of_scope_beats_in_scope(self):
        profile = _profile(
            target="10.0.0.1", targets=["10.0.0.1", "10.0.0.2"], out_of_scope=["10.0.0.2"]
        )
        self.assertTrue(profile.is_in_scope("10.0.0.1"))
        self.assertFalse(profile.is_in_scope("10.0.0.2"), "out-of-scope must win")

    def test_severity_allowed_honours_floor(self):
        profile = _profile(validation=eng.Validation(min_severity="high"))
        self.assertTrue(profile.severity_allowed("critical"))
        self.assertTrue(profile.severity_allowed("high"))
        self.assertFalse(profile.severity_allowed("medium"))
        self.assertFalse(profile.severity_allowed("info"))

    def test_severity_unknown_string_is_rejected(self):
        profile = _profile(validation=eng.Validation(min_severity="info"))
        self.assertFalse(profile.severity_allowed("apocalyptic"))

    def test_checkpoint_uses_the_same_0_to_100_scale_as_budget_state(self):
        budget = eng.MissionBudget(checkpoints=[20, 40, 60, 80])
        self.assertTrue(budget.checkpoint_at(20))
        self.assertTrue(budget.checkpoint_at(61))
        self.assertFalse(budget.checkpoint_at(10))
        self.assertFalse(budget.checkpoint_at(0))

    def test_checkpoint_is_not_skipped_when_a_cycle_overshoots_it(self):
        # Budget is sampled once per cycle, so a cycle can land past a
        # checkpoint without ever being observed inside a narrow band around it.
        budget = eng.MissionBudget(checkpoints=[20, 40, 60, 80])
        self.assertEqual(budget.next_checkpoint(27.0, set()), 20)
        self.assertEqual(budget.next_checkpoint(27.0, {20}), None)
        self.assertEqual(budget.next_checkpoint(85.0, {20}), 40)
        self.assertEqual(budget.next_checkpoint(85.0, {20, 40}), 60)
        self.assertEqual(budget.next_checkpoint(85.0, {20, 40, 60}), 80)
        self.assertIsNone(budget.next_checkpoint(85.0, {20, 40, 60, 80}))

    def test_no_checkpoint_before_the_first_one_is_reached(self):
        budget = eng.MissionBudget(checkpoints=[20, 40, 60, 80])
        self.assertIsNone(budget.next_checkpoint(5.0, set()))

    def test_canary_values_extracts_only_populated_entries(self):
        validation = eng.Validation(
            canaries=[
                {"label": "a", "value": "AAA", "kind": "generic"},
                {"label": "b", "value": "", "kind": "generic"},
                {"label": "c", "value": "CCC", "kind": "sqli"},
            ]
        )
        self.assertEqual(validation.canary_values(), ["AAA", "CCC"])

    def test_guidance_block_covers_all_four_cards(self):
        block = _profile().guidance_block()
        self.assertIn("ATTACK SURFACE", block)
        self.assertIn("PRIORITIES", block)
        self.assertIn("ATTACK STRATEGY", block)
        self.assertIn("VALIDATION", block)
        self.assertIn("/api/v1/login", block)
        # Canary values reach the verifier through canary_values(), never through
        # the prompt/log-facing guidance block.
        self.assertIn("1 canary", block)
        self.assertNotIn("CANARY-abc123", block)

    def test_attack_surface_is_empty_detection(self):
        self.assertTrue(eng.AttackSurface().is_empty())
        self.assertFalse(eng.AttackSurface(endpoints=["/x"]).is_empty())


class RedactionTests(unittest.TestCase):
    """Secrets must never reach the terminal or a JSON dump."""

    def test_mask_secret_short_value_is_fully_hidden(self):
        self.assertEqual(eng.mask_secret("abc"), "•••")

    def test_mask_secret_long_value_keeps_only_ends(self):
        masked = eng.mask_secret("supersecretpassword")
        self.assertTrue(masked.startswith("sup"))
        self.assertTrue(masked.endswith("ord"))
        self.assertIn("•", masked)
        self.assertNotIn("ersecretpass", masked)

    def test_mask_secret_empty(self):
        self.assertEqual(eng.mask_secret(""), "")

    def test_redact_masks_secret_keys_deeply(self):
        data = {
            "name": "lab",
            "attack_surface": {
                "credentials": [{"username": "admin", "secret": "hunter2hunter2"}]
            },
            "validation": {"canaries": [{"label": "c1", "value": "CANARY-abc123"}]},
        }
        redacted = eng.redact(data)
        self.assertEqual(redacted["name"], "lab")
        self.assertEqual(redacted["attack_surface"]["credentials"][0]["username"], "admin")
        self.assertNotEqual(redacted["attack_surface"]["credentials"][0]["secret"], "hunter2hunter2")
        self.assertNotEqual(redacted["validation"]["canaries"][0]["value"], "CANARY-abc123")

    def test_redact_does_not_mutate_input(self):
        data = {"password": "hunter2hunter2"}
        eng.redact(data)
        self.assertEqual(data["password"], "hunter2hunter2")

    def test_profile_json_dump_is_redacted(self):
        data = eng.redact(_profile().to_dict())
        dumped = json.dumps(data)
        self.assertNotIn("CANARY-abc123", dumped)


def _ns(**kwargs):
    base = dict(
        command="engagement", action="list", name="", json=False, no_color=True,
        plain=True, quiet=False, verbose=False, target="", target_type="lab",
        scope="", out_of_scope="", focus="", vuln_classes="", spec=[], endpoint=[],
        canary=[], weakness=[], rules="", destructive=False, min_severity="low",
        max_seconds=1800, max_commands=500, max_llm_calls=200, what="all", force=False,
    )
    base.update(kwargs)
    return argparse.Namespace(**base)


class EngagementCommandTests(unittest.TestCase):
    """`x19 engagement …` end to end through the CLI handlers."""

    def setUp(self):
        init_console(force_terminal=False)
        self._tmp = tempfile.TemporaryDirectory()
        self._saved_env = os.environ.get("X19_ENGAGEMENTS_DIR")
        os.environ["X19_ENGAGEMENTS_DIR"] = self._tmp.name

    def tearDown(self):
        if self._saved_env is None:
            os.environ.pop("X19_ENGAGEMENTS_DIR", None)
        else:
            os.environ["X19_ENGAGEMENTS_DIR"] = self._saved_env
        self._tmp.cleanup()

    def test_new_creates_profile_and_reports_location(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.cmd_engagement(_ns(action="new", name="lab", target="127.0.0.1"))
        self.assertEqual(code, 0)
        self.assertTrue(eng.profile_path("lab").exists())
        self.assertIn("profile saved", buffer.getvalue())

    def test_new_json_mode_emits_path_and_problems(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.cmd_engagement(_ns(action="new", name="lab", target="127.0.0.1", json=True))
        self.assertEqual(code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertTrue(payload["saved"].endswith("lab.json"))
        self.assertEqual(payload["problems"], [])

    def test_new_without_name_is_refused(self):
        with self.assertRaises(SystemExit):
            cli.cmd_engagement(_ns(action="new", name="", target="127.0.0.1"))

    def test_new_inserts_target_into_scope(self):
        cli.cmd_engagement(_ns(action="new", name="lab", target="127.0.0.1", scope="10.0.0.9"))
        profile = eng.load_profile("lab")
        self.assertEqual(profile.scope_allowlist(), ["127.0.0.1", "10.0.0.9"])

    def test_new_maps_guidance_cards_from_flags(self):
        cli.cmd_engagement(_ns(
            action="new", name="lab", target="127.0.0.1",
            focus="auth,api", vuln_classes="sqli,idor",
            canary=["CANARY-1"], weakness=["legacy panel"],
            endpoint=["/api/v1/login"], max_seconds=90, max_commands=40,
        ))
        profile = eng.load_profile("lab")
        self.assertEqual(profile.priorities.focus, ["auth", "api"])
        self.assertEqual(profile.priorities.vuln_classes, ["sqli", "idor"])
        self.assertEqual(profile.strategy.known_weaknesses, ["legacy panel"])
        self.assertEqual(profile.attack_surface.endpoints, ["/api/v1/login"])
        self.assertEqual(profile.validation.canary_values(), ["CANARY-1"])
        self.assertEqual(profile.budget.max_seconds, 90)
        self.assertEqual(profile.budget.max_commands, 40)

    def test_show_renders_the_four_cards(self):
        cli.cmd_engagement(_ns(action="new", name="lab", target="127.0.0.1", canary=["CANARY-1"]))
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.cmd_engagement(_ns(action="show", name="lab"))
        out = buffer.getvalue()
        self.assertEqual(code, 0)
        for card in ("attack surface", "priorities", "attack strategy", "validation"):
            self.assertIn(card, out.lower())

    def test_show_json_is_redacted(self):
        cli.cmd_engagement(_ns(action="new", name="lab", target="127.0.0.1", canary=["CANARY-1"]))
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            cli.cmd_engagement(_ns(action="show", name="lab", json=True))
        payload = json.loads(buffer.getvalue())
        self.assertNotIn("CANARY-1", json.dumps(payload))

    def test_show_missing_profile_fails(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.cmd_engagement(_ns(action="show", name="ghost"))
        self.assertEqual(code, 1)

    def test_list_shows_saved_profiles(self):
        cli.cmd_engagement(_ns(action="new", name="lab", target="127.0.0.1"))
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            cli.cmd_engagement(_ns(action="list"))
        self.assertIn("lab", buffer.getvalue())

    def test_list_empty_store_prints_hint(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.cmd_engagement(_ns(action="list"))
        self.assertEqual(code, 0)
        self.assertIn("engagement new", buffer.getvalue())

    def test_rm_removes_profile(self):
        cli.cmd_engagement(_ns(action="new", name="lab", target="127.0.0.1"))
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.cmd_engagement(_ns(action="rm", name="lab"))
        self.assertEqual(code, 0)
        self.assertFalse(eng.profile_path("lab").exists())

    def test_rm_missing_profile_fails(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.cmd_engagement(_ns(action="rm", name="ghost"))
        self.assertEqual(code, 1)

    def test_path_prints_store_directory(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            cli.cmd_engagement(_ns(action="path"))
        self.assertEqual(buffer.getvalue().strip(), self._tmp.name)

    def test_path_json_mode(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            cli.cmd_engagement(_ns(action="path", json=True))
        self.assertEqual(json.loads(buffer.getvalue())["directory"], self._tmp.name)


class EngagementResolutionTests(unittest.TestCase):
    """`--engagement` resolution for run/dash."""

    def setUp(self):
        init_console(force_terminal=False)
        self._tmp = tempfile.TemporaryDirectory()
        self._saved_env = os.environ.get("X19_ENGAGEMENTS_DIR")
        os.environ["X19_ENGAGEMENTS_DIR"] = self._tmp.name

    def tearDown(self):
        if self._saved_env is None:
            os.environ.pop("X19_ENGAGEMENTS_DIR", None)
        else:
            os.environ["X19_ENGAGEMENTS_DIR"] = self._saved_env
        self._tmp.cleanup()

    def test_named_profile_is_loaded(self):
        _profile().save()
        profile = cli._resolve_engagement(_ns(engagement="lab"))
        self.assertIsNotNone(profile)
        self.assertEqual(profile.name, "lab")
        self.assertEqual(profile.target, "127.0.0.1")

    def test_unknown_profile_is_a_hard_error(self):
        with self.assertRaises(SystemExit):
            cli._resolve_engagement(_ns(engagement="ghost"))

    def test_no_profile_falls_back_to_conservative_ad_hoc(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            profile = cli._resolve_engagement(_ns(target="10.0.0.7", target_type="auto"))
        self.assertIsNotNone(profile)
        self.assertFalse(profile.strategy.allow_destructive)
        self.assertTrue(profile.validation.require_poc)
        self.assertIn("ad-hoc", buffer.getvalue().lower())

    def test_no_target_and_no_profile_is_none(self):
        self.assertIsNone(cli._resolve_engagement(_ns(target="")))

    def test_lab_target_type_is_passed_through(self):
        profile = cli._resolve_engagement(_ns(target="10.0.0.7", target_type="lab"))
        self.assertEqual(profile.target_type, "lab")


class EngagementParserTests(unittest.TestCase):
    """The argparse surface must accept what the help text advertises."""

    def test_engagement_is_a_registered_command(self):
        self.assertIn("engagement", cli.COMMANDS)

    def test_parser_builds_engagement_subcommand(self):
        parser = cli.build_parser()
        args = parser.parse_args(["engagement", "new", "lab", "-t", "127.0.0.1", "--canary", "C1"])
        self.assertEqual(args.command, "engagement")
        self.assertEqual(args.action, "new")
        self.assertEqual(args.name, "lab")
        self.assertEqual(args.target, "127.0.0.1")
        self.assertEqual(args.canary, ["C1"])

    def test_parser_accepts_repeatable_guidance_flags(self):
        parser = cli.build_parser()
        args = parser.parse_args([
            "engagement", "new", "lab", "-t", "127.0.0.1",
            "--endpoint", "/a", "--endpoint", "/b",
            "--weakness", "w1", "--weakness", "w2",
            "--spec", "openapi.yaml",
        ])
        self.assertEqual(args.endpoint, ["/a", "/b"])
        self.assertEqual(args.weakness, ["w1", "w2"])
        self.assertEqual(args.spec, ["openapi.yaml"])

    def test_parser_accepts_engagement_and_cycles_on_dash(self):
        parser = cli.build_parser()
        args = parser.parse_args(["dash", "-t", "127.0.0.1", "--engagement", "lab",
                                  "--max-cycles", "5", "--legacy"])
        self.assertEqual(args.engagement, "lab")
        self.assertEqual(args.max_cycles, 5)
        self.assertTrue(args.legacy)

    def test_parser_accepts_engagement_on_run(self):
        parser = cli.build_parser()
        args = parser.parse_args(["run", "-t", "127.0.0.1", "--engagement", "lab"])
        self.assertEqual(args.engagement, "lab")

    def test_setup_takes_a_what_positional(self):
        parser = cli.build_parser()
        self.assertEqual(parser.parse_args(["setup"]).what, "all")
        self.assertEqual(parser.parse_args(["setup", "app"]).what, "app")
        self.assertEqual(parser.parse_args(["setup", "engagement"]).what, "engagement")
        self.assertEqual(parser.parse_args(["setup", "engagement", "-t", "127.0.0.1"]).target, "127.0.0.1")

    def test_help_screen_mentions_engagement(self):
        from ui.screens import help_screen

        from rich.console import Console

        from ui.theme import X19_THEME

        buffer = io.StringIO()
        Console(file=buffer, force_terminal=False, width=110, theme=X19_THEME).print(
            help_screen(cli.HELP_COMMANDS, version="4.0.0")
        )
        self.assertIn("engagement", buffer.getvalue())


class SetupCommandTests(unittest.TestCase):
    """`x19 setup` routes app / engagement / all correctly."""

    def setUp(self):
        init_console(force_terminal=False)
        self._tmp = tempfile.TemporaryDirectory()
        self._saved_env = os.environ.get("X19_ENGAGEMENTS_DIR")
        os.environ["X19_ENGAGEMENTS_DIR"] = self._tmp.name

    def tearDown(self):
        if self._saved_env is None:
            os.environ.pop("X19_ENGAGEMENTS_DIR", None)
        else:
            os.environ["X19_ENGAGEMENTS_DIR"] = self._saved_env
        self._tmp.cleanup()

    def test_setup_engagement_runs_only_the_wizard(self):
        calls = {}

        def fake_wizard(target=""):
            calls["target"] = target
            return _profile()

        original = cli.engagement_wizard
        cli.engagement_wizard = fake_wizard
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = cli.cmd_setup(_ns(what="engagement", target="127.0.0.1"))
        finally:
            cli.engagement_wizard = original

        self.assertEqual(code, 0)
        self.assertEqual(calls["target"], "127.0.0.1")
        self.assertIn("x19 dash", buffer.getvalue())

    def test_setup_engagement_failure_returns_error(self):
        original = cli.engagement_wizard
        cli.engagement_wizard = lambda target="": None
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = cli.cmd_setup(_ns(what="engagement"))
        finally:
            cli.engagement_wizard = original
        self.assertEqual(code, 1)

    def test_setup_app_only_never_touches_the_wizard(self):
        import provider_setup

        def boom(target=""):
            raise AssertionError("engagement wizard must not run for `setup app`")

        original_wizard = cli.engagement_wizard
        original_setup = provider_setup.setup_if_needed
        cli.engagement_wizard = boom
        provider_setup.setup_if_needed = lambda force=False: True
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = cli.cmd_setup(_ns(what="app"))
        finally:
            cli.engagement_wizard = original_wizard
            provider_setup.setup_if_needed = original_setup

        self.assertEqual(code, 0)
        self.assertIn("provider chain saved", buffer.getvalue())

    def test_setup_app_failure_is_an_error(self):
        import provider_setup

        original_setup = provider_setup.setup_if_needed
        provider_setup.setup_if_needed = lambda force=False: False
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = cli.cmd_setup(_ns(what="app"))
        finally:
            provider_setup.setup_if_needed = original_setup

        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
