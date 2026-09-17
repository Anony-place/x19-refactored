"""Active-run authorization: evidence decides, flags only *claim*.

The one-shot path and the terminal workspace disagreed about what authorizes a
target. ``x19 run -t <host> --bug-bounty`` wrote ``TARGET_TYPE=authorized`` into
the config the moment the flag was parsed — full testing on any public host, no
verification, and the verdict persisted into ``~/.x19/config.json`` for every
later run — while the workspace refused the *same* host without a verified
program. These tests pin the single policy that replaced both:

- ``scope_guard.classify_target`` is the one posture heuristic (parity with the
  agent's old inline copy, so the extraction cannot drift apart again);
- ``scope_guard.decide_active_run`` turns evidence + a claim into a posture;
- ``cli._authorize_active_run``, ``cmd_run``, ``cmd_dash`` and ``fleet.cli`` all
  answer to it, per target;
- the recon-only fallback clears ``BUG_BOUNTY_MODE``, because the agent loop
  widens the posture on that flag alone and would otherwise re-authorize what
  the gate just refused.
"""

from __future__ import annotations

import io
import ipaddress
import os
import re
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import brain.fleet as fleet_mod
import cli
import scope_guard
from config import CONFIG
from scope_guard import ScopeResult, classify_target, decide_active_run
from ui.console import init_console

#: Keys the gate reads or writes — snapshotted so tests cannot leak into others.
ENV_KEYS = (
    "X19_ALLOW_UNVERIFIED", "X19_BUG_BOUNTY_MODE", "X19_CTF_MODE",
    "X19_SCOPE_URL", "X19_TARGET", "X19_TARGET_TYPE",
)

PUBLIC = "scanme.nmap.org"          # a real host nobody authorized here
IN_SCOPE = "www.paytm.com"          # verified by Paytm's own scope metadata
OUT_OF_SCOPE = "paytm.com"          # program found, apex not declared
LAB = "10.0.0.5"
CTF = "machine.hackthebox.eu"


def _ns(**over):
    """A ``cmd_run``/``cmd_dash`` namespace with everything defaulted."""
    base = dict(
        target="", target_pos="", target_type="", bug_bounty=False, ctf=False,
        fast=False, swarm=False, interactive=False, quiet=True, engagement="",
        scope_url="", provider="", model="", api_key="", set_data="",
        strict_gates=False, max_iterations=0, browser="", setup_groq="",
        setup_cerebras="", json=False, no_start=True, once=True,
    )
    base.update(over)
    return SimpleNamespace(**base)


def _legacy_classify(target: str) -> str:
    """The heuristic ``agent._resolve_target_type`` used to inline — verbatim."""
    target = target.strip().lower()
    if re.search(r"\.(apk|ipa|aab|dex|jar|so|elf|exe|bin|war)$", target):
        return "authorized"
    private_patterns = [
        r"^10\.", r"^172\.(1[6-9]|2\d|3[01])\.", r"^192\.168\.",
        r"^127\.", r"^localhost$", r"^0\.",
        r"^::1$", r"^fe80:", r"^fc00:", r"^fd00:",
        r"\.local$", r"\.internal$", r"\.lan$",
    ]
    for pat in private_patterns:
        if re.match(pat, target):
            return "authorized"
    ctf_hints = ["ctf", "hackme", "hack.me", "capturetheflag", "challenge",
                 "vulnhub", "hackthebox", "tryhackme"]
    if any(h in target for h in ctf_hints):
        return "ctf"
    if (re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,}", target)
            and not re.match(r"^\d+\.\d+\.\d+\.\d+$", target)):
        return "public_real_world"
    try:
        ip = ipaddress.ip_address(target)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return "authorized"
        return "public_real_world"
    except ValueError:
        pass
    return "authorized"  # safe default


class _EnvIsolated(unittest.TestCase):
    """Restore env + CONFIG so a gate test cannot authorize the next one."""

    def setUp(self):
        init_console(force_terminal=False)
        self._env = {k: os.environ.get(k) for k in ENV_KEYS}
        for key in ENV_KEYS:
            os.environ.pop(key, None)
        self._cfg = (CONFIG.TARGET_TYPE, CONFIG.BUG_BOUNTY_MODE, CONFIG.CTF_MODE)
        CONFIG.TARGET_TYPE = "auto"
        CONFIG.BUG_BOUNTY_MODE = False
        CONFIG.CTF_MODE = False
        #: the config file is not part of the fixture: claims come from args/env
        config_patcher = mock.patch.object(cli, "load_config", return_value={})
        config_patcher.start()
        self.addCleanup(config_patcher.stop)
        #: every set_data() the gate makes, instead of touching ~/.x19
        self.saved: list[dict] = []
        self.save_flags: list[bool] = []

        def record(data, save=True, **kw):
            self.saved.append(dict(data))
            self.save_flags.append(save)

        patcher = mock.patch.object(cli, "set_data", side_effect=record)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        for key, value in self._env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        CONFIG.TARGET_TYPE, CONFIG.BUG_BOUNTY_MODE, CONFIG.CTF_MODE = self._cfg

    def saved_value(self, key: str):
        for data in reversed(self.saved):
            if key in data:
                return data[key]
        return None

    def saved_persistently(self, key: str) -> bool:
        """True when the value was written to ~/.x19/config.json, not just this run."""
        for data, save in zip(reversed(self.saved), reversed(self.save_flags)):
            if key in data:
                return bool(save)
        return False

    def capture(self, fn, *a, **kw):
        """Run ``fn`` with the rich console pointed at a buffer; return (rc, text)."""
        from ui.console import get_console

        buffer = io.StringIO()
        console = get_console()
        previous = console.file
        console.file = buffer
        try:
            rc = fn(*a, **kw)
        finally:
            console.file = previous
        return rc, buffer.getvalue()


# ---------------------------------------------------------------------------
# one heuristic, two callers
# ---------------------------------------------------------------------------
class ClassificationParityTests(unittest.TestCase):
    SAMPLES = [
        "10.0.0.5", "172.16.0.1", "172.31.255.255", "172.15.0.1", "192.168.1.1",
        "127.0.0.1", "localhost", "0.0.0.0", "::1", "fe80::1", "fc00::1", "fd12::1",
        "app.local", "db.internal", "nas.lan",
        "app.apk", "payload.exe", "lib.so", "classes.dex", "bundle.ipa",
        "scanme.nmap.org", "www.paytm.com", "paytm.com", "account.mi.com",
        "8.8.8.8", "1.1.1.1", "203.0.113.7", "999.999.999.999",
        "machine.hackthebox.eu", "x.tryhackme.com", "ctf.example.com",
        "challenge.io", "vulnhub.local",
        "weird", "not a target", "HTTP://Example.COM/path", "example.invalid",
        "sub.domain.co.uk", "a.b",
    ]

    def test_extraction_matches_the_heuristic_it_replaced(self):
        drift = [(t, _legacy_classify(t), classify_target(t))
                 for t in self.SAMPLES if _legacy_classify(t) != classify_target(t)]
        self.assertEqual(drift, [], f"classify_target drifted from the agent heuristic: {drift}")

    def test_empty_target_fails_closed(self):
        # The one deliberate difference: the old default called an empty target
        # "authorized". Nothing is authorized by saying nothing.
        self.assertEqual(_legacy_classify(""), "authorized")
        self.assertEqual(classify_target(""), "public_real_world")

    def test_agent_delegates_to_scope_guard(self):
        from agent import X19

        for sample in ("scanme.nmap.org", LAB, CTF, "app.apk"):
            self.assertEqual(X19._resolve_target_type(sample, "auto"), classify_target(sample))
        # An explicit configuration still wins over the heuristic.
        self.assertEqual(X19._resolve_target_type(PUBLIC, "authorized"), "authorized")


# ---------------------------------------------------------------------------
# the decision matrix
# ---------------------------------------------------------------------------
class DecisionMatrixTests(_EnvIsolated):
    def test_lab_target_needs_no_program(self):
        decision = decide_active_run(LAB, claimed=True)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.target_type, "authorized")

    def test_practice_platform_is_its_own_evidence(self):
        decision = decide_active_run(CTF, claimed=True)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.target_type, "ctf")

    def test_public_host_without_a_claim_stays_recon_only(self):
        decision = decide_active_run(PUBLIC)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.target_type, "")     # posture left to classification
        self.assertIn("recon", decision.reason)

    def test_public_host_with_a_bare_claim_is_refused(self):
        """The hole: --bug-bounty used to be the only input that mattered."""
        decision = decide_active_run(PUBLIC, claimed=True)
        self.assertFalse(decision.allowed)
        self.assertTrue(decision.needs_input)
        self.assertEqual(decision.target_type, "")

    def test_verified_program_authorizes_the_host_it_declares(self):
        decision = decide_active_run(IN_SCOPE, claimed=True)
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.verified)
        self.assertEqual(decision.target_type, "authorized")
        self.assertIn("Paytm", decision.reason)

    def test_verified_program_does_not_authorize_what_it_omits(self):
        decision = decide_active_run(OUT_OF_SCOPE, claimed=True)
        self.assertFalse(decision.allowed)
        self.assertFalse(decision.needs_input)         # nothing to confirm — wrong evidence
        self.assertIn("*.paytm.com", decision.reason)  # the declared scope is named

    def test_recorded_engagement_is_evidence(self):
        decision = decide_active_run(PUBLIC, claimed=True, engagement=True)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.target_type, "authorized")
        self.assertIn("engagement", decision.reason)

    def test_operator_override_is_evidence(self):
        os.environ["X19_ALLOW_UNVERIFIED"] = "1"
        decision = decide_active_run(PUBLIC, claimed=True)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.target_type, "authorized")
        self.assertIn("X19_ALLOW_UNVERIFIED", decision.reason)

    def test_scope_url_is_verified_not_believed(self):
        """A supplied URL must actually declare the target, not just be present."""
        fake = mock.patch.object(
            scope_guard, "resolve_scope",
            side_effect=lambda target, *, scope_url="": ScopeResult(
                target=target, normalized_target=target,
                state="verified_in_scope" if scope_url else "unknown",
                program="ACME" if scope_url else "",
                matched_pattern="*.acme.test" if scope_url else "",
                reason="test",
            ),
        )
        with fake:
            self.assertFalse(decide_active_run("app.acme.test", claimed=True).allowed)
            proven = decide_active_run("app.acme.test", claimed=True,
                                       scope_url="https://acme.test/security.txt")
        self.assertTrue(proven.allowed)
        self.assertTrue(proven.verified)
        self.assertEqual(proven.target_type, "authorized")


# ---------------------------------------------------------------------------
# the CLI gate
# ---------------------------------------------------------------------------
class CliGateTests(_EnvIsolated):
    def test_lab_target_runs_without_ceremony(self):
        decision, out = self.capture(cli._authorize_active_run, LAB, _ns(bug_bounty=True))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.target_type, "authorized")
        self.assertIn("scope:", out)                   # one factual line, not a lecture

    def test_verified_program_runs(self):
        decision, _ = self.capture(cli._authorize_active_run, IN_SCOPE, _ns(bug_bounty=True))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.target_type, "authorized")

    def test_unverified_claim_is_refused_without_a_terminal(self):
        with mock.patch.object(sys.stdin, "isatty", return_value=False):
            decision, out = self.capture(cli._authorize_active_run, PUBLIC, _ns(bug_bounty=True))
        self.assertFalse(decision.allowed)
        self.assertIn("active run not started", out)
        # Every way out is named, so the refusal is actionable rather than a wall.
        self.assertIn("--scope-url", out)
        self.assertIn("X19_ALLOW_UNVERIFIED", out)
        self.assertIn("engagement", out)
        self.assertEqual(self.saved, [])               # nothing was persisted

    def test_out_of_scope_host_is_refused_even_with_a_terminal(self):
        with mock.patch.object(sys.stdin, "isatty", return_value=True):
            decision, out = self.capture(cli._authorize_active_run, OUT_OF_SCOPE, _ns(bug_bounty=True))
        self.assertFalse(decision.allowed)
        self.assertIn("*.paytm.com", out)

    def test_no_claim_means_no_prompt_just_a_narrower_run(self):
        with mock.patch.object(sys.stdin, "isatty", return_value=False):
            decision, _ = self.capture(cli._authorize_active_run, PUBLIC, _ns())
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.target_type, "")

    def test_empty_answer_falls_back_to_recon_and_clears_the_flag(self):
        with mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch("rich.prompt.Prompt.ask", return_value=""):
            decision, out = self.capture(cli._authorize_active_run, PUBLIC, _ns(bug_bounty=True))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.target_type, "public_real_world")
        # Without this the agent loop re-widens on BUG_BOUNTY_MODE alone.
        self.assertEqual(self.saved_value("BUG_BOUNTY_MODE"), "0")
        self.assertEqual(self.saved_value("TARGET_TYPE"), "public_real_world")
        self.assertIn("recon", out)

    def test_retyped_target_is_recorded_as_an_assertion(self):
        with mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch("rich.prompt.Prompt.ask", return_value=PUBLIC):
            decision, out = self.capture(cli._authorize_active_run, PUBLIC, _ns(bug_bounty=True))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.target_type, "authorized")
        self.assertEqual(self.saved_value("TARGET_TYPE"), "authorized")
        self.assertIn("asserted written authorization", out)
        self.assertIsNone(self.saved_value("BUG_BOUNTY_MODE"))   # the claim stands

    def test_pasted_scope_url_only_counts_when_it_verifies(self):
        unverified = ScopeResult(target=PUBLIC, normalized_target=PUBLIC, state="unknown",
                                 reason="no trusted public program matched this target")
        verified = ScopeResult(target=PUBLIC, normalized_target=PUBLIC, state="verified_in_scope",
                               program="Nmap", matched_pattern="scanme.nmap.org",
                               reason="declared")
        calls = []

        def fake_resolve(target, *, scope_url=""):
            calls.append(scope_url)
            return verified if scope_url else unverified

        with mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch("rich.prompt.Prompt.ask", return_value="https://nmap.org/scope"), \
                mock.patch.object(scope_guard, "resolve_scope", side_effect=fake_resolve):
            decision, out = self.capture(cli._authorize_active_run, PUBLIC, _ns(bug_bounty=True))
        self.assertEqual(calls[-1], "https://nmap.org/scope")
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.verified)
        self.assertEqual(decision.target_type, "authorized")
        self.assertIn("Nmap", out)

    def test_pasted_url_that_proves_nothing_narrows_the_run(self):
        with mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch("rich.prompt.Prompt.ask", return_value="https://blog.example/our-bb"), \
                mock.patch.object(scope_guard, "resolve_scope",
                                  return_value=ScopeResult(target=PUBLIC, normalized_target=PUBLIC,
                                                           state="unknown", reason="unparsed")):
            decision, out = self.capture(cli._authorize_active_run, PUBLIC, _ns(bug_bounty=True))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.target_type, "public_real_world")
        self.assertEqual(self.saved_value("BUG_BOUNTY_MODE"), "0")
        self.assertIn("still not verified", out)

    def test_interrupted_prompt_fails_closed_to_recon(self):
        with mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch("rich.prompt.Prompt.ask", side_effect=KeyboardInterrupt):
            decision, _ = self.capture(cli._authorize_active_run, PUBLIC, _ns(bug_bounty=True))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.target_type, "public_real_world")

    def test_json_mode_refusal_is_machine_readable_and_never_prompts(self):
        """`--json` consumers get the refusal as a document, not as prose."""
        import json as jsonlib

        from ui.console import init_console

        asked = mock.MagicMock(side_effect=AssertionError("must not prompt in json mode"))
        stdout = io.StringIO()
        init_console(force_terminal=False, json_mode=True)
        try:
            with mock.patch.object(sys, "stdout", stdout), \
                    mock.patch.object(sys.stdin, "isatty", return_value=True), \
                    mock.patch("rich.prompt.Prompt.ask", asked):
                decision = cli._authorize_active_run(PUBLIC, _ns(bug_bounty=True))
        finally:
            init_console(force_terminal=False, json_mode=False)
        self.assertFalse(decision.allowed)
        asked.assert_not_called()
        payload = jsonlib.loads(stdout.getvalue())
        self.assertFalse(payload["authorized"])
        self.assertEqual(payload["target"], PUBLIC)
        self.assertTrue(payload["needs_input"])
        self.assertTrue(any("--scope-url" in step for step in payload["next"]))

    def test_a_posture_left_in_the_config_file_is_a_claim_not_evidence(self):
        """The sticky half of the same bug: an old verdict must not be inherited."""
        with mock.patch.object(cli, "load_config", return_value={"TARGET_TYPE": "authorized"}):
            self.assertTrue(cli._authorization_claimed(_ns(target=PUBLIC)))
            with mock.patch.object(sys.stdin, "isatty", return_value=False):
                decision, out = self.capture(cli._authorize_active_run, PUBLIC, _ns())
        self.assertFalse(decision.allowed)
        self.assertIn("active run not started", out)
        # A lab host still needs no proof, whatever the file says.
        with mock.patch.object(cli, "load_config", return_value={"TARGET_TYPE": "authorized"}):
            self.assertTrue(cli._authorize_active_run(LAB, _ns()).allowed)

    def test_bug_bounty_flag_no_longer_writes_an_authorization_verdict(self):
        cli._apply_runtime_config(_ns(bug_bounty=True, target=PUBLIC))
        self.assertEqual(self.saved_value("BUG_BOUNTY_MODE"), "1")   # intent recorded
        self.assertIsNone(self.saved_value("TARGET_TYPE"))           # verdict is the gate's
        self.assertNotEqual(os.environ.get("X19_TARGET_TYPE"), "authorized")

    def test_explicit_target_type_flag_is_still_recorded(self):
        cli._apply_runtime_config(_ns(bug_bounty=True, target_type="authorized"))
        self.assertEqual(self.saved_value("TARGET_TYPE"), "authorized")

    def test_no_authorization_verdict_is_written_to_the_config_file(self):
        """A persisted TARGET_TYPE=authorized would authorize *every* later run.

        The agent trusts a configured posture without asking again, so one
        command line must not quietly authorize all the others: flags and gate
        verdicts live for the process, the config file keeps no verdicts.
        """
        cli._apply_runtime_config(_ns(bug_bounty=True, target_type="authorized"))
        self.assertFalse(self.saved_persistently("TARGET_TYPE"))
        self.assertFalse(self.saved_persistently("BUG_BOUNTY_MODE"))

        self.saved.clear(), self.save_flags.clear()
        with mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch("rich.prompt.Prompt.ask", return_value=PUBLIC):
            self.capture(cli._authorize_active_run, PUBLIC, _ns(bug_bounty=True))
        self.assertEqual(self.saved_value("TARGET_TYPE"), "authorized")
        self.assertFalse(self.saved_persistently("TARGET_TYPE"))

        self.saved.clear(), self.save_flags.clear()
        with mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch("rich.prompt.Prompt.ask", return_value=""):
            self.capture(cli._authorize_active_run, PUBLIC, _ns(bug_bounty=True))
        self.assertFalse(self.saved_persistently("BUG_BOUNTY_MODE"))

    def test_provider_and_key_configuration_still_persists(self):
        # The per-run rule is about authorization, not about setup: naming a
        # provider on the command line is still a configuration change.
        cli._apply_runtime_config(_ns(provider="groq", model="llama-3.3-70b-versatile"))
        self.assertEqual(self.saved_value("AI_PROVIDER"), "groq")
        self.assertTrue(self.saved_persistently("AI_PROVIDER"))

    def test_scope_url_flag_reaches_the_resolver_through_env(self):
        cli._apply_runtime_config(_ns(target=PUBLIC, scope_url="https://nmap.org/scope"))
        self.assertEqual(os.environ.get("X19_SCOPE_URL"), "https://nmap.org/scope")

    def test_ad_hoc_engagement_is_not_evidence(self):
        # `engagement.ad_hoc_profile` is synthesised from the command line, so
        # naming a target cannot bootstrap its own authorization.
        self.assertFalse(cli._engagement_authorizes(_ns(engagement="")))
        self.assertFalse(cli._engagement_authorizes(_ns(engagement="ghost-profile")))
        with mock.patch("engagement.load_profile",
                        return_value=SimpleNamespace(target_type="auto")):
            self.assertFalse(cli._engagement_authorizes(_ns(engagement="adhoc")))
        with mock.patch("engagement.load_profile",
                        return_value=SimpleNamespace(target_type="authorized")):
            self.assertTrue(cli._engagement_authorizes(_ns(engagement="written")))


# ---------------------------------------------------------------------------
# the entry points are actually wired to the gate
# ---------------------------------------------------------------------------
class EntryPointTests(_EnvIsolated):
    class _FakeAgent:
        """Everything cmd_run touches after autonomous_loop() returns."""

        def __init__(self):
            self.calls: list[str] = []
            self.session = SimpleNamespace(id="x19_test_gate",
                                           data={"status": "complete", "iterations": 1, "findings": []})

        def autonomous_loop(self, target):
            self.calls.append(target)

        def findings(self):
            return []

    def _run(self, args):
        """Drive cmd_run far enough to reach the gate, with no provider needed."""
        fake = self._FakeAgent()
        self.ran = fake.calls
        self.built = mock.MagicMock(return_value=(fake, SimpleNamespace(name=lambda: "fake")))
        self.telegram = mock.MagicMock()
        with mock.patch.object(cli, "_ensure_provider", return_value=True), \
                mock.patch.object(cli, "_make_agent", self.built), \
                mock.patch.object(cli, "_maybe_start_telegram", self.telegram), \
                mock.patch.object(cli, "_print_ai_chain_banner", lambda: None), \
                mock.patch("ui.console.banner", lambda *a, **k: None), \
                mock.patch.object(sys.stdin, "isatty", return_value=False):
            return self.capture(cli.cmd_run, args)

    def test_cmd_run_refuses_an_unverified_bounty_claim(self):
        rc, out = self._run(_ns(target=PUBLIC, bug_bounty=True))
        self.assertEqual(rc, 1)
        self.assertEqual(self.ran, [])                 # the loop never started
        self.assertIn("active run not started", out)

    def test_a_refused_run_starts_nothing(self):
        """No agent, no session, no telegram poller for a run that will not happen."""
        rc, _ = self._run(_ns(target=PUBLIC, bug_bounty=True))
        self.assertEqual(rc, 1)
        self.assertEqual(self.built.call_count, 0)
        self.assertEqual(self.telegram.call_count, 0)

    def test_an_allowed_run_builds_the_agent_once(self):
        rc, _ = self._run(_ns(target=LAB, bug_bounty=True))
        self.assertEqual(rc, 0)
        self.assertEqual(self.built.call_count, 1)

    def test_cmd_run_allows_a_lab_target_with_the_same_flag(self):
        rc, _ = self._run(_ns(target=LAB, bug_bounty=True))
        self.assertEqual(rc, 0)
        self.assertEqual(self.ran, [LAB])
        # Classification already calls a lab host authorized, so there is nothing
        # to persist — and persisting it would leak into every later run.
        self.assertIsNone(self.saved_value("TARGET_TYPE"))

    def test_cmd_run_allows_a_verified_program_host(self):
        rc, _ = self._run(_ns(target=IN_SCOPE, bug_bounty=True))
        self.assertEqual(rc, 0)
        self.assertEqual(self.ran, [IN_SCOPE])
        # Evidence upgraded a public host: that verdict is worth remembering.
        self.assertEqual(self.saved_value("TARGET_TYPE"), "authorized")

    def test_a_lab_target_does_not_move_the_global_posture(self):
        """Regression: gating `x19 dash -t 127.0.0.1` used to write TARGET_TYPE
        into the config, which then authorized exploitation for unrelated runs."""
        before = CONFIG.TARGET_TYPE
        rc, _ = self.capture(cli.cmd_dash, _ns(target=LAB))
        self.assertEqual(rc, 0)
        self.assertIsNone(self.saved_value("TARGET_TYPE"))
        self.assertEqual(CONFIG.TARGET_TYPE, before)

    def test_cmd_run_without_a_claim_runs_recon_only(self):
        rc, _ = self._run(_ns(target=PUBLIC))
        self.assertEqual(rc, 0)
        self.assertEqual(self.ran, [PUBLIC])
        self.assertNotEqual(self.saved_value("TARGET_TYPE"), "authorized")

    def test_cmd_dash_is_gated_too(self):
        rc, out = self.capture(cli.cmd_dash, _ns(target=PUBLIC, bug_bounty=True))
        self.assertEqual(rc, 1)
        self.assertIn("active run not started", out)

    def test_gate_runs_before_the_agent_loop_in_source_order(self):
        """Ordering is the guarantee: nothing offensive happens before the gate."""
        source = Path("cli.py").read_text(encoding="utf-8")

        def body(name: str) -> str:
            start = source.index(f"def {name}(")
            end = re.search(r"\ndef (?!%s)" % re.escape(name), source[start:])
            return source[start:start + (end.start() if end else len(source))]

        run_body = body("cmd_run")
        self.assertLess(run_body.index("_authorize_active_run(target, args)"),
                        run_body.index("agent.autonomous_loop(target)"))
        dash_body = body("cmd_dash")
        self.assertLess(dash_body.index("_authorize_active_run(target, args)"),
                        dash_body.index("coordinator = SwarmCoordinator()"))


class FleetGateTests(_EnvIsolated):
    """A fleet is many active runs, so the gate is per target."""

    def _cli(self, argv):
        made: list[str] = []

        class FakeSession:
            id = "s"

        class FakeAgent:
            def __init__(self, target):
                self.target = target
                self.stop = False
                self.session = FakeSession()
                self.model = SimpleNamespace(findings=[], tech_stack={})

            def autonomous_loop(self, target):
                made.append(target)

        with mock.patch.object(fleet_mod.FleetSupervisor, "_default_factory",
                               staticmethod(lambda t: FakeAgent(t))):
            with redirect_stdout(io.StringIO()) as out:
                rc = fleet_mod.cli(argv)
        return rc, made, out.getvalue()

    def test_unverified_public_targets_are_dropped_not_escalated(self):
        rc, made, out = self._cli(["-t", f"{LAB},{PUBLIC}"])
        self.assertEqual(rc, 0)
        self.assertEqual(made, [LAB])
        self.assertIn(f"{PUBLIC}: skipped", out)
        self.assertIn("need evidence", out)

    def test_verified_program_hosts_sail_through(self):
        rc, made, _ = self._cli(["-t", IN_SCOPE])
        self.assertEqual(rc, 0)
        self.assertEqual(made, [IN_SCOPE])

    def test_a_fleet_with_nothing_authorized_does_not_start(self):
        rc, made, out = self._cli(["-t", f"{PUBLIC},other.example"])
        self.assertEqual(rc, 2)
        self.assertEqual(made, [])
        self.assertIn("nothing left to run", out)

    def test_operator_override_lets_the_fleet_run(self):
        os.environ["X19_ALLOW_UNVERIFIED"] = "1"
        rc, made, _ = self._cli(["-t", PUBLIC])
        self.assertEqual(rc, 0)
        self.assertEqual(made, [PUBLIC])


# ---------------------------------------------------------------------------
# the agent loop cannot re-widen what the gate narrowed
# ---------------------------------------------------------------------------
class AgentPostureTests(unittest.TestCase):
    def test_bug_bounty_mode_is_evidence_based_in_the_loop(self):
        source = Path("agent.py").read_text(encoding="utf-8")
        branch = source[source.index("elif is_bug_bounty_mode():"):]
        branch = branch[:branch.index("CONFIG.PARALLEL_PLAN = True")]
        self.assertIn("decide_active_run(target, claimed=True)", branch)
        self.assertNotIn('self.target_type = "authorized"', branch)

    def test_an_explicitly_configured_posture_is_honored_without_a_second_lookup(self):
        source = Path("agent.py").read_text(encoding="utf-8")
        branch = source[source.index("elif is_bug_bounty_mode():"):]
        branch = branch[:branch.index("CONFIG.PARALLEL_PLAN = True")]
        self.assertIn('self.target_type != "auto"', branch)


if __name__ == "__main__":
    unittest.main()
