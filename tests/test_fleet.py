"""Fleet mode: one supervisor, many targets (XBOW scale pattern).

Verifies: dedupe on submit, bounded concurrency, lifecycle transitions with
failure isolation, cooperative stop (single + all), severity/tech collection,
fleet summary with shared-stack correlation, the headless CLI (arg parsing,
exit codes, default-factory override), and workspace/run.py wiring.
"""

from __future__ import annotations

import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

import brain.fleet as fleet_mod
from brain.fleet import FleetSupervisor, fleet_concurrency


class FakeSession:
    id = "sess-42"


class FakeModel:
    def __init__(self):
        self.findings = []
        self.tech_stack = {}


class FakeAgent:
    """Configurable unit agent: sleep, crash, or finish instantly."""

    sleeps = 0.15
    crash_on = ()

    def __init__(self, target):
        self.target = target
        self.stop = False
        self.session = FakeSession()
        self.model = FakeModel()
        self.model.tech_stack = {"nginx": "1.18"}

    def autonomous_loop(self, target):
        if target in FakeAgent.crash_on:
            raise RuntimeError("scope refused")
        time.sleep(FakeAgent.sleeps)
        self.model.findings.append(SimpleNamespace(severity="high"))


def _fleet(targets, max_c=2, bus=None):
    sup = FleetSupervisor(unit_factory=lambda t: FakeAgent(t),
                          max_concurrency=max_c, bus=bus)
    sup.submit(targets)
    return sup


class SubmitTests(unittest.TestCase):
    def test_dedupe_and_order(self):
        sup = _fleet(["a.com", "b.com", "a.com", ""])
        self.assertEqual(list(sup.units), ["a.com", "b.com"])
        self.assertEqual(sup.active_count(), 2)

    def test_concurrency_env_bounds(self):
        with mock.patch.dict("os.environ", {"X19_FLEET_CONCURRENCY": "99"}):
            self.assertEqual(fleet_concurrency(), 8)
        with mock.patch.dict("os.environ", {"X19_FLEET_CONCURRENCY": "junk"}):
            self.assertEqual(fleet_concurrency(), 2)


class LifecycleTests(unittest.TestCase):
    def test_transitions_and_failure_isolation(self):
        FakeAgent.crash_on = ("bad.com",)
        try:
            sup = _fleet(["a.com", "bad.com", "c.com"])
            sup.run(wait=True, timeout=10)
            rows = {r["target"]: r for r in sup.status_rows()}
            self.assertEqual(rows["a.com"]["status"], "done")
            self.assertEqual(rows["c.com"]["status"], "done")
            self.assertEqual(rows["bad.com"]["status"], "failed")
            self.assertIn("scope refused", rows["bad.com"]["error"])
            self.assertEqual(rows["a.com"]["findings"], 1)
            self.assertEqual(rows["a.com"]["session"], "sess-42")
        finally:
            FakeAgent.crash_on = ()

    def test_bounded_concurrency_observed(self):
        running_now = []
        peak = []

        class SlowAgent(FakeAgent):
            def autonomous_loop(self, target):
                running_now.append(target)
                peak.append(len(running_now))
                time.sleep(0.15)
                running_now.remove(target)

        sup = FleetSupervisor(unit_factory=lambda t: SlowAgent(t), max_concurrency=2)
        sup.submit(["t1", "t2", "t3", "t4", "t5"])
        sup.run(wait=True, timeout=15)
        self.assertLessEqual(max(peak), 2, "pool must never exceed max_concurrency")
        self.assertEqual(len(sup.status_rows()), 5)

    def test_run_is_idempotent_while_active(self):
        sup = _fleet(["a.com", "b.com"])
        sup.run(wait=False)
        sup.run(wait=False)          # second call must not spawn more workers
        self.assertTrue(sup.wait(timeout=10))
        self.assertEqual(len(sup._threads), min(sup.max_concurrency, 2))

    def test_events_published(self):
        from events import AgentEventBus

        class Recorder:
            def __init__(self):
                self.texts = []

            def publish(self, kind, text="", **detail):
                self.texts.append((kind, text))

        bus = Recorder()
        sup = FleetSupervisor(unit_factory=lambda t: FakeAgent(t), max_concurrency=2, bus=bus)
        sup.submit(["a.com", "b.com"])
        sup.run(wait=True, timeout=10)
        kinds = [k for k, _ in bus.texts]
        self.assertTrue(all(k == "fleet" for k in kinds))
        texts = [txt for _, txt in bus.texts]        # (kind, text) tuples
        self.assertTrue(any("start a.com" in txt for txt in texts))
        self.assertTrue(any("done b.com" in txt for txt in texts))


class StopTests(unittest.TestCase):
    def test_stop_all_stops_running_and_cancels_queued(self):
        gate = threading.Event()

        class SlowAgent(FakeAgent):
            def autonomous_loop(self, target):
                while not gate.is_set() and not self.stop:
                    time.sleep(0.05)

        sup = FleetSupervisor(unit_factory=lambda t: SlowAgent(t), max_concurrency=1)
        sup.submit(["slow1", "slow2"])
        sup.run(wait=False)
        time.sleep(0.3)                      # slow1 running, slow2 queued
        n = sup.stop_all()
        self.assertGreaterEqual(n, 1)
        gate.set()
        self.assertTrue(sup.wait(timeout=10))
        rows = {r["target"]: r for r in sup.status_rows()}
        self.assertEqual(rows["slow1"]["status"], "stopped")
        self.assertEqual(rows["slow2"]["status"], "stopped")

    def test_stop_single_target(self):
        gate = threading.Event()

        class SlowAgent(FakeAgent):
            def autonomous_loop(self, target):
                while not gate.is_set() and not self.stop:
                    time.sleep(0.05)

        sup = FleetSupervisor(unit_factory=lambda t: SlowAgent(t), max_concurrency=1)
        sup.submit(["x.com"])
        sup.run(wait=False)
        time.sleep(0.3)
        self.assertTrue(sup.stop("x.com"))
        self.assertFalse(sup.stop("unknown.com"))
        gate.set()
        self.assertTrue(sup.wait(timeout=10))
        self.assertEqual(sup.status_rows()[0]["status"], "stopped")


class SummaryTests(unittest.TestCase):
    def test_summary_aggregates_and_finds_shared_stacks(self):
        sup = _fleet(["a.com", "b.com", "bad.com"])
        FakeAgent.crash_on = ("bad.com",)
        try:
            sup.run(wait=True, timeout=10)
        finally:
            FakeAgent.crash_on = ()
        s = sup.summary()
        self.assertEqual(s["targets"], 3)
        self.assertEqual(s["done"], 2)
        self.assertEqual(s["failed"], 1)
        self.assertEqual(s["severity"], {"high": 2})
        self.assertEqual(s["shared_stacks"], {"nginx": ["a.com", "b.com"]})


class CliTests(unittest.TestCase):
    def test_cli_requires_targets(self):
        self.assertEqual(fleet_mod.cli([]), 2)
        self.assertEqual(fleet_mod.cli(["-h"]), 0)

    def test_cli_runs_with_overridden_factory(self):
        # Lab hosts: the CLI's authorization gate must let the fleet through
        # without evidence, so these tests stay about supervisor mechanics.
        FakeAgent.crash_on = ("10.0.0.9",)
        try:
            with mock.patch.object(fleet_mod.FleetSupervisor, "_default_factory",
                                   staticmethod(lambda t: FakeAgent(t))):
                rc = fleet_mod.cli(["-t", "10.0.0.5,10.0.0.9", "--max", "2"])
        finally:
            FakeAgent.crash_on = ()
        self.assertEqual(rc, 1)          # one unit failed -> nonzero exit

    def test_cli_zero_exit_when_all_done(self):
        with mock.patch.object(fleet_mod.FleetSupervisor, "_default_factory",
                               staticmethod(lambda t: FakeAgent(t))):
            rc = fleet_mod.cli(["--targets=10.0.0.5"])
        self.assertEqual(rc, 0)


class WiringTests(unittest.TestCase):
    def test_run_py_routes_fleet(self):
        with open("run.py") as fh:
            src = fh.read()
        self.assertIn('if route == "fleet":', src)
        self.assertIn("from brain.fleet import cli as fleet_cli", src)

    def test_workspace_has_fleet_command(self):
        with open("ui/app.py") as fh:
            src = fh.read()
        self.assertIn("def cmd_fleet(self, *args: str) -> None:", src)
        self.assertIn('/fleet <t1,t2,…>', src)          # registry entry
        self.assertIn("/fleet stop", src)
        self.assertIn("self._fleet = sup", src)
        self.assertIn("FleetSupervisor(bus=None, max_concurrency=fleet_concurrency())", src)

    def test_default_factory_uses_real_x19(self):
        with open("brain/fleet.py") as fh:
            src = fh.read()
        self.assertIn("from agent import X19", src)


if __name__ == "__main__":
    unittest.main()


class QueuedStopTests(unittest.TestCase):
    def test_stop_queued_unit_before_start(self):
        gate = threading.Event()

        class SlowAgent(FakeAgent):
            def autonomous_loop(self, target):
                while not gate.is_set() and not self.stop:
                    time.sleep(0.05)

        sup = FleetSupervisor(unit_factory=lambda t: SlowAgent(t), max_concurrency=1)
        sup.submit(["running-one", "queued-one"])
        sup.run(wait=False)
        time.sleep(0.3)
        # queued-one has no agent yet — stop() must cancel it, not fail
        self.assertTrue(sup.stop("queued-one"))
        rows = {r["target"]: r for r in sup.status_rows()}
        self.assertEqual(rows["queued-one"]["status"], "stopped")
        gate.set()
        self.assertTrue(sup.wait(timeout=10))
        # the worker skipped it: no session, still marked stopped
        unit = sup.units["queued-one"]
        self.assertEqual(unit.status, "stopped")
        self.assertIsNone(unit.agent)

    def test_stop_unknown_still_false(self):
        sup = _fleet(["a.com"])
        self.assertFalse(sup.stop("never-submitted.com"))
        sup.shutdown if hasattr(sup, "shutdown") else None
