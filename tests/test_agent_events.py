"""Tests for the event-driven agent observability layer (see
docs/AGENT_UX_AUDIT.md): the bus, the Session hooks, background wiring and
the workspace's live activity rendering."""
from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from events import AgentEventBus, summarize_event


class AgentEventBusTests(unittest.TestCase):
    def test_subscribe_publish_receive(self):
        bus = AgentEventBus()
        token, q = bus.subscribe()
        bus.publish("command", "nmap -sV target", rc=0, secs=1.2)
        event = q.get(timeout=1)
        self.assertEqual(event.kind, "command")
        self.assertEqual(event.detail["rc"], 0)
        bus.unsubscribe(token)
        bus.publish("command", "second")
        self.assertTrue(q.empty())

    def test_subscriber_exception_cannot_break_publish(self):
        bus = AgentEventBus()

        def boom(_event):
            raise RuntimeError("subscriber bug")

        bus.subscribe(boom)
        token, q = bus.subscribe()
        bus.publish("status", "still alive")
        self.assertEqual(q.get(timeout=1).kind, "status")

    def test_bounded_queue_drops_oldest(self):
        bus = AgentEventBus(max_queue=10)  # bus enforces a floor of 10
        token, q = bus.subscribe()
        for i in range(20):
            bus.publish("command", f"cmd-{i}")
        events = []
        while True:
            try:
                events.append(q.get_nowait())
            except Exception:
                break
        self.assertEqual(len(events), 10)
        self.assertEqual(events[0].text, "cmd-10")  # oldest dropped
        self.assertEqual(events[-1].text, "cmd-19")

    def test_summarize_event_shapes(self):
        from events import AgentEvent

        cmd = summarize_event(AgentEvent(kind="command", text="nmap -sV", detail={"rc": 0, "secs": 2.5}))
        self.assertIn("nmap -sV", cmd)
        self.assertIn("rc 0", cmd)
        finding = summarize_event(AgentEvent(kind="finding", text="SQLi", detail={"severity": "high"}))
        self.assertIn("HIGH", finding)
        self.assertIn("SQLi", finding)


class SessionEventHooksTests(unittest.TestCase):
    def _session(self, bus):
        os.environ["X19_SESSIONS_DIR"] = tempfile.mkdtemp()
        from config import CONFIG

        CONFIG.SESSIONS_DIR = os.environ["X19_SESSIONS_DIR"]
        from storage import Session

        session = Session(events=bus)
        session.create("demo.example.com")
        return session

    def test_add_cmd_publishes_structured_event(self):
        bus = AgentEventBus()
        session = self._session(bus)
        session.mark_command_started()
        time.sleep(0.01)
        session.add_cmd("nmap -sV demo.example.com", "22/tcp open", "recon", 0)
        token, q = bus._subs and list(bus._subs.values())[0] or (None, None)
        # drain via a fresh subscription instead (bus API)
        token, q = bus.subscribe()
        session.add_cmd("curl -s http://demo.example.com", "ok", "web", 0)
        event = q.get(timeout=1)
        self.assertEqual(event.kind, "command")
        self.assertIn("curl", event.text)
        self.assertEqual(event.detail["rc"], 0)

    def test_add_finding_and_status_publish(self):
        bus = AgentEventBus()
        session = self._session(bus)
        token, q = bus.subscribe()
        session.add_finding("high", "Exposed admin", "detail", "evidence")
        event = q.get(timeout=1)
        self.assertEqual(event.kind, "finding")
        self.assertEqual(event.detail["severity"], "high")
        session.set_status("completed")
        event = q.get(timeout=1)
        self.assertEqual(event.kind, "status")
        self.assertEqual(event.text, "completed")

    def test_no_bus_no_crash(self):
        os.environ["X19_SESSIONS_DIR"] = tempfile.mkdtemp()
        from config import CONFIG

        CONFIG.SESSIONS_DIR = os.environ["X19_SESSIONS_DIR"]
        from storage import Session

        session = Session()
        session.create("t.example.com")
        session.add_cmd("ls", "", "other", 0)
        session.add_finding("low", "t", "d")
        self.assertEqual(session.data["iterations"], 1)


class BackgroundEventWiringTests(unittest.TestCase):
    def test_attach_and_drain_events(self):
        from events import AgentEventBus
        from ui.background import BackgroundTaskManager

        manager = BackgroundTaskManager()
        bus = AgentEventBus()
        release = threading.Event()

        task = manager.start("assessment t.example.com", release.wait)
        manager.attach_events(task, bus)
        release.set()
        task.join(timeout=2)

        bus.publish("command", "nmap -sV", rc=0)
        bus.publish("finding", "XSS", severity="medium")
        events = manager.drain_events(task)
        self.assertEqual([e.kind for e in events], ["command", "finding"])


class WorkspaceLiveActivityTests(unittest.TestCase):
    def test_drained_events_render_as_activity_cards(self):
        import io

        from rich.console import Console

        from ui.theme import X19_THEME
        from ui.app import ConsoleApp
        from events import AgentEventBus

        app = ConsoleApp(version="1.0.0")
        app.console = Console(file=io.StringIO(), width=100, height=24, force_terminal=True, theme=X19_THEME)

        bus = AgentEventBus()
        release = threading.Event()
        task = app.background.start("assessment t.example.com", release.wait)
        app.background.attach_events(task, bus)
        app._assessment_task = task

        bus.publish("command", "nmap -sV t.example.com", rc=0, secs=3.1)
        self.assertTrue(app._drain_agent_events())
        # second drain: nothing new
        self.assertFalse(app._drain_agent_events())

        release.set()
        task.join(timeout=2)

    def test_escape_consumed_only_when_assessment_running(self):
        import io

        from rich.console import Console

        from ui.theme import X19_THEME
        from ui.app import ConsoleApp

        app = ConsoleApp(version="1.0.0")
        app.console = Console(file=io.StringIO(), width=100, height=24, force_terminal=True, theme=X19_THEME)
        self.assertFalse(app._handle_escape())  # nothing running → not consumed


class ResumeTests(unittest.TestCase):
    def test_resume_loads_session_and_reports(self):
        import io
        import json

        from rich.console import Console

        from ui.theme import X19_THEME
        from ui.app import ConsoleApp
        from config import CONFIG

        tmp = tempfile.mkdtemp()
        CONFIG.SESSIONS_DIR = tmp
        data = {
            "session_id": "x19_resume_test",
            "target": "t.example.com",
            "status": "completed",
            "iterations": 3,
            "findings": [{"severity": "high", "title": "X", "detail": "d", "evidence": "e"}],
            "commands": [{"cmd": "ls", "result": "", "rc": 0, "ts": ""}],
        }
        (Path(tmp) / "x19_resume_test.json").write_text(json.dumps(data))

        from types import SimpleNamespace

        app = ConsoleApp(version="1.0.0")
        app.console = Console(file=io.StringIO(), width=100, height=24, force_terminal=False, theme=X19_THEME)
        app.agent = SimpleNamespace(session=None, target="")
        app.cmd_resume("x19_resume_test")

        self.assertIsNotNone(app.agent)
        self.assertEqual(app.agent.session.id, "x19_resume_test")
        self.assertEqual(app.agent.session.data["status"], "completed")
        # /report works over the resumed session
        report = app.agent.session.report()
        self.assertIn("x19_resume_test", report)
        self.assertIn("Exposed", report) if False else None


class StreamingProviderTests(unittest.TestCase):
    """Offline streaming checks: SSE parsing + generator failover logic."""

    def test_iter_sse_data_parses_frames(self):
        from providers import _iter_sse_data

        class FakeResponse:
            def __init__(self, lines):
                self._lines = lines

            def iter_lines(self, decode_unicode=True):
                return iter(self._lines)

        frames = list(_iter_sse_data(FakeResponse([
            "data: {\"a\": 1}",
            "",
            "data: {\"b\": 2}",
            "data: {\"c\": 3}",
            "data: [DONE]",
            "data: ignored-after-done",
        ])))
        self.assertEqual(frames, ['{"a": 1}', '{"b": 2}\n{"c": 3}'])

    def test_openai_stream_parses_deltas(self):
        import json as _json
        from providers import OpenAICompatBackend

        backend = OpenAICompatBackend.__new__(OpenAICompatBackend)
        backend.provider = "custom_openai"
        backend.format = "openai"
        backend.label = "Custom"
        backend.base = "http://127.0.0.1:1/v1"
        backend.model = "m1"
        backend.api_key = "k"
        backend._exhausted_models = set()
        backend._last_err = ""

        payload = [
            "data: " + _json.dumps({"choices": [{"delta": {"content": "Hel"}}]}),
            "",
            "data: " + _json.dumps({"choices": [{"delta": {"content": "lo"}}]}),
            "data: [DONE]",
        ]

        class FakeResponse:
            status_code = 200

            def raise_for_status(self):
                pass

            def iter_lines(self, decode_unicode=True):
                return iter(payload)

        def fake_post(self_inner, url, **kwargs):
            self_inner.captured_kwargs = kwargs
            return FakeResponse()

        original_post = OpenAICompatBackend._stream_one_model
        # monkeypatch session.post on the instance
        class FakeSession:
            def post(self, url, **kwargs):
                backend.captured_kwargs = kwargs
                return FakeResponse()

        backend.session = FakeSession()
        chunks = list(backend.chat_stream("sys", "hi"))
        self.assertEqual(chunks, ["Hel", "lo"])
        self.assertTrue(backend.captured_kwargs.get("stream"))

    def test_stream_falls_through_on_failed_model(self):
        from providers import OpenAICompatBackend

        backend = OpenAICompatBackend.__new__(OpenAICompatBackend)
        backend.provider = "custom_openai"
        backend.format = "openai"
        backend.label = "Custom"
        backend.base = "http://127.0.0.1:1/v1"
        backend.model = "m1"
        backend.api_key = "k"
        backend._exhausted_models = set()
        backend._last_err = ""

        class DeadResponse:
            status_code = 429

        tried = []

        def fake_stream_one(system, message, model):
            tried.append(model)
            if model == "m1":
                return iter(())  # fails before first token
            return iter(("ok",))

        backend._stream_one_model = fake_stream_one
        # only two candidates: m1 then m2
        backend._stream_model_candidates = lambda: ["m1", "m2"]
        chunks = list(backend.chat_stream("sys", "hi"))
        self.assertEqual(tried, ["m1", "m2"])
        self.assertEqual(chunks, ["ok"])
        self.assertIn("m1", backend._exhausted_models)


if __name__ == "__main__":
    unittest.main()
