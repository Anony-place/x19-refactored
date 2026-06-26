import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mission import TaskGraph
from tools import ToolExecutor
from utils import validate_target


class TargetValidationTests(unittest.TestCase):
    def test_empty_target_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_target("")

    def test_placeholder_target_is_rejected_when_noninteractive(self):
        with mock.patch("sys.stdin.isatty", return_value=False):
            with self.assertRaises(ValueError):
                validate_target("127.0.0.1")

    def test_explicit_non_placeholder_target_is_returned(self):
        self.assertEqual(validate_target("example.com"), "example.com")


class ToolExecutorBaselineTests(unittest.TestCase):
    def test_destructive_command_is_blocked_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            executor = ToolExecutor(tmp)
            result = executor.run("rm -rf /", timeout=1)

        self.assertEqual(result.returncode, -1)
        self.assertEqual(result.error, "blocked")
        self.assertIn("Blocked", result.stderr)

    def test_safe_command_executes_in_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            executor = ToolExecutor(tmp)
            result = executor.run("echo x19-baseline", timeout=5)

        self.assertEqual(result.returncode, 0)
        self.assertIn("x19-baseline", result.stdout)

    def test_tool_template_resolution_injects_legacy_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            executor = ToolExecutor(tmp)
            command, description, timeout = executor.resolve_tool("msfconsole", "10.0.0.1")

        self.assertIn("msfconsole", command)
        self.assertIn("10.0.0.1", command)
        self.assertIn("exploit/multi/handler", command)
        self.assertIn("127.0.0.1", command)
        self.assertEqual(timeout, 300)
        self.assertIn("Metasploit", description)


class MissionGraphBaselineTests(unittest.TestCase):
    def test_task_graph_dedupes_and_persists_tasks(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            graph = TaskGraph(base)
            task = {
                "goal": "fingerprint web",
                "category": "web",
                "command": "curl -I http://example.com",
                "mode": "recon",
            }

            self.assertEqual(graph.add_tasks([task, task]), 1)
            self.assertTrue(graph.has_open_work())

            selected = graph.next_task()
            self.assertIsNotNone(selected)
            self.assertEqual(selected.goal, "fingerprint web")

            graph.mark(selected.key, "done", evidence="HTTP/1.1 200 OK", reason="baseline")
            self.assertFalse(graph.has_open_work())

            reloaded = TaskGraph(base)
            self.assertFalse(reloaded.has_open_work())


if __name__ == "__main__":
    unittest.main()
