import os
import shutil
import tempfile
import unittest
from pathlib import Path

from x19upgrader import X19Upgrader


class TestX19Upgrader(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.root_dir = Path(self.test_dir) / "main_repo"
        self.sandbox_dir = Path(self.test_dir) / ".x19_sandbox"

        self.root_dir.mkdir(parents=True, exist_ok=True)

        # Create dummy core files
        (self.root_dir / "agent.py").write_text("print('hello agent')\n", encoding="utf-8")
        (self.root_dir / "cli.py").write_text("print('hello cli')\n", encoding="utf-8")
        (self.root_dir / "x19debugger.py").write_text(
            "class X19Debugger:\n"
            "    def __init__(self, source_path=None):\n"
            "        self.source_path = source_path\n"
            "    def scan(self):\n"
            "        return []\n"
            "    def auto_fix(self):\n"
            "        return 0\n"
            "    def save(self):\n"
            "        pass\n",
            encoding="utf-8",
        )

        # Create dummy test directory
        tests_dir = self.root_dir / "tests"
        tests_dir.mkdir(parents=True, exist_ok=True)
        (tests_dir / "__init__.py").write_text("", encoding="utf-8")
        (tests_dir / "test_sample.py").write_text(
            "import unittest\n\n"
            "class TestSample(unittest.TestCase):\n"
            "    def test_pass(self):\n"
            "        self.assertTrue(True)\n",
            encoding="utf-8",
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_clone_to_sandbox(self):
        upgrader = X19Upgrader(root_dir=self.root_dir, sandbox_dir=self.sandbox_dir)
        success = upgrader.clone_to_sandbox()
        self.assertTrue(success)
        self.assertTrue((self.sandbox_dir / "agent.py").exists())
        self.assertTrue((self.sandbox_dir / "tests" / "test_sample.py").exists())

    def test_run_research_plan(self):
        upgrader = X19Upgrader(root_dir=self.root_dir, sandbox_dir=self.sandbox_dir)
        upgrader.clone_to_sandbox()
        audit = upgrader.run_research_plan()
        self.assertTrue(audit["passed"])
        self.assertTrue(audit["syntax_check"])
        self.assertTrue(upgrader.research_plan_completed)

    def test_apply_upgrades_and_test_and_import(self):
        upgrader = X19Upgrader(root_dir=self.root_dir, sandbox_dir=self.sandbox_dir)
        upgrader.clone_to_sandbox()
        upgrader.run_research_plan()

        patch = [
            {
                "file": "agent.py",
                "original": "print('hello agent')",
                "replacement": "print('hello upgraded agent')",
                "description": "Upgrade print string",
            }
        ]

        applied = upgrader.apply_upgrades(custom_patches=patch)
        self.assertTrue(applied)
        self.assertIn("hello upgraded agent", (self.sandbox_dir / "agent.py").read_text(encoding="utf-8"))

        test_res = upgrader.test_sandbox()
        self.assertTrue(test_res["success"])

        imported = upgrader.import_to_main()
        self.assertTrue(imported)
        self.assertIn("hello upgraded agent", (self.root_dir / "agent.py").read_text(encoding="utf-8"))

    def test_import_blocked_if_tests_fail(self):
        upgrader = X19Upgrader(root_dir=self.root_dir, sandbox_dir=self.sandbox_dir)
        upgrader.clone_to_sandbox()
        upgrader.run_research_plan()

        # Write failing test in sandbox
        failing_test = self.sandbox_dir / "tests" / "test_sample.py"
        failing_test.write_text(
            "import unittest\n\n"
            "class TestSample(unittest.TestCase):\n"
            "    def test_fail(self):\n"
            "        self.assertTrue(False)\n",
            encoding="utf-8",
        )

        test_res = upgrader.test_sandbox()
        self.assertFalse(test_res["success"])

        imported = upgrader.import_to_main()
        self.assertFalse(imported)


if __name__ == "__main__":
    unittest.main()
