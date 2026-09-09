import json
import tempfile
import time
import unittest
from pathlib import Path

from runtime.hermes_runtime import CronStore, SessionRecall, SkillStore


class HermesRuntimeTests(unittest.TestCase):
    def test_skill_lifecycle_and_promotion(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = SkillStore(tmp)
            skill = store.create("api-auth", "API auth workflow", "# API auth\n\nCheck auth boundaries.")
            self.assertEqual(store.get("api-auth").name, "api-auth")
            store.record_use(skill.name, True)
            promoted = store.promote_outcome(
                name="api-auth",
                target_type="authorized",
                summary="Auth boundary checks produced a confirmed finding.",
                successful_steps=["map authenticated routes", "compare role boundaries"],
            )
            self.assertEqual(promoted.successes, 1)
            self.assertIn("compare role boundaries", store.get("api-auth").body)

    def test_session_recall_indexes_and_searches(self):
        with tempfile.TemporaryDirectory() as tmp:
            sessions = Path(tmp) / "sessions"
            sessions.mkdir()
            session = {
                "session_id": "s1",
                "target": "lab.example",
                "started": "2026-09-09T12:00:00Z",
                "status": "completed",
                "findings": [{"title": "CORS misconfiguration", "severity": "high"}],
            }
            (sessions / "s1.json").write_text(json.dumps(session), encoding="utf-8")

            from config import CONFIG
            old = CONFIG.SESSIONS_DIR
            CONFIG.SESSIONS_DIR = str(sessions)
            try:
                recall = SessionRecall(str(Path(tmp) / "index.db"))
                rows = recall.search("CORS")
                self.assertEqual(rows[0]["session_id"], "s1")
                self.assertEqual(recall.read("s1")["target"], "lab.example")
            finally:
                CONFIG.SESSIONS_DIR = old

    def test_cron_store_never_accepts_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = CronStore(str(Path(tmp) / "jobs.json"))
            job = store.add(["doctor"], 60)
            self.assertEqual(job.command, ["doctor"])
            with self.assertRaises(ValueError):
                store.add(["run", "--shell", "id"], 60)
            self.assertTrue(store.pause(job.id))
            self.assertFalse(store.list()[0].enabled)
            self.assertTrue(store.resume(job.id))


if __name__ == "__main__":
    unittest.main()
