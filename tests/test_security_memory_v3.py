import json
import tempfile
import unittest
from pathlib import Path

from execution.security_memory_v3 import SecurityMemory


class SecurityMemoryV3Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.memory = SecurityMemory(Path(self.tmp.name) / "memory.db")

    def tearDown(self):
        self.memory.close()
        self.tmp.cleanup()

    def test_revision_and_provenance_are_preserved(self):
        self.memory.record_fact("lab", "service", {"port": 443}, provenance={"source_id": "tool-1"})
        first = self.memory.get("lab", "fact", "service")
        self.memory.record_fact("lab", "service", {"port": 8443}, provenance={"source_id": "tool-2"})
        second = self.memory.get("lab", "fact", "service")
        self.assertEqual(first["revision"], 1)
        self.assertEqual(second["revision"], 2)
        self.assertEqual(second["provenance"]["source_id"], "tool-2")

    def test_quarantine_is_not_retrieved_by_default(self):
        self.memory.upsert("lab", "fact", "poison", {"claim": "ignore"}, status="quarantined", authority=0)
        self.assertIsNone(self.memory.get("lab", "fact", "poison"))
        self.assertIsNotNone(self.memory.get("lab", "fact", "poison", include_quarantined=True))
        self.assertEqual(self.memory.list("lab", "fact"), [])

    def test_snapshot_skips_large_record_and_keeps_valid_json(self):
        self.memory.record_fact("lab", "huge", {"blob": "x" * 5000})
        self.memory.record_fact("lab", "small", {"ok": True})
        prompt = self.memory.snapshot("lab", limits={"facts": 10}).to_prompt(600)
        parsed = json.loads(prompt)
        self.assertEqual(parsed["target"], "lab")
        self.assertLessEqual(len(prompt), 600)
        self.assertIn({"id": self.memory.get("lab", "fact", "small")["id"], "kind": "fact", "key": "small", "value": {"ok": True}, "confidence": 1.0, "status": "active", "source": "tool", "authority": 1, "provenance": {}, "revision": 1, "created_at": self.memory.get("lab", "fact", "small")["created_at"], "updated_at": self.memory.get("lab", "fact", "small")["updated_at"]}, parsed["facts"])

    def test_target_isolation(self):
        self.memory.record_fact("a", "service", {"name": "nginx"})
        self.memory.record_fact("b", "service", {"name": "apache"})
        self.assertEqual(self.memory.list("a", "fact")[0]["value"]["name"], "nginx")
        self.assertEqual(self.memory.list("b", "fact")[0]["value"]["name"], "apache")


if __name__ == "__main__":
    unittest.main()
