import json
import tempfile
import unittest
from pathlib import Path

from execution.security_memory_v2 import SecurityMemory


class SecurityMemoryV2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.memory = SecurityMemory(Path(self.tmp.name) / "memory.db")

    def tearDown(self):
        self.memory.close()
        self.tmp.cleanup()

    def test_evidence_hypothesis_graph(self):
        self.memory.record_fact("lab", "service", {"host": "api.lab", "port": 443})
        hid = self.memory.record_hypothesis("lab", "H-1", "authorization boundary is weak",
                                            confidence=0.7, basis=[])
        eid = self.memory.record_evidence("lab", "E-1", observation="observed distinct object response",
                                          source="http-test", hypothesis_id=hid, strength="verified",
                                          receipt={"request_id": "req-1"})
        edges = self.memory.relations("lab")
        self.assertTrue(any(e["from_id"] == eid and e["to_id"] == hid for e in edges))

    def test_attempt_failure_and_checkpoint(self):
        aid = self.memory.record_attempt("lab", "probe-1", outcome="blocked by state",
                                        status="failed", failure_level="L2")
        self.assertTrue(aid)
        self.memory.record_failure_lesson("lab", "probe-2", level="L2",
                                          reason="same response", lesson="do not repeat unchanged state")
        self.memory.save_checkpoint("lab", {"phase": "recon", "cursor": 7}, "task-7")
        checkpoint = self.memory.checkpoint("lab")
        self.assertEqual(checkpoint["state"]["cursor"], 7)
        self.assertEqual(checkpoint["cursor"], "task-7")

    def test_target_isolation(self):
        self.memory.record_fact("a", "service", {"name": "nginx"})
        self.memory.record_fact("b", "service", {"name": "apache"})
        self.assertEqual(self.memory.list("a", "fact")[0]["value"]["name"], "nginx")
        self.assertEqual(self.memory.list("b", "fact")[0]["value"]["name"], "apache")

    def test_snapshot_prompt_is_valid_json_and_bounded(self):
        for i in range(30):
            self.memory.record_fact("lab", f"f-{i}", {"value": "x" * 100})
        snapshot = self.memory.snapshot("lab", limits={"facts": 30})
        prompt = snapshot.to_prompt(1000)
        json.loads(prompt)
        self.assertLessEqual(len(prompt), 1000)


if __name__ == "__main__":
    unittest.main()
