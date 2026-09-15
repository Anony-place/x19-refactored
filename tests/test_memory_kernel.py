import tempfile
import unittest
from pathlib import Path

from execution.memory_kernel import MemoryKernel


class MemoryKernelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.kernel = MemoryKernel(Path(self.tmp.name) / "memory.db")

    def tearDown(self):
        self.kernel.close()
        self.tmp.cleanup()

    def test_fact_upsert_is_authoritative(self):
        self.kernel.upsert("lab.local", "fact", "api", {"host": "api.lab.local"})
        self.kernel.upsert("lab.local", "fact", "api", {"host": "api.lab.local", "ports": [443]})
        facts = self.kernel.list("lab.local", "fact")
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0]["value"]["ports"], [443])

    def test_hypothesis_evidence_and_dead_end(self):
        self.kernel.record_hypothesis(
            "lab.local", "H-1", "IDOR on /api/users/{id}",
            state="testing", confidence=0.7, basis=["numeric object ids"],
            next_test="compare two authorized identities",
        )
        evidence_id = self.kernel.record_evidence(
            "lab.local", "E-1", observation="Account B object returned to account A",
            source="http-test", hypothesis_id="H-1", strength="verified",
        )
        self.kernel.record_dead_end("lab.local", "D-1", "same response across five probes", evidence_id=evidence_id)
        snap = self.kernel.snapshot("lab.local")
        self.assertEqual(snap.hypotheses[0]["value"]["state"], "testing")
        self.assertEqual(snap.evidence[0]["value"]["hypothesis_id"], "H-1")
        self.assertEqual(snap.dead_ends[0]["status"], "closed")

    def test_target_isolation(self):
        self.kernel.upsert("a.local", "fact", "service", {"name": "nginx"})
        self.kernel.upsert("b.local", "fact", "service", {"name": "apache"})
        self.assertEqual(self.kernel.list("a.local", "fact")[0]["value"]["name"], "nginx")
        self.assertEqual(self.kernel.list("b.local", "fact")[0]["value"]["name"], "apache")

    def test_snapshot_is_bounded(self):
        for i in range(10):
            self.kernel.upsert("lab.local", "fact", f"f-{i}", {"i": i})
        snap = self.kernel.snapshot("lab.local", limits={"fact": 3})
        self.assertEqual(len(snap.facts), 3)
        self.assertLessEqual(len(snap.to_prompt(300)), 300)


if __name__ == "__main__":
    unittest.main()
