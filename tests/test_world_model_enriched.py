import unittest

from brain.world_model import (
    WorldModel,
    HostRecord,
    ServiceRecord,
    VulnerabilityRecord,
    EvidenceRecord,
)


class EnrichedWorldModelTests(unittest.TestCase):
    def test_default_telemetry_fields(self):
        wm = WorldModel(target="example.com")
        self.assertEqual(wm.confidence, 0.0)
        self.assertEqual(wm.provenance, "")
        self.assertEqual(wm.completed_checks, [])
        self.assertEqual(wm.remaining_unknowns, [])
        self.assertEqual(wm.candidate_attack_paths, [])

    def test_mark_check_complete(self):
        wm = WorldModel(target="example.com")
        wm.mark_check_complete("port_scan")
        self.assertIn("port_scan", wm.completed_checks)
        wm.mark_check_complete("port_scan")
        self.assertEqual(len(wm.completed_checks), 1)

    def test_add_unknown(self):
        wm = WorldModel(target="example.com")
        wm.add_unknown("web_framework")
        self.assertIn("web_framework", wm.remaining_unknowns)

    def test_add_attack_path(self):
        wm = WorldModel(target="example.com")
        wm.add_attack_path({"vector": "sqli", "endpoint": "/login"})
        self.assertEqual(len(wm.candidate_attack_paths), 1)
        self.assertEqual(wm.candidate_attack_paths[0]["vector"], "sqli")

    def test_to_dict_includes_telemetry(self):
        wm = WorldModel(target="example.com")
        wm.confidence = 0.75
        wm.provenance = "test"
        wm.mark_check_complete("recon")
        data = wm.to_dict()
        self.assertEqual(data["confidence"], 0.75)
        self.assertEqual(data["provenance"], "test")
        self.assertIn("recon", data["completed_checks"])


if __name__ == "__main__":
    unittest.main()
