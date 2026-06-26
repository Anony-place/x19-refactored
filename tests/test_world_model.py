import unittest

from brain.world_model import (
    WorldModel,
    WorldModelSnapshot,
    HostRecord,
    ServiceRecord,
    EndpointRecord,
    VulnerabilityRecord,
    EvidenceRecord,
    Observation,
)


class WorldModelTests(unittest.TestCase):
    def test_empty_world_model_has_zero_counts(self):
        wm = WorldModel(target="example.com")
        snap = wm.snapshot()
        self.assertEqual(snap.hosts, 0)
        self.assertEqual(snap.services, 0)
        self.assertEqual(snap.endpoints, 0)
        self.assertEqual(snap.vulnerabilities, 0)

    def test_ensure_host_creates_record(self):
        wm = WorldModel(target="example.com")
        host = wm.ensure_host("example.com")
        self.assertEqual(host.hostname, "example.com")
        self.assertIn("example.com", wm.hosts)

    def test_ensure_host_returns_same_record_on_duplicate(self):
        wm = WorldModel(target="example.com")
        h1 = wm.ensure_host("example.com")
        h2 = wm.ensure_host("example.com")
        self.assertIs(h1, h2)

    def test_ingest_observation_appends(self):
        wm = WorldModel(target="example.com")
        obs = Observation(kind="port_scan", source="nmap", data={"ports": [22, 80]})
        wm.ingest(obs)
        self.assertEqual(len(wm.observations), 1)
        self.assertEqual(wm.observations[0].kind, "port_scan")

    def test_snapshot_counts_match_ingested_data(self):
        wm = WorldModel(target="10.0.0.1")
        host = wm.ensure_host("10.0.0.1")
        host.services["80/tcp"] = ServiceRecord(port=80, proto="tcp", service="http")
        host.endpoints["GET http://10.0.0.1"] = EndpointRecord(url="http://10.0.0.1", status=200)
        host.vulnerabilities.append(
            VulnerabilityRecord(title="SQLi", severity="high")
        )
        snap = wm.snapshot()
        self.assertEqual(snap.hosts, 1)
        self.assertEqual(snap.services, 1)
        self.assertEqual(snap.endpoints, 1)
        self.assertEqual(snap.vulnerabilities, 1)

    def test_from_legacy_converts_target_model(self):
        class FakeModel:
            hostname = "legacy.local"
            ip_addresses = ["10.0.0.1", "10.0.0.2"]
            ports = [{"port": 80, "proto": "tcp", "service": "http", "version": "nginx", "state": "open"}]
            tech_stack = {"nginx": "1.18"}
            endpoints = [{"url": "http://legacy.local", "method": "GET", "status": 200}]
            findings = []

        wm = WorldModel.from_legacy(FakeModel())
        self.assertEqual(wm.target, "legacy.local")
        self.assertEqual(len(wm.hosts), 1)
        host = list(wm.hosts.values())[0]
        self.assertIn("80/tcp", host.services)
        self.assertEqual(host.services["80/tcp"].service, "http")
        self.assertEqual(host.technologies.get("nginx"), "1.18")

    def test_snapshot_string_summary(self):
        wm = WorldModel(target="example.com")
        self.assertIn("target=example.com", wm.snapshot().summary())

    def test_evidence_chain_through_vulnerabilities(self):
        wm = WorldModel(target="example.com")
        host = wm.ensure_host("example.com")
        host.vulnerabilities.append(
            VulnerabilityRecord(
                title="XSS",
                severity="medium",
                evidence=[
                    EvidenceRecord(source="nuclei", summary="Reflected XSS found", confidence=0.8)
                ],
            )
        )
        ev = list(wm.evidence())
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0].source, "nuclei")
        self.assertIn("XSS", ev[0].summary)


class WorldModelSnapshotTests(unittest.TestCase):
    def test_summary_contains_all_counts(self):
        snap = WorldModelSnapshot(
            target="t", hosts=1, services=2, endpoints=3,
            credentials=4, vulnerabilities=5, technologies=6, observations=7,
        )
        text = snap.summary()
        for field in ["hosts=1", "services=2", "endpoints=3", "creds=4", "vulns=5"]:
            self.assertIn(field, text)


if __name__ == "__main__":
    unittest.main()
