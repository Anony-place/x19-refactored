"""Dynamic knowledge layer: live intel sources, TTL cache, custom corpus.

All network is mocked — the tests verify parsing, cache/TTL behaviour,
correlation with the world-model tech stack, bounded rendering, custom
corpus ingestion and, critically, that no source failure ever propagates.
"""

from __future__ import annotations

import json
import os
import time
import unittest
from pathlib import Path
from unittest import mock

import knowledge
from knowledge import (
    CHAR_CAP,
    IntelItem,
    KnowledgeLayer,
    _cache_read,
    _cache_write,
    _chunks,
)


def _fake_response(payload):
    class R:
        def raise_for_status(self):
            return None

        def json(self):
            return payload

    return R()


KEV_PAYLOAD = {
    "vulnerabilities": [
        {"cveID": "CVE-2021-41773", "vendorProject": "Apache",
         "product": "HTTP Server", "vulnerabilityName": "Apache path traversal RCE",
         "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2023-99999", "vendorProject": "SomeCorp",
         "product": "Widget", "vulnerabilityName": "Widget auth bypass",
         "knownRansomwareCampaignUse": "Unknown"},
    ]
}

NVD_PAYLOAD = {
    "vulnerabilities": [
        {"cve": {
            "id": "CVE-2021-41773",
            "descriptions": [{"lang": "en",
                              "value": "A flaw exists in Apache HTTP Server 2.4.49 path handling"}],
            "metrics": {"cvssMetricV31": [
                {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
            "references": [{"url": "https://example.com/x", "tags": ["Exploit", "Vendor Advisory"]}],
            "published": "2021-10-05T00:00:00Z",
        }},
        {"cve": {
            "id": "CVE-2018-13000",
            "descriptions": [{"lang": "en", "value": "Low severity docs issue"}],
            "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 4.3,
                                                       "baseSeverity": "MEDIUM"}}]},
            "references": [],
            "published": "2018-06-01T00:00:00Z",
        }},
    ]
}


class TempCacheTest(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        cache = Path(self._tmp.name) / "cache"
        cache.mkdir()
        self._patch_cache = mock.patch.multiple(
            knowledge, CACHE_DIR=cache)
        self._patch_cache.start()
        # fresh env per test: layer caches are per-instance anyway
        self.layer = KnowledgeLayer(memory=None)

    def tearDown(self):
        self._patch_cache.stop()
        self._tmp.cleanup()


class KevSourceTests(TempCacheTest):
    def test_fetch_parse_and_cache(self):
        with mock.patch.object(knowledge.requests, "get",
                               return_value=_fake_response(KEV_PAYLOAD)) as mg:
            entries = self.layer.kev_entries()
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["cve"], "CVE-2021-41773")
        self.assertTrue(entries[0]["ransomware"])
        mg.assert_called_once()
        # second call serves from disk cache — no second HTTP
        with mock.patch.object(knowledge.requests, "get") as mg2:
            self.layer.kev_entries()
        mg2.assert_not_called()

    def test_ttl_expiry_refetches(self):
        with mock.patch.object(knowledge.requests, "get",
                               return_value=_fake_response(KEV_PAYLOAD)):
            self.layer.kev_entries()
        # age the cache beyond TTL
        name = knowledge.CACHE_DIR / "kev.json"
        blob = json.loads(name.read_text())
        blob["fetched_at"] = time.time() - knowledge.KEV_TTL - 10
        name.write_text(json.dumps(blob))
        with mock.patch.object(knowledge.requests, "get",
                               return_value=_fake_response(KEV_PAYLOAD)) as mg:
            self.layer.kev_entries()
        mg.assert_called_once()

    def test_network_failure_falls_back_to_stale_cache(self):
        with mock.patch.object(knowledge.requests, "get",
                               return_value=_fake_response(KEV_PAYLOAD)):
            self.layer.kev_entries()
        name = knowledge.CACHE_DIR / "kev.json"
        blob = json.loads(name.read_text())
        blob["fetched_at"] = time.time() - knowledge.KEV_TTL - 10
        name.write_text(json.dumps(blob))
        with mock.patch.object(knowledge.requests, "get",
                               side_effect=RuntimeError("network down")):
            entries = self.layer.kev_entries()
        self.assertEqual(len(entries), 2, "stale cache must survive outages")

    def test_total_failure_returns_empty_not_raise(self):
        with mock.patch.object(knowledge.requests, "get",
                               side_effect=RuntimeError("no network")):
            self.assertEqual(self.layer.kev_entries(), [])


class NvdSourceTests(TempCacheTest):
    def test_parse_scores_and_poc_flag(self):
        with mock.patch.object(knowledge.requests, "get",
                               return_value=_fake_response(NVD_PAYLOAD)):
            items = self.layer.nvd_lookup("apache")
        self.assertEqual(items[0]["cve"], "CVE-2021-41773")
        self.assertAlmostEqual(items[0]["cvss"], 9.8)
        self.assertTrue(items[0]["public_exploit"])
        # low-severity, no-PoC entry still parsed (filtering happens later)
        self.assertTrue(any(i["cve"] == "CVE-2018-13000" for i in items))

    def test_failure_returns_empty_not_raise(self):
        with mock.patch.object(knowledge.requests, "get",
                               side_effect=RuntimeError("429")):
            self.assertEqual(self.layer.nvd_lookup("nginx"), [])


class ProductIntelTests(TempCacheTest):
    def test_kev_match_and_version_matched_nvd(self):
        with mock.patch.object(knowledge.requests, "get",
                               side_effect=lambda url, **kw: (
                                   _fake_response(KEV_PAYLOAD) if "cisa.gov" in url
                                   else _fake_response(NVD_PAYLOAD))):
            items = self.layer.product_intel({"Apache": "2.4.49"})
        self.assertTrue(any(i.known_exploited for i in items))
        apache_nvd = [i for i in items if i.source == "nvd"]
        self.assertTrue(any(i.version_matched for i in apache_nvd),
                        "2.4.49 appears in the description — must be version-matched")
        self.assertTrue(all(i.cvss >= 7.0 or i.version_matched or i.public_exploit
                            for i in apache_nvd))

    def test_sorted_by_exploitation_signal(self):
        with mock.patch.object(knowledge.requests, "get",
                               side_effect=lambda url, **kw: (
                                   _fake_response(KEV_PAYLOAD) if "cisa.gov" in url
                                   else _fake_response(NVD_PAYLOAD))):
            items = self.layer.product_intel({"Apache": "2.4.49"})
        rendered = [i.known_exploited for i in items]
        if rendered and rendered[0] is False:
            self.fail("KEV (actively exploited) items must sort first")
        self.assertEqual([i.known_exploited for i in items],
                         sorted([i.known_exploited for i in items], reverse=True))

    def test_empty_stack_no_calls(self):
        with mock.patch.object(knowledge.requests, "get") as mg:
            self.assertEqual(self.layer.product_intel({}), [])
        mg.assert_not_called()

    def test_disable_switch(self):
        os.environ["X19_INTEL_DISABLE"] = "1"
        try:
            with mock.patch.object(knowledge.requests, "get") as mg:
                self.assertEqual(self.layer.kev_entries(), [])
                self.assertEqual(
                    self.layer.product_intel({"Apache": "2.4.49"}), [])
            mg.assert_not_called()
        finally:
            os.environ.pop("X19_INTEL_DISABLE", None)


class RenderTests(TempCacheTest):
    def _prime(self):
        with mock.patch.object(knowledge.requests, "get",
                               side_effect=lambda url, **kw: (
                                   _fake_response(KEV_PAYLOAD) if "cisa.gov" in url
                                   else _fake_response(NVD_PAYLOAD))):
            return self.layer.render_context({"Apache": "2.4.49"})

    def test_block_shape_and_focus_line(self):
        block = self._prime()
        self.assertIn("LIVE INTEL", block)
        self.assertIn("KEV: actively exploited", block)
        self.assertIn("FOCUS:", block)
        self.assertIn("verify version applies", block)

    def test_bounded(self):
        self.assertLessEqual(len(self._prime()), CHAR_CAP)

    def test_no_match_renders_nothing(self):
        with mock.patch.object(knowledge.requests, "get",
                               side_effect=lambda url, **kw: (
                                   _fake_response({"vulnerabilities": []})
                                   if "cisa.gov" in url
                                   else _fake_response({"vulnerabilities": []}))):
            self.assertEqual(self.layer.render_context({"ObscureWare": "9.9"}), "")

    def test_source_failure_renders_empty_gracefully(self):
        with mock.patch.object(knowledge.requests, "get",
                               side_effect=RuntimeError("offline, no cache")):
            self.assertEqual(self.layer.render_context({"Apache": "2.4.49"}), "")


class CorpusTests(TempCacheTest):
    def _layer_with_fake_memory(self):
        class FakeMemory:
            def __init__(self):
                self.added = []
                self.ready = True

            def add(self, collection, text, metadata=None, doc_id=None):
                self.added.append((collection, doc_id, text))
                return True

            def query(self, collection, q, n=5):
                return [{"text": f"rec: {q}"}]

        return FakeMemory()

    def setUp(self):
        super().setUp()
        import tempfile
        self._ktmp = tempfile.TemporaryDirectory()
        self._patch_kdir = mock.patch.object(knowledge, "KNOWLEDGE_DIR", Path(self._ktmp.name))
        self._patch_kdir.start()
        state = Path(knowledge.CACHE_DIR) / "corpus_state.json"
        self._state = state

    def tearDown(self):
        self._patch_kdir.stop()
        self._ktmp.cleanup()
        super().tearDown()

    def test_ingest_chunks_and_dedupes(self):
        mem = self._layer_with_fake_memory()
        layer = KnowledgeLayer(memory=mem)
        (knowledge.KNOWLEDGE_DIR / "notes.md").write_text(
            "# Playbook\n\nCheck /actuator/env first.\n\nThen try Spring errors.\n\n" + "filler " * 300)
        added = layer.ingest_custom()
        self.assertGreater(added, 0)
        self.assertTrue(all(c == "intel" for c, _, _ in mem.added))
        # second ingest: nothing new
        self.assertEqual(layer.ingest_custom(), 0)

    def test_reingests_after_file_change(self):
        mem = self._layer_with_fake_memory()
        layer = KnowledgeLayer(memory=mem)
        f = knowledge.KNOWLEDGE_DIR / "notes.md"
        f.write_text("v1 content")
        layer.ingest_custom()
        f.write_text("v2 totally different content")
        self.assertGreater(layer.ingest_custom(), 0)

    def test_recall_uses_memory(self):
        mem = self._layer_with_fake_memory()
        layer = KnowledgeLayer(memory=mem)
        out = layer.recall("spring boot actuator")
        self.assertEqual(out, ["rec: spring boot actuator"])

    def test_unavailable_memory_returns_zero_and_empty(self):
        layer = KnowledgeLayer(memory=None)
        # knowledge.py imports memory lazily; force the import path to fail
        import builtins
        real_import = builtins.__import__

        def boom(name, *a, **kw):
            if name == "memory":
                raise RuntimeError("chromadb missing")
            return real_import(name, *a, **kw)

        with mock.patch("builtins.__import__", side_effect=boom):
            self.assertEqual(layer.ingest_custom(), 0)
            self.assertEqual(layer.recall("anything"), [])



class IntelItemUnitTests(unittest.TestCase):
    def test_sort_key_prefers_kev_version_matched(self):
        kev = IntelItem(product="x", known_exploited=True)
        plain = IntelItem(product="x", cvss=9.8)
        self.assertLess(kev.sort_key(), plain.sort_key())

    def test_render_flags_and_cap(self):
        it = IntelItem(product="Apache", cve="CVE-2021-41773",
                       title="path traversal", known_exploited=True,
                       ransomware=True, epss=0.9, cvss=9.8,
                       detail="d" * 500)
        text = it.render()
        self.assertIn("KEV", text)
        self.assertIn("ransomware", text)
        self.assertIn("EPSS 0.90", text)
        self.assertLessEqual(len(text), 230 + 1)

    def test_chunks_paragraph_aware(self):
        text = "\n\n".join(f"para {i} " + "w" * 80 for i in range(30))
        chunks = _chunks(text, size=400, overlap=50)
        self.assertGreater(len(chunks), 1)
        self.assertTrue(all(len(c) <= 400 + 1 for c in chunks))


if __name__ == "__main__":
    unittest.main()
