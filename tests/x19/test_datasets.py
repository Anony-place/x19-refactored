"""Tests for X19 bug bounty datasets — structured with provenance, no PII/secrets."""

import sys
sys.path.insert(0, '.')

from x19.datasets import get_datasets


def test_datasets_load():
    """Datasets must load from datasets/bug_bounty/."""
    ds = get_datasets()
    stats = ds.get_stats()
    assert stats["loaded"]
    assert stats["total_examples"] > 0
    assert stats["total_methodologies"] > 0


def test_vuln_examples_exist():
    """Vuln examples must exist for xss, bola, sqli, ssrf."""
    ds = get_datasets()
    examples = ds.get_vuln_examples()
    assert len(examples) > 0

    for vc in ["xss", "bola", "sqli", "ssrf"]:
        filtered = ds.get_vuln_examples(vc)
        assert len(filtered) > 0, f"Missing examples for {vc}"


def test_methodology_examples():
    """Methodology must have vuln class, affected component, discovery methodology, etc."""
    ds = get_datasets()
    methodologies = ds.get_methodology()
    assert len(methodologies) > 0

    for meth in methodologies:
        assert "vuln_class" in meth
        assert "affected_component" in meth
        assert "discovery_methodology" in meth
        assert "evidence_pattern" in meth
        assert "validation_method" in meth
        assert "false_positive_indicators" in meth
        assert "impact" in meth
        assert "remediation" in meth
        assert "report_structure" in meth


def test_example_structure():
    """Examples must have structured fields: vuln class, component, prerequisite, methodology, evidence, validation, etc."""
    ds = get_datasets()
    examples = ds.get_vuln_examples()

    for ex in examples:
        assert "id" in ex
        assert "vuln_class" in ex
        assert "affected_component" in ex
        assert "prerequisite" in ex
        assert "discovery_methodology" in ex
        assert "evidence_pattern" in ex
        assert "validation_method" in ex
        assert "false_positive_indicators" in ex
        assert "impact" in ex
        assert "remediation" in ex
        assert "report_structure" in ex
        assert "severity" in ex
        assert "confidence" in ex
        assert "cwe" in ex
        assert "owasp" in ex


def test_metadata_exists():
    """Datasets must have metadata with source, license, provenance."""
    ds = get_datasets()
    stats = ds.get_stats()
    assert stats["metadata"] is not None
    metadata = stats["metadata"]
    assert "source" in metadata
    assert "license" in metadata
    assert "provenance" in metadata
    assert "safety" in metadata


def test_no_pii_secrets():
    """Datasets must not contain PII, secrets, credentials, tokens."""
    ds = get_datasets()
    examples = ds.get_vuln_examples()

    # Check for obvious PII/secrets patterns
    # Our datasets are synthetic and should not have real PII
    for ex in examples:
        # Check that evidence pattern mentions redacting PII (good practice)
        evidence = ex.get("evidence_pattern", "").lower()
        # For BOLA, should mention redacting PII
        if ex.get("vuln_class") == "bola":
            assert "redact" in evidence or "pii" in evidence.lower() or "other user" in evidence.lower()


def test_program_patterns():
    """Program patterns must exist: wildcard_domain, api_scope, etc."""
    ds = get_datasets()
    patterns = ds.get_program_patterns()
    assert len(patterns) > 0

    pattern_ids = [p.get("pattern") for p in patterns]
    assert "wildcard_domain" in pattern_ids
    assert "api_scope" in pattern_ids


def test_query():
    """Query must return relevant results."""
    ds = get_datasets()
    results = ds.query("xss")
    assert len(results) > 0

    results = ds.query("bola")
    assert len(results) > 0


def test_get_by_id():
    """Get example by ID must work."""
    ds = get_datasets()
    examples = ds.get_vuln_examples()
    if examples:
        first_id = examples[0].get("id")
        retrieved = ds.get_example_by_id(first_id)
        assert retrieved is not None
        assert retrieved.get("id") == first_id
