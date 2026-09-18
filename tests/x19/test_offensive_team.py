"""Tests for X19 offensive team — payloads, methodology, autonomous team."""

import sys
sys.path.insert(0, '.')

from x19.offensive import PayloadGenerator, OffensiveMethodology
from x19.autonomous import AutonomousOffensiveTeam, AutonomousTeamConfig


def test_payload_generator_witness():
    """Payload generator must provide witness payloads, minimal proof, not destructive."""
    pg = PayloadGenerator()

    xss_witness = pg.get_witness_payloads("xss")
    assert len(xss_witness) > 0
    assert "<script>alert(1)</script>" in xss_witness or "<img src=x onerror=alert(1)>" in xss_witness

    sqli_witness = pg.get_witness_payloads("sqli")
    assert len(sqli_witness) > 0
    assert "'" in sqli_witness

    ssrf_witness = pg.get_witness_payloads("ssrf")
    assert len(ssrf_witness) > 0
    assert "http://127.0.0.1" in ssrf_witness


def test_payload_generator_bypass():
    """Payload generator must provide bypass payloads."""
    pg = PayloadGenerator()

    xss_bypass = pg.get_bypass_payloads("xss")
    assert len(xss_bypass) > 0

    sqli_bypass = pg.get_bypass_payloads("sqli")
    assert len(sqli_bypass) > 0


def test_payload_generator_context():
    """Payload generator must provide context-aware payloads."""
    pg = PayloadGenerator()

    html_payloads = pg.get_context_payloads("xss", "html")
    assert len(html_payloads) > 0

    attr_payloads = pg.get_context_payloads("xss", "attribute")
    assert len(attr_payloads) > 0

    js_payloads = pg.get_context_payloads("xss", "javascript")
    assert len(js_payloads) > 0


def test_payload_encoding():
    """Payload encoding for bypass: url, html, etc."""
    pg = PayloadGenerator()

    payload = "<script>alert(1)</script>"
    url_encoded = pg.encode_payload(payload, "url")
    assert url_encoded != payload
    assert "%3Cscript%3E" in url_encoded

    html_encoded = pg.encode_payload(payload, "html")
    assert html_encoded != payload
    assert "&lt;script&gt;" in html_encoded


def test_payloads_for_endpoint():
    """Generate payloads for specific endpoint and param."""
    pg = PayloadGenerator()

    payloads = pg.generate_payloads_for_endpoint("xss", "/search", "q", "html")
    assert len(payloads) > 0
    assert len(payloads) >= 3  # At least witness + bypass + encoded

    for p in payloads:
        assert "payload" in p
        assert "type" in p
        assert "endpoint" in p
        assert "param" in p
        assert "safety" in p
        assert "evidence_required" in p
        assert p["endpoint"] == "/search"
        assert p["param"] == "q"


def test_offensive_methodology_hypothesis_generation():
    """Offensive methodology must generate hypotheses from recon observations."""
    off = OffensiveMethodology()

    discoveries = {
        "endpoints": ["/search?q=test", "/api/users/123", "/api/fetch?url=https://example.com", "/redirect?url=https://example.com"],
        "tech": ["nginx", "react"],
        "subdomains": ["api.target.com"],
        "auth": ["jwt"],
    }

    hypotheses = off.generate_hypotheses_from_recon(discoveries)
    assert len(hypotheses) > 0

    # Should generate XSS for /search, BOLA for /api/users, SSRF for /api/fetch, open redirect for /redirect
    vuln_classes = [h.vuln_class for h in hypotheses]
    assert "xss" in vuln_classes
    assert "bola" in vuln_classes or "idor" in vuln_classes
    assert "ssrf" in vuln_classes

    for h in hypotheses:
        assert h.id
        assert h.vuln_class
        assert h.endpoint
        assert h.rationale
        assert h.observation
        assert h.test_method
        assert h.expected_evidence


def test_attack_surface_modeling():
    """Attack surface modeling from discoveries."""
    off = OffensiveMethodology()

    discoveries = {
        "endpoints": ["/api/users", "/search?q=test"],
        "tech": ["nginx", "react"],
        "subdomains": ["api.target.com"],
        "auth": ["jwt", "login"],
    }

    model = off.build_attack_surface_model(discoveries)
    assert "inputs" in model
    assert "sinks" in model
    assert "trust_boundaries" in model
    assert "auth_flows" in model
    assert "endpoints" in model
    assert "model_summary" in model
    assert len(model["inputs"]) > 0
    assert len(model["endpoints"]) == 2


def test_prioritize_hypotheses():
    """Prioritize hypotheses by severity."""
    off = OffensiveMethodology()

    from x19.offensive.methodology import Hypothesis

    h1 = Hypothesis(id="H-1", vuln_class="xss", endpoint="/search", severity="medium", confidence="low", rationale="Test", observation="Test", test_method="Test", expected_evidence="Test")
    h2 = Hypothesis(id="H-2", vuln_class="sqli", endpoint="/api/users", severity="critical", confidence="low", rationale="Test", observation="Test", test_method="Test", expected_evidence="Test")
    h3 = Hypothesis(id="H-3", vuln_class="open_redirect", endpoint="/redirect", severity="low", confidence="low", rationale="Test", observation="Test", test_method="Test", expected_evidence="Test")

    prioritized = off.prioritize_hypotheses([h1, h2, h3])
    assert prioritized[0].severity == "critical"
    assert prioritized[0].vuln_class == "sqli"


def test_autonomous_team_status():
    """Autonomous offensive team status — like overall offensive team."""
    team = AutonomousOffensiveTeam(storage_dir="/tmp/x19_test_autonomous_status")

    status = team.get_team_status()
    assert status["team"] == "X19 Autonomous Offensive Team"
    assert "hierarchy" in status
    assert "boss" in status
    assert "managers" in status
    assert "specialists" in status
    assert "knowledge" in status
    assert "datasets" in status
    assert "offensive_capabilities" in status
    assert "autonomous_loop" in status
    assert "controls" in status

    # Check managers
    assert "recon_manager" in status["managers"]
    assert "web_manager" in status["managers"]
    assert "api_manager" in status["managers"]

    # Check specialists (9)
    assert len(status["specialists"]) == 9
    assert "web_security" in status["specialists"]
    assert "api_security" in status["specialists"]
    assert "auth" in status["specialists"]


def test_autonomous_mission_creation():
    """Autonomous mission creation with explicit scope."""
    import tempfile
    import shutil

    tmpdir = tempfile.mkdtemp()
    try:
        team = AutonomousOffensiveTeam(storage_dir=tmpdir)

        config = AutonomousTeamConfig(
            target="https://target.com",
            authorized_domains=["target.com", "*.target.com"],
            excluded_assets=["/admin"],
            program_name="Test Program",
            objectives=["Assess target.com for OWASP Top 10"],
        )

        mission, msg = team.create_autonomous_mission(config)
        assert mission is not None
        assert mission.scope.target == "https://target.com"
        assert "target.com" in mission.scope.authorized_domains
        assert "/admin" in mission.scope.excluded_assets
        assert mission.id in msg
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_autonomous_recon():
    """Autonomous recon using methodology from knowledge base."""
    import tempfile
    import shutil

    tmpdir = tempfile.mkdtemp()
    try:
        team = AutonomousOffensiveTeam(storage_dir=tmpdir)

        config = AutonomousTeamConfig(
            target="https://target.com",
            authorized_domains=["target.com"],
        )

        mission, _ = team.create_autonomous_mission(config)

        discoveries = {
            "subdomains": ["api.target.com", "admin.target.com"],
            "endpoints": ["/api/users", "/search"],
            "tech": ["nginx"],
        }

        result = team.autonomous_recon(mission, discoveries)
        assert result["status"] == "completed"
        assert "api.target.com" in mission.discoveries["subdomains"]
        assert "/api/users" in mission.discoveries["endpoints"]
        assert "attack_surface" in result
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_autonomous_full_mission():
    """Fully autonomous mission: SCOPE→PLAN→RECON→...→REPORT→LEARN→REASSESS."""
    import tempfile
    import shutil

    tmpdir = tempfile.mkdtemp()
    try:
        team = AutonomousOffensiveTeam(storage_dir=tmpdir)

        config = AutonomousTeamConfig(
            target="https://target.com",
            authorized_domains=["target.com", "*.target.com"],
            excluded_assets=["/admin"],
            program_name="Test Program",
            max_iterations=1,
            auto_report=True,
        )

        results = team.run_autonomous_mission(
            config,
            initial_discoveries={
                "subdomains": ["api.target.com"],
                "endpoints": ["/api/users/123", "/search?q=test", "/api/fetch?url=https://example.com"],
                "tech": ["nginx", "react"],
            },
        )

        assert results["status"] == "completed"
        assert "mission_id" in results
        assert "phases" in results
        assert "scope" in results["phases"]
        assert "plan" in results["phases"]
        assert "recon" in results["phases"]
        assert "hypothesis" in results["phases"]
        assert "test" in results["phases"]
        assert "verify" in results["phases"]
        assert "report" in results["phases"]
        assert "learn" in results["phases"]
        assert "reassess" in results["phases"]
        assert "final_status" in results

        # Should have generated hypotheses
        assert results["phases"]["hypothesis"]["count"] > 0

        # Should have findings
        assert results["final_status"]["findings"]["total"] > 0
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
