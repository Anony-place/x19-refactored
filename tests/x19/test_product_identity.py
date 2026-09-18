"""X19 product identity and runtime-truth invariants."""

from pathlib import Path


def test_x19_is_default_identity(monkeypatch):
    monkeypatch.delenv("X19_ENABLED", raising=False)

    from x19.identity import is_x19_enabled, get_x19_identity, get_x19_soul_md

    assert is_x19_enabled({"x19": {}}) is True
    assert get_x19_identity().startswith("You are X19")
    assert "You are X19" in get_x19_soul_md()


def test_explicit_disable_still_works(monkeypatch):
    monkeypatch.setenv("X19_ENABLED", "0")

    from x19.identity import is_x19_enabled

    assert is_x19_enabled() is False


def test_prompt_pipeline_places_x19_identity_before_custom_soul():
    import agent.system_prompt as system_prompt

    class Agent:
        load_soul_identity = True
        skip_context_files = False

    # This is a structural regression check: the implementation must keep
    # X19 identity authoritative while retaining user SOUL customization.
    source = Path(system_prompt.__file__).read_text(encoding="utf-8")
    assert "x19_identity = _get_x19_identity_if_enabled()" in source
    assert "return ([x19_identity, _soul_content], True)" in source


def test_autonomous_runner_contains_no_synthetic_finding_generation():
    source = Path("x19/autonomous/team.py").read_text(encoding="utf-8")
    assert "Tool output for " not in source
    assert "Simulate some findings" not in source
    assert 'verified_by="verification"' not in source
