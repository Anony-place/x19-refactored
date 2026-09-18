"""Tests for X19 team hierarchy Boss → Managers → Specialists."""

import sys
sys.path.insert(0, '.')

from x19.team import (
    ALL_ROLES,
    ELEVEN_CORE_ROLES,
    TEAM_HIERARCHY,
    ROLE_HIERARCHY,
    get_role,
    get_delegation_chain,
    validate_team,
    is_manager,
    is_specialist,
    is_boss,
    get_delegation_role,
    list_all_role_ids,
    list_eleven_core_role_ids,
)


def test_eleven_core_roles_exist():
    """11 core roles as defined in audit must exist."""
    assert len(ELEVEN_CORE_ROLES) == 11
    expected_ids = [
        "boss",
        "recon_manager",
        "web_security",
        "api_security",
        "auth",
        "cloud_infra",
        "vuln_research",
        "bugbounty_research",
        "verification",
        "evidence_reporting",
        "defensive_validation",
    ]
    for rid in expected_ids:
        assert rid in ELEVEN_CORE_ROLES, f"Missing core role {rid}"


def test_all_roles_count():
    """All roles including managers should be 13 (Boss + 3 Managers + 9 Specialists)."""
    assert len(ALL_ROLES) == 13
    # Check managers
    assert "recon_manager" in ALL_ROLES
    assert "web_manager" in ALL_ROLES
    assert "api_manager" in ALL_ROLES


def test_team_hierarchy_valid():
    """Hierarchy must be valid."""
    valid, errors = validate_team()
    assert valid, f"Hierarchy invalid: {errors}"


def test_boss_is_orchestrator():
    """Boss must be orchestrator (can delegate)."""
    assert is_boss("boss")
    assert get_delegation_role("boss") == "orchestrator"


def test_managers_are_orchestrator():
    """Managers must be orchestrator."""
    for mid in ["recon_manager", "web_manager", "api_manager"]:
        assert is_manager(mid), f"{mid} should be manager"
        assert get_delegation_role(mid) == "orchestrator", f"{mid} should be orchestrator"


def test_specialists_are_leaf():
    """Specialists must be leaf (cannot delegate)."""
    specialists = [
        "web_security",
        "api_security",
        "auth",
        "cloud_infra",
        "vuln_research",
        "bugbounty_research",
        "verification",
        "evidence_reporting",
        "defensive_validation",
    ]
    for sid in specialists:
        assert is_specialist(sid), f"{sid} should be specialist"
        assert get_delegation_role(sid) == "leaf", f"{sid} should be leaf"


def test_delegation_rules():
    """Boss can delegate to any specialist, specialists cannot delegate."""
    # Boss can delegate to web_security
    assert TEAM_HIERARCHY.can_delegate("boss", "web_security")
    assert TEAM_HIERARCHY.can_delegate("boss", "auth")
    assert TEAM_HIERARCHY.can_delegate("boss", "recon_manager")

    # Specialists cannot delegate
    assert not TEAM_HIERARCHY.can_delegate("web_security", "api_security")
    assert not TEAM_HIERARCHY.can_delegate("auth", "web_security")

    # Managers can delegate to specialists
    assert TEAM_HIERARCHY.can_delegate("recon_manager", "web_security")
    assert TEAM_HIERARCHY.can_delegate("web_manager", "web_security")
    assert TEAM_HIERARCHY.can_delegate("api_manager", "api_security")


def test_delegation_chain():
    """Delegation chain Boss → Manager → Specialist."""
    chain = get_delegation_chain("web_security")
    assert chain[0] == "boss"
    assert "web_security" in chain

    chain = get_delegation_chain("api_security")
    assert chain[0] == "boss"
    assert "api_security" in chain


def test_role_distinct_prompts():
    """Each role must have distinct prompt fragment (not 11 copies)."""
    prompts = {}
    for rid, role in ALL_ROLES.items():
        prompts[rid] = role.prompt_fragment

    # Check all prompts are unique
    unique_prompts = set(prompts.values())
    assert len(unique_prompts) == len(prompts), "Roles have duplicate prompts — must be distinct"

    # Check each prompt mentions its role name or specific expertise
    for rid, prompt in prompts.items():
        assert len(prompt) > 50, f"Prompt for {rid} too short"
        # Each prompt should mention X19
        assert "X19" in prompt, f"Prompt for {rid} missing X19"


def test_role_evidence_requirements():
    """Every role must have evidence requirements."""
    for rid, role in ALL_ROLES.items():
        assert len(role.evidence_requirements) > 0, f"Role {rid} missing evidence requirements"
        assert len(role.responsibilities) > 0, f"Role {rid} missing responsibilities"
        assert len(role.allowed_tools) > 0, f"Role {rid} missing allowed tools"


def test_hierarchy_levels():
    """Hierarchy levels must be correct."""
    levels = TEAM_HIERARCHY.levels
    assert len(levels) == 5
    assert levels[0]["name"] == "Operator"
    assert levels[1]["name"] == "Boss/Commander"
    assert levels[4]["name"] == "Tools"
