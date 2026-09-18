"""Tests for X19 scope control — explicit scope enforcement."""

import sys
sys.path.insert(0, '.')

from x19.scope import create_scope, ScopeEnforcer, validate_scope, HIGH_IMPACT_ACTIONS


def test_scope_creation():
    """Scope must have target, authorized domains, exclusions, allowed/prohibited actions."""
    scope = create_scope(
        target="https://target.com",
        authorized_domains=["target.com", "*.target.com"],
        excluded_assets=["/admin"],
        program_name="Test Program",
    )

    assert scope.target == "https://target.com"
    assert "target.com" in scope.authorized_domains
    assert "*.target.com" in scope.authorized_domains
    assert "/admin" in scope.excluded_assets
    assert len(scope.allowed_actions) > 0
    assert len(scope.prohibited_actions) > 0


def test_scope_validation():
    """Scope validation must catch errors."""
    scope = create_scope(target="https://target.com", authorized_domains=["target.com"])
    valid, errors = validate_scope(scope)
    assert valid, f"Valid scope reported invalid: {errors}"

    # Invalid: no target
    from x19.scope.scope import ScopeDefinition
    invalid_scope = ScopeDefinition(target="", authorized_domains=[])
    valid, errors = validate_scope(invalid_scope)
    assert not valid
    assert len(errors) > 0


def test_domain_authorization():
    """Domain authorization must handle wildcards."""
    scope = create_scope(target="https://target.com", authorized_domains=["target.com", "*.target.com"])
    enforcer = ScopeEnforcer(scope)

    assert enforcer.is_domain_authorized("target.com")
    assert enforcer.is_domain_authorized("sub.target.com")
    assert enforcer.is_domain_authorized("a.b.target.com")
    assert not enforcer.is_domain_authorized("evil.com")


def test_excluded_assets():
    """Excluded assets must be detected."""
    scope = create_scope(target="https://target.com", excluded_assets=["/admin", "api.internal.com"])
    enforcer = ScopeEnforcer(scope)

    assert enforcer.is_asset_excluded("/admin/dashboard")
    assert enforcer.is_asset_excluded("https://api.internal.com/users")
    assert not enforcer.is_asset_excluded("/api/users")


def test_action_allowed():
    """Allowed/prohibited actions must be enforced."""
    scope = create_scope(target="https://target.com")
    enforcer = ScopeEnforcer(scope)

    assert enforcer.is_action_allowed("read_only_get")
    assert enforcer.is_action_allowed("header_analysis")
    assert not enforcer.is_action_allowed("destructive_payload")
    assert not enforcer.is_action_allowed("data_deletion")


def test_high_impact_requires_approval():
    """High-impact actions must require approval."""
    scope = create_scope(target="https://target.com")
    enforcer = ScopeEnforcer(scope)

    for action in HIGH_IMPACT_ACTIONS:
        assert enforcer.requires_approval(action), f"{action} should require approval"

    assert not enforcer.requires_approval("read_only_get")


def test_validate_target():
    """Validate target against scope."""
    scope = create_scope(target="https://target.com", authorized_domains=["target.com", "*.target.com"], excluded_assets=["/admin"])
    enforcer = ScopeEnforcer(scope)

    ok, msg = enforcer.validate_target("https://target.com/api/users")
    assert ok, f"Should allow target.com: {msg}"

    ok, msg = enforcer.validate_target("https://sub.target.com/api")
    assert ok, f"Should allow sub.target.com: {msg}"

    ok, msg = enforcer.validate_target("https://evil.com/api")
    assert not ok, "Should reject evil.com"

    ok, msg = enforcer.validate_target("https://target.com/admin/dashboard")
    assert not ok, "Should reject excluded /admin"


def test_enforce_before_delegation():
    """Boss must enforce scope before delegation."""
    scope = create_scope(target="https://target.com", authorized_domains=["target.com"])
    enforcer = ScopeEnforcer(scope)

    ok, msg = enforcer.enforce_before_delegation("https://target.com/api/users", "read_only_get")
    assert ok

    ok, msg = enforcer.enforce_before_delegation("https://evil.com/api", "read_only_get")
    assert not ok

    ok, msg = enforcer.enforce_before_delegation("https://target.com/api/users", "destructive_payload")
    assert not ok, "Should reject destructive payload without approval"


def test_scope_summary():
    """Scope summary must be human-readable."""
    scope = create_scope(target="https://target.com", authorized_domains=["target.com"])
    enforcer = ScopeEnforcer(scope)
    summary = enforcer.get_scope_summary()
    assert "target.com" in summary
    assert "Target:" in summary
