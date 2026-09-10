from scope_guard import normalize_pattern, normalize_target, resolve_scope


def test_normalize_target_strips_url_details():
    assert normalize_target("https://www.paytm.com:443/login") == "www.paytm.com"


def test_wildcard_pattern_is_preserved():
    assert normalize_pattern("*.paytm.com") == "*.paytm.com"


def test_paytm_subdomain_is_verified_in_scope():
    result = resolve_scope("www.paytm.com")
    assert result.state == "verified_in_scope"
    assert result.program == "Paytm Bug Bounty"
    assert result.platform == "paytm"
    assert result.matched_pattern == "*.paytm.com"


def test_nested_paytm_subdomain_is_verified_in_scope():
    result = resolve_scope("api.foo.paytm.com")
    assert result.state == "verified_in_scope"
    assert result.matched_pattern == "*.paytm.com"


def test_paytm_apex_is_not_assumed_in_scope():
    result = resolve_scope("paytm.com")
    assert result.state == "verified_out_of_scope"
    assert result.program == "Paytm Bug Bounty"


def test_xiaomi_apex_is_recognized_but_not_implied_by_wildcard():
    result = resolve_scope("mi.com")
    assert result.state == "verified_out_of_scope"
    assert result.program == "Xiaomi Bug Bounty"
    assert result.platform == "hackerone"
    assert "*.mi.com" in result.scope_patterns


def test_xiaomi_subdomain_is_verified_in_scope():
    result = resolve_scope("account.mi.com")
    assert result.state == "verified_in_scope"
    assert result.program == "Xiaomi Bug Bounty"
    assert result.matched_pattern == "*.mi.com"


def test_unknown_target_does_not_get_authorization_assumed():
    result = resolve_scope("example.invalid")
    assert result.state == "unknown"
