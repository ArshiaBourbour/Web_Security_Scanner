from scanners.clickjacking_checker import _analyze, _extract_frame_ancestors


def test_extract_frame_ancestors_from_csp():
    raw = "default-src 'self'; frame-ancestors 'self' https://trusted.example.com"
    assert _extract_frame_ancestors(raw) == "'self' https://trusted.example.com"


def test_extract_frame_ancestors_missing_returns_none():
    assert _extract_frame_ancestors("default-src 'self'") is None


def test_no_headers_at_all_is_unprotected():
    protected, source, issues = _analyze(None, None)
    assert protected is False
    assert source == "none"
    assert any(i["severity"] == "HIGH" for i in issues)


def test_xfo_deny_is_protected():
    protected, source, issues = _analyze("DENY", None)
    assert protected is True
    assert source == "x-frame-options"
    assert issues == []


def test_xfo_sameorigin_is_protected():
    protected, source, _ = _analyze("SAMEORIGIN", None)
    assert protected is True


def test_csp_none_is_protected_and_takes_priority():
    protected, source, issues = _analyze("DENY", "'none'")
    assert protected is True
    assert source == "csp"
    assert issues == []


def test_csp_wildcard_is_unprotected_even_with_xfo():
    # CSP frame-ancestors takes priority in modern browsers; a wildcard here
    # should be flagged even though XFO alone would have been fine
    protected, source, issues = _analyze("DENY", "*")
    assert protected is False
    assert any("wildcard" in i["title"].lower() or "*" in i["title"] for i in issues)


def test_xfo_allow_from_is_deprecated_but_weakly_protected():
    protected, source, issues = _analyze("ALLOW-FROM https://example.com", None)
    assert protected is True
    assert any("deprecated" in i["title"].lower() for i in issues)


def test_xfo_garbage_value_is_unprotected():
    protected, source, issues = _analyze("NOT-A-REAL-VALUE", None)
    assert protected is False
    assert any(i["severity"] == "MEDIUM" for i in issues)
