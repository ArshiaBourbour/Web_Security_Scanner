from scanners.csp_checker import _analyze_directives, _effective, _parse_csp


def test_parse_csp_splits_directives_and_values():
    raw = "default-src 'self'; script-src 'self' https://cdn.example.com"
    directives = _parse_csp(raw)
    assert directives["default-src"] == ["'self'"]
    assert directives["script-src"] == ["'self'", "https://cdn.example.com"]


def test_parse_csp_handles_empty_directive():
    directives = _parse_csp("default-src 'self';;")
    assert directives == {"default-src": ["'self'"]}


def test_effective_falls_back_to_default_src():
    directives = {"default-src": ["'none'"]}
    assert _effective(directives, "script-src") == ["'none'"]
    assert _effective(directives, "object-src") == ["'none'"]


def test_effective_uses_explicit_value_when_present():
    directives = {"default-src": ["'none'"], "script-src": ["'self'"]}
    assert _effective(directives, "script-src") == ["'self'"]


def test_effective_non_fallback_directive_returns_empty_when_missing():
    assert _effective({}, "base-uri") == []


def test_unsafe_inline_flagged_high():
    issues = _analyze_directives({"script-src": ["'unsafe-inline'"]})
    titles = [i["title"] for i in issues]
    assert any("unsafe-inline" in t for t in titles)
    high = [i for i in issues if "unsafe-inline" in i["title"]]
    assert high[0]["severity"] == "HIGH"


def test_wildcard_script_src_flagged_high():
    issues = _analyze_directives({"script-src": ["*"]})
    assert any("Wildcard" in i["title"] for i in issues)


def test_strict_policy_has_minimal_issues():
    directives = {
        "default-src": ["'none'"],
        "script-src": ["'self'"],
        "object-src": ["'none'"],
        "base-uri": ["'self'"],
        "frame-ancestors": ["'none'"],
    }
    issues = _analyze_directives(directives)
    # no unsafe-inline/eval/wildcard/data: issues should appear for a clean policy
    assert not any(i["severity"] == "HIGH" for i in issues)


def test_missing_default_src_flagged():
    issues = _analyze_directives({"script-src": ["'self'"]})
    assert any("default-src" in i["title"] for i in issues)


def test_object_src_none_not_flagged():
    directives = {"default-src": ["'self'"], "object-src": ["'none'"]}
    issues = _analyze_directives(directives)
    assert not any("object-src" in i["title"] for i in issues)
