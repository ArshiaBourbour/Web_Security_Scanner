from scanners.hsts_checker import ONE_YEAR, SIX_MONTHS, _analyze, _parse_hsts


def test_parse_hsts_extracts_all_directives():
    d = _parse_hsts("max-age=31536000; includeSubDomains; preload")
    assert d["max-age"] == "31536000"
    assert d["includesubdomains"] is True
    assert d["preload"] is True


def test_parse_hsts_case_insensitive_keys():
    d = _parse_hsts("Max-Age=100; IncludeSubDomains")
    assert d["max-age"] == "100"
    assert d["includesubdomains"] is True


def test_analyze_good_policy_has_no_issues():
    issues = _analyze("https", ONE_YEAR, True, True)
    assert issues == []


def test_analyze_zero_max_age_is_high():
    issues = _analyze("https", 0, True, True)
    assert any(i["severity"] == "HIGH" for i in issues)


def test_analyze_short_max_age_is_low():
    issues = _analyze("https", 100, True, True)
    assert any("short" in i["title"] for i in issues)


def test_analyze_none_max_age_is_medium():
    issues = _analyze("https", None, True, True)
    assert any(i["severity"] == "MEDIUM" and "max-age" in i["title"] for i in issues)


def test_analyze_http_scheme_flagged():
    issues = _analyze("http", ONE_YEAR, True, True)
    assert any("plain HTTP" in i["title"] for i in issues)


def test_analyze_missing_subdomains_and_preload_are_low():
    issues = _analyze("https", ONE_YEAR, False, False)
    titles = [i["title"] for i in issues]
    assert any("includeSubDomains" in t for t in titles)
    assert any("preload" in t for t in titles)


def test_six_months_boundary_not_flagged_as_short():
    issues = _analyze("https", SIX_MONTHS, True, True)
    assert not any("short" in i["title"] for i in issues)
