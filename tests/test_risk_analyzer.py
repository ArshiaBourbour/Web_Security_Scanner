from core.result import CheckResult, CheckStatus
from scanners.analysis import RiskAnalyzer


def _ok(name, data):
    return CheckResult(name=name, status=CheckStatus.OK, data=data)


def _error(name, error="failed"):
    return CheckResult(name=name, status=CheckStatus.ERROR, error=error, data={})


def test_missing_step_defaults_to_error_and_is_handled_gracefully():
    # no results at all -> _result() should fall back to a synthetic ERROR CheckResult
    analyzer = RiskAnalyzer({})
    analysis = analyzer.analyze()
    assert isinstance(analysis["findings"], list)
    assert analysis["risk"] in ("LOW", "MEDIUM", "HIGH")


def test_ssl_missing_raises_high_finding():
    analyzer = RiskAnalyzer({"ssl": _error("ssl")})
    analyzer.analyze_ssl()
    titles = [f["title"] for f in analyzer.findings]
    assert "SSL Missing" in titles


def test_ssl_ok_raises_no_finding():
    analyzer = RiskAnalyzer({"ssl": _ok("ssl", {"notAfter": "2030-01-01"})})
    analyzer.analyze_ssl()
    assert analyzer.findings == []


def test_dns_missing_a_record_is_high():
    analyzer = RiskAnalyzer({"dns": _ok("dns", {})})
    analyzer.analyze_dns()
    high = [f for f in analyzer.findings if f["severity"] == "HIGH"]
    assert any(f["title"] == "No A Record" for f in high)


def test_cookies_flags_all_three_issues():
    data = {"insecure_count": 1, "no_httponly_count": 1, "no_samesite_count": 1}
    analyzer = RiskAnalyzer({"cookies": _ok("cookies", data)})
    analyzer.analyze_cookies()
    assert len(analyzer.findings) == 3


def test_cookies_no_data_produces_no_findings():
    analyzer = RiskAnalyzer({"cookies": _ok("cookies", {})})
    analyzer.analyze_cookies()
    assert analyzer.findings == []


def test_http_methods_trace_reflects_body_is_high():
    data = {"trace_reflects_body": True, "trace_enabled": True, "risky_methods": ["TRACE"]}
    analyzer = RiskAnalyzer({"http_methods": _ok("http_methods", data)})
    analyzer.analyze_http_methods()
    assert any(f["severity"] == "HIGH" and "XST" in f["title"] for f in analyzer.findings)


def test_http_methods_put_allowed_is_medium():
    data = {"trace_enabled": False, "risky_methods": ["PUT"]}
    analyzer = RiskAnalyzer({"http_methods": _ok("http_methods", data)})
    analyzer.analyze_http_methods()
    assert any(f["severity"] == "MEDIUM" for f in analyzer.findings)


def test_sitemap_small_sensitive_set_raises_finding():
    data = {"found": True, "sensitive_urls": ["/admin/x"]}
    analyzer = RiskAnalyzer({"sitemap": _ok("sitemap", data)})
    analyzer.analyze_sitemap()
    assert len(analyzer.findings) == 1


def test_sitemap_large_sensitive_set_is_treated_as_noise():
    # regression test: >20 matches should NOT raise a finding (likely coincidental keywords)
    data = {"found": True, "sensitive_urls": [f"/pkg-test-{i}" for i in range(50)]}
    analyzer = RiskAnalyzer({"sitemap": _ok("sitemap", data)})
    analyzer.analyze_sitemap()
    assert analyzer.findings == []


def test_directory_listing_root_is_high_severity():
    analyzer = RiskAnalyzer({"directory_listing": _ok("directory_listing", {"found": True, "listings": ["/"]})})
    analyzer.analyze_directory_listing()
    assert analyzer.findings[0]["severity"] == "HIGH"


def test_directory_listing_subpath_is_medium_severity():
    analyzer = RiskAnalyzer(
        {"directory_listing": _ok("directory_listing", {"found": True, "listings": ["/images/"]})}
    )
    analyzer.analyze_directory_listing()
    assert analyzer.findings[0]["severity"] == "MEDIUM"


def test_risk_level_thresholds():
    analyzer = RiskAnalyzer({})
    analyzer.add("HIGH", "a", "x")
    analyzer.add("HIGH", "b", "x")
    assert analyzer.risk_level() == "HIGH"

    analyzer2 = RiskAnalyzer({})
    analyzer2.add("MEDIUM", "a", "x")
    analyzer2.add("MEDIUM", "b", "x")
    assert analyzer2.risk_level() == "MEDIUM"

    analyzer3 = RiskAnalyzer({})
    analyzer3.add("LOW", "a", "x")
    assert analyzer3.risk_level() == "LOW"


def test_full_analyze_runs_all_checks_without_error():
    results = {
        "ssl": _ok("ssl", {"notAfter": "2030-01-01"}),
        "dns": _ok("dns", {"A": ["1.2.3.4"], "AAAA": ["::1"], "MX": ["mx"], "TXT": ["v=spf1"]}),
        "cookies": _ok("cookies", {}),
        "http_methods": _ok("http_methods", {}),
        "robots": _ok("robots", {"found": False}),
        "sitemap": _ok("sitemap", {"found": False}),
        "csp": _ok("csp", {"found": False}),
        "cors": _ok("cors", {"found": False}),
        "hsts": _ok("hsts", {"found": False}),
        "clickjacking": _ok("clickjacking", {"issues": []}),
        "directory_listing": _ok("directory_listing", {"found": False}),
    }
    analysis = RiskAnalyzer(results).analyze()
    assert "risk" in analysis and "findings" in analysis
