from scanners.cors_checker import TEST_ORIGIN, _analyze, _extract_cors


def test_extract_cors_pulls_known_headers():
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
        "X-Other-Header": "ignored",
    }
    cors = _extract_cors(headers)
    assert cors["allow_origin"] == "*"
    assert cors["allow_credentials"] == "true"
    assert cors["allow_methods"] is None


def test_reflected_origin_with_credentials_is_high():
    issues = _analyze({"allow_origin": TEST_ORIGIN, "allow_credentials": "true"})
    assert len(issues) == 1
    assert issues[0]["severity"] == "HIGH"
    assert "credentials" in issues[0]["title"].lower()


def test_reflected_origin_without_credentials_is_still_high():
    issues = _analyze({"allow_origin": TEST_ORIGIN, "allow_credentials": None})
    assert issues[0]["severity"] == "HIGH"
    assert "credentials" not in issues[0]["title"].lower()


def test_wildcard_with_credentials_flagged_high_as_invalid():
    issues = _analyze({"allow_origin": "*", "allow_credentials": "true"})
    assert issues[0]["severity"] == "HIGH"
    assert "invalid" in issues[0]["title"].lower()


def test_wildcard_without_credentials_is_low():
    issues = _analyze({"allow_origin": "*", "allow_credentials": None})
    assert issues[0]["severity"] == "LOW"


def test_specific_trusted_origin_no_issues():
    issues = _analyze({"allow_origin": "https://trusted.example.com", "allow_credentials": "true"})
    assert issues == []


def test_no_cors_headers_no_issues():
    issues = _analyze({"allow_origin": None, "allow_credentials": None})
    assert issues == []


def test_credentials_flag_is_case_insensitive():
    issues = _analyze({"allow_origin": TEST_ORIGIN, "allow_credentials": "TRUE"})
    assert "credentials" in issues[0]["title"].lower()
