from reporting.pdf_report import _break_long_tokens, _truncate


def test_break_long_tokens_inserts_zero_width_space():
    text = "a" * 100
    broken = _break_long_tokens(text, max_run=40)
    assert "\u200b" in broken
    # underlying visible characters must be unchanged
    assert broken.replace("\u200b", "") == text


def test_break_long_tokens_leaves_short_text_untouched():
    text = "short and normal text"
    assert _break_long_tokens(text) == text


def test_break_long_tokens_resets_run_on_whitespace():
    text = ("a" * 39) + " " + ("b" * 39)
    broken = _break_long_tokens(text, max_run=40)
    # neither run reaches max_run, so no break should be inserted
    assert "\u200b" not in broken


def test_truncate_short_value_unchanged():
    assert _truncate("short value", limit=300) == "short value"


def test_truncate_long_value_is_shortened_with_note():
    long_value = "x" * 1000
    result = _truncate(long_value, limit=300)
    assert len(result) < len(long_value)
    assert "1000 chars total" in result
    assert result.startswith("x" * 300)


def test_truncate_preserves_non_string_short_values():
    # values under the limit are returned completely untouched (same object)
    value = 12345
    assert _truncate(value, limit=300) == 12345


def test_generate_pdf_report_survives_extremely_long_header_value(tmp_path):
    from core.result import CheckResult, CheckStatus
    from reporting.pdf_report import generate_pdf_report

    long_csp = "default-src 'self'; script-src " + " ".join(
        f"host{i}.example.com" for i in range(300)
    )
    results = {
        "headers": CheckResult(
            name="headers",
            status=CheckStatus.OK,
            data={"server": "nginx", "security_headers": {"Content-Security-Policy": long_csp}},
        ),
    }
    analysis = {"findings": []}
    score = {"score": 100, "grade": "A+", "risk": "LOW", "high": 0, "medium": 0, "low": 0}

    output_path = tmp_path / "report.pdf"
    result_path = generate_pdf_report(
        "https://example.com", results, analysis, score, ["headers"], output_path
    )

    assert result_path.exists()
    assert result_path.stat().st_size > 0
