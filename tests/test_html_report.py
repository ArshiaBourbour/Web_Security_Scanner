from core.result import CheckResult, CheckStatus
from reporting.html_report import _esc, _kv_table, generate_html_report


def test_esc_escapes_script_tags():
    assert _esc("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"


def test_esc_none_returns_dash():
    assert _esc(None) == "-"


def test_esc_passes_through_plain_text():
    assert _esc("hello world") == "hello world"


def test_kv_table_escapes_dynamic_values():
    html_out = _kv_table([("Key", "<img src=x onerror=alert(1)>")])
    assert "<img src=x" not in html_out
    assert "&lt;img" in html_out


def test_generate_html_report_end_to_end_escapes_malicious_data():
    results = {
        "ssl": CheckResult(name="ssl", status=CheckStatus.OK, data={"subject": "<script>evil()</script>"}),
    }
    analysis = {"findings": []}
    score = {"score": 100, "grade": "A+", "risk": "LOW", "high": 0, "medium": 0, "low": 0}
    html_out = generate_html_report("https://example.com", results, analysis, score, ["ssl"])
    assert "<script>evil()</script>" not in html_out
    assert "&lt;script&gt;evil()" in html_out
    assert html_out.startswith("<!DOCTYPE html>")
    assert html_out.rstrip().endswith("</html>")


def test_generate_html_report_handles_missing_step_gracefully():
    results = {}
    analysis = {"findings": []}
    score = {"score": 100, "grade": "A+", "risk": "LOW", "high": 0, "medium": 0, "low": 0}
    # "ssl" is requested but not present in results -> should not raise
    html_out = generate_html_report("https://example.com", results, analysis, score, ["ssl"])
    assert "step did not run" in html_out
