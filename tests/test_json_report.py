import json

from core.result import CheckResult, CheckStatus
from reporting.json_report import build_report_dict, generate_json_report


def _basic_args():
    results = {
        "ssl": CheckResult(name="ssl", status=CheckStatus.OK, data={"subject": "example.com"}),
    }
    analysis = {"findings": []}
    score = {"score": 100, "grade": "A+", "risk": "LOW", "high": 0, "medium": 0, "low": 0}
    return "https://example.com", results, analysis, score, ["ssl"]


def test_build_report_dict_has_expected_top_level_keys():
    report = build_report_dict(*_basic_args())
    assert set(report.keys()) == {
        "target",
        "generated_at",
        "score",
        "executive_summary",
        "risk_analysis",
        "checks",
    }


def test_missing_step_defaults_to_error_status():
    target, results, analysis, score, steps = _basic_args()
    report = build_report_dict(target, {}, analysis, score, ["ssl"])
    assert report["checks"]["ssl"]["status"] == "error"
    assert report["checks"]["ssl"]["error"] == "step did not run"


def test_check_result_serializes_status_as_plain_string():
    report = build_report_dict(*_basic_args())
    assert report["checks"]["ssl"]["status"] == "ok"
    assert report["checks"]["ssl"]["data"] == {"subject": "example.com"}


def test_generate_json_report_produces_valid_parseable_json():
    content = generate_json_report(*_basic_args())
    parsed = json.loads(content)
    assert parsed["target"] == "https://example.com"


def test_json_report_round_trips_special_characters():
    results = {
        "cookies": CheckResult(
            name="cookies",
            status=CheckStatus.OK,
            data={"raw": 'quote"backslash\\tab\ttab newline\n<script>evil</script>'},
        ),
    }
    analysis = {"findings": []}
    score = {"score": 100, "grade": "A+", "risk": "LOW", "high": 0, "medium": 0, "low": 0}
    content = generate_json_report("https://example.com", results, analysis, score, ["cookies"])
    parsed = json.loads(content)
    assert parsed["checks"]["cookies"]["data"]["raw"] == results["cookies"].data["raw"]
