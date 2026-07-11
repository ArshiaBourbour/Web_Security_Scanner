from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from config import REPORT_DIR
from core.report_naming import safe_report_filename
from core.result import CheckResult, CheckStatus
from reporting.executive_summary import generate_executive_summary


def _result_to_dict(result: CheckResult) -> dict[str, Any]:
    return {
        "status": result.status.value,
        "data": result.data,
        "error": result.error,
        "duration_seconds": result.duration_seconds,
    }


def _default_result(step: str) -> CheckResult:
    return CheckResult(name=step, status=CheckStatus.ERROR, error="step did not run")


def build_report_dict(
    target: str,
    results: dict[str, CheckResult],
    analysis: dict[str, Any],
    score: dict[str, Any],
    steps: list[str],
) -> dict[str, Any]:
    return {
        "target": target,
        "generated_at": datetime.now().isoformat(),
        "score": score,
        "executive_summary": generate_executive_summary(target, analysis, score),
        "risk_analysis": analysis,
        "checks": {
            step: _result_to_dict(results.get(step, _default_result(step)))
            for step in steps
        },
    }


def generate_json_report(
    target: str,
    results: dict[str, CheckResult],
    analysis: dict[str, Any],
    score: dict[str, Any],
    steps: list[str],
) -> str:
    report = build_report_dict(target, results, analysis, score, steps)
    # default=str is a safety net in case any checker ever returns a
    # non-JSON-native value (e.g. a datetime) inside its data dict
    return json.dumps(report, indent=2, ensure_ascii=False, default=str)


def save_json_report(
    target: str,
    results: dict[str, CheckResult],
    analysis: dict[str, Any],
    score: dict[str, Any],
    steps: list[str],
) -> Path:
    content = generate_json_report(target, results, analysis, score, steps)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORT_DIR / safe_report_filename(target, "json")
    path.write_text(content, encoding="utf-8")
    return path
