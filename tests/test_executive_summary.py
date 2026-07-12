from reporting.executive_summary import generate_executive_summary


def _score(grade="A+", score=100, risk="LOW"):
    return {"grade": grade, "score": score, "risk": risk}


def test_no_findings_narrative_is_positive():
    summary = generate_executive_summary("example.com", {"findings": []}, _score())
    assert "strong security posture" in summary["narrative"]
    assert summary["high_count"] == 0


def test_high_findings_mentioned_in_narrative():
    findings = [{"severity": "HIGH", "title": "x", "recommendation": "y"}]
    summary = generate_executive_summary("example.com", {"findings": findings}, _score(grade="F", score=30, risk="HIGH"))
    assert "priority" in summary["narrative"]
    assert summary["high_count"] == 1


def test_only_medium_findings_narrative():
    findings = [{"severity": "MEDIUM", "title": "x", "recommendation": "y"}]
    summary = generate_executive_summary("example.com", {"findings": findings}, _score(grade="B", score=70))
    assert "No high-severity issues" in summary["narrative"]


def test_only_low_findings_narrative():
    findings = [{"severity": "LOW", "title": "x", "recommendation": "y"}]
    summary = generate_executive_summary("example.com", {"findings": findings}, _score(grade="A", score=95))
    assert "minor low-severity" in summary["narrative"]


def test_top_findings_capped_at_five_and_sorted_by_severity():
    findings = (
        [{"severity": "LOW", "title": f"low-{i}", "recommendation": "y"} for i in range(3)]
        + [{"severity": "HIGH", "title": f"high-{i}", "recommendation": "y"} for i in range(3)]
    )
    summary = generate_executive_summary("example.com", {"findings": findings}, _score())
    assert len(summary["top_findings"]) == 5
    assert summary["top_findings"][0]["severity"] == "HIGH"


def test_counts_match_findings_by_severity():
    findings = [
        {"severity": "HIGH", "title": "a", "recommendation": "x"},
        {"severity": "HIGH", "title": "b", "recommendation": "x"},
        {"severity": "MEDIUM", "title": "c", "recommendation": "x"},
        {"severity": "LOW", "title": "d", "recommendation": "x"},
    ]
    summary = generate_executive_summary("example.com", {"findings": findings}, _score())
    assert summary["high_count"] == 2
    assert summary["medium_count"] == 1
    assert summary["low_count"] == 1
