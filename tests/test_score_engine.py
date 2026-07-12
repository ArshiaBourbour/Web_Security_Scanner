from scanners.score_engine import ScoreEngine


def _analysis(findings, risk="LOW"):
    return {"findings": findings, "risk": risk}


def test_perfect_score_no_findings():
    result = ScoreEngine(_analysis([])).calculate()
    assert result["score"] == 100
    assert result["grade"] == "A+"
    assert result["high"] == 0 and result["medium"] == 0 and result["low"] == 0


def test_deducts_correct_weights_per_severity():
    findings = [
        {"severity": "HIGH", "title": "a", "recommendation": "x"},
        {"severity": "MEDIUM", "title": "b", "recommendation": "x"},
        {"severity": "LOW", "title": "c", "recommendation": "x"},
    ]
    result = ScoreEngine(_analysis(findings)).calculate()
    assert result["score"] == 100 - 20 - 10 - 5
    assert result["high"] == 1 and result["medium"] == 1 and result["low"] == 1


def test_score_never_goes_below_zero():
    findings = [{"severity": "HIGH", "title": "a", "recommendation": "x"}] * 10
    result = ScoreEngine(_analysis(findings)).calculate()
    assert result["score"] == 0
    assert result["grade"] == "F"


def test_unknown_severity_does_not_affect_score():
    findings = [{"severity": "WEIRD", "title": "a", "recommendation": "x"}]
    result = ScoreEngine(_analysis(findings)).calculate()
    assert result["score"] == 100


def test_grade_boundaries():
    cases = [(100, "A+"), (90, "A+"), (89, "A"), (80, "A"), (79, "B"), (70, "B"), (69, "C"), (60, "C"), (59, "F"), (0, "F")]
    engine = ScoreEngine(_analysis([]))
    for score, expected_grade in cases:
        assert engine.grade(score) == expected_grade


def test_risk_passed_through_from_analysis():
    result = ScoreEngine(_analysis([], risk="HIGH")).calculate()
    assert result["risk"] == "HIGH"
