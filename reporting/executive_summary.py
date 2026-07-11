from __future__ import annotations

from typing import Any

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def generate_executive_summary(
    target: str, analysis: dict[str, Any], score: dict[str, Any]
) -> dict[str, Any]:
    findings = analysis["findings"]
    high = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]
    low = [f for f in findings if f["severity"] == "LOW"]

    if not findings:
        narrative = (
            f"{target} shows a strong security posture, with no issues identified "
            f"during this scan (grade {score['grade']}, {score['score']}/100)."
        )
    elif high:
        narrative = (
            f"{target} received a security grade of {score['grade']} ({score['score']}/100). "
            f"{len(high)} high-severity issue(s) were identified and should be treated as a "
            f"priority, alongside {len(medium)} medium- and {len(low)} low-severity finding(s)."
        )
    elif medium:
        narrative = (
            f"{target} received a security grade of {score['grade']} ({score['score']}/100). "
            f"No high-severity issues were found, but {len(medium)} medium-severity finding(s) "
            "should be reviewed to further strengthen the site's security posture."
        )
    else:
        narrative = (
            f"{target} received a security grade of {score['grade']} ({score['score']}/100), "
            f"with only {len(low)} minor low-severity observation(s) noted."
        )

    top_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 3))[:5]

    return {
        "narrative": narrative,
        "grade": score["grade"],
        "score": score["score"],
        "risk": score["risk"],
        "high_count": len(high),
        "medium_count": len(medium),
        "low_count": len(low),
        "top_findings": top_findings,
    }
