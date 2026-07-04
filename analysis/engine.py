from __future__ import annotations

from typing import Any, Dict, List

from .finding import Finding, Severity
from .rules import HEADER_RULES


class FindingEngine:
    def analyze_headers(self, headers: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []

        for rule in HEADER_RULES:
            value = headers.get(rule.field)

            # rule trigger condition
            if value is None or value == "-" or value == "":
                findings.append(
                    Finding(
                        id=rule.id,
                        scanner=rule.scanner,
                        severity=rule.severity,
                        title=rule.title,
                        description=rule.description,
                        recommendation=rule.recommendation,
                        affected=rule.field,
                        evidence=None,
                    )
                )

        return findings

    def analyze(self, scan_result) -> List[Finding]:
        findings: List[Finding] = []

        # headers analysis
        if hasattr(scan_result, "headers"):
            findings.extend(self.analyze_headers(scan_result.headers))

        return findings
