from __future__ import annotations

from typing import Any, Optional

import requests

from core.base_checker import BaseChecker
from core.http_client import fetch
from core.registry import register

# Directives that inherit from default-src if not set explicitly.
FALLBACK_TO_DEFAULT = {"script-src", "object-src", "style-src"}


def _parse_csp(raw: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}

    for part in raw.split(";"):
        tokens = part.strip().split()

        if not tokens:
            continue

        name = tokens[0].lower()
        directives[name] = tokens[1:]

    return directives


def _effective(directives: dict[str, list[str]], name: str) -> list[str]:
    # value for `name`, falling back to default-src per CSP inheritance rules
    if name in directives:
        return directives[name]

    if name in FALLBACK_TO_DEFAULT:
        return directives.get("default-src", [])

    return []


def _analyze_directives(directives: dict[str, list[str]]) -> list[dict[str, str]]:
    # run the actual misconfiguration checks against parsed directives
    issues = []

    script_src = _effective(directives, "script-src")

    if "'unsafe-inline'" in script_src:
        issues.append(
            {
                "severity": "HIGH",
                "title": "unsafe-inline allowed in script-src",
                "detail": "Allows inline <script> execution, defeating most XSS protection CSP provides",
            }
        )

    if "'unsafe-eval'" in script_src:
        issues.append(
            {
                "severity": "MEDIUM",
                "title": "unsafe-eval allowed in script-src",
                "detail": "Allows eval()/new Function(), a common XSS gadget",
            }
        )

    if "*" in script_src:
        issues.append(
            {
                "severity": "HIGH",
                "title": "Wildcard (*) allowed in script-src",
                "detail": "Any external domain can serve scripts for this site",
            }
        )

    if "data:" in script_src:
        issues.append(
            {
                "severity": "MEDIUM",
                "title": "data: scheme allowed in script-src",
                "detail": "data: URIs can be used to smuggle inline scripts",
            }
        )

    if "default-src" not in directives:
        issues.append(
            {
                "severity": "MEDIUM",
                "title": "No default-src directive",
                "detail": "Directives without an explicit source list fall back to allowing everything",
            }
        )

    object_src = _effective(directives, "object-src")

    if not object_src or object_src == ["*"]:
        issues.append(
            {
                "severity": "LOW",
                "title": "object-src not restricted",
                "detail": "Set object-src 'none' to block legacy plugin-based content (Flash/Java)",
            }
        )

    if "base-uri" not in directives:
        issues.append(
            {
                "severity": "LOW",
                "title": "No base-uri directive",
                "detail": "Without it, an injected <base> tag can redirect relative URLs site-wide",
            }
        )

    if "frame-ancestors" not in directives:
        issues.append(
            {
                "severity": "LOW",
                "title": "No frame-ancestors directive",
                "detail": "This site can be framed by other origins (clickjacking risk)",
            }
        )

    return issues


@register("csp")
class CSPChecker(BaseChecker):
    """Analyze the Content-Security-Policy header for common misconfigurations."""

    name = "csp"
    needs_shared_page = True

    def __init__(self, url: str, response: Optional[requests.Response] = None):
        super().__init__(url)
        self._response = response

    def _check(self) -> dict[str, Any]:
        r = self._response if self._response is not None else fetch(self.url)

        enforced = r.headers.get("Content-Security-Policy")
        report_only = r.headers.get("Content-Security-Policy-Report-Only")

        raw = enforced or report_only

        if not raw:
            return {"found": False}

        directives = _parse_csp(raw)
        issues = _analyze_directives(directives)

        if not enforced and report_only:
            issues.append(
                {
                    "severity": "MEDIUM",
                    "title": "CSP is report-only",
                    "detail": "Content-Security-Policy-Report-Only does not block anything, only reports violations",
                }
            )

        return {
            "found": True,
            "report_only": not bool(enforced),
            "raw": raw,
            "directives": directives,
            "issues": issues,
        }