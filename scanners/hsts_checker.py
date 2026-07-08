from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlparse

import requests

from core.base_checker import BaseChecker
from core.http_client import fetch
from core.registry import register

# Recommended minimums per the HSTS preload guidelines.
SIX_MONTHS = 15552000
ONE_YEAR = 31536000


def _parse_hsts(raw: str) -> dict[str, Any]:
    # split "max-age=N; includeSubDomains; preload" into a directive dict
    directives: dict[str, Any] = {}

    for part in raw.split(";"):
        part = part.strip()

        if not part:
            continue

        if "=" in part:
            key, _, value = part.partition("=")
            directives[key.strip().lower()] = value.strip()
        else:
            directives[part.lower()] = True

    return directives


def _analyze(scheme: str, max_age: Optional[int], include_subdomains: bool, preload: bool) -> list[dict[str, str]]:
    # run the actual HSTS misconfiguration checks
    issues = []

    if scheme != "https":
        issues.append(
            {
                "severity": "MEDIUM",
                "title": "HSTS header sent over plain HTTP",
                "detail": "Strict-Transport-Security is ignored by browsers unless delivered over HTTPS; serve this over HTTPS",
            }
        )

    if max_age is None:
        issues.append(
            {
                "severity": "MEDIUM",
                "title": "Invalid or missing max-age",
                "detail": "max-age could not be parsed as a number, so the policy has no effective duration",
            }
        )
    elif max_age == 0:
        issues.append(
            {
                "severity": "HIGH",
                "title": "max-age=0 disables HSTS",
                "detail": "This actively tells browsers to stop enforcing HTTPS for this site",
            }
        )
    elif max_age < SIX_MONTHS:
        issues.append(
            {
                "severity": "LOW",
                "title": f"max-age is short ({max_age}s)",
                "detail": f"Recommended minimum is 6 months ({SIX_MONTHS}s), ideally 1 year ({ONE_YEAR}s) for preload eligibility",
            }
        )

    if not include_subdomains:
        issues.append(
            {
                "severity": "LOW",
                "title": "includeSubDomains not set",
                "detail": "Subdomains are not covered by this HSTS policy and remain vulnerable to downgrade attacks",
            }
        )

    if not preload:
        issues.append(
            {
                "severity": "LOW",
                "title": "Not marked for HSTS preload",
                "detail": "Consider adding 'preload' and submitting to hstspreload.org for protection on the very first visit",
            }
        )

    return issues


@register("hsts")
class HSTSChecker(BaseChecker):
    """Analyze the Strict-Transport-Security header for common misconfigurations."""

    name = "hsts"
    needs_shared_page = True

    def __init__(self, url: str, response: Optional[requests.Response] = None):
        super().__init__(url)
        self._response = response

    def _check(self) -> dict[str, Any]:
        r = self._response if self._response is not None else fetch(self.url)

        scheme = urlparse(self.url).scheme
        raw = r.headers.get("Strict-Transport-Security")

        if not raw:
            return {"found": False, "scheme": scheme}

        directives = _parse_hsts(raw)

        try:
            max_age = int(directives.get("max-age", ""))
        except ValueError:
            max_age = None

        include_subdomains = "includesubdomains" in directives
        preload = "preload" in directives

        issues = _analyze(scheme, max_age, include_subdomains, preload)

        return {
            "found": True,
            "scheme": scheme,
            "raw": raw,
            "max_age": max_age,
            "include_subdomains": include_subdomains,
            "preload": preload,
            "issues": issues,
        }