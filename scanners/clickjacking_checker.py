from __future__ import annotations

from typing import Any, Optional

import requests

from core.base_checker import BaseChecker
from core.http_client import fetch
from core.registry import register


def _extract_frame_ancestors(csp_raw: str) -> Optional[str]:
    # pull the frame-ancestors directive's value out of a raw CSP header
    for part in csp_raw.split(";"):
        tokens = part.strip().split()
        if tokens and tokens[0].lower() == "frame-ancestors":
            return " ".join(tokens[1:])
    return None


def _analyze(xfo: Optional[str], frame_ancestors: Optional[str]) -> tuple[bool, str, list[dict[str, str]]]:
    # decide if the page is protected and collect the reasons why not
    issues = []

    csp_protects = None
    if frame_ancestors is not None:
        values = frame_ancestors.split()
        csp_protects = bool(values) and "*" not in values

        if csp_protects is False:
            issues.append(
                {
                    "severity": "HIGH",
                    "title": "CSP frame-ancestors allows any origin (*)",
                    "detail": "Any site can embed this page in an iframe, enabling clickjacking/UI redress attacks",
                }
            )

    xfo_protects = None
    if xfo:
        xfo_norm = xfo.strip().upper()
        if xfo_norm in ("DENY", "SAMEORIGIN"):
            xfo_protects = True
        elif xfo_norm.startswith("ALLOW-FROM"):
            xfo_protects = True
            issues.append(
                {
                    "severity": "LOW",
                    "title": "X-Frame-Options: ALLOW-FROM is deprecated",
                    "detail": "Modern browsers ignore ALLOW-FROM; use CSP frame-ancestors instead",
                }
            )
        else:
            xfo_protects = False
            issues.append(
                {
                    "severity": "MEDIUM",
                    "title": f"Unrecognized X-Frame-Options value: {xfo}",
                    "detail": "Browsers may ignore an unrecognized value and allow framing anyway",
                }
            )

    if csp_protects is not None:
        protected = csp_protects
    else:
        protected = bool(xfo_protects)

    source = "csp" if csp_protects else ("x-frame-options" if xfo_protects else "none")

    if not protected:
        issues.insert(
            0,
            {
                "severity": "HIGH",
                "title": "No clickjacking protection",
                "detail": "Neither CSP frame-ancestors nor X-Frame-Options: DENY/SAMEORIGIN is set; this page can be embedded in an iframe by any site",
            },
        )

    return protected, source, issues


@register("clickjacking")
class ClickjackingChecker(BaseChecker):
    """Check X-Frame-Options / CSP frame-ancestors for clickjacking protection."""

    name = "clickjacking"
    needs_shared_page = True

    def __init__(self, url: str, response: Optional[requests.Response] = None):
        super().__init__(url)
        self._response = response

    def _check(self) -> dict[str, Any]:
        r = self._response if self._response is not None else fetch(self.url)

        xfo = r.headers.get("X-Frame-Options")
        csp_raw = r.headers.get("Content-Security-Policy")
        frame_ancestors = _extract_frame_ancestors(csp_raw) if csp_raw else None

        protected, source, issues = _analyze(xfo, frame_ancestors)

        return {
            "found": bool(xfo) or frame_ancestors is not None,
            "x_frame_options": xfo,
            "frame_ancestors": frame_ancestors,
            "protected": protected,
            "protection_source": source,
            "issues": issues,
        }
