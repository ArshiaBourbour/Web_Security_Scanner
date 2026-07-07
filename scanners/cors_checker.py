from __future__ import annotations

from typing import Any

import requests

from core.base_checker import BaseChecker
from core.http_client import request_with_headers
from core.registry import register

# RFC 2606 reserved TLD, guaranteed non-resolvable — safe fake attacker origin.
TEST_ORIGIN = "https://cors-reflection-test.invalid"


def _extract_cors(headers) -> dict[str, Any]:
    # pull the handful of CORS-relevant response headers we care about
    return {
        "allow_origin": headers.get("Access-Control-Allow-Origin"),
        "allow_credentials": headers.get("Access-Control-Allow-Credentials"),
        "allow_methods": headers.get("Access-Control-Allow-Methods"),
        "allow_headers": headers.get("Access-Control-Allow-Headers"),
    }


def _analyze(cors: dict[str, Any]) -> list[dict[str, str]]:
    # flag the well-known CORS misconfiguration patterns
    issues = []

    origin = cors.get("allow_origin")
    credentials = (cors.get("allow_credentials") or "").lower() == "true"

    if origin == TEST_ORIGIN:
        if credentials:
            issues.append(
                {
                    "severity": "HIGH",
                    "title": "Arbitrary Origin reflected with credentials allowed",
                    "detail": "Any website can make authenticated requests here and read the response. Use a strict origin allowlist.",
                }
            )
        else:
            issues.append(
                {
                    "severity": "HIGH",
                    "title": "Arbitrary Origin reflected",
                    "detail": "Access-Control-Allow-Origin echoes back any Origin sent, so any site can read this response via CORS.",
                }
            )
    elif origin == "*":
        if credentials:
            issues.append(
                {
                    "severity": "HIGH",
                    "title": "Wildcard Origin combined with credentials (invalid)",
                    "detail": "'*' with Access-Control-Allow-Credentials: true is spec-invalid and browsers will reject it, but it signals a broken CORS config.",
                }
            )
        else:
            issues.append(
                {
                    "severity": "LOW",
                    "title": "Wildcard Origin allowed",
                    "detail": "Any website can read non-credentialed responses from this endpoint.",
                }
            )

    return issues


@register("cors")
class CORSChecker(BaseChecker):
    """Probe CORS response headers for common misconfigurations."""

    name = "cors"

    def _probe(self, method: str) -> dict[str, str]:
        extra_headers = {"Origin": TEST_ORIGIN}

        if method == "OPTIONS":
            extra_headers["Access-Control-Request-Method"] = "GET"
            extra_headers["Access-Control-Request-Headers"] = "X-Requested-With"

        response = request_with_headers(self.url, method, extra_headers)
        return dict(response.headers)

    def _check(self) -> dict[str, Any]:
        merged: dict[str, str] = {}
        succeeded = False
        last_exc: Exception | None = None

        for method in ("OPTIONS", "GET"):
            try:
                headers = self._probe(method)
                merged.update({k: v for k, v in headers.items() if k not in merged})
                succeeded = True
            except requests.RequestException as exc:
                last_exc = exc

        if not succeeded:
            raise last_exc

        cors = _extract_cors(merged)

        if not any(cors.values()):
            return {"found": False}

        issues = _analyze(cors)

        return {
            "found": True,
            "test_origin": TEST_ORIGIN,
            **cors,
            "issues": issues,
        }