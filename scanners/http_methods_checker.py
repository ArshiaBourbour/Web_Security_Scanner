from __future__ import annotations

from typing import Any

import requests

from core.base_checker import BaseChecker
from core.http_client import request
from core.registry import register

# Methods we actively probe against the target.
METHODS_TO_TEST = [
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "OPTIONS",
    "TRACE",
    "CONNECT",
    "HEAD",
]

# Methods that are considered a security concern if the server confirms them.
RISKY_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT"}

# Status codes that explicitly mean "this method is not supported here".
DISALLOWED_STATUSES = {405, 501}


def _classify(status: "int | None") -> str:
    if status is None:
        return "unreachable"
    if status in DISALLOWED_STATUSES:
        return "disallowed"
    if 200 <= status < 400:
        return "allowed"
    return "unknown"


@register("http_methods")
class HTTPMethodsChecker(BaseChecker):
    """Probe which HTTP methods the target server accepts."""

    name = "http_methods"

    def _check(self) -> dict[str, Any]:
        allow_header_methods: set[str] = set()

        try:
            options_response = request(self.url, "OPTIONS")
            allow_header = options_response.headers.get("Allow", "")
            allow_header_methods = {
                m.strip().upper() for m in allow_header.split(",") if m.strip()
            }
        except requests.RequestException:
            pass

        results = []
        confirmed_allowed = set(allow_header_methods)

        for method in METHODS_TO_TEST:
            try:
                response = request(self.url, method)
                status = response.status_code
            except requests.RequestException:
                status = None

            classification = _classify(status)

            if classification == "allowed":
                confirmed_allowed.add(method)

            results.append(
                {
                    "method": method,
                    "status": status,
                    "classification": classification,
                }
            )

        if not confirmed_allowed and not any(
            r["classification"] != "unreachable" for r in results
        ):
            return {}

        trace_reflects_body = False

        if "TRACE" in confirmed_allowed:
            try:
                trace_response = request(self.url, "TRACE")
                trace_reflects_body = "TRACE" in (trace_response.text or "")
            except requests.RequestException:
                pass

        risky_methods = sorted(m for m in confirmed_allowed if m in RISKY_METHODS)

        return {
            "results": results,
            "confirmed_allowed": sorted(confirmed_allowed),
            "allow_header_methods": sorted(allow_header_methods),
            "risky_methods": risky_methods,
            "trace_enabled": "TRACE" in confirmed_allowed,
            "trace_reflects_body": trace_reflects_body,
        }