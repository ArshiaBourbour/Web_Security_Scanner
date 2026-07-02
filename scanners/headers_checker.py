from typing import Any, Optional

import requests

from core.base_checker import BaseChecker
from core.http_client import fetch
from core.registry import register


@register("headers")
class HeaderChecker(BaseChecker):
    """Reads HTTP security headers from the response.

    Same fields as before. Accepts an optional pre-fetched `response` so
    ScanManager can share one HTTP request with HTMLChecker instead of
    both fetching the same page separately. If no response is given, it
    fetches its own -- so it still works standalone, same as before.
    """

    name = "headers"
    needs_shared_page = True

    def __init__(self, url: str, response: Optional[requests.Response] = None):
        super().__init__(url)
        self._response = response

    def _check(self) -> dict[str, Any]:
        r = self._response if self._response is not None else fetch(self.url)
        headers = r.headers

        security_headers = {
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
            "Referrer-Policy": headers.get("Referrer-Policy"),
            "Permissions-Policy": headers.get("Permissions-Policy"),
        }

        return {
            "security_headers": security_headers,
            "server": headers.get("Server"),
        }

