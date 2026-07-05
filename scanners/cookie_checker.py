from __future__ import annotations

from typing import Any, Optional

import requests

from core.base_checker import BaseChecker
from core.http_client import fetch
from core.registry import register


@register("cookies")
class CookieChecker(BaseChecker):
    """Analyze cookies set by the target for common security flags."""

    name = "cookies"
    needs_shared_page = True

    def __init__(self, url: str, response: Optional[requests.Response] = None):
        super().__init__(url)
        self._response = response

    def _check(self) -> dict[str, Any]:
        r = self._response if self._response is not None else fetch(self.url)

        cookies = []

        for cookie in r.cookies:
            samesite = cookie.get_nonstandard_attr("SameSite")
            http_only = cookie.has_nonstandard_attr("HttpOnly")

            cookies.append(
                {
                    "name": cookie.name,
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": bool(cookie.secure),
                    "http_only": http_only,
                    "samesite": samesite,
                    "session_cookie": cookie.expires is None,
                }
            )

        if not cookies:
            return {}

        return {
            "cookies": cookies,
            "total": len(cookies),
            "insecure_count": sum(1 for c in cookies if not c["secure"]),
            "no_httponly_count": sum(1 for c in cookies if not c["http_only"]),
            "no_samesite_count": sum(1 for c in cookies if not c["samesite"]),
        }