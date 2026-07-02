from typing import Any, Optional

import requests

from core.base_checker import BaseChecker
from core.http_client import fetch
from core.registry import register


@register("html")
class HTMLChecker(BaseChecker):
    name = "html"
    needs_shared_page = True

    def __init__(self, url: str, response: Optional[requests.Response] = None):
        super().__init__(url)
        self._response = response

    def _check(self) -> dict[str, Any]:
        r = self._response if self._response is not None else fetch(self.url)
        html = r.text

        return {
            "script_count": html.count("<script"),
            "iframe_count": html.count("<iframe"),
            "form_count": html.count("<form"),
            "external_links": html.count("http"),
        }

