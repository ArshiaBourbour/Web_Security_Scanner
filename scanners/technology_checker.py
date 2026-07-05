from __future__ import annotations

from typing import Optional

import requests
from bs4 import BeautifulSoup

from core.base_checker import BaseChecker
from core.http_client import fetch
from core.registry import register
from detection.engine import DetectionEngine


@register("technology")
class TechnologyChecker(BaseChecker):
    """Detect technologies used by the target website."""

    needs_shared_page = True

    def __init__(self, url: str, response: Optional[requests.Response] = None):
        super().__init__(url)
        self._response = response

    def _check(self) -> dict:
        response = self._response if self._response is not None else fetch(self.url)

        headers = dict(response.headers)

        cookies = {
            cookie.name: cookie.value
            for cookie in response.cookies
        }

        html = response.text

        soup = BeautifulSoup(html, "html.parser")

        meta = {}

        for tag in soup.find_all("meta"):
            name = (
                tag.get("name")
                or tag.get("property")
                or tag.get("http-equiv")
            )

            content = tag.get("content")

            if name and content:
                meta[name.lower()] = content

        engine = DetectionEngine()

        technologies = engine.detect(
            headers=headers,
            cookies=cookies,
            html=html,
            meta=meta,
        )

        return technologies