from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import requests

from core.base_checker import BaseChecker
from core.http_client import request
from core.registry import register

# Common directories that sometimes get left open on misconfigured servers.
COMMON_PATHS = [
    "/",
    "/images/",
    "/img/",
    "/uploads/",
    "/files/",
    "/assets/",
    "/backup/",
    "/backups/",
    "/includes/",
    "/css/",
    "/js/",
    "/tmp/",
    "/logs/",
    "/data/",
    "/admin/",
]

# Signature strings produced by common webserver directory-listing pages.
SIGNATURES = [
    "index of /",
    "<title>index of",
    "parent directory</a>",
    "directory listing for",
    "[to parent directory]",
]


def _looks_like_listing(text: str) -> bool:
    lowered = text.lower()
    return any(sig in lowered for sig in SIGNATURES)


@register("directory_listing")
class DirectoryListingChecker(BaseChecker):
    """Probe common directories for exposed directory listings."""

    name = "directory_listing"

    def _base_url(self) -> str:
        parsed = urlparse(self.url)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc or parsed.path
        return f"{scheme}://{netloc}"

    def _check(self) -> dict[str, Any]:
        base = self._base_url()
        listings = []

        for path in COMMON_PATHS:
            try:
                response = request(f"{base}{path}", "GET", allow_redirects=True)
            except requests.RequestException:
                continue

            if response.status_code == 200 and _looks_like_listing(response.text):
                listings.append(path)

        if not listings:
            return {"found": False}

        return {"found": True, "listings": listings}