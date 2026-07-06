from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from core.base_checker import BaseChecker
from core.http_client import request
from core.registry import register
from core.sensitive_paths import looks_sensitive


@register("robots")
class RobotsChecker(BaseChecker):
    """Fetch and analyze robots.txt for disclosure of sensitive paths."""

    name = "robots"

    def _robots_url(self) -> str:
        parsed = urlparse(self.url)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc or parsed.path
        return f"{scheme}://{netloc}/robots.txt"

    def _check(self) -> dict[str, Any]:
        robots_url = self._robots_url()

        response = request(robots_url, "GET", allow_redirects=True)

        if response.status_code == 404:
            return {
                "found": False,
                "status_code": 404,
                "url": robots_url,
            }

        if response.status_code != 200:
            return {
                "found": False,
                "status_code": response.status_code,
                "url": robots_url,
            }

        text = response.text or ""

        user_agents: set[str] = set()
        disallowed_paths: set[str] = set()
        allowed_paths: set[str] = set()
        sitemaps: set[str] = set()
        crawl_delay = None

        for raw_line in text.splitlines():
            line = raw_line.split("#", 1)[0].strip()

            if not line or ":" not in line:
                continue

            field, _, value = line.partition(":")
            field = field.strip().lower()
            value = value.strip()

            if not value:
                continue

            if field == "user-agent":
                user_agents.add(value)
            elif field == "disallow":
                disallowed_paths.add(value)
            elif field == "allow":
                allowed_paths.add(value)
            elif field == "sitemap":
                sitemaps.add(value)
            elif field == "crawl-delay":
                crawl_delay = value

        sensitive_paths = sorted(p for p in disallowed_paths if looks_sensitive(p))

        return {
            "found": True,
            "status_code": 200,
            "url": robots_url,
            "user_agents": sorted(user_agents),
            "disallowed_paths": sorted(disallowed_paths),
            "allowed_paths": sorted(allowed_paths),
            "sitemaps": sorted(sitemaps),
            "sensitive_paths": sensitive_paths,
            "crawl_delay": crawl_delay,
            "raw_length": len(text),
        }