from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlparse

import requests

from core.base_checker import BaseChecker
from core.http_client import request
from core.registry import register
from core.sensitive_paths import looks_sensitive


def _local_name(tag: str) -> str:
    return tag.split("}")[-1] if "}" in tag else tag


def _parse_sitemap_xml(text: str) -> tuple[str, list[str]]:
    root = ET.fromstring(text)
    root_name = _local_name(root.tag)

    locations = []

    if root_name == "sitemapindex":
        for sitemap_el in root:
            if _local_name(sitemap_el.tag) != "sitemap":
                continue
            for child in sitemap_el:
                if _local_name(child.tag) == "loc" and child.text:
                    locations.append(child.text.strip())
        return "index", locations

    if root_name == "urlset":
        for url_el in root:
            if _local_name(url_el.tag) != "url":
                continue
            for child in url_el:
                if _local_name(child.tag) == "loc" and child.text:
                    locations.append(child.text.strip())
        return "urlset", locations

    return "unknown", locations


@register("sitemap")
class SitemapChecker(BaseChecker):
    name = "sitemap"

    MAX_URLS_TO_REPORT = 500
    MAX_CHILD_SITEMAPS = 5

    def _base_url(self) -> str:
        parsed = urlparse(self.url)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc or parsed.path
        return f"{scheme}://{netloc}"

    def _discover_candidate_urls(self, base: str) -> list[str]:
        """Default location plus anything declared in robots.txt."""
        candidates = [f"{base}/sitemap.xml"]

        try:
            robots_response = request(f"{base}/robots.txt", "GET", allow_redirects=True)
        except requests.RequestException:
            return candidates

        if robots_response.status_code != 200:
            return candidates

        for raw_line in robots_response.text.splitlines():
            line = raw_line.split("#", 1)[0].strip()

            if not line.lower().startswith("sitemap:"):
                continue

            _, _, value = line.partition(":")
            value = value.strip()

            if value and value not in candidates:
                candidates.append(value)

        return candidates

    def _fetch_and_parse(self, sitemap_url: str) -> dict[str, Any]:
        try:
            response = request(sitemap_url, "GET", allow_redirects=True)
        except requests.RequestException:
            return {"url": sitemap_url, "found": False, "status_code": None}

        if response.status_code != 200:
            return {
                "url": sitemap_url,
                "found": False,
                "status_code": response.status_code,
            }

        try:
            kind, locations = _parse_sitemap_xml(response.text)
        except ET.ParseError:
            return {
                "url": sitemap_url,
                "found": True,
                "status_code": 200,
                "error": "invalid XML",
            }

        return {
            "url": sitemap_url,
            "found": True,
            "status_code": 200,
            "type": kind,
            "entry_count": len(locations),
            "locations": locations,
        }

    def _check(self) -> dict[str, Any]:
        base = self._base_url()
        candidate_urls = self._discover_candidate_urls(base)

        seen = set(candidate_urls)
        sources = []
        all_urls: set[str] = set()
        child_sitemaps: list[str] = []

        for sitemap_url in candidate_urls:
            source = self._fetch_and_parse(sitemap_url)
            locations = source.pop("locations", [])
            sources.append(source)

            if source.get("type") == "index":
                child_sitemaps.extend(locations)
            else:
                all_urls.update(locations)

        for child_url in child_sitemaps[: self.MAX_CHILD_SITEMAPS]:
            if child_url in seen:
                continue
            seen.add(child_url)

            source = self._fetch_and_parse(child_url)
            locations = source.pop("locations", [])
            sources.append(source)
            all_urls.update(locations)

        if not any(s.get("found") for s in sources):
            return {"found": False, "sources": sources}

        sensitive_urls = sorted(u for u in all_urls if looks_sensitive(u))
        sample_urls = sorted(all_urls)

        return {
            "found": True,
            "sources": sources,
            "total_urls": len(all_urls),
            "sample_urls": sample_urls[: self.MAX_URLS_TO_REPORT],
            "truncated": len(all_urls) > self.MAX_URLS_TO_REPORT,
            "sensitive_urls": sensitive_urls[: self.MAX_URLS_TO_REPORT],
        }