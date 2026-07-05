from __future__ import annotations

from collections import defaultdict

from .fingerprints import FINGERPRINTS, Fingerprint


class DetectionEngine:
    """Detect technologies from response data."""

    def detect(
        self,
        *,
        headers: dict[str, str],
        cookies: dict[str, str],
        html: str,
        meta: dict[str, str],
    ) -> dict[str, list[str]]:

        detected: dict[str, set[str]] = defaultdict(set)

        headers = {k.lower(): str(v).lower() for k, v in headers.items()}
        cookies = {k.lower(): str(v).lower() for k, v in cookies.items()}
        meta = {k.lower(): str(v).lower() for k, v in meta.items()}
        html = html.lower()

        for fingerprint in FINGERPRINTS:

            if self._match(fingerprint, headers, cookies, meta, html):
                detected[fingerprint.category].add(fingerprint.name)

        return {
            category: sorted(values)
            for category, values in detected.items()
        }

    def _match(
        self,
        fp: Fingerprint,
        headers: dict[str, str],
        cookies: dict[str, str],
        meta: dict[str, str],
        html: str,
    ) -> bool:

        if fp.headers:
            if self._match_headers(fp.headers, headers):
                return True

        if fp.cookies:
            if self._match_cookies(fp.cookies, cookies):
                return True

        if fp.meta:
            if self._match_meta(fp.meta, meta):
                return True

        if fp.html:
            if self._match_html(fp.html, html):
                return True

        if fp.scripts:
            if self._match_html(fp.scripts, html):
                return True

        return False

    @staticmethod
    def _match_headers(
        expected: dict[str, str],
        headers: dict[str, str],
    ) -> bool:

        for key, value in expected.items():

            current = headers.get(key.lower())

            if current is None:
                return False

            if value and value.lower() not in current:
                return False

        return True

    @staticmethod
    def _match_cookies(
        expected: dict[str, str | None],
        cookies: dict[str, str],
    ) -> bool:

        for key, value in expected.items():

            current = cookies.get(key.lower())

            if current is None:
                return False

            if value is not None and value.lower() not in current:
                return False

        return True

    @staticmethod
    def _match_meta(
        expected: dict[str, str],
        meta: dict[str, str],
    ) -> bool:

        for key, value in expected.items():

            current = meta.get(key.lower())

            if current is None:
                return False

            if value.lower() not in current:
                return False

        return True

    @staticmethod
    def _match_html(
        signatures: tuple[str, ...],
        html: str,
    ) -> bool:

        for signature in signatures:

            if signature.lower() in html:
                return True

        return False