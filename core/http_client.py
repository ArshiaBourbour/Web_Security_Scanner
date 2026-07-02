"""
Shared page fetch, used by both HeaderChecker and HTMLChecker.

Previously each of those checkers called requests.get(url) independently,
meaning every scan made two separate HTTP requests for the exact same
page. ScanManager now fetches the page once and hands the same Response
to both checkers.

Each checker still works standalone too (e.g. in tests, or if used
outside ScanManager) -- if no pre-fetched response is given, it just
fetches its own, same as before.
"""

from __future__ import annotations

import requests

from config import REQUEST_TIMEOUT, USER_AGENT


def fetch(url: str) -> requests.Response:
    """Fetch a URL with the project's shared timeout/user-agent config.
    Raises on failure -- callers (BaseChecker.run) handle/log the error."""
    response = requests.get(
        url,
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
    )
    return response
