from __future__ import annotations

import requests

from config import REQUEST_TIMEOUT, USER_AGENT


def fetch(url: str) -> requests.Response:
    response = requests.get(
        url,
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
    )
    return response


def request(url: str, method: str, allow_redirects: bool = False) -> requests.Response:
    return requests.request(
        method,
        url,
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
        allow_redirects=allow_redirects,
    )