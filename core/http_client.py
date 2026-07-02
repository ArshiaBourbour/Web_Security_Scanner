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
