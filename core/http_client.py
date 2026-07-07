from __future__ import annotations

import time

import requests

from config import REQUEST_TIMEOUT, USER_AGENT

# Transient network errors worth a single quiet retry before giving up.
_RETRYABLE_ERRORS = (requests.exceptions.Timeout, requests.exceptions.ConnectionError)


def _with_retry(send, attempts: int = 2, delay: float = 0.5):
    # retries a transient timeout/connection error once before raising
    last_exc = None

    for attempt in range(attempts):
        try:
            return send()
        except _RETRYABLE_ERRORS as exc:
            last_exc = exc
            if attempt < attempts - 1:
                time.sleep(delay)

    raise last_exc


def fetch(url: str) -> requests.Response:
    return _with_retry(
        lambda: requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
    )


def request(url: str, method: str, allow_redirects: bool = False) -> requests.Response:
    return _with_retry(
        lambda: requests.request(
            method,
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=allow_redirects,
        )
    )


def request_with_headers(
    url: str, method: str, extra_headers: dict, allow_redirects: bool = False
) -> requests.Response:
    return _with_retry(
        lambda: requests.request(
            method,
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT, **extra_headers},
            allow_redirects=allow_redirects,
        )
    )