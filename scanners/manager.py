import threading
from typing import Optional

import requests

from core.http_client import fetch
from core.registry import available_steps, discover_checkers, get_checker
from core.result import CheckResult, CheckStatus
from logging_config import get_logger

_log = get_logger("manager")

# Importing the checker modules is what triggers their @register(...)
# decorators. discover_checkers() auto-imports every module in the
# scanner package, so adding a new scanner file (with @register on its
# class) is the only change needed -- ScanManager itself never changes.
discover_checkers()


class ScanManager:
    """Dispatches each scan step to its registered checker.

    Headers and HTML both need the same page, so the manager fetches it
    once and shares the response with any checker that declares
    needs_shared_page = True -- this replaces the two separate,
    duplicate GET requests that used to happen. Steps may now run
    concurrently (see app.py), so the shared fetch is guarded by a lock:
    without it, two threads could both see "not fetched yet" at the same
    time and fetch the page twice anyway.
    """

    def __init__(self, target: str):
        self.target = target
        self._page_cache: Optional[requests.Response] = None
        self._page_fetch_attempted = False
        self._page_lock = threading.Lock()

    def _get_page(self) -> Optional[requests.Response]:
        """Fetch the target page once and cache it for this scan.
        Thread-safe: concurrent callers block on the lock instead of
        racing. Returns None if the fetch fails -- callers fall back to
        fetching it themselves individually (each still handles its own
        errors)."""
        with self._page_lock:
            if self._page_fetch_attempted:
                return self._page_cache

            self._page_fetch_attempted = True
            try:
                self._page_cache = fetch(self.target)
            except Exception as exc:
                _log.debug(
                    "shared page fetch failed, checkers will fetch individually: %s", exc
                )
                self._page_cache = None

            return self._page_cache

    def run_step(self, step: str) -> CheckResult:
        """Runs one scan step and returns the full typed CheckResult
        (status, data, error, duration) -- not just the raw dict. This
        is what RiskAnalyzer and the report printer consume now, so a
        genuine failure is distinguishable from "nothing found"."""
        try:
            checker_cls = get_checker(step)
        except KeyError:
            _log.warning("no scanner registered for step '%s'", step)
            return CheckResult(name=step, status=CheckStatus.ERROR, error="unknown step")

        if checker_cls.needs_shared_page:
            checker = checker_cls(self.target, response=self._get_page())
        else:
            checker = checker_cls(self.target)

        return checker.run()

    @staticmethod
    def available_steps() -> list[str]:
        """All registered scanner names, for callers that want to
        introspect what's available instead of hardcoding a list."""
        return available_steps()
