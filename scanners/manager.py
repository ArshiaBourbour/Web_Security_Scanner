import threading
from typing import Optional

import requests

from core.http_client import fetch
from core.registry import available_steps, discover_checkers, get_checker
from core.result import CheckResult, CheckStatus
from logging_config import get_logger

_log = get_logger("manager")
discover_checkers()


class ScanManager:
    def __init__(self, target: str):
        self.target = target
        self._page_cache: Optional[requests.Response] = None
        self._page_fetch_attempted = False
        self._page_lock = threading.Lock()

    def _get_page(self) -> Optional[requests.Response]:
        with self._page_lock:
            if self._page_fetch_attempted:
                return self._page_cache

            self._page_fetch_attempted = True
            try:
                self._page_cache = fetch(self.target)
            except Exception as exc:
                _log.debug(
                    "shared page fetch failed, checkers will fetch individually: %s",
                    exc,
                )
                self._page_cache = None

            return self._page_cache

    def run_step(self, step: str) -> CheckResult:
        try:
            checker_cls = get_checker(step)
        except KeyError:
            _log.warning("no scanner registered for step '%s'", step)
            return CheckResult(
                name=step, status=CheckStatus.ERROR, error="unknown step"
            )

        if checker_cls.needs_shared_page:
            checker = checker_cls(self.target, response=self._get_page())
        else:
            checker = checker_cls(self.target)

        return checker.run()

    @staticmethod
    def available_steps() -> list[str]:
        return available_steps()
