"""
BaseChecker: shared behavior for every scanner module.

Previously, hostname extraction (`_extract` / `_extract_hostname`) and
try/except-return-{} error handling were copy-pasted into ssl_checker.py,
dns_checker.py, whois_checker.py, headers_checker.py and html_checker.py.

Subclasses now only implement `_check()` with their actual logic (the
part that's genuinely different per checker) and raise normal exceptions
on failure -- BaseChecker.run() takes care of timing, catching, logging,
and wrapping everything into a CheckResult.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import urlparse

from core.result import CheckResult, CheckStatus
from logging_config import get_logger


class BaseChecker(ABC):
    #: short identifier used in CheckResult.name and in progress/report output
    name: str = "base"

    #: set True on checkers that want ScanManager's shared page fetch
    #: (e.g. HeaderChecker, HTMLChecker) passed in as `response=...`
    needs_shared_page: bool = False

    def __init__(self, url: str):
        self.url = url
        self.hostname = self._extract_hostname(url)
        self._log = get_logger(self.name)

    @staticmethod
    def _extract_hostname(url: str) -> str:
        """Shared hostname extraction, used to be duplicated in every checker."""
        return urlparse(url).hostname or url

    @abstractmethod
    def _check(self) -> dict[str, Any]:
        """Perform the actual check and return raw data.
        Subclasses should let exceptions propagate -- run() handles them."""
        raise NotImplementedError

    def _is_empty(self, data: dict[str, Any]) -> bool:
        """Override in a subclass if 'empty' means something more specific
        than an empty dict (default is fine for most checkers)."""
        return not data

    def check(self) -> dict[str, Any]:
        """Backward-compatible entry point. Old callers (ScanManager,
        RiskAnalyzer, and any external code) that used
        SomeChecker(url).check() and expect a plain dict keep working
        unchanged -- run() does the actual work including error
        handling/logging/timing."""
        return self.run().data

    def run(self) -> CheckResult:
        """Public entry point used by ScanManager. Always returns a
        CheckResult -- never raises."""
        start = time.perf_counter()

        try:
            data = self._check()
            duration = time.perf_counter() - start

            if self._is_empty(data):
                return CheckResult(
                    name=self.name,
                    status=CheckStatus.EMPTY,
                    data=data,
                    duration_seconds=duration,
                )

            return CheckResult(
                name=self.name,
                status=CheckStatus.OK,
                data=data,
                duration_seconds=duration,
            )

        except Exception as exc:  # noqa: BLE001 - intentional: this is the one
            # place in the whole project allowed to catch broadly, because it
            # logs and reports the failure instead of hiding it.
            duration = time.perf_counter() - start
            self._log.warning("check failed for %s: %s", self.hostname, exc)

            return CheckResult(
                name=self.name,
                status=CheckStatus.ERROR,
                data={},
                error=str(exc),
                duration_seconds=duration,
            )
