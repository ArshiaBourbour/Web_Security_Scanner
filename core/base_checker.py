from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import urlparse

from core.result import CheckResult, CheckStatus
from logging_config import get_logger


class BaseChecker(ABC):
    name: str = "base"

    needs_shared_page: bool = False

    def __init__(self, url: str):
        self.url = url
        self.hostname = self._extract_hostname(url)
        self._log = get_logger(self.name)

    @staticmethod
    def _extract_hostname(url: str) -> str:
        return urlparse(url).hostname or url

    @abstractmethod
    def _check(self) -> dict[str, Any]:
        raise NotImplementedError

    def _is_empty(self, data: dict[str, Any]) -> bool:
        return not data

    def check(self) -> dict[str, Any]:
        return self.run().data

    def run(self) -> CheckResult:
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

        except Exception as exc: 
            duration = time.perf_counter() - start
            self._log.warning("check failed for %s: %s", self.hostname, exc)

            return CheckResult(
                name=self.name,
                status=CheckStatus.ERROR,
                data={},
                error=str(exc),
                duration_seconds=duration,
            )
