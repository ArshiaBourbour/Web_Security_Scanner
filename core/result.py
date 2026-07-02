"""
Standard output schema for every checker (SSL, Headers, DNS, WHOIS, HTML, ...).

Before this, each checker returned a bare dict and either returned {} on
failure or on "no data found" -- the caller (RiskAnalyzer, the CLI printer)
had no way to tell those two situations apart. CheckResult makes that
explicit and gives every consumer one shape to rely on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class CheckStatus(str, Enum):
    OK = "ok"          # check ran, data found
    EMPTY = "empty"     # check ran fine, but there was nothing to report
    ERROR = "error"      # check failed (network error, timeout, exception, ...)


@dataclass
class CheckResult:
    name: str                          # e.g. "ssl", "dns"
    status: CheckStatus
    data: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration_seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status == CheckStatus.OK

    @property
    def failed(self) -> bool:
        return self.status == CheckStatus.ERROR

    def get(self, key: str, default: Any = None) -> Any:
        """Convenience passthrough so existing dict-style access
        (e.g. ssl_result.get('notAfter')) keeps working on the result's data."""
        return self.data.get(key, default)
