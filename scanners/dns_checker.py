from typing import Any

import dns.resolver

from core.base_checker import BaseChecker
from core.registry import register


@register("dns")
class DNSChecker(BaseChecker):
    """Resolves A, AAAA, MX, NS and TXT records.

    Each record type is looked up independently: a missing AAAA record
    (very common) shouldn't be treated as a failure of the whole check,
    so per-record lookups still catch their own errors -- same behavior
    as before, just logged at debug level instead of silently swallowed.
    """

    name = "dns"

    def _query(self, record: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(self.hostname, record)
            return [str(a) for a in answers]
        except Exception as exc:
            self._log.debug("no %s record for %s: %s", record, self.hostname, exc)
            return []

    def _check(self) -> dict[str, Any]:
        return {
            "A": self._query("A"),
            "AAAA": self._query("AAAA"),
            "MX": self._query("MX"),
            "NS": self._query("NS"),
            "TXT": self._query("TXT"),
        }

