from typing import Any

import whois

from core.base_checker import BaseChecker
from core.registry import register


@register("whois")
class WhoisChecker(BaseChecker):
    """Looks up domain registrar, creation/expiration dates, name servers.

    Same fields as before. The bare except that used to hide lookup
    failures is now handled by BaseChecker.run(), which logs the error
    and reports it as a proper ERROR status instead of an empty {}.
    """

    name = "whois"

    def _check(self) -> dict[str, Any]:
        domain = whois.whois(self.hostname)

        return {
            "domain": domain.domain_name,
            "registrar": domain.registrar,
            "creation_date": str(domain.creation_date),
            "expiration_date": str(domain.expiration_date),
            "name_servers": domain.name_servers,
        }

