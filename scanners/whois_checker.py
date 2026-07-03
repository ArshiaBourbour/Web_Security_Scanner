from typing import Any

import whois

from core.base_checker import BaseChecker
from core.registry import register


@register("whois")
class WhoisChecker(BaseChecker):
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
