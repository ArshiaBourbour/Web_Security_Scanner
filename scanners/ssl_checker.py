import socket
import ssl
from typing import Any

from config import REQUEST_TIMEOUT
from core.base_checker import BaseChecker
from core.registry import register


@register("ssl")
class SSLChecker(BaseChecker):
    """Fetches the TLS certificate presented on port 443.

    Same fields as before (subject, issuer, notBefore, notAfter, version,
    serialNumber, san). The try/except-return-{} that used to live here is
    now handled once by BaseChecker.run(), which also logs failures instead
    of hiding them.
    """

    name = "ssl"

    def _check(self) -> dict[str, Any]:
        context = ssl.create_default_context()

        with socket.create_connection(
            (self.hostname, 443), timeout=REQUEST_TIMEOUT
        ) as sock:
            with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                cert = ssock.getpeercert()

                return {
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                    "version": cert.get("version"),
                    "serialNumber": cert.get("serialNumber"),
                    "san": cert.get("subjectAltName"),
                }

