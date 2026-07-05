from __future__ import annotations

from dataclasses import dataclass

from .finding import Severity


@dataclass(slots=True, frozen=True)
class Rule:
    
    ## Generic rule used by FindingEngine.
    

    id: str

    scanner: str

    field: str

    severity: Severity

    title: str

    description: str

    recommendation: str

    expected: str | None = None

HEADER_RULES = [

    Rule(
        id="HDR001",

        scanner="headers",

        field="Content-Security-Policy",

        severity=Severity.HIGH,

        title="Missing Content Security Policy",

        description="The response does not include a Content-Security-Policy header.",

        recommendation="Configure a restrictive Content-Security-Policy."
    ),

    Rule(
        id="HDR002",

        scanner="headers",

        field="Strict-Transport-Security",

        severity=Severity.MEDIUM,

        title="Missing HSTS",

        description="Strict Transport Security is not enabled.",

        recommendation="Enable HSTS with a long max-age."
    ),

    Rule(
        id="HDR003",

        scanner="headers",

        field="X-Frame-Options",

        severity=Severity.MEDIUM,

        title="Missing X-Frame-Options",

        description="Clickjacking protection is missing.",

        recommendation="Use DENY or SAMEORIGIN."
    ),

    Rule(
        id="HDR004",

        scanner="headers",

        field="X-Content-Type-Options",

        severity=Severity.LOW,

        title="Missing X-Content-Type-Options",

        description="MIME sniffing protection is disabled.",

        recommendation="Use X-Content-Type-Options: nosniff."
    ),

    Rule(
        id="HDR005",

        scanner="headers",

        field="Referrer-Policy",

        severity=Severity.LOW,

        title="Missing Referrer-Policy",

        description="The browser may leak sensitive URLs.",

        recommendation="Set Referrer-Policy."
    ),

    Rule(
        id="HDR006",

        scanner="headers",

        field="Permissions-Policy",

        severity=Severity.LOW,

        title="Missing Permissions-Policy",

        description="Browser features are not restricted.",

        recommendation="Configure Permissions-Policy."
    ),

]