from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping


@dataclass(slots=True, frozen=True)
class Fingerprint:
    name: str
    category: str

    headers: Mapping[str, str] = field(default_factory=dict)
    cookies: Mapping[str, str | None] = field(default_factory=dict)
    meta: Mapping[str, str] = field(default_factory=dict)
    html: tuple[str, ...] = ()
    scripts: tuple[str, ...] = ()

    confidence: int = 100


FINGERPRINTS: tuple[Fingerprint, ...] = (

    # Web Servers

    Fingerprint(
        name="nginx",
        category="server",
        headers={
            "server": "nginx",
        },
    ),

    Fingerprint(
        name="Apache",
        category="server",
        headers={
            "server": "apache",
        },
    ),

    Fingerprint(
        name="Microsoft IIS",
        category="server",
        headers={
            "server": "microsoft-iis",
        },
    ),

    Fingerprint(
        name="Caddy",
        category="server",
        headers={
            "server": "caddy",
        },
    ),

    # CDN

    Fingerprint(
        name="Cloudflare",
        category="cdn",
        headers={
            "server": "cloudflare",
        },
    ),

    Fingerprint(
        name="Fastly",
        category="cdn",
        headers={
            "x-served-by": "",
        },
    ),

    Fingerprint(
        name="Akamai",
        category="cdn",
        headers={
            "server": "akamai",
        },
    ),

    # CMS

    Fingerprint(
        name="WordPress",
        category="cms",
        html=(
            "/wp-content/",
            "/wp-includes/",
        ),
    ),

    Fingerprint(
        name="Joomla",
        category="cms",
        html=(
            "/media/system/",
            "joomla",
        ),
    ),

    Fingerprint(
        name="Drupal",
        category="cms",
        html=(
            "/sites/default/",
            "drupal-settings-json",
        ),
    ),

    # Frameworks

    Fingerprint(
        name="Laravel",
        category="framework",
        cookies={
            "laravel_session": None,
        },
    ),

    Fingerprint(
        name="Django",
        category="framework",
        cookies={
            "csrftoken": None,
            "sessionid": None,
        },
    ),

    Fingerprint(
        name="ASP.NET",
        category="framework",
        headers={
            "x-powered-by": "asp.net",
        },
    ),

    Fingerprint(
        name="Express",
        category="framework",
        headers={
            "x-powered-by": "express",
        },
    ),

    # JavaScript Frameworks

    Fingerprint(
        name="React",
        category="javascript",
        html=(
            "__REACT_DEVTOOLS_GLOBAL_HOOK__",
            "_reactRootContainer",
        ),
    ),

    Fingerprint(
        name="Vue.js",
        category="javascript",
        html=(
            "__VUE__",
            "data-v-",
        ),
    ),

    Fingerprint(
        name="Angular",
        category="javascript",
        html=(
            "ng-version",
        ),
    ),

    Fingerprint(
        name="Next.js",
        category="framework",
        html=(
            "__NEXT_DATA__",
            "/_next/static/",
        ),
    ),
)
Fingerprint(
    name="Cloudflare WAF",
    category="waf",
    headers={
        "cf-ray": "",
    },
),

Fingerprint(
    name="PHP",
    category="language",
    headers={
        "x-powered-by": "php",
    },
),

Fingerprint(
    name="ASP.NET",
    category="language",
    headers={
        "x-powered-by": "asp.net",
    },
),

Fingerprint(
    name="Bootstrap",
    category="frontend",
    html=(
        "bootstrap.min.css",
        "bootstrap.bundle.min.js",
    ),
),

Fingerprint(
    name="jQuery",
    category="frontend",
    html=(
        "jquery.min.js",
        "jquery.js",
    ),
),

Fingerprint(
    name="Tailwind CSS",
    category="frontend",
    html=(
        "tailwindcss",
        "tailwind.min.css",
    ),
),

Fingerprint(
    name="Google Analytics",
    category="analytics",
    html=(
        "googletagmanager.com",
        "google-analytics.com",
        "gtag(",
    ),
),

Fingerprint(
    name="Google Tag Manager",
    category="analytics",
    html=(
        "googletagmanager",
        "gtm.js",
    ),
),

Fingerprint(
    name="Cloudinary",
    category="service",
    html=(
        "res.cloudinary.com",
    ),
),

Fingerprint(
    name="Font Awesome",
    category="frontend",
    html=(
        "font-awesome",
        "fontawesome",
    ),
),