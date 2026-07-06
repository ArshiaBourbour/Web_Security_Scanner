from __future__ import annotations
SENSITIVE_KEYWORDS = [
    "admin",
    "backup",
    "config",
    "secret",
    "private",
    "credential",
    "database",
    ".git",
    ".env",
    ".sql",
    ".bak",
    ".zip",
    ".tar",
    "wp-admin",
    "phpmyadmin",
    "api-key",
    "apikey",
    "internal",
    "staging",
    "debug",
    "test",
    "console",
    "dashboard",
]


def looks_sensitive(path: str) -> bool:
    lowered = path.lower()
    return any(keyword in lowered for keyword in SENSITIVE_KEYWORDS)