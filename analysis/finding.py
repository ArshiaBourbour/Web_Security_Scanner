from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """
    Severity levels used across the entire application.
    """

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def weight(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 2,
            Severity.MEDIUM: 5,
            Severity.HIGH: 10,
            Severity.CRITICAL: 20,
        }[self]


@dataclass(slots=True, frozen=True)
class Finding:
    """
    Represents a single security finding.
    """

    id: str

    scanner: str

    severity: Severity

    title: str

    description: str

    recommendation: str

    affected: str | None = None

    evidence: Any | None = None

    cwe: str | None = None

    cve: str | None = None

    references: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return asdict(self)
