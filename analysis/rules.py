from __future__ import annotations

from dataclasses import dataclass

from .finding import Severity


@dataclass(slots=True, frozen=True)
class Rule:
    """
    Generic rule used by FindingEngine.
    """

    id: str

    scanner: str

    field: str

    severity: Severity

    title: str

    description: str

    recommendation: str

    expected: str | None = None
