from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class CheckStatus(str, Enum):
    OK = "ok"         
    EMPTY = "empty"    
    ERROR = "error"     


@dataclass
class CheckResult:
    name: str                        
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
        return self.data.get(key, default)
