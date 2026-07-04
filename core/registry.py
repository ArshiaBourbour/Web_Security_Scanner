
from __future__ import annotations

import importlib
import pkgutil
from typing import Type

from core.base_checker import BaseChecker

_REGISTRY: dict[str, Type[BaseChecker]] = {}
_ORDER: list[str] = []

_DISCOVERED = False


def register(name: str):

    def decorator(cls: Type[BaseChecker]) -> Type[BaseChecker]:
        if name in _REGISTRY and _REGISTRY[name] is not cls:
            raise ValueError(f"Scanner '{name}' is already registered")
        cls.name = name
        _REGISTRY[name] = cls
        if name not in _ORDER:
            _ORDER.append(name)
        return cls

    return decorator


def get_checker(name: str) -> Type[BaseChecker]:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(f"No scanner registered under '{name}'") from None


def available_steps() -> list[str]:
    return list(_ORDER)


def discover_checkers(package_name: str = "scanners") -> None:
    global _DISCOVERED
    if _DISCOVERED:
        return

    package = importlib.import_module(package_name)
    for _, module_name, _ in pkgutil.iter_modules(
        package.__path__, prefix=f"{package_name}."
    ):
        importlib.import_module(module_name)

    _DISCOVERED = True
