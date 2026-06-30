"""Shared contracts for platform-specific LibertyGSM engines."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol


LogCallback = Callable[[str], None]
EventCallback = Callable[[str, Any], None]
DiagnosticLogCallback = Callable[[str, str], None]


@dataclass(frozen=True)
class EngineInfo:
    key: str
    name: str
    supported: bool
    requires_admin: bool
    transparent: bool
    reason: str = ""
    proxy_address: str = ""
    supports_port_diagnostics: bool = False


class BypassEngine(Protocol):
    mode: str
    running: bool
    stats: dict[str, int]

    def start(self) -> bool:
        ...

    def stop(self) -> None:
        ...


class UnsupportedPlatformError(RuntimeError):
    """Raised when no packet engine exists for the current platform yet."""
