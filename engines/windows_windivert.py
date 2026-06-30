"""Windows WinDivert engine adapter."""

from __future__ import annotations

from .base import EngineInfo, EventCallback, LogCallback
from divert_engine import DivertEngine, sniff_outbound_ports as _sniff_outbound_ports


ENGINE_INFO = EngineInfo(
    key="windows_windivert",
    name="Windows WinDivert",
    supported=True,
    requires_admin=True,
    transparent=True,
    reason="",
    supports_port_diagnostics=True,
)


def create_engine(
    mode: str = "Standard",
    log_callback: LogCallback | None = None,
    event_callback: EventCallback | None = None,
) -> DivertEngine:
    return DivertEngine(
        mode=mode,
        log_callback=log_callback,
        event_callback=event_callback,
    )


def sniff_outbound_ports(log, duration: float = 30.0, stop_event=None):
    return _sniff_outbound_ports(log, duration=duration, stop_event=stop_event)
