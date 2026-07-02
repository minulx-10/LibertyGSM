"""Select the best packet engine for the current platform."""

from __future__ import annotations

import sys

from .base import DiagnosticLogCallback, EngineInfo, EventCallback, LogCallback, UnsupportedPlatformError


_MACOS_REASON = (
    "Browsers are covered automatically — the system HTTP/HTTPS proxy is pointed "
    "at the local proxy on start and restored on stop. Full all-app transparent "
    "mode still needs a Network Extension/Packet Tunnel backend."
)
_IOS_REASON = (
    "iOS/iPadOS support needs an NEPacketTunnelProvider app extension and Apple entitlements. "
    "The packet engine is not implemented yet."
)
_ANDROID_REASON = (
    "Android support needs a VpnService/TUN backend. "
    "The packet engine is not implemented yet."
)
_LINUX_REASON = (
    "Browsers/GNOME apps are covered automatically — the GNOME proxy is pointed "
    "at the local proxy on start and restored on stop. Full all-app transparent "
    "mode needs a TUN/netfilter backend."
)
_GENERIC_REASON = "No packet engine is implemented for this platform yet."


def _unsupported_info(reason: str) -> EngineInfo:
    return EngineInfo(
        key="unsupported",
        name="Unsupported platform",
        supported=False,
        requires_admin=False,
        transparent=False,
        reason=reason,
    )


def _portable_proxy_backend():
    from . import portable_proxy

    return portable_proxy


def _platform_unsupported_info() -> EngineInfo:
    if sys.platform in {"ios", "tvos"}:
        return _unsupported_info(_IOS_REASON)
    if sys.platform == "android":
        return _unsupported_info(_ANDROID_REASON)
    return _unsupported_info(_GENERIC_REASON)


def _windows_backend():
    if sys.platform != "win32":
        raise UnsupportedPlatformError(_platform_unsupported_info().reason)
    try:
        from . import windows_windivert
    except Exception as exc:
        raise UnsupportedPlatformError(f"Windows WinDivert backend unavailable: {exc}") from exc
    return windows_windivert


def get_engine_info() -> EngineInfo:
    if sys.platform == "win32":
        try:
            return _windows_backend().ENGINE_INFO
        except UnsupportedPlatformError as exc:
            return EngineInfo(
                key="windows_windivert",
                name="Windows WinDivert",
                supported=False,
                requires_admin=False,
                transparent=True,
                reason=str(exc),
            )
    if sys.platform == "darwin":
        info = _portable_proxy_backend().ENGINE_INFO
        return EngineInfo(**{**info.__dict__, "reason": _MACOS_REASON + " " + info.reason})
    if sys.platform.startswith("linux"):
        info = _portable_proxy_backend().ENGINE_INFO
        return EngineInfo(**{**info.__dict__, "reason": _LINUX_REASON + " " + info.reason})
    return _platform_unsupported_info()


def create_engine(
    mode: str = "Standard",
    log_callback: LogCallback | None = None,
    event_callback: EventCallback | None = None,
):
    if sys.platform == "win32":
        backend = _windows_backend()
    elif sys.platform == "darwin" or sys.platform.startswith("linux"):
        backend = _portable_proxy_backend()
    else:
        raise UnsupportedPlatformError(_platform_unsupported_info().reason)
    return backend.create_engine(
        mode=mode,
        log_callback=log_callback,
        event_callback=event_callback,
    )


def sniff_outbound_ports(
    log: DiagnosticLogCallback,
    duration: float = 30.0,
    stop_event=None,
):
    try:
        backend = _windows_backend()
    except UnsupportedPlatformError as exc:
        log(f"포트 진단은 현재 Windows WinDivert 엔진에서만 지원됩니다: {exc}", "ERROR")
        return []
    return backend.sniff_outbound_ports(log, duration=duration, stop_event=stop_event)
