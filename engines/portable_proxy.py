"""Portable local proxy engine.

This backend is not a transparent packet engine. It starts the legacy
HTTP/HTTPS proxy and relies on the user or host OS to route selected apps
through it.
"""

from __future__ import annotations

import time

from .base import EngineInfo, EventCallback, LogCallback
from bypass_proxy import BypassProxyServer


HOST = "127.0.0.1"
PORT = 10809
PROXY_ADDRESS = f"{HOST}:{PORT}"

ENGINE_INFO = EngineInfo(
    key="portable_proxy",
    name="Portable local proxy",
    supported=True,
    requires_admin=False,
    transparent=False,
    reason=(
        "Local proxy mode is available. Configure the app or OS proxy to "
        f"{PROXY_ADDRESS}; traffic that ignores proxy settings is not covered."
    ),
    proxy_address=PROXY_ADDRESS,
    supports_port_diagnostics=False,
)


class PortableProxyEngine:
    def __init__(
        self,
        mode: str = "Standard",
        log_callback: LogCallback | None = None,
        event_callback: EventCallback | None = None,
    ):
        self._mode = mode
        self.log_callback = log_callback
        self.event_callback = event_callback
        self.server = BypassProxyServer(
            host=HOST,
            port=PORT,
            bypass_mode=mode,
            use_doh=True,
            log_callback=log_callback,
            event_callback=event_callback,
        )
        self.stats = self.server.stats
        self.running = False

    @property
    def mode(self) -> str:
        return self._mode

    @mode.setter
    def mode(self, value: str) -> None:
        self._mode = value
        if hasattr(self, "server"):
            self.server.bypass_mode = value

    def _log(self, message: str, level: str = "SYSTEM") -> None:
        if self.log_callback:
            self.log_callback(f"[{time.strftime('%H:%M:%S')}] [{level}] {message}")

    def start(self) -> bool:
        self.server.bypass_mode = self.mode
        ok = self.server.start()
        self.running = ok
        if ok:
            self._log(
                f"Local proxy mode active on {PROXY_ADDRESS}. "
                "Configure HTTP and HTTPS proxy settings manually for apps you want covered."
            )
        return ok

    def stop(self) -> None:
        self.server.stop()
        self.running = False


def create_engine(
    mode: str = "Standard",
    log_callback: LogCallback | None = None,
    event_callback: EventCallback | None = None,
) -> PortableProxyEngine:
    return PortableProxyEngine(
        mode=mode,
        log_callback=log_callback,
        event_callback=event_callback,
    )
