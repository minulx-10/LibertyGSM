"""Portable local proxy engine.

This backend is not a transparent packet engine. It starts the legacy
HTTP/HTTPS proxy and relies on the user or host OS to route selected apps
through it.
"""

from __future__ import annotations

import time

from .base import EngineInfo, EventCallback, LogCallback
from bypass_proxy import BypassProxyServer
from system_proxy import SystemProxy


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
        # Auto-configures the OS proxy on macOS/Linux so browsers use us without
        # manual setup; reverted on stop. No-op / best-effort elsewhere.
        self._sysproxy = SystemProxy(HOST, PORT, log=self._sysproxy_log)

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

    def _sysproxy_log(self, message: str, level: str = "SYSTEM") -> None:
        self._log(message, level)

    def start(self) -> bool:
        self.server.bypass_mode = self.mode
        ok = self.server.start()
        self.running = ok
        if ok:
            # Point the OS proxy at us so browsers are covered automatically.
            if self._sysproxy.apply():
                self._log(f"Local proxy active on {PROXY_ADDRESS} — system proxy auto-configured.")
            else:
                self._log(
                    f"Local proxy active on {PROXY_ADDRESS}. Auto-config unavailable; "
                    "set HTTP+HTTPS proxy to this address for apps you want covered."
                )
        return ok

    def stop(self) -> None:
        # Restore the OS proxy first so the browser isn't left pointing at a dead port.
        self._sysproxy.revert()
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
