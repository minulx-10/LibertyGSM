"""Best-effort system HTTP/HTTPS proxy auto-configuration for macOS and Linux.

The portable proxy engine runs a local HTTP/HTTPS proxy (with TLS ClientHello
fragmentation + DoH). On its own that only helps apps whose proxy is set by
hand. This module points the OS's proxy at it on start and restores the prior
settings on stop, so browsers "just work" without manual setup.

Everything here is best-effort: the proxy itself runs fine regardless, so any
failure is logged and swallowed, never raised. Windows is handled separately
(sys_proxy.py / the transparent WinDivert engine), so this module only
implements darwin (networksetup) and linux (GNOME gsettings).
"""

from __future__ import annotations

import shutil
import subprocess
import sys


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    """Run a command, capturing output; never raises on non-zero exit."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)


def parse_networksetup_proxy(output: str) -> dict:
    """Parse `networksetup -getwebproxy`/-getsecurewebproxy output into a dict
    with 'enabled' (bool), 'server' (str), 'port' (str). Pure/testable."""
    info = {"enabled": False, "server": "", "port": ""}
    for line in output.splitlines():
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "enabled":
            info["enabled"] = value.lower() in ("yes", "true", "1")
        elif key == "server":
            info["server"] = value
        elif key == "port":
            info["port"] = value
    return info


class SystemProxy:
    """Applies/reverts the OS proxy for host:port. One instance per engine run."""

    def __init__(self, host: str, port: int, log=None):
        self.host = str(host)
        self.port = int(port)
        self._log = log or (lambda *a, **k: None)
        self._applied = False
        self._macos_backup: dict[str, tuple[dict, dict]] = {}  # svc -> (web, secure)
        self._linux_backup_mode: str | None = None

    # -- public API --------------------------------------------------------- #
    def apply(self) -> bool:
        try:
            if sys.platform == "darwin":
                return self._apply_macos()
            if sys.platform.startswith("linux"):
                return self._apply_linux()
        except Exception as exc:  # never let proxy auto-config break the engine
            self._log(f"system proxy auto-config failed: {exc}", "WARNING")
        return False

    def revert(self) -> None:
        if not self._applied:
            return
        try:
            if sys.platform == "darwin":
                self._revert_macos()
            elif sys.platform.startswith("linux"):
                self._revert_linux()
        except Exception as exc:
            self._log(f"system proxy revert failed: {exc}", "WARNING")
        finally:
            self._applied = False

    # -- macOS (networksetup) ---------------------------------------------- #
    def _macos_services(self) -> list[str]:
        # First line is a header; a leading '*' marks a disabled service.
        out = _run(["networksetup", "-listallnetworkservices"]).stdout.splitlines()
        return [s.strip() for s in out[1:] if s.strip() and not s.startswith("*")]

    def _apply_macos(self) -> bool:
        services = self._macos_services()
        if not services:
            return False
        for svc in services:
            self._macos_backup[svc] = (
                parse_networksetup_proxy(_run(["networksetup", "-getwebproxy", svc]).stdout),
                parse_networksetup_proxy(_run(["networksetup", "-getsecurewebproxy", svc]).stdout),
            )
            _run(["networksetup", "-setwebproxy", svc, self.host, str(self.port)])
            _run(["networksetup", "-setsecurewebproxy", svc, self.host, str(self.port)])
        self._applied = True
        self._log(f"System proxy set to {self.host}:{self.port} on: {', '.join(services)}")
        return True

    def _revert_macos(self) -> None:
        for svc, (web, secure) in self._macos_backup.items():
            self._restore_macos_one(svc, "-setwebproxy", "-setwebproxystate", web)
            self._restore_macos_one(svc, "-setsecurewebproxy", "-setsecurewebproxystate", secure)
        self._log("System proxy restored.")

    def _restore_macos_one(self, svc: str, set_cmd: str, state_cmd: str, prior: dict) -> None:
        # If the user had a proxy before, put it back; otherwise turn it off.
        if prior.get("enabled") and prior.get("server"):
            _run(["networksetup", set_cmd, svc, prior["server"], prior.get("port") or "80"])
        else:
            _run(["networksetup", state_cmd, svc, "off"])

    # -- Linux (GNOME gsettings) ------------------------------------------- #
    def _apply_linux(self) -> bool:
        if not shutil.which("gsettings"):
            self._log(
                f"Could not auto-configure the proxy (no gsettings). Set the "
                f"system/browser HTTP+HTTPS proxy to {self.host}:{self.port} manually.",
                "WARNING",
            )
            return False
        self._linux_backup_mode = _run(
            ["gsettings", "get", "org.gnome.system.proxy", "mode"]
        ).stdout.strip().strip("'")
        _run(["gsettings", "set", "org.gnome.system.proxy.http", "host", self.host])
        _run(["gsettings", "set", "org.gnome.system.proxy.http", "port", str(self.port)])
        _run(["gsettings", "set", "org.gnome.system.proxy.https", "host", self.host])
        _run(["gsettings", "set", "org.gnome.system.proxy.https", "port", str(self.port)])
        _run(["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"])
        self._applied = True
        self._log(f"System proxy (GNOME) set to {self.host}:{self.port}.")
        return True

    def _revert_linux(self) -> None:
        mode = self._linux_backup_mode or "none"
        _run(["gsettings", "set", "org.gnome.system.proxy", "mode", mode])
        self._log(f"System proxy (GNOME) restored to '{mode}'.")
