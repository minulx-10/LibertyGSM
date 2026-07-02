# LibertyGSM platform support

LibertyGSM now has a platform engine boundary in `engines/`. The shared Python
core can be imported on non-Windows systems. Full transparent packet handling
still requires a native packet engine for each operating system, but desktop
non-Windows hosts can run the portable local proxy preview.

## Release support matrix

| Platform | Release status | Packet engine | Notes |
| --- | --- | --- | --- |
| Windows 10/11 | Supported | WinDivert via `pydivert` | Current production path. Requires Administrator. |
| macOS | Supported (browsers) | Portable local proxy + auto system-proxy | Local proxy (TLS fragmentation + DoH); the system HTTP/HTTPS proxy is auto-set via `networksetup` on start and restored on stop, so browsers work with no manual setup. Apps that ignore the OS proxy aren't covered — full all-app transparent mode still needs a signed Network Extension. |
| Linux desktop | Supported (browsers) | Portable local proxy + auto system-proxy | Same, with the GNOME proxy auto-configured via `gsettings` (falls back to a manual-config hint on non-GNOME). Full all-app mode needs a TUN/netfilter backend. |
| Android | Supported (5.0+/API 21) | `VpnService` / TUN + Go core (`core-go/tunnel`) | System-wide, all apps. Go gVisor netstack drives the TUN fd; DoH for DNS, TLS ClientHello record fragmentation, QUIC dropped to TCP. Tested on a real device on a filtered school network. |
| iOS | Compiles (CI-verified), not device-tested | `NEPacketTunnelProvider` + Go core (`core-go/tunnel`) | Swift extension + container app + xcframework in `apple/` reuse the same Go core as Android. The `ios-build` GitHub Actions workflow builds the Go core into an xcframework (gomobile) and compiles the app + extension on a macOS runner — **green**. Installing on a real device still needs a Mac + paid Apple Developer account (packet-tunnel entitlement); the runtime `// VERIFY:` items in `apple/README.md` are unconfirmed. |
| iPadOS | Compiles (CI-verified), not device-tested | `NEPacketTunnelProvider` + Go core | Same universal target as iOS. |

## Why the non-Windows targets are gated

The current Windows release works by diverting outbound packets through
WinDivert. WinDivert is Windows-specific, so the same transparent behavior must
be implemented through the native packet APIs on other platforms.

The portable local proxy preview runs the legacy HTTP/HTTPS CONNECT proxy on
`127.0.0.1:10809`. It can fragment proxied TLS ClientHello messages, but it
only covers traffic from apps that honor proxy settings. It cannot intercept
raw UDP/53 DNS, force QUIC fallback globally, or cover apps that bypass proxy
configuration.

Apple's packet tunnel provider model exposes a virtual network interface through
`NEPacketTunnelProvider.packetFlow`. A release-quality macOS, iOS, or iPadOS
build must therefore include a native Network Extension target, correct
entitlements, signing, install/activation UX, and device-level packet tests.

Android's `VpnService` creates a VPN interface with `VpnService.Builder` and
returns a file descriptor for packet exchange. The shipped Android build
(`android/`) does exactly this: `LibertyVpnService` establishes an IPv4 TUN and
hands the fd to the shared Go core (`core-go/tunnel`, gomobile-bound to
`libgsm.aar`), which drives a gVisor userspace TCP/IP stack — DoH for DNS, TLS
record fragmentation for TCP, QUIC dropped so apps fall back to fragmented TCP.
The native side only implements `VpnService.protect` so the core's upstream
sockets escape the tunnel. Consent flow, foreground service, and revoke handling
are wired up; verified on a real device on a filtered school network.

Reference APIs:

- Apple `NEPacketTunnelProvider`: https://developer.apple.com/documentation/networkextension/nepackettunnelprovider
- Apple `packetFlow`: https://developer.apple.com/documentation/networkextension/nepackettunnelprovider/packetflow
- Android `VpnService.Builder`: https://developer.android.com/reference/android/net/VpnService.Builder
- WinDivert: https://reqrypt.org/windivert.html

## Shared logic that should be reused

The long-term plan is a **single portable core in Go** (`core-go/`) that backs
every platform — desktop binaries directly, and Android/iOS via `gomobile bind`
— so the bypass algorithm is maintained once instead of once per language (the
approach Jigsaw's Intra uses). The Python modules remain the Windows runtime
until a Go-based engine replaces them; both are kept equivalent via the same
test fixtures.

- Portable cross-platform core (canonical, going forward): `core-go/tlsfrag`
  (fragmentation, SNI parsing, exclude-host matching; DoH next).
- TLS ClientHello parsing and record-layer fragmentation (Python runtime): `tls_frag.py`
- Exclude-host matching and default whitelist handling (Python runtime): `tls_frag.py`
- Platform engine contract and target state: `engines/`
- Desktop local proxy preview: `engines/portable_proxy.py` and `bypass_proxy.py`
- Release smoke checks: `scripts/release_check.py` (Python) + `core-go` Go tests in CI

## Criteria before marking another OS supported

1. The target has a native packet engine checked into the repo, unless it is
   explicitly documented as local-proxy preview only.
2. The engine implements the same lifecycle as `engines.base.BypassEngine`.
3. DNS interception, QUIC blocking/fallback behavior, and TLS record
   fragmentation are covered by automated tests where possible.
4. The target has a reproducible build command documented in `README.md`.
5. The target is tested on at least one real device or host OS install.
6. `scripts/release_check.py` passes on the target OS.
