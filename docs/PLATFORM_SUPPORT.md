# LibertyGSM platform support

LibertyGSM now has a platform engine boundary in `engines/`. The shared Python
core can be imported on non-Windows systems. Full transparent packet handling
still requires a native packet engine for each operating system, but desktop
non-Windows hosts can run the portable local proxy preview.

## Release support matrix

| Platform | Release status | Packet engine | Notes |
| --- | --- | --- | --- |
| Windows 10/11 | Supported | WinDivert via `pydivert` | Current production path. Requires Administrator. |
| macOS | Preview | Portable local proxy | Requires manual HTTP/HTTPS proxy settings. Full-system mode still needs a signed Network Extension target and device testing. |
| Linux desktop | Preview | Portable local proxy | Requires manual HTTP/HTTPS proxy settings. Full-system mode needs a TUN/netfilter backend. |
| Android | Not release-supported yet | `VpnService` / TUN | Needs a native Android service that reads/writes the VPN file descriptor. |
| iOS | Not release-supported yet | `NEPacketTunnelProvider` | Needs Apple Network Extension entitlement, app extension, signing, and real-device testing. |
| iPadOS | Not release-supported yet | `NEPacketTunnelProvider` | Same constraints as iOS. |

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
returns a file descriptor for packet exchange. A release-quality Android build
must include a native service, VPN consent flow, lifecycle/revoke handling, and
packet tests on real devices.

Reference APIs:

- Apple `NEPacketTunnelProvider`: https://developer.apple.com/documentation/networkextension/nepackettunnelprovider
- Apple `packetFlow`: https://developer.apple.com/documentation/networkextension/nepackettunnelprovider/packetflow
- Android `VpnService.Builder`: https://developer.android.com/reference/android/net/VpnService.Builder
- WinDivert: https://reqrypt.org/windivert.html

## Shared logic that should be reused

- TLS ClientHello parsing and record-layer fragmentation: `tls_frag.py`
- Exclude-host matching and default whitelist handling: `tls_frag.py`
- Platform engine contract and target state: `engines/`
- Desktop local proxy preview: `engines/portable_proxy.py` and `bypass_proxy.py`
- Release smoke checks: `scripts/release_check.py`

## Criteria before marking another OS supported

1. The target has a native packet engine checked into the repo, unless it is
   explicitly documented as local-proxy preview only.
2. The engine implements the same lifecycle as `engines.base.BypassEngine`.
3. DNS interception, QUIC blocking/fallback behavior, and TLS record
   fragmentation are covered by automated tests where possible.
4. The target has a reproducible build command documented in `README.md`.
5. The target is tested on at least one real device or host OS install.
6. `scripts/release_check.py` passes on the target OS.
