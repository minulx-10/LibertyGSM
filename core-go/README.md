# LibertyGSM core (Go)

The **portable, single-source cross-platform core**. The bypass algorithm —
TLS ClientHello record-layer fragmentation, SNI parsing, exclude-host matching
(and, next, the DoH resolver) — lives here once, in Go, instead of being
re-implemented per platform.

## Why Go

The goal is **easy maintenance + the widest device coverage**. Go is the one
language whose output can back every target we care about, so the algorithm is
written and tested a single time:

| Target | How the Go core is used |
| --- | --- |
| Android | `gomobile bind` → `.aar`, called from a `VpnService` app (Kotlin) |
| iOS / iPadOS | `gomobile bind` → `.xcframework`, called from a `NEPacketTunnelProvider` app (Swift) |
| macOS / Linux / Windows desktop | native Go binary driving the OS packet layer (NE / TUN / WinDivert) |

This is the same approach Jigsaw's **Intra** uses to share one core across
Android and iOS.

## What's here

- `tlsfrag/` — `FragmentClientHello`, `SNILocation`/`SNIName`, `TLSRecordLen`,
  and `IsHostExcluded` + `DefaultExcludeHosts`. A faithful port of `tls_frag.py`.
- `doh/` — DoH resolver (RFC 8484 wire format) with automatic HTTP/2 connection
  pooling and endpoint failover. Port of the Python `DohClient`.
- `mobile/` — the gomobile-friendly facade (mobile-safe signatures) the Android
  and iOS wrappers call: `FragmentToWire`, `SNIName`, `IsHostExcluded`,
  `DefaultExcludeHosts`, and a `Resolver`.

All three have unit tests (`go test ./...`, also run in CI).

## Status / roadmap

- [x] Fragmentation + SNI + exclude-host core, with tests.
- [x] DoH resolver (wire-format, HTTP/2 pooled, failover) — port of `DohClient`.
- [x] gomobile-friendly facade (`mobile/`): `[][]byte` is exposed via a
      length-prefixed wire format (`FragmentToWire`); `[]string` via newline
      strings; DoH via a `Resolver` object.
- [ ] Go `tunnel` package: gVisor netstack ↔ TUN fd (the shared packet engine
      for Android/iOS, modeled on Intra). See `../android/README.md`.
- [ ] Android `VpnService` app wrapping the `.aar`.
- [ ] iOS/iPadOS `NEPacketTunnelProvider` app wrapping the `.xcframework`
      (needs an Apple Developer account + real-device testing).
- [ ] Replace the desktop engines' algorithm with this core over time. Until
      then, the Windows runtime keeps using the Python `tls_frag.py`; both are
      kept equivalent (same fixtures/tests).

## Develop

```bash
cd core-go
go test ./...
```
