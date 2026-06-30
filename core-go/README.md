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
  and `IsHostExcluded` + `DefaultExcludeHosts`. A faithful port of the Python
  `tls_frag.py`, with unit tests (`go test ./...`).

## Status / roadmap

- [x] Fragmentation + SNI + exclude-host core, with tests.
- [ ] DoH resolver (wire-format, connection pool) — port of the Python `DohClient`.
- [ ] A minimal gomobile-friendly facade (gomobile can't export `[][]byte`, so
      expose a small `Fragmenter` object or a length-prefixed buffer).
- [ ] Android `VpnService` app wrapping the `.aar`.
- [ ] iOS/iPadOS `NEPacketTunnelProvider` app wrapping the `.xcframework`
      (needs an Apple Developer account + real-device testing).
- [ ] Replace the desktop engines' algorithm with this core over time. Until
      then, the Windows runtime keeps using the Python `tls_frag.py`; both are
      kept byte-for-byte equivalent (same fixtures/tests).

## Develop

```bash
cd core-go
go test ./...
```
