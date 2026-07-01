# LibertyGSM — Apple (iOS / iPadOS / macOS)

This directory is the Apple front-end for LibertyGSM. It reuses the **exact same
Go core** as the Android app (`core-go/tunnel`, the gVisor userspace TCP/IP
engine) via `gomobile bind`, wrapped in a `NEPacketTunnelProvider` Network
Extension. One bypass implementation, four platforms.

> ⚠️ **This scaffolding was written on Windows and has NOT been compiled.**
> Building an Apple Network Extension requires a **Mac with Xcode** (and, for
> installing on a real iPhone/iPad, a paid **Apple Developer account** — the
> Packet Tunnel entitlement is not available to free personal teams). Treat the
> Swift here as a strong starting point, not a finished build. Every spot that
> needs on-device verification is marked `// VERIFY:` in the source.

## Architecture (same as Android)

```
NEPacketTunnelProvider (Swift)                 core-go/tunnel (Go, shared)
  ├─ setTunnelNetworkSettings (IPv4-only)        ├─ gVisor netstack from the utun fd
  ├─ extract the utun file descriptor  ──fd──▶   ├─ TCP → protected dial + TLS record frag
  ├─ Protector: bind sockets to the phys. iface  ├─ UDP/53 → DoH
  └─ Tunnel.connect(fd, mode, "", protector)     └─ UDP/443 (QUIC) → drop → TCP fallback
```

Why IPv4-only, why full-ClientHello read, why per-segment flush, why the DoT
sink RST: see the commit that shipped Android (`git log --grep "ship the
VpnService"`). The same reasons apply here — the Go core already does all of it.

## Build steps (on a Mac)

### 1. Prerequisites
```sh
xcode-select --install
brew install go
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
brew install xcodegen        # generates the .xcodeproj from project.yml
```

### 2. Build the Go core into an xcframework
```sh
./build-xcframework.sh       # → apple/LibGSM.xcframework (ios + iossimulator + macos)
```

### 3. Generate and open the Xcode project
```sh
cd LibertyGSM
xcodegen generate            # reads project.yml → LibertyGSM.xcodeproj
open LibertyGSM.xcodeproj
```

### 4. Set your signing team + bundle IDs
In Xcode, for BOTH targets (`LibertyGSMApp` and `PacketTunnel`):
- Signing & Capabilities → select your Team.
- Confirm the **App Groups** id matches in both entitlements (used so the app and
  the extension can share status). Default: `group.com.libertygsm.app`.
- Confirm the extension bundle id is the app id + `.PacketTunnel`.

### 5. Run
Select the `LibertyGSMApp` scheme → run on a real device (the Network Extension
does not work in the iOS Simulator). First launch installs the VPN profile
(system prompt); then the in-app toggle starts/stops the tunnel.

## What still needs Mac verification (the `// VERIFY:` list)

1. **utun fd extraction** (`PacketTunnelProvider.tunnelFileDescriptor`) — the KVC
   path `packetFlow.value(forKeyPath: "socket.fileDescriptor")` is undocumented;
   the fd scan fallback should cover it, but confirm the fd is valid and that the
   Go side can read/write it.
2. **Socket protection** (`InterfaceProtector.protect`) — binding upstream
   sockets to the physical interface so they don't loop back into the tunnel. The
   physical interface is assumed to be the system default route; verify on both
   Wi-Fi and cellular.
3. **Entitlements / provisioning** — `packet-tunnel-provider` needs a paid
   developer account and matching App IDs / provisioning profiles.
4. **App Group** — used for app↔extension status; verify the id is registered.
5. **QUIC** — the Go core drops UDP/443. Confirm apps fall back to TCP cleanly on
   iOS as they do on Android.

## Files

| File | What |
| --- | --- |
| `build-xcframework.sh` | `gomobile bind` of `core-go/tunnel` → `LibGSM.xcframework` |
| `LibertyGSM/project.yml` | XcodeGen spec (two targets: app + extension) |
| `LibertyGSM/App/` | SwiftUI container app + `NETunnelProviderManager` control |
| `LibertyGSM/PacketTunnel/` | the `NEPacketTunnelProvider` that drives the Go core |
