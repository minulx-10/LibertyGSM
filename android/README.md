# LibertyGSM for Android

A `VpnService` app whose entire packet engine is the shared Go core
(`core-go/tunnel`, built on gVisor netstack) exposed via gomobile — **no bypass
logic is re-implemented in Kotlin.** Same architecture as Jigsaw's Intra.

```
Kotlin shell (this module)                     Go core (gomobile .aar)
  MainActivity  ─ START/STOP, VPN consent        tunnel.Connect(fd, mode, …)
  LibertyVpnService                                gVisor netstack on the TUN fd
    • Builder.establish() → TUN fd                  • TCP → protected dial +
    • Tunnel.connect(fd, mode, "", protector)         ClientHello fragmentation
    • Protector.protect(fd)  ◄── Go calls back       • UDP/53 → DoH
                                                     • UDP/443 (QUIC) → drop
```

## Build

1. **Generate the .aar** from the Go core (needs Go 1.26.3+, the Android NDK, and
   gomobile — see the script header):
   ```bash
   cd android
   ./build-aar.sh        # Windows: build-aar.bat
   ```
   This runs `gomobile bind` on `core-go/tunnel` and writes
   `app/libs/libgsm.aar` (gitignored).

2. **Open the `android/` folder in Android Studio** and Run. The app asks for VPN
   permission, then START routes every app through the bypass.

> The `.aar` is generated, not committed, so the Kotlin builds only after step 1.

## Files

| File | Role |
| --- | --- |
| `core-go/tunnel/tunnel.go` | the engine: netstack ↔ TUN, fragmentation, DoH, QUIC drop |
| `app/src/main/java/.../LibertyVpnService.kt` | establishes the TUN, calls `Tunnel.connect`, provides `protect()` |
| `app/src/main/java/.../MainActivity.kt` | START/STOP + VPN consent + mode picker |
| `app/src/main/AndroidManifest.xml` | `BIND_VPN_SERVICE`, foreground-service, the VpnService intent-filter |
| `build-aar.sh` / `.bat` | `gomobile bind` of the Go core |

## Status

- [x] Go packet engine (`core-go/tunnel`) — cross-compiles for android in CI.
- [x] Kotlin VpnService + UI, gradle project, gomobile bridge.
- [ ] On-device testing (build the .aar + run in Android Studio on a real phone).
      The Go side compiles for `GOOS=android` but has not yet been device-tested;
      expect to iterate on routes/MTU/edge cases on first run.

## References

- Intra (Go core shared across Android/iOS): https://github.com/Jigsaw-Code/Intra
- `VpnService.Builder`: https://developer.android.com/reference/android/net/VpnService.Builder
- gomobile: https://pkg.go.dev/golang.org/x/mobile/cmd/gomobile
