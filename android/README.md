# LibertyGSM for Android (plan)

Android's transparent bypass is a `VpnService` app that reuses the Go core
(`core-go/`) via gomobile — **no algorithm is re-implemented in Kotlin.** This is
the same architecture Jigsaw's Intra uses.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Android app (Kotlin) — thin shell                            │
│  • VpnService.Builder: create TUN, addRoute("0.0.0.0", 0)    │
│  • hand the TUN file descriptor to Go                        │
│  • VpnService.protect(socket) so upstream sockets bypass VPN │
└───────────────┬─────────────────────────────────────────────┘
                │ gomobile (.aar)
┌───────────────▼─────────────────────────────────────────────┐
│ Go core (core-go/) — all the real logic, one codebase        │
│  • a userspace TCP/IP stack (gVisor netstack) reads the TUN  │
│  • TCP :443/8080/... → dial protected upstream, then         │
│      mobile.FragmentToWire(firstClientHello, mode) →         │
│      write each record separately, then pipe                 │
│  • UDP :53 → mobile.Resolver.Resolve(query) → write answer   │
│  • UDP :443 (QUIC) → drop, forcing TCP fallback              │
└─────────────────────────────────────────────────────────────┘
```

`core-go/mobile` already exposes everything the shell needs in
gomobile-safe signatures: `FragmentToWire`, `SNIName`, `IsHostExcluded`,
`DefaultExcludeHosts`, and a `Resolver` (`NewResolver`, `Resolve`, `Probe`).

## Build the bindings

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
gomobile bind -target=android -androidapi 21 -o android/libgsm.aar ./core-go/mobile
```

Drop `libgsm.aar` into the app module and call it from Kotlin.

## Kotlin shell (skeleton)

```kotlin
class LibertyVpnService : VpnService() {
    override fun onStartCommand(i: Intent?, f: Int, id: Int): Int {
        val tun = Builder()
            .setSession("LibertyGSM")
            .addAddress("10.111.0.1", 32)
            .addRoute("0.0.0.0", 0)          // capture all IPv4
            .addDnsServer("10.111.0.2")      // sink DNS into the tunnel
            .establish() ?: return START_NOT_STICKY

        // Hand the fd to the Go tunnel. `protect` lets Go's upstream sockets
        // skip the VPN (no loop). Tunnel is a gomobile-bound Go type.
        Tunnel.start(tun.fd, mode = "Standard", protector = { fd -> protect(fd) })
        return START_STICKY
    }
}
```

## Status

- [x] Shared core + DoH + gomobile facade (`core-go/mobile`), tested in CI.
- [ ] Go `tunnel` package: wire gVisor netstack to the TUN fd and route TCP/UDP
      through the facade (the largest remaining piece; model it on Intra's
      `intra/` package).
- [ ] Kotlin app: `VpnService`, consent flow (`VpnService.prepare`), start/stop
      UI, foreground notification, and the `protect()` bridge.
- [ ] Build + on-device testing in Android Studio (cannot be done from the
      Python/Windows dev box; the `.aar` and Kotlin compile there).

## References

- Intra (Go core shared across Android/iOS): https://github.com/Jigsaw-Code/Intra
- `VpnService.Builder`: https://developer.android.com/reference/android/net/VpnService.Builder
- gVisor netstack: https://pkg.go.dev/gvisor.dev/gvisor/pkg/tcpip
- gomobile: https://pkg.go.dev/golang.org/x/mobile/cmd/gomobile
