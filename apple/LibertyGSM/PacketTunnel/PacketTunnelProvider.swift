import NetworkExtension
import os.log
// gomobile names the module after the xcframework's file name (LibGSM), while
// the exported symbols keep the Go PACKAGE prefix (tunnel → TunnelConnect,
// TunnelSession, TunnelProtector). So: import LibGSM, call Tunnel*.
import LibGSM

/// LibertyGSM packet tunnel. It establishes an IPv4-only utun, extracts its file
/// descriptor, and hands it to the shared Go core (`core-go/tunnel`) — the exact
/// same engine the Android VpnService drives. All packet handling (DoH DNS, TLS
/// record fragmentation, QUIC drop) happens in Go; Swift only provides the fd and
/// a `Protector` so the core's upstream sockets escape the tunnel.
class PacketTunnelProvider: NEPacketTunnelProvider {

    private var session: TunnelSession?
    private let log = OSLog(subsystem: "com.libertygsm.app", category: "tunnel")

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        let settings = makeNetworkSettings()

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                os_log("setTunnelNetworkSettings failed: %{public}@",
                       log: self.log, type: .error, error.localizedDescription)
                completionHandler(error)
                return
            }

            // VERIFY: the utun fd must exist by the time settings are applied.
            guard let fd = self.tunnelFileDescriptor() else {
                let e = NSError(domain: "com.libertygsm.app", code: 1,
                                userInfo: [NSLocalizedDescriptionKey: "no utun fd"])
                os_log("could not find utun fd", log: self.log, type: .error)
                completionHandler(e)
                return
            }

            let mode = (options?["mode"] as? String) ?? "Standard"
            let protector = InterfaceProtector(log: self.log)
            do {
                // gomobile: package `tunnel` → `TunnelConnect`, `TunnelSession`.
                self.session = try TunnelConnect(Int(fd), mode, "", protector)
                os_log("tunnel started (fd=%d, mode=%{public}@)",
                       log: self.log, type: .info, fd, mode)
                completionHandler(nil)
            } catch {
                os_log("TunnelConnect failed: %{public}@",
                       log: self.log, type: .error, error.localizedDescription)
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        session?.stop()
        session = nil
        completionHandler()
    }

    // MARK: - Network settings (mirror the Android VpnService.Builder: IPv4-only)

    private func makeNetworkSettings() -> NEPacketTunnelNetworkSettings {
        // tunnelRemoteAddress is informational; use the tunnel's own address.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.111.0.1")

        // IPv4-only. Advertising IPv6 makes apps prefer AAAA and connect over
        // IPv6, but our protected upstream sockets have no IPv6 route on most
        // mobile/Wi-Fi networks. Not routing IPv6 lets apps fall back to IPv4.
        let ipv4 = NEIPv4Settings(addresses: ["10.111.0.1"],
                                  subnetMasks: ["255.255.255.255"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4

        // Sink all DNS into the tunnel; the Go core answers UDP/53 over DoH.
        let dns = NEDNSSettings(servers: ["10.111.0.2"])
        dns.matchDomains = [""]   // route every query through us
        settings.dnsSettings = dns

        settings.mtu = 1500
        return settings
    }

    // MARK: - utun file descriptor

    /// Finds the file descriptor of the utun interface this provider created.
    /// Mirrors wireguard-apple: try the (undocumented) KVC path first, then scan.
    private func tunnelFileDescriptor() -> Int32? {
        // VERIFY: KVC path is undocumented but used in production by WireGuard.
        if let fd = packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32 {
            return fd
        }
        // Fallback: scan fds for the one whose UTUN_OPT_IFNAME starts with "utun".
        for fd: Int32 in 0..<1024 {
            var name = [CChar](repeating: 0, count: Int(IFNAMSIZ))
            var len = socklen_t(name.count)
            // SYSPROTO_CONTROL = 2, UTUN_OPT_IFNAME = 2
            if getsockopt(fd, 2, 2, &name, &len) == 0,
               String(cString: name).hasPrefix("utun") {
                return fd
            }
        }
        return nil
    }
}

/// Keeps the Go core's upstream sockets off the tunnel by binding them to the
/// physical interface (the iOS analogue of Android's `VpnService.protect`).
/// gomobile generates both a class `TunnelProtector` and a same-named protocol;
/// Swift imports the protocol with a `Protocol` suffix, so we conform to
/// `TunnelProtectorProtocol` (not the class).
final class InterfaceProtector: NSObject, TunnelProtectorProtocol {
    private let log: OSLog
    init(log: OSLog) { self.log = log }

    func protect(_ fd: Int) -> Bool {
        // VERIFY: bind to the current physical default-route interface. en0 is
        // Wi-Fi; on cellular it's typically pdp_ip0. A robust version resolves
        // the default route interface dynamically — this is a best-effort start.
        let candidates = ["en0", "pdp_ip0"]
        for ifname in candidates {
            let idx = if_nametoindex(ifname)
            if idx == 0 { continue }
            var index = UInt32(idx)
            // IP_BOUND_IF = 25 (IPPROTO_IP). Also set IPV6_BOUND_IF if needed.
            let r = setsockopt(Int32(fd), IPPROTO_IP, 25,
                               &index, socklen_t(MemoryLayout<UInt32>.size))
            if r == 0 { return true }
        }
        os_log("protect(%d): no bindable physical interface", log: log, type: .error, fd)
        return false
    }
}
