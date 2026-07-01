import Foundation
import NetworkExtension
import Combine

/// Installs and controls the LibertyGSM packet-tunnel profile from the container
/// app. iOS/macOS require the VPN configuration to be created here (the extension
/// can't install itself); the app saves a `NETunnelProviderManager` and then
/// start/stops the tunnel session.
@MainActor
final class TunnelManager: ObservableObject {

    enum State: Equatable {
        case disconnected, connecting, connected, disconnecting
        case invalid(String)
    }

    @Published private(set) var state: State = .disconnected

    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?

    /// Bundle id of the PacketTunnel extension (app id + ".PacketTunnel").
    private let extensionBundleID = "com.libertygsm.app.PacketTunnel"

    init() {
        Task { await load() }
        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: nil, queue: .main
        ) { [weak self] note in
            guard let conn = note.object as? NEVPNConnection else { return }
            Task { @MainActor in self?.syncState(from: conn.status) }
        }
    }

    deinit { if let o = observer { NotificationCenter.default.removeObserver(o) } }

    /// Load an existing profile or prepare a fresh one.
    func load() async {
        do {
            let all = try await NETunnelProviderManager.loadAllFromPreferences()
            let mgr = all.first ?? NETunnelProviderManager()
            self.manager = mgr
            if let conn = mgr.connection as NEVPNConnection? {
                syncState(from: conn.status)
            }
        } catch {
            state = .invalid(error.localizedDescription)
        }
    }

    /// Save the profile (installs the VPN config; first time prompts the user).
    private func ensureSaved() async throws -> NETunnelProviderManager {
        let mgr = manager ?? NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = extensionBundleID
        // serverAddress is shown in Settings; informational only.
        proto.serverAddress = "LibertyGSM"
        mgr.protocolConfiguration = proto
        mgr.localizedDescription = "LibertyGSM"
        mgr.isEnabled = true
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()   // reload to get a live connection
        self.manager = mgr
        return mgr
    }

    func start() {
        Task {
            do {
                state = .connecting
                let mgr = try await ensureSaved()
                try mgr.connection.startVPNTunnel(options: ["mode": "Standard" as NSObject])
            } catch {
                state = .invalid(error.localizedDescription)
            }
        }
    }

    func stop() {
        state = .disconnecting
        manager?.connection.stopVPNTunnel()
    }

    private func syncState(from status: NEVPNStatus) {
        switch status {
        case .connected:      state = .connected
        case .connecting, .reasserting: state = .connecting
        case .disconnecting:  state = .disconnecting
        case .disconnected, .invalid: state = .disconnected
        @unknown default:     state = .disconnected
        }
    }
}
