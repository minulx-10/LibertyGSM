import SwiftUI

/// Minimal START/STOP UI. Mirrors the desktop/Android app: one big toggle plus a
/// status line and the version.
struct ContentView: View {
    @EnvironmentObject var tunnel: TunnelManager

    private var isOn: Bool {
        if case .connected = tunnel.state { return true }
        return false
    }

    private var statusText: String {
        switch tunnel.state {
        case .disconnected:   return "꺼짐"
        case .connecting:     return "연결 중…"
        case .connected:      return "우회 작동 중 — 모든 앱 보호"
        case .disconnecting:  return "종료 중…"
        case .invalid(let m): return "오류: \(m)"
        }
    }

    private var appVersion: String {
        let v = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"
        return "v\(v)"
    }

    var body: some View {
        VStack(spacing: 28) {
            VStack(spacing: 6) {
                Text("LibertyGSM").font(.largeTitle).bold()
                Text(appVersion).font(.subheadline).foregroundStyle(.secondary)
            }

            Button(action: toggle) {
                Text(isOn ? "STOP" : "START")
                    .font(.title2).bold()
                    .frame(width: 200, height: 200)
                    .background(isOn ? Color.green : Color.purple)
                    .foregroundStyle(.white)
                    .clipShape(Circle())
            }
            .disabled(tunnel.state == .connecting || tunnel.state == .disconnecting)

            Text(statusText)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding()
        .task { await tunnel.load() }
    }

    private func toggle() {
        if isOn { tunnel.stop() } else { tunnel.start() }
    }
}
