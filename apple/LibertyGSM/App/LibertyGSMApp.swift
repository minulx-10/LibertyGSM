import SwiftUI

@main
struct LibertyGSMApp: App {
    @StateObject private var tunnel = TunnelManager()

    var body: some Scene {
        WindowGroup {
            ContentView().environmentObject(tunnel)
        }
    }
}
