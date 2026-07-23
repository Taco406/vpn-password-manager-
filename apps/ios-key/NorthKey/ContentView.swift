// The app's three phases, same mental model as the desktop: connect (scan the desktop's QR),
// unlock (master password, optional Face ID), vault (list/detail/edit). Dark aesthetic matches
// the desktop (#0A0E14 base, electric-cyan accent).

import SwiftUI

struct ContentView: View {
    @StateObject private var vault = VaultStore()
    @State private var configured = Keychain.read(KeychainAccounts.serverConfig) != nil

    var body: some View {
        ZStack {
            Color(hex: 0x0A0E14).ignoresSafeArea()
            if !configured {
                VStack(spacing: 24) {
                    header(connected: false)
                    ScanSetupView(vault: vault, onDone: { configured = true })
                    Spacer()
                }
                .padding(20)
            } else if !vault.isUnlocked {
                VStack(spacing: 24) {
                    header(connected: true)
                    UnlockView(vault: vault, onForgetServer: forgetServer)
                    Spacer()
                }
                .padding(20)
            } else {
                TabView {
                    VaultListView(vault: vault)
                        .tabItem { Label("Vault", systemImage: "key.fill") }
                    ServersView(vault: vault)
                        .tabItem { Label("Servers", systemImage: "server.rack") }
                    TransfersView(vault: vault)
                        .tabItem { Label("Transfers", systemImage: "paperplane.fill") }
                }
            }
        }
        .accentColor(Color(hex: 0x22D3EE))
    }

    private func header(connected: Bool) -> some View {
        HStack {
            Image(systemName: "shield.lefthalf.filled")
                .foregroundColor(Color(hex: 0x22D3EE))
            Text("NorthKey").font(.headline.bold())
            Spacer()
            Circle().fill(connected ? Color(hex: 0x2ED47A) : Color.gray)
                .frame(width: 8, height: 8)
        }
        .padding(.top, 8)
    }

    /// Disconnect this phone from the sync server (vault data stays on the server + other devices).
    private func forgetServer() {
        vault.lock()
        vault.error = nil
        Keychain.delete(KeychainAccounts.serverConfig)
        Keychain.delete(KeychainAccounts.session)
        VaultStore.clearOfflineCache()
        configured = false
    }
}

// A rounded surface matching the desktop cards.
struct Card<Content: View>: View {
    @ViewBuilder let content: Content
    var body: some View {
        content
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
            .background(Color(hex: 0x0F141C))
            .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color(hex: 0x1C2531)))
            .cornerRadius(16)
    }
}

extension Color {
    init(hex: UInt32) {
        self.init(.sRGB,
                  red: Double((hex >> 16) & 0xff) / 255,
                  green: Double((hex >> 8) & 0xff) / 255,
                  blue: Double(hex & 0xff) / 255)
    }
}

/// Cap content to a readable centered column on a regular width class (iPad), full-width on
/// compact (iPhone) — so cards/tiles don't stretch edge-to-edge when the app runs full-screen on
/// an iPad. Apply to the content inside a `ScrollView`.
private struct ReadableColumn: ViewModifier {
    @Environment(\.horizontalSizeClass) private var hSize
    func body(content: Content) -> some View {
        content
            .frame(maxWidth: hSize == .regular ? 720 : .infinity)
            .frame(maxWidth: .infinity)
    }
}

extension View {
    func readableColumn() -> some View { modifier(ReadableColumn()) }
}
