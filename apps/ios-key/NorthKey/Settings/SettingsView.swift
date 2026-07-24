// The phone's Settings tab — the counterpart to the desktop's Account & Sync screen.
//
// Its most important job is making SYNC VISIBLE. Everything the phone shows (servers, monitoring)
// depends on settings the computer shares through the encrypted `northkey:system` vault item; when
// that doesn't arrive, the Servers tab just renders an empty "set this up on your computer" state
// and there is no way to tell whether the phone is out of date, offline, or simply never received
// the token. This screen answers that directly: when the last successful sync was, exactly which
// settings arrived, and a Sync now button that reports what it found.
//
// Nothing secret is displayed — only whether a value is present, never its contents.

import SwiftUI

struct SettingsView: View {
    @ObservedObject var vault: VaultStore
    /// Disconnect this phone from the sync server (owned by ContentView, which holds the flag).
    let onForgetServer: () -> Void

    @State private var faceIDOn = VaultStore.faceIDAvailable()
    @State private var syncNote = ""
    @State private var confirmingSignOut = false

    private var tokens: ProviderTokens { vault.providerTokens }

    var body: some View {
        NavigationStack {
            List {
                syncSection
                sharedSettingsSection
                securitySection
                deviceSection
                aboutSection
            }
            .scrollContentBackground(.hidden)
            .background(Color(hex: 0x0A0E14))
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .refreshable { await syncNow() }
        }
    }

    // MARK: - Sync

    private var syncSection: some View {
        Section {
            Button {
                Task { await syncNow() }
            } label: {
                HStack {
                    Label("Sync now", systemImage: "arrow.triangle.2.circlepath")
                    Spacer()
                    if vault.busy { ProgressView() }
                }
            }
            .disabled(vault.busy)

            LabeledContent("Last synced") {
                Text(lastSyncedText).foregroundColor(.gray)
            }
            LabeledContent("Items in vault") {
                Text("\(vault.items.count)").foregroundColor(.gray)
            }

            if vault.offline {
                Label(
                    "Offline — showing the vault from your last sync. Reconnect to get changes.",
                    systemImage: "wifi.slash"
                )
                .font(.caption)
                .foregroundColor(Color(hex: 0xFBBF24))
            }
            if let error = vault.error {
                Text(error).font(.caption).foregroundColor(Color(hex: 0xF87171))
            }
            if !syncNote.isEmpty {
                Text(syncNote).font(.caption).foregroundColor(.gray)
            }
        } header: {
            Text("Sync")
        } footer: {
            Text("Your vault and settings are end-to-end encrypted. Your server only ever stores ciphertext — it can't read any of this.")
        }
        .listRowBackground(Color(hex: 0x0F141C))
    }

    private var lastSyncedText: String {
        guard let at = vault.lastSyncedAt else { return "not yet" }
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .full
        return f.localizedString(for: at, relativeTo: Date())
    }

    // MARK: - What the computer has shared

    private var sharedSettingsSection: some View {
        Section {
            sharedRow("Linode API token", present: !tokens.linode.isEmpty, hint: "your Linode servers")
            sharedRow("Hetzner API token", present: !tokens.hetzner.isEmpty, hint: "your Hetzner servers")
            sharedRow(
                "Netdata monitors", present: !tokens.netdataConfigJSON.isEmpty,
                hint: "live server dashboards")
        } header: {
            Text("Shared from your computer")
        } footer: {
            Text(
                tokens.hasAny
                    ? "These arrived from your computer and are what the Servers tab uses."
                    : "Nothing has arrived yet. On your computer open Account & Sync → Shared settings and tap “Push to all my devices”, then tap Sync now above."
            )
        }
        .listRowBackground(Color(hex: 0x0F141C))
    }

    private func sharedRow(_ label: String, present: Bool, hint: String) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(label)
                Text(hint).font(.caption2).foregroundColor(.gray)
            }
            Spacer()
            if present {
                Label("received", systemImage: "checkmark.circle.fill")
                    .labelStyle(.titleAndIcon)
                    .font(.caption)
                    .foregroundColor(Color(hex: 0x2ED47A))
            } else {
                Text("not received").font(.caption).foregroundColor(.gray)
            }
        }
    }

    // MARK: - Security

    private var securitySection: some View {
        Section {
            Toggle("Unlock with Face ID", isOn: $faceIDOn)
                .onChange(of: faceIDOn) { on in
                    if on { vault.enableFaceID() } else { vault.disableFaceID() }
                }
            Button(role: .destructive) {
                vault.lock()
            } label: {
                Label("Lock vault now", systemImage: "lock.fill")
            }
        } header: {
            Text("Security")
        } footer: {
            Text("Face ID unlocks this phone's copy only. Your master password is never stored — it unwraps your vault key on the device.")
        }
        .listRowBackground(Color(hex: 0x0F141C))
    }

    // MARK: - This phone

    private var deviceSection: some View {
        Section {
            LabeledContent("Server") {
                Text(serverAddress).foregroundColor(.gray).lineLimit(1).truncationMode(.middle)
            }
            Button(role: .destructive) {
                confirmingSignOut = true
            } label: {
                Label("Disconnect this phone", systemImage: "iphone.slash")
            }
        } header: {
            Text("This phone")
        } footer: {
            Text("Disconnecting only signs this phone out. Your vault stays safe on your server and your other devices.")
        }
        .listRowBackground(Color(hex: 0x0F141C))
        .confirmationDialog(
            "Disconnect this phone from your server?",
            isPresented: $confirmingSignOut,
            titleVisibility: .visible
        ) {
            Button("Disconnect", role: .destructive, action: onForgetServer)
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("You'll sign in again with your server address and master password. Nothing is deleted.")
        }
    }

    private var serverAddress: String {
        ApiClient.shared.serverConfig()?.baseUrl ?? "not configured"
    }

    // MARK: - About

    private var aboutSection: some View {
        Section("About") {
            LabeledContent("NorthKey") {
                Text(appVersion).foregroundColor(.gray)
            }
        }
        .listRowBackground(Color(hex: 0x0F141C))
    }

    private var appVersion: String {
        let info = Bundle.main.infoDictionary
        let short = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "\(short) (\(build))"
    }

    // MARK: - Actions

    /// Force a pull and say what came back, so "Sync now" is never a button that appears to do
    /// nothing. Reports the providers that arrived, or names the reason it couldn't sync.
    private func syncNow() async {
        syncNote = ""
        do {
            try await vault.pull()
            let got = [
                !tokens.linode.isEmpty ? "Linode" : nil,
                !tokens.hetzner.isEmpty ? "Hetzner" : nil,
            ].compactMap { $0 }
            syncNote = got.isEmpty
                ? "Synced, but your computer hasn't shared any server tokens yet."
                : "Synced ✓ — received: \(got.joined(separator: ", "))."
        } catch {
            syncNote = "Couldn't sync: \(error.localizedDescription)"
        }
    }
}
