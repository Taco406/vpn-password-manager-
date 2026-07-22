// THE login, phone edition: server address + master password (+ 6-digit code when 2-step is
// on). First contact shows the server's identity code to compare against another device
// (trust-on-first-use); after that the certificate is pinned. One Argon2 derivation covers both
// the sign-in proof and the vault-key unwrap, so the vault opens right after login.

import SwiftUI

struct ServerSetupView: View {
    @ObservedObject var vault: VaultStore
    let onConfigured: () -> Void

    @State private var address = ""
    @State private var password = ""
    @State private var code = ""
    @State private var needCode = false
    @State private var probe: ServerProbe?
    @State private var trusted = false
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                Text("Sign in to your server").font(.subheadline.bold())
                Text("Type the server address shown on your computer (Account & Sync), then your master password.")
                    .font(.caption).foregroundColor(.gray)

                TextField("Server address — e.g. 172.234.28.91", text: $address)
                    .textFieldStyle(.roundedBorder)
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .onChange(of: address) { _ in
                        probe = nil
                        trusted = false
                        needCode = false
                    }

                if probe == nil {
                    Button(busy ? "Connecting…" : "Connect") { doProbe() }
                        .buttonStyle(.borderedProminent)
                        .disabled(busy || address.trimmingCharacters(in: .whitespaces).isEmpty)
                }

                if let probe, !trusted {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("First time connecting").font(.caption.bold())
                        Text("This server's identity code is")
                            .font(.caption).foregroundColor(.gray)
                        Text(probe.fingerprint)
                            .font(.system(.callout, design: .monospaced).bold())
                            .foregroundColor(Color(hex: 0x22D3EE))
                        Text("Your computer shows the same code under Account & Sync. Matching codes mean nobody is between you and your server.")
                            .font(.caption).foregroundColor(.gray)
                        Button("They match — trust this server") { trusted = true }
                            .buttonStyle(.bordered)
                    }
                    .padding(10)
                    .background(Color(hex: 0x1C2531).opacity(0.5))
                    .cornerRadius(10)
                }

                if let probe, trusted {
                    if probe.passwordSigninReady {
                        SecureField("Master password", text: $password)
                            .textFieldStyle(.roundedBorder)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        if needCode {
                            TextField("6-digit code", text: $code)
                                .textFieldStyle(.roundedBorder)
                                .keyboardType(.numberPad)
                        }
                        Button(busy ? "Signing in…" : "Sign in") { doSignin() }
                            .buttonStyle(.borderedProminent)
                            .disabled(busy || password.isEmpty || (needCode && code.count < 6))
                    } else {
                        Text("Found your server, but master-password sign-in isn't turned on yet. On your computer: Account & Sync → Advanced → Turn on master-password sign-in (update the server first if it's old), then tap Connect again.")
                            .font(.caption).foregroundColor(Color(hex: 0xFBBF24))
                    }
                }

                if let error {
                    Text(error).font(.caption).foregroundColor(Color(hex: 0xF87171))
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func doProbe() {
        busy = true
        error = nil
        Task {
            do {
                let p = try await ApiClient.shared.probe(address: address)
                await MainActor.run {
                    probe = p
                    busy = false
                }
            } catch {
                await MainActor.run {
                    self.error = error.localizedDescription
                    self.busy = false
                }
            }
        }
    }

    private func doSignin() {
        guard let probe else { return }
        busy = true
        error = nil
        let pw = password
        let c = needCode ? code : nil
        Task {
            do {
                let kek = try await ApiClient.shared.passwordLogin(probe: probe, password: pw, code: c)
                if let kek {
                    await vault.unlockWithKek(kek)
                    await MainActor.run {
                        busy = false
                        if vault.isUnlocked { onConfigured() }
                        else { error = vault.error }
                    }
                } else {
                    await MainActor.run {
                        needCode = true
                        busy = false
                        error = "2-step sign-in is on — enter the 6-digit code from your authenticator app."
                    }
                }
            } catch {
                await MainActor.run {
                    self.error = error.localizedDescription
                    self.busy = false
                }
            }
        }
    }
}
