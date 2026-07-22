// Advanced/manual onboarding: type the sync server address + personal setup token
// (SENTINEL_BOOTSTRAP_TOKEN). The primary path is scanning the desktop's QR (ScanSetupView);
// this stays for real-CA custom servers and recovery scenarios.

import SwiftUI

struct ServerSetupView: View {
    let onConfigured: () -> Void
    @State private var url = ""
    @State private var token = ""
    @State private var busy = false
    @State private var error: String?

    private var canConnect: Bool {
        !busy && !url.trimmingCharacters(in: .whitespaces).isEmpty && !token.isEmpty
    }

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                Text("Connect to your sync server").font(.subheadline.bold())
                Text("Enter your NorthKey sync server address and personal setup token. Most people should use the QR scan instead — this manual path is for custom servers.")
                    .font(.caption).foregroundColor(.gray)

                TextField("https://sync.example.com", text: $url)
                    .textFieldStyle(.roundedBorder)
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()

                SecureField("Setup token", text: $token)
                    .textFieldStyle(.roundedBorder)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()

                if let error {
                    Text(error).font(.caption).foregroundColor(Color(hex: 0xF87171))
                }

                Button(busy ? "Connecting…" : "Connect") {
                    busy = true
                    error = nil
                    Task {
                        do {
                            try await ApiClient.shared.configure(baseUrl: url, bootstrapToken: token)
                            await MainActor.run { onConfigured() }
                        } catch {
                            await MainActor.run {
                                self.error = error.localizedDescription
                                self.busy = false
                            }
                        }
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(!canConnect)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
