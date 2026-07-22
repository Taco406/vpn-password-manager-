// First-run onboarding: point the phone at your NorthKey sync server. The setup token is the
// personal `SENTINEL_BOOTSTRAP_TOKEN` from your one-click sync-server deploy; entering it once mints
// a session (held in the Keychain) and enrolls this phone as an approved iOS device.

import SwiftUI

struct ServerSetupView: View {
    @ObservedObject var model: AppModel
    @State private var url = ""
    @State private var token = ""
    @State private var busy = false

    private var canConnect: Bool {
        !busy && !url.trimmingCharacters(in: .whitespaces).isEmpty && !token.isEmpty
    }

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                Text("Connect to your sync server").font(.subheadline.bold())
                Text("Enter your NorthKey sync server address and personal setup token. Find the token in the desktop app under Sync.")
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

                Button(busy ? "Connecting…" : "Connect") {
                    busy = true
                    Task {
                        await model.saveServer(url: url, token: token)
                        busy = false
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(!canConnect)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
