// QR-first onboarding: scan the desktop's "Add a device" QR — {v:2, ip, cert, enroll, ts} — to
// pin the server cert and redeem the one-time enrollment code. Replaces hand-typing a URL +
// token; the manual path stays available under "Advanced".

import SwiftUI

struct DesktopSetupQR: Decodable {
    let v: Int
    let ip: String
    let cert: String
    let enroll: String
    let ts: Int64?
}

struct ScanSetupView: View {
    let vault: VaultStore
    let onDone: () -> Void
    @State private var scanning = true
    @State private var busy = false
    @State private var error: String?
    @State private var showManual = false

    var body: some View {
        VStack(spacing: 16) {
            if showManual {
                ServerSetupView(vault: vault, onConfigured: onDone)
                Button("Back to QR scan") { showManual = false }
                    .font(.caption)
            } else {
                Card {
                    VStack(spacing: 12) {
                        Text("Scan the QR on your computer").font(.subheadline.bold())
                        Text("In NorthKey on your computer: Account & Sync → Add a device. Point the camera at the QR.")
                            .font(.caption).foregroundColor(.gray)
                            .multilineTextAlignment(.center)
                        if busy {
                            ProgressView("Connecting…").frame(height: 240)
                        } else if scanning {
                            QRScannerView { raw in
                                scanning = false
                                handle(raw)
                            }
                            .frame(height: 240)
                            .cornerRadius(12)
                        } else {
                            Button("Scan again") {
                                error = nil
                                scanning = true
                            }
                            .buttonStyle(.bordered)
                        }
                        if let error {
                            Text(error).font(.caption).foregroundColor(Color(hex: 0xF87171))
                        }
                    }
                    .frame(maxWidth: .infinity)
                }
                Button("No camera handy? Type the server address instead") { showManual = true }
                    .font(.caption)
                    .foregroundColor(.gray)
            }
        }
    }

    private func handle(_ raw: String) {
        guard let data = raw.data(using: .utf8),
              let qr = try? JSONDecoder().decode(DesktopSetupQR.self, from: data),
              qr.v == 2
        else {
            error = "That QR isn't a NorthKey device code. Use Account & Sync → Add a device on your computer."
            return
        }
        busy = true
        Task {
            do {
                try await ApiClient.shared.configureFromQR(
                    ip: qr.ip, certPEM: qr.cert, enrollCode: qr.enroll)
                await MainActor.run { onDone() }
            } catch {
                await MainActor.run {
                    self.error = "Couldn't connect: \(error.localizedDescription). Codes expire after ~5 minutes — mint a fresh one and rescan."
                    self.busy = false
                }
            }
        }
    }
}
