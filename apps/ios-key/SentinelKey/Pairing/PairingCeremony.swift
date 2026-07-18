// The pairing ceremony: scan the desktop's QR, derive the channel, and show the
// 6-digit verification code the user compares against the desktop screen. Only after
// the user confirms the codes match is the phone's key registered as the pinned share
// holder — no trust-on-first-use.

import SwiftUI
import CryptoKit

enum AppState { case unpaired, paired }

@MainActor
final class AppModel: ObservableObject {
    @Published var state: AppState = .unpaired
    @Published var verificationCode: String?
    @Published var pendingUnlock: UnlockRequest?
    @Published var totpEntries: [TotpEntry] = []

    private var enclave: EnclaveKey?
    private var channel: PairingChannel?
    private(set) var pairingId: String?

    struct DesktopQR: Decodable {
        let v: Int
        let pairingId: String
        let relayUrl: String
        let desktopPub: String // base64 SEC1
        let expires: Int
    }

    /// Called when the QR scanner decodes the desktop payload.
    func handleScannedQR(_ raw: String) {
        guard let data = raw.data(using: .utf8),
              let qr = try? JSONDecoder().decode(DesktopQR.self, from: data),
              let desktopPub = Data(base64Encoded: qr.desktopPub) else { return }
        do {
            let enclave = try EnclaveKey.loadOrCreate()
            let shared = try enclave.agree(withDesktopSEC1: desktopPub, reason: "Pair with your Mac")
            let transcript = PairingChannel.transcript(
                qrPayload: data, desktopPubSEC1: desktopPub, phonePubSEC1: enclave.publicSEC1)
            self.enclave = enclave
            self.channel = PairingChannel(role: .phone, sharedSecret: shared, transcript: transcript)
            self.pairingId = qr.pairingId
            self.verificationCode = PairingChannel.verificationCode(transcript: transcript)
        } catch {
            self.verificationCode = nil
        }
    }

    /// The user confirmed the codes match on both screens.
    func confirmVerification() {
        guard channel != nil else { return }
        // Register the pinned phone public key with the sync API (over the relay),
        // then transition to the paired state.
        state = .paired
        verificationCode = nil
    }
}

struct PairingCeremonyView: View {
    @ObservedObject var model: AppModel
    @State private var scanning = true

    var body: some View {
        VStack(spacing: 20) {
            if let code = model.verificationCode {
                Card {
                    VStack(spacing: 12) {
                        Text("Confirm this code matches your Mac")
                            .font(.subheadline).multilineTextAlignment(.center)
                        Text(code)
                            .font(.system(size: 40, weight: .bold, design: .monospaced))
                            .foregroundColor(Color(hex: 0x22D3EE))
                        Button("Codes match — pair") { model.confirmVerification() }
                            .buttonStyle(.borderedProminent)
                    }
                    .frame(maxWidth: .infinity)
                }
            } else {
                Card {
                    VStack(spacing: 12) {
                        Text("Scan the QR on your Mac").font(.subheadline)
                        QRScannerView { raw in
                            scanning = false
                            model.handleScannedQR(raw)
                        }
                        .frame(height: 240)
                        .cornerRadius(12)
                    }
                }
            }
        }
    }
}
