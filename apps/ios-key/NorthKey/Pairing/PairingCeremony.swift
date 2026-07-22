// The pairing ceremony: scan the desktop's QR, derive the channel, and show the
// 6-digit verification code the user compares against the desktop screen. Only after
// the user confirms the codes match is the phone's key registered as the pinned share
// holder — no trust-on-first-use.

import SwiftUI
import CryptoKit

enum AppState { case needsServer, unpaired, paired }

@MainActor
final class AppModel: ObservableObject {
    @Published var state: AppState
    @Published var verificationCode: String?
    @Published var pendingUnlock: UnlockRequest?
    @Published var totpEntries: [TotpEntry] = []
    /// Transient status/error shown under the header (nil = hidden).
    @Published var banner: String?

    private var enclave: EnclaveKey?
    private var channel: PairingChannel?
    private var phonePubB64: String?
    private(set) var pairingId: String?

    struct DesktopQR: Decodable {
        let v: Int
        let pairingId: String
        let relayUrl: String
        let desktopPub: String // base64 SEC1
        let expires: Int
    }

    init() {
        // Resume where we left off: no server yet → onboarding; server but not paired → pairing.
        if Keychain.read(KeychainAccounts.serverConfig) == nil {
            state = .needsServer
        } else if Keychain.read(KeychainAccounts.pairingMarker) == nil {
            state = .unpaired
        } else {
            state = .paired
        }
        // A push delivered an unlock-request id → fetch it and surface the approval sheet.
        PushHandler.shared.onUnlockRequest = { [weak self] id in
            Task { await self?.loadUnlock(id: id) }
        }
    }

    /// Save the sync server URL + bootstrap token, proving them by minting a first session.
    func saveServer(url: String, token: String) async {
        do {
            try await ApiClient.shared.configure(baseUrl: url, bootstrapToken: token)
            banner = nil
            state = Keychain.read(KeychainAccounts.pairingMarker) == nil ? .unpaired : .paired
        } catch {
            banner = error.localizedDescription
        }
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
            self.phonePubB64 = enclave.publicSEC1.base64EncodedString()
            self.pairingId = qr.pairingId
            self.verificationCode = PairingChannel.verificationCode(transcript: transcript)
        } catch {
            self.verificationCode = nil
        }
    }

    /// The user confirmed the codes match on both screens. Register the pinned phone key with the
    /// sync server so the desktop can seal unlock requests to it, then move to the paired state.
    func confirmVerification() {
        guard channel != nil, let pub = phonePubB64 else { return }
        Task {
            do {
                try await ApiClient.shared.pinKey(phonePubB64: pub)
                Keychain.write(
                    KeychainAccounts.pairingMarker, Data((pairingId ?? "paired").utf8))
                verificationCode = nil
                banner = nil
                state = .paired
            } catch {
                banner = "Couldn't register with the sync server: \(error.localizedDescription)"
            }
        }
    }

    /// Fetch a pushed unlock request over the relay and surface the approval sheet.
    private func loadUnlock(id: String) async {
        do {
            let u = try await ApiClient.shared.fetchUnlock(id: id)
            pendingUnlock = UnlockRequest(id: u.id, requestPayload: u.requestPayload)
        } catch {
            banner = error.localizedDescription
        }
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
