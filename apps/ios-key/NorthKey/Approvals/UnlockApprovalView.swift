// The unlock-approval sheet: a push arrived, Face ID gates it, and on success the key
// share is released over the pinned E2E channel. Deny sends a denial. Either way the
// desktop card updates in real time via the relay.

import SwiftUI
import LocalAuthentication

struct UnlockRequest: Identifiable {
    let id: String
    let requestPayload: Data // opaque E2E ciphertext from the desktop
}

struct UnlockApprovalView: View {
    let request: UnlockRequest
    @ObservedObject var model: AppModel
    @State private var status: String = "Approve this unlock?"

    var body: some View {
        VStack {
            Spacer()
            Card {
                VStack(spacing: 16) {
                    Image(systemName: "faceid")
                        .font(.system(size: 40))
                        .foregroundColor(Color(hex: 0x22D3EE))
                    Text("Unlock NorthKey on your Mac").font(.headline)
                    Text(status).font(.caption).foregroundColor(.gray)
                    HStack(spacing: 12) {
                        Button("Deny", role: .destructive) { deny() }
                            .buttonStyle(.bordered)
                        Button("Approve with Face ID") { approve() }
                            .buttonStyle(.borderedProminent)
                    }
                }
                .frame(maxWidth: .infinity)
            }
            .padding()
        }
        .background(Color.black.opacity(0.4).ignoresSafeArea())
    }

    private func approve() {
        let ctx = LAContext()
        ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                           localizedReason: "Release your vault key share") { ok, _ in
            Task { @MainActor in
                guard ok else { status = "Face ID failed"; return }
                status = "Approved — notifying your Mac…"
                // iOS-1 wires the approval transport and the Face ID gate. Sealing the actual vault
                // key share over the pinned channel is the next increment — it needs the desktop to
                // emit a per-unlock ECDH payload — so this response carries no share payload yet.
                do {
                    try await ApiClient.shared.respondUnlock(
                        id: request.id, approved: true, responsePayloadB64: nil)
                    model.pendingUnlock = nil
                } catch {
                    status = "Couldn't reach your Mac: \(error.localizedDescription)"
                }
            }
        }
    }

    private func deny() {
        Task { @MainActor in
            try? await ApiClient.shared.respondUnlock(
                id: request.id, approved: false, responsePayloadB64: nil)
            model.pendingUnlock = nil
        }
    }
}
