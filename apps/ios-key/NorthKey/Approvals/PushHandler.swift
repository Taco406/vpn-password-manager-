// APNs registration + routing an incoming unlock-request push to the UI.

import Foundation

@MainActor
final class PushHandler: ObservableObject {
    static let shared = PushHandler()

    /// Set by `AppModel` — invoked (on the main actor) when a push delivers an unlock-request id.
    var onUnlockRequest: ((String) -> Void)?

    @Published var pendingUnlockRequestId: String? {
        didSet { if let id = pendingUnlockRequestId { onUnlockRequest?(id) } }
    }

    /// Register the APNs device token with the sync server (`POST /v1/push/register`), so unlock
    /// requests can wake the app. Best-effort: a transient failure just means no push until relaunch.
    func register(token: Data) {
        let hex = token.map { String(format: "%02x", $0) }.joined()
        Task { try? await ApiClient.shared.registerPush(tokenHex: hex) }
    }
}
