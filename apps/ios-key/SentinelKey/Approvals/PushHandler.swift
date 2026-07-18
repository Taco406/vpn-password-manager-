// APNs registration + routing an incoming unlock-request push to the UI.

import Foundation

@MainActor
final class PushHandler: ObservableObject {
    static let shared = PushHandler()

    @Published var pendingUnlockRequestId: String?

    /// Register the device token with the sync API (`POST /v1/push/register`).
    func register(token: Data) {
        let hex = token.map { String(format: "%02x", $0) }.joined()
        // URLSession POST to the API with the bearer token from the Keychain.
        _ = hex
    }
}
