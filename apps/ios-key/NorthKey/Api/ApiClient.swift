// The phone's client for the NorthKey sync server (`sentinel-api`). This is the "relay" the pairing
// docs refer to: every call is plain HTTPS to the sync server, and the unlock request/response
// payloads it carries are opaque E2E ciphertext (sealed with the pinned pairing channel) — the
// server only moves and expires them.
//
// Auth uses the personal self-hosted **bootstrap** path: the user enters the sync server URL and the
// `SENTINEL_BOOTSTRAP_TOKEN` once; the phone exchanges it for a session (access + refresh) held in
// the Keychain, registered as an already-approved iOS device. Thereafter it rotates the short-lived
// access token via the refresh endpoint and only re-bootstraps if the refresh chain is revoked.

import Foundation

/// The Keychain accounts NorthKey stores things under, in one place so the app model, the API
/// client, and the enclave key all agree.
enum KeychainAccounts {
    static let enclaveKey = "northkey.enclave.key"
    static let serverConfig = "northkey.server.config"
    static let session = "northkey.session"
    /// Set once pairing is confirmed, so a relaunch returns straight to the paired screen.
    static let pairingMarker = "northkey.pairing.id"
}

/// Where to reach the sync server, plus the personal bootstrap secret. Persisted in the Keychain.
struct ServerConfig: Codable, Equatable {
    /// Base URL, e.g. `https://sync.example.com` (no trailing slash).
    var baseUrl: String
    var bootstrapToken: String
}

/// A minted session. `expiresAt` is when the access token stops being accepted.
private struct Session: Codable {
    var accessToken: String
    var refreshToken: String
    var expiresAt: Date
}

/// A pending unlock/new-device request as the phone sees it after fetching it from the relay.
struct PendingUnlock {
    let id: String
    let kind: String
    /// Opaque E2E ciphertext the phone opens with the pinned channel to produce its response.
    let requestPayload: Data
}

enum ApiError: Error, LocalizedError {
    case notConfigured
    case http(Int, String)
    case badResponse
    case transport(String)

    var errorDescription: String? {
        switch self {
        case .notConfigured: return "No sync server is configured yet."
        case let .http(code, msg): return "Server error \(code): \(msg)"
        case .badResponse: return "The server sent an unexpected response."
        case let .transport(m): return "Couldn't reach the server: \(m)"
        }
    }
}

/// One client, serialized so a burst of calls doesn't mint parallel sessions. `@MainActor`-free:
/// callers hop to it with `await`.
actor ApiClient {
    static let shared = ApiClient()

    private let session = URLSession(configuration: .ephemeral)
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    private let configAccount = KeychainAccounts.serverConfig
    private let sessionAccount = KeychainAccounts.session

    // MARK: - Configuration

    func serverConfig() -> ServerConfig? {
        Keychain.read(configAccount).flatMap { try? decoder.decode(ServerConfig.self, from: $0) }
    }

    var isConfigured: Bool { serverConfig() != nil }

    /// Save the sync server URL + bootstrap token and prove them by minting a first session. Clears
    /// any previous session so the next call bootstraps fresh.
    func configure(baseUrl: String, bootstrapToken: String) async throws {
        let trimmed = baseUrl.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalized = trimmed.hasSuffix("/") ? String(trimmed.dropLast()) : trimmed
        let cfg = ServerConfig(baseUrl: normalized, bootstrapToken: bootstrapToken)
        if let data = try? encoder.encode(cfg) { Keychain.write(configAccount, data) }
        Keychain.delete(sessionAccount)
        _ = try await bootstrap() // fails (and the UI reports) if URL/token are wrong
    }

    // MARK: - Endpoints

    /// Register the APNs device token so unlock pushes can wake the app.
    func registerPush(tokenHex: String) async throws {
        _ = try await authed("POST", "/v1/push/register", body: ["token": tokenHex])
    }

    /// Pin this phone's Secure-Enclave public key (SEC1 base64) after the pairing code is confirmed.
    func pinKey(phonePubB64: String) async throws {
        _ = try await authed("POST", "/v1/devices/pin", body: ["phone_pub_b64": phonePubB64])
    }

    /// Fetch a pending unlock request so the phone can open its opaque payload.
    func fetchUnlock(id: String) async throws -> PendingUnlock {
        let data = try await authed("GET", "/v1/unlock-requests/\(id)", body: nil)
        guard
            let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let kind = obj["kind"] as? String,
            let b64 = obj["request_payload_b64"] as? String,
            let payload = Data(base64Encoded: b64)
        else { throw ApiError.badResponse }
        return PendingUnlock(id: id, kind: kind, requestPayload: payload)
    }

    /// Respond to an unlock request. On approval `responsePayloadB64` carries the sealed share.
    func respondUnlock(id: String, approved: Bool, responsePayloadB64: String?) async throws {
        var body: [String: String] = ["state": approved ? "approved" : "denied"]
        if let p = responsePayloadB64 { body["response_payload_b64"] = p }
        _ = try await authed("POST", "/v1/unlock-requests/\(id)/respond", body: body)
    }

    // MARK: - Session management

    /// Run an authenticated request, refreshing the access token if it's stale and retrying once on
    /// a 401 (the token may have been revoked server-side between the expiry check and the call).
    private func authed(_ method: String, _ path: String, body: [String: String]?) async throws
        -> Data
    {
        let token = try await validAccessToken()
        do {
            return try await send(method, path, bearer: token, body: body)
        } catch ApiError.http(let code, _) where code == 401 {
            // The token was revoked between the expiry check and the call — renew and retry once.
            let fresh = try await renew()
            return try await send(method, path, bearer: fresh, body: body)
        }
    }

    /// A currently-valid access token: reuse the cached one, else renew.
    private func validAccessToken() async throws -> String {
        if let s = loadSession(), s.expiresAt > Date().addingTimeInterval(30) {
            return s.accessToken
        }
        return try await renew()
    }

    /// Force a fresh access token: rotate via the refresh token if we have one, else re-bootstrap
    /// (keeping the refresh token means a normal rotation doesn't enroll a new device row).
    private func renew() async throws -> String {
        if let s = loadSession(), let refreshed = try? await refresh(using: s.refreshToken) {
            return refreshed
        }
        return try await bootstrap()
    }

    private func loadSession() -> Session? {
        Keychain.read(sessionAccount).flatMap { try? decoder.decode(Session.self, from: $0) }
    }

    private func store(_ tokens: TokenResponse) -> String {
        let s = Session(
            accessToken: tokens.access_token,
            refreshToken: tokens.refresh_token,
            expiresAt: Date().addingTimeInterval(TimeInterval(tokens.expires_in)))
        if let data = try? encoder.encode(s) { Keychain.write(sessionAccount, data) }
        return s.accessToken
    }

    private func bootstrap() async throws -> String {
        guard let cfg = serverConfig() else { throw ApiError.notConfigured }
        let body: [String: Any] = [
            "token": cfg.bootstrapToken,
            "device": ["name": "NorthKey iPhone", "platform": "ios"],
        ]
        let data = try await send("POST", "/v1/auth/bootstrap", bearer: nil, jsonBody: body)
        let tokens = try decoder.decode(TokenResponse.self, from: data)
        return store(tokens)
    }

    private func refresh(using refreshToken: String) async throws -> String {
        let data = try await send(
            "POST", "/v1/auth/refresh", bearer: nil, body: ["refresh_token": refreshToken])
        let tokens = try decoder.decode(TokenResponse.self, from: data)
        return store(tokens)
    }

    private struct TokenResponse: Decodable {
        let access_token: String
        let refresh_token: String
        let expires_in: Int
    }

    // MARK: - Transport

    private func send(_ method: String, _ path: String, bearer: String?, body: [String: String]?)
        async throws -> Data
    {
        try await send(method, path, bearer: bearer, jsonBody: body.map { $0.mapValues { $0 as Any } })
    }

    private func send(_ method: String, _ path: String, bearer: String?, jsonBody: [String: Any]?)
        async throws -> Data
    {
        guard let cfg = serverConfig(), let url = URL(string: cfg.baseUrl + path) else {
            throw ApiError.notConfigured
        }
        var req = URLRequest(url: url)
        req.httpMethod = method
        if let bearer { req.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization") }
        if let jsonBody {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try JSONSerialization.data(withJSONObject: jsonBody)
        }
        let (data, resp): (Data, URLResponse)
        do {
            (data, resp) = try await session.data(for: req)
        } catch {
            throw ApiError.transport(error.localizedDescription)
        }
        guard let http = resp as? HTTPURLResponse else { throw ApiError.badResponse }
        guard (200..<300).contains(http.statusCode) else {
            let msg = String(data: data, encoding: .utf8) ?? ""
            throw ApiError.http(http.statusCode, msg)
        }
        return data
    }
}
