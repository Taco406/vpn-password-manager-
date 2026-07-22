// The phone's client for the NorthKey sync server (`sentinel-api`). This is the "relay" the pairing
// docs refer to: every call is plain HTTPS to the sync server, and the unlock request/response
// payloads it carries are opaque E2E ciphertext (sealed with the pinned pairing channel) — the
// server only moves and expires them.
//
// Auth uses the personal self-hosted **bootstrap** path: the user enters the sync server URL and the
// `SENTINEL_BOOTSTRAP_TOKEN` once; the phone exchanges it for a session (access + refresh) held in
// the Keychain, registered as an already-approved iOS device. Thereafter it rotates the short-lived
// access token via the refresh endpoint and only re-bootstraps if the refresh chain is revoked.

import CryptoKit
import Foundation
import Security

/// The Keychain accounts NorthKey stores things under, in one place so the app model, the API
/// client, and the enclave key all agree.
enum KeychainAccounts {
    static let enclaveKey = "northkey.enclave.key"
    static let serverConfig = "northkey.server.config"
    static let session = "northkey.session"
    /// Set once pairing is confirmed, so a relaunch returns straight to the paired screen.
    static let pairingMarker = "northkey.pairing.id"
}

/// Where to reach the sync server. Persisted in the Keychain. QR onboarding fills `certPEM`
/// (the app-generated self-signed cert to pin) and no bootstrap token (the one-time enroll code
/// mints the session); manual/advanced setup fills `bootstrapToken` instead.
struct ServerConfig: Codable, Equatable {
    /// Base URL, e.g. `https://203.0.113.5` or `https://sync.example.com` (no trailing slash).
    var baseUrl: String
    var bootstrapToken: String?
    /// PEM of the exact server certificate to trust (self-signed one-click servers). When set,
    /// TLS accepts ONLY this certificate — stronger than hostname checks, and required because
    /// the one-click server has no public CA or domain.
    var certPEM: String?
}

/// Exact-certificate TLS pinning: accept the connection only when the presented leaf certificate
/// is byte-identical to the pinned one (mirrors the desktop's pinned reqwest client).
final class CertPinDelegate: NSObject, URLSessionDelegate {
    private let pinnedDER: Data
    init(pinnedDER: Data) { self.pinnedDER = pinnedDER }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust,
              let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let leaf = chain.first
        else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        let presented = SecCertificateCopyData(leaf) as Data
        if presented == pinnedDER {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    /// PEM → DER (strips armor lines, base64-decodes the body).
    static func der(fromPEM pem: String) -> Data? {
        let body = pem
            .components(separatedBy: .newlines)
            .filter { !$0.hasPrefix("-----") && !$0.isEmpty }
            .joined()
        return Data(base64Encoded: body)
    }
}

/// Captures (without trusting) the leaf certificate a server presents, for trust-on-first-use:
/// the user compares its fingerprint against another signed-in device before anything sensitive
/// is sent — and everything after the probe runs over a session PINNED to exactly this cert.
final class CertCaptureDelegate: NSObject, URLSessionDelegate {
    private(set) var leafDER: Data?

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust,
              let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let leaf = chain.first
        else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        leafDER = SecCertificateCopyData(leaf) as Data
        completionHandler(.useCredential, URLCredential(trust: trust))
    }

    /// DER → PEM (the storage format the pinned config uses).
    static func pem(fromDER der: Data) -> String {
        let b64 = der.base64EncodedString()
        var lines: [String] = ["-----BEGIN CERTIFICATE-----"]
        var i = b64.startIndex
        while i < b64.endIndex {
            let end = b64.index(i, offsetBy: 64, limitedBy: b64.endIndex) ?? b64.endIndex
            lines.append(String(b64[i..<end]))
            i = end
        }
        lines.append("-----END CERTIFICATE-----")
        return lines.joined(separator: "\n")
    }

    /// Same human-comparable identity code the desktop shows: SHA-256 of the DER, first 8 bytes
    /// as `AB12-CD34-EF56-7890`.
    static func fingerprint(der: Data) -> String {
        let hash = Data(CryptoKit.SHA256.hash(data: der))
        let hex = hash.prefix(8).map { String(format: "%02X", $0) }
        return "\(hex[0])\(hex[1])-\(hex[2])\(hex[3])-\(hex[4])\(hex[5])-\(hex[6])\(hex[7])"
    }
}

/// What a first-contact probe learns about a server.
struct ServerProbe {
    let baseUrl: String
    let certPEM: String
    let fingerprint: String
    let passwordSigninReady: Bool
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

    /// Session cache keyed by the pinned cert (nil = plain TLS for real-CA servers).
    private var cachedSession: URLSession?
    private var cachedCertPEM: String?
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    private var session: URLSession {
        let pem = serverConfig()?.certPEM
        if let s = cachedSession, cachedCertPEM == pem { return s }
        let s: URLSession
        if let pem, let der = CertPinDelegate.der(fromPEM: pem) {
            s = URLSession(
                configuration: .ephemeral,
                delegate: CertPinDelegate(pinnedDER: der),
                delegateQueue: nil)
        } else {
            s = URLSession(configuration: .ephemeral)
        }
        cachedSession = s
        cachedCertPEM = pem
        return s
    }

    private let configAccount = KeychainAccounts.serverConfig
    private let sessionAccount = KeychainAccounts.session

    // MARK: - Configuration

    func serverConfig() -> ServerConfig? {
        Keychain.read(configAccount).flatMap { try? decoder.decode(ServerConfig.self, from: $0) }
    }

    var isConfigured: Bool { serverConfig() != nil }

    /// Save the sync server URL + bootstrap token and prove them by minting a first session. Clears
    /// any previous session so the next call bootstraps fresh. (Advanced/manual path.)
    func configure(baseUrl: String, bootstrapToken: String) async throws {
        let trimmed = baseUrl.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalized = trimmed.hasSuffix("/") ? String(trimmed.dropLast()) : trimmed
        let cfg = ServerConfig(baseUrl: normalized, bootstrapToken: bootstrapToken, certPEM: nil)
        if let data = try? encoder.encode(cfg) { Keychain.write(configAccount, data) }
        Keychain.delete(sessionAccount)
        _ = try await bootstrap() // fails (and the UI reports) if URL/token are wrong
    }

    /// Onboard from the desktop's "Add a device" QR: pin the server cert, redeem the one-time
    /// enrollment code, and store the minted session. No long-lived secret ever enters the phone.
    func configureFromQR(ip: String, certPEM: String, enrollCode: String) async throws {
        let cfg = ServerConfig(baseUrl: "https://\(ip)", bootstrapToken: nil, certPEM: certPEM)
        if let data = try? encoder.encode(cfg) { Keychain.write(configAccount, data) }
        Keychain.delete(sessionAccount)
        cachedSession = nil // rebuild with the new pin
        let body: [String: Any] = [
            "code": enrollCode,
            "device": ["name": "NorthKey iPhone", "platform": "ios"],
        ]
        let data = try await send("POST", "/v1/auth/enroll", bearer: nil, jsonBody: body)
        let tokens = try decoder.decode(TokenResponse.self, from: data)
        _ = store(tokens)
    }

    // MARK: - THE login (v0.1.48): server address + master password (+ 6-digit code)

    /// First contact with a server typed by address: capture the certificate it presents and
    /// whether master-password sign-in is on. Nothing sensitive is sent; the UI shows the
    /// fingerprint for the user to compare before continuing.
    func probe(address: String) async throws -> ServerProbe {
        let trimmed = address.trimmingCharacters(in: .whitespacesAndNewlines)
        let host = trimmed
            .replacingOccurrences(of: "https://", with: "")
            .replacingOccurrences(of: "http://", with: "")
            .split(separator: "/").first.map(String.init) ?? trimmed
        guard !host.isEmpty else { throw ApiError.transport("enter your server's address") }
        let baseUrl = "https://\(host)"

        let capture = CertCaptureDelegate()
        let session = URLSession(configuration: .ephemeral, delegate: capture, delegateQueue: nil)
        guard let metaUrl = URL(string: "\(baseUrl)/v1/meta") else {
            throw ApiError.transport("bad address")
        }
        let (_, resp) = try await session.data(from: metaUrl)
        guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode),
              let der = capture.leafDER
        else {
            throw ApiError.transport(
                "that server didn't identify itself — it may be too old (update it from your computer) or the address is wrong")
        }
        var ready = false
        if let paramsUrl = URL(string: "\(baseUrl)/v1/auth/password/params"),
           let (_, presp) = try? await session.data(from: paramsUrl),
           let phttp = presp as? HTTPURLResponse
        {
            ready = (200..<300).contains(phttp.statusCode)
        }
        return ServerProbe(
            baseUrl: baseUrl,
            certPEM: CertCaptureDelegate.pem(fromDER: der),
            fingerprint: CertCaptureDelegate.fingerprint(der: der),
            passwordSigninReady: ready)
    }

    /// Sign in with the master password: derive the KEK + login proof locally, mint a session,
    /// and pin the probed cert for every later call. Returns the derived KEK so the vault can be
    /// unwrapped without a second Argon2 run, or nil when a 6-digit code is required.
    func passwordLogin(probe p: ServerProbe, password: String, code: String?) async throws -> Data? {
        // Pin FIRST, so params + login already run over the pinned connection.
        let cfg = ServerConfig(baseUrl: p.baseUrl, bootstrapToken: nil, certPEM: p.certPEM)
        if let data = try? encoder.encode(cfg) { Keychain.write(configAccount, data) }
        Keychain.delete(sessionAccount)
        cachedSession = nil

        let data = try await send("GET", "/v1/auth/password/params", bearer: nil, body: nil)
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let saltB64 = obj["salt_b64"] as? String,
              let salt = Data(base64Encoded: saltB64), salt.count == 16
        else { throw ApiError.badResponse }

        let kek = try VaultCrypto.argon2idKek(password: password, salt: salt)
        let proof = VaultCrypto.loginProof(kek: kek)
        var body: [String: Any] = [
            "proof_b64": proof.base64EncodedString(),
            "device": ["name": "NorthKey iPhone", "platform": "ios"],
        ]
        if let code, !code.trimmingCharacters(in: .whitespaces).isEmpty {
            body["code"] = code.trimmingCharacters(in: .whitespaces)
        }
        do {
            let data = try await send("POST", "/v1/auth/password", bearer: nil, jsonBody: body)
            let tokens = try decoder.decode(TokenResponse.self, from: data)
            _ = store(tokens)
            return kek
        } catch let ApiError.http(400, msg) where msg.contains("totp_required") {
            return nil // second factor needed — the UI shows the 6-digit field and retries
        }
    }

    // MARK: - Vault endpoints (E2E ciphertext only — decrypted in VaultCrypto on-device)

    /// The escrowed master-password-wrapped vault key (SNTL type-4 blob).
    func getWrappedPasswordKey() async throws -> Data {
        let data = try await authed("GET", "/v1/wrapped-keys/4", body: nil)
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let b64 = obj["blob_b64"] as? String,
              let blob = Data(base64Encoded: b64)
        else { throw ApiError.badResponse }
        return blob
    }

    /// The encrypted vault: (version, ciphertext), or nil when the server holds none yet.
    func getVault() async throws -> (Int64, Data)? {
        do {
            let data = try await authed("GET", "/v1/vault", body: nil)
            guard !data.isEmpty,
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let version = obj["version"] as? Int64 ?? (obj["version"] as? Int).map(Int64.init),
                  let b64 = obj["ciphertext_b64"] as? String,
                  let ct = Data(base64Encoded: b64)
            else { return nil }
            return (version, ct)
        } catch let ApiError.http(code, _) where code == 404 {
            return nil
        }
    }

    /// Optimistic-concurrency push. Returns the new version, or nil on a version conflict
    /// (caller re-pulls and retries).
    func putVault(ifMatch: Int64, ciphertext: Data) async throws -> Int64? {
        guard let cfg = serverConfig(), let url = URL(string: cfg.baseUrl + "/v1/vault") else {
            throw ApiError.notConfigured
        }
        let token = try await validAccessToken()
        var req = URLRequest(url: url)
        req.httpMethod = "PUT"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("\"\(ifMatch)\"", forHTTPHeaderField: "If-Match")
        req.httpBody = try JSONSerialization.data(withJSONObject: [
            "ciphertext_b64": ciphertext.base64EncodedString()
        ])
        let (data, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse else { throw ApiError.badResponse }
        if http.statusCode == 409 { return nil }
        guard (200..<300).contains(http.statusCode) else {
            throw ApiError.http(http.statusCode, String(data: data, encoding: .utf8) ?? "")
        }
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let v = obj["version"] as? Int64 ?? (obj["version"] as? Int).map(Int64.init)
        else { throw ApiError.badResponse }
        return v
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
        guard let cfg = serverConfig(), let token = cfg.bootstrapToken else {
            // QR-enrolled devices have no bootstrap token; their refresh chain is the session.
            throw ApiError.notConfigured
        }
        let body: [String: Any] = [
            "token": token,
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
