// The phone's vault session: unlock with the account master password (downloads + unwraps the
// escrowed key), pull/decrypt the vault, edit, and push back with optimistic concurrency — the
// exact same E2E blob the desktops sync. The vault key lives in memory; optionally in the
// Keychain behind Face ID (`.biometryCurrentSet`) so relaunches unlock with a glance.

import Foundation
import LocalAuthentication
import Security

/// Provider settings the desktop shares through the encrypted `northkey:system` item, so the phone
/// can monitor Linode/Hetzner/Netdata directly. Field names mirror the desktop's `SET_*` constants
/// (`apps/desktop/src-tauri/src/sync.rs`) — additive-only, like every synced field.
struct ProviderTokens: Equatable {
    var linode = ""
    var hetzner = ""
    /// JSON map of `"provider:id" -> {port, https, hasAuth}` from the desktop's Netdata config.
    var netdataConfigJSON = ""
    /// JSON map of `"provider:id" -> Authorization header` (v0.1.57) for auth-protected Netdata
    /// agents, so the phone can load those dashboards too instead of skipping them. SECRET —
    /// decrypted only in-app; the sync server still only ever holds ciphertext.
    var netdataAuthJSON = ""

    var hasAny: Bool { !linode.isEmpty || !hetzner.isEmpty }

    /// Parsed `"provider:id" -> Authorization header` map (empty when none synced).
    var netdataAuthMap: [String: String] {
        guard !netdataAuthJSON.isEmpty, let data = netdataAuthJSON.data(using: .utf8) else {
            return [:]
        }
        return (try? JSONDecoder().decode([String: String].self, from: data)) ?? [:]
    }

    init() {}

    /// Pull the fields out of the (already-decrypted) system settings item, if present.
    init(fromSystemItems items: [VaultItem]) {
        guard let sys = items.first(where: { $0.tags.contains("northkey:system") }) else { return }
        func field(_ name: String) -> String {
            sys.customFields.first(where: { $0.name == name })?.value ?? ""
        }
        linode = field("linode_token")
        hetzner = field("hetzner_token")
        netdataConfigJSON = field("netdata_config")
        netdataAuthJSON = field("netdata_auth")
    }
}

@MainActor
final class VaultStore: ObservableObject {
    @Published var items: [VaultItem] = []
    @Published var busy = false
    @Published var error: String?
    /// True when the vault on screen came from the offline snapshot because the server was
    /// unreachable. Read-only mode: the list shows, edits are refused until back online.
    @Published var offline = false
    /// Provider tokens the desktop shares through the encrypted `northkey:system` settings item,
    /// so the phone can call Linode/Hetzner/Netdata directly for monitoring (same as the desktop).
    /// Decrypted only here, in-app — the sync server still only ever holds ciphertext.
    @Published var providerTokens = ProviderTokens()

    /// The vault key from the live session, exposed so the Transfers tab can seal/open file blobs.
    var currentVaultKey: Data? { vaultKey }

    private var vaultKey: Data?
    private var version: Int64 = 0
    private var document = VaultDocument(format: 1, items: [], tombstones: [])

    private static let faceIDKeyAccount = "northkey.vault.key.faceid"
    /// A NON-secret marker that Face ID unlock is enabled. Critically, this is what the UI checks
    /// to decide whether to show the "Unlock with Face ID" button — reading the biometric-protected
    /// key itself would pop a Face ID prompt on every SwiftUI re-render (every keystroke), which is
    /// exactly the "scans several times before it opens" bug. The protected key is only ever read
    /// on an explicit unlock tap.
    private static let faceIDEnabledFlag = "northkey.faceid.enabled"

    var isUnlocked: Bool { vaultKey != nil }

    /// Whether Face ID unlock is set up (cheap flag read — never triggers a biometric prompt).
    static func faceIDAvailable() -> Bool {
        UserDefaults.standard.bool(forKey: faceIDEnabledFlag)
    }

    // MARK: - Unlock

    /// Sign-in + master password: download the escrowed wrapped key, unwrap locally, pull.
    /// When the server is unreachable, both steps fall back to the offline snapshot from the
    /// last successful sync — the master password still gates everything.
    func unlock(masterPassword: String) async {
        busy = true
        error = nil
        do {
            let blob: Data
            do {
                blob = try await ApiClient.shared.getWrappedPasswordKey()
                Self.cacheWriteWrappedKey(blob)
            } catch let e where Self.isTransport(e) {
                guard let cached = Self.cacheReadWrappedKey() else { throw e }
                blob = cached
            }
            // Argon2id at 64 MiB — run off the main thread.
            let password = masterPassword
            let key = try await Task.detached(priority: .userInitiated) {
                try VaultCrypto.unwrapPasswordBlob(blob, password: password)
            }.value
            vaultKey = key
            try await pull()
        } catch let ApiError.http(code, _) where code == 404 {
            error = "This account has no master-password unlock set up yet. On your computer: Account & Sync → Enable master-password unlock."
        } catch {
            self.error = error.localizedDescription
        }
        busy = false
    }

    /// Finish a master-password sign-in: the login already derived the KEK, so unwrap the
    /// escrowed key with it directly (no second Argon2 run) and pull.
    func unlockWithKek(_ kek: Data) async {
        busy = true
        error = nil
        do {
            let blob = try await ApiClient.shared.getWrappedPasswordKey()
            Self.cacheWriteWrappedKey(blob)
            let key = try VaultCrypto.unwrapPasswordBlob(blob, kek: kek)
            vaultKey = key
            try await pull()
        } catch let ApiError.http(code, _) where code == 404 {
            error = "Signed in, but no escrowed key yet — on your computer: Account & Sync → Advanced → Turn on master-password sign-in."
        } catch {
            self.error = error.localizedDescription
        }
        busy = false
    }

    /// Relaunch unlock via the Face-ID-protected key (if the user enabled it). Reads the protected
    /// item exactly ONCE, on this explicit tap, with a dedicated LAContext so it's a single Face ID
    /// evaluation with a clear reason — not the per-render storm the availability check used to cause.
    func unlockWithFaceID() async {
        busy = true
        error = nil
        defer { busy = false }
        let ctx = LAContext()
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: Self.faceIDKeyAccount,
            kSecReturnData as String: true,
            kSecUseAuthenticationContext as String: ctx,
            kSecUseOperationPrompt as String: "Unlock your NorthKey vault",
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        guard status == errSecSuccess, let key = item as? Data, key.count == 32 else {
            if status == errSecUserCanceled || status == errSecAuthFailed {
                // User cancelled or Face ID failed — say nothing loud; they can retry or use the password.
                return
            }
            // The protected key is gone (e.g. biometric enrollment changed, which invalidates it).
            // Clear the flag so the button hides and the user is nudged back to the password.
            UserDefaults.standard.set(false, forKey: Self.faceIDEnabledFlag)
            error = "Face ID unlock needs setting up again — unlock with your master password, then re-enable it."
            return
        }
        vaultKey = key
        do { try await pull() } catch { self.error = error.localizedDescription }
    }

    /// Store the vault key behind Face ID for future launches (optional, off by default). Uses an
    /// LAContext so writing the item never itself prompts, and only flips the enabled flag on a
    /// successful store.
    func enableFaceID() {
        guard let key = vaultKey else { return }
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .biometryCurrentSet, nil)
        else { return }
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: Self.faceIDKeyAccount,
        ] as CFDictionary)
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: Self.faceIDKeyAccount,
            kSecValueData as String: key,
            kSecAttrAccessControl as String: access,
            kSecUseAuthenticationContext as String: LAContext(),
        ]
        if SecItemAdd(q as CFDictionary, nil) == errSecSuccess {
            UserDefaults.standard.set(true, forKey: Self.faceIDEnabledFlag)
        }
    }

    func disableFaceID() {
        Keychain.delete(Self.faceIDKeyAccount)
        UserDefaults.standard.set(false, forKey: Self.faceIDEnabledFlag)
    }

    func lock() {
        vaultKey = nil
        items = []
        document = VaultDocument(format: 1, items: [], tombstones: [])
        version = 0
        offline = false
        providerTokens = ProviderTokens()
    }

    // MARK: - Sync

    func pull() async throws {
        guard let key = vaultKey else { return }
        do {
            if let (v, ct) = try await ApiClient.shared.getVault() {
                try await adopt(key: key, version: v, blob: ct)
                Self.cacheWrite(version: v, blob: ct)
            } else {
                document = VaultDocument(format: 1, items: [], tombstones: [])
                version = 0
                items = []
                Self.cacheClearBlob()
            }
            offline = false
        } catch let e where Self.isTransport(e) {
            // Server unreachable — show the snapshot from the last successful sync (read-only).
            guard let (v, ct) = Self.cacheRead() else { throw e }
            try await adopt(key: key, version: v, blob: ct)
            offline = true
        }
    }

    /// Decode a sync blob and adopt it as the current document + visible item list.
    private func adopt(key: Data, version v: Int64, blob ct: Data) async throws {
        let doc = try await Task.detached(priority: .userInitiated) {
            try VaultCrypto.decodeSyncBlob(vaultKey: key, blob: ct, version: UInt64(v))
        }.value
        document = doc
        version = v
        let opened: [VaultItem] = doc.items.compactMap { b64 in
            guard let env = Data(base64Encoded: b64) else { return nil }
            return try? VaultCrypto.openItem(vaultKey: key, envelope: env)
        }
        // Capture the synced provider tokens from the system settings item (used for monitoring),
        // then hide system items from the visible list — they're managed automatically.
        providerTokens = ProviderTokens(fromSystemItems: opened)
        items = opened
            .filter { !$0.tags.contains("northkey:system") }
            .sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
    }

    /// Insert-or-replace an item locally, then push. Retries once on a version conflict by
    /// re-pulling (last-writer-wins per item id — the same shape as the desktop's merge).
    func save(_ item: VaultItem) async {
        busy = true
        error = nil
        do {
            var it = item
            it.updatedAt = Int64(Date().timeIntervalSince1970)
            try await applyAndPush { [weak self] key in
                guard let self else { return }
                var kept: [String] = []
                for b64 in self.document.items {
                    guard let env = Data(base64Encoded: b64),
                          let existing = try? VaultCrypto.openItem(vaultKey: key, envelope: env)
                    else { continue }
                    if existing.id != it.id { kept.append(b64) }
                }
                let sealed = try VaultCrypto.sealItem(vaultKey: key, item: it)
                kept.append(sealed.base64EncodedString())
                self.document.items = kept
            }
        } catch {
            self.error = error.localizedDescription
        }
        busy = false
    }

    func delete(_ item: VaultItem) async {
        busy = true
        error = nil
        do {
            let now = Int64(Date().timeIntervalSince1970)
            try await applyAndPush { [weak self] key in
                guard let self else { return }
                var kept: [String] = []
                for b64 in self.document.items {
                    guard let env = Data(base64Encoded: b64),
                          let existing = try? VaultCrypto.openItem(vaultKey: key, envelope: env)
                    else { continue }
                    if existing.id != item.id { kept.append(b64) }
                }
                self.document.items = kept
                self.document.tombstones.append([.id(item.id), .ts(now)])
            }
        } catch {
            self.error = error.localizedDescription
        }
        busy = false
    }

    private func applyAndPush(_ mutate: @escaping (Data) throws -> Void) async throws {
        guard let key = vaultKey else { return }
        if offline {
            // Give the server one chance to be back before refusing the edit outright.
            try? await pull()
            if offline {
                throw ApiError.transport(
                    "you're offline, so this vault is read-only right now. Reconnect and try again.")
            }
        }
        for attempt in 0..<2 {
            try mutate(key)
            let doc = document
            let v = version
            let blob = try await Task.detached(priority: .userInitiated) {
                try VaultCrypto.encodeSyncBlob(vaultKey: key, document: doc, version: UInt64(v + 1))
            }.value
            if let newVersion = try await ApiClient.shared.putVault(ifMatch: v, ciphertext: blob) {
                version = newVersion
                try await pull()
                return
            }
            // Conflict: another device pushed first — refresh and reapply once.
            try await pull()
            if attempt == 1 { throw ApiError.http(409, "sync conflict — try again") }
        }
    }

    // MARK: - Offline snapshot (server-side ciphertext only — the same bytes the server stores,
    // so keeping them on the phone changes nothing about the zero-knowledge model)

    private static var cacheDir: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let dir = base.appendingPathComponent("NorthKey", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }
    private static var blobFile: URL { cacheDir.appendingPathComponent("vault-cache.bin") }
    private static var versionFile: URL { cacheDir.appendingPathComponent("vault-cache-version") }
    private static var wrappedKeyFile: URL { cacheDir.appendingPathComponent("wrapped-key-4.bin") }

    private static func cacheWrite(version: Int64, blob: Data) {
        try? blob.write(to: blobFile, options: [.atomic, .completeFileProtection])
        try? String(version).data(using: .utf8)?
            .write(to: versionFile, options: [.atomic, .completeFileProtection])
    }

    private static func cacheRead() -> (Int64, Data)? {
        guard let blob = try? Data(contentsOf: blobFile),
              let vdata = try? Data(contentsOf: versionFile),
              let vs = String(data: vdata, encoding: .utf8),
              let v = Int64(vs.trimmingCharacters(in: .whitespacesAndNewlines))
        else { return nil }
        return (v, blob)
    }

    private static func cacheClearBlob() {
        try? FileManager.default.removeItem(at: blobFile)
        try? FileManager.default.removeItem(at: versionFile)
    }

    static func cacheWriteWrappedKey(_ blob: Data) {
        try? blob.write(to: wrappedKeyFile, options: [.atomic, .completeFileProtection])
    }

    static func cacheReadWrappedKey() -> Data? {
        try? Data(contentsOf: wrappedKeyFile)
    }

    /// Remove everything cached for offline use ("forget server" calls this).
    static func clearOfflineCache() {
        cacheClearBlob()
        try? FileManager.default.removeItem(at: wrappedKeyFile)
    }

    private static func isTransport(_ error: Error) -> Bool {
        if case ApiError.transport = error { return true }
        return false
    }
}
