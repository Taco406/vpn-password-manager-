// The phone's vault session: unlock with the account master password (downloads + unwraps the
// escrowed key), pull/decrypt the vault, edit, and push back with optimistic concurrency — the
// exact same E2E blob the desktops sync. The vault key lives in memory; optionally in the
// Keychain behind Face ID (`.biometryCurrentSet`) so relaunches unlock with a glance.

import Foundation
import LocalAuthentication
import Security

@MainActor
final class VaultStore: ObservableObject {
    @Published var items: [VaultItem] = []
    @Published var busy = false
    @Published var error: String?
    /// True when the vault on screen came from the offline snapshot because the server was
    /// unreachable. Read-only mode: the list shows, edits are refused until back online.
    @Published var offline = false

    private var vaultKey: Data?
    private var version: Int64 = 0
    private var document = VaultDocument(format: 1, items: [], tombstones: [])

    private static let faceIDKeyAccount = "northkey.vault.key.faceid"

    var isUnlocked: Bool { vaultKey != nil }

    /// Whether a Face-ID-protected key is stored (so the UI can offer "Unlock with Face ID").
    static func faceIDAvailable() -> Bool {
        Keychain.read(faceIDKeyAccount) != nil
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

    /// Relaunch unlock via the Face-ID-protected key (if the user enabled it).
    func unlockWithFaceID() async {
        busy = true
        error = nil
        // Reading the item triggers the Face ID prompt via its access control.
        if let key = Keychain.read(Self.faceIDKeyAccount), key.count == 32 {
            vaultKey = key
            do { try await pull() } catch { self.error = error.localizedDescription }
        } else {
            error = "Face ID unlock isn't set up on this phone yet."
        }
        busy = false
    }

    /// Store the vault key behind Face ID for future launches (optional, off by default).
    func enableFaceID() {
        guard let key = vaultKey else { return }
        let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .biometryCurrentSet, nil)!
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: Self.faceIDKeyAccount,
            kSecValueData as String: key,
            kSecAttrAccessControl as String: access,
        ]
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: Self.faceIDKeyAccount,
        ] as CFDictionary)
        SecItemAdd(q as CFDictionary, nil)
    }

    func disableFaceID() {
        Keychain.delete(Self.faceIDKeyAccount)
    }

    func lock() {
        vaultKey = nil
        items = []
        document = VaultDocument(format: 1, items: [], tombstones: [])
        version = 0
        offline = false
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
        items = doc.items.compactMap { b64 in
            guard let env = Data(base64Encoded: b64) else { return nil }
            return try? VaultCrypto.openItem(vaultKey: key, envelope: env)
        }
        // System items (synced app settings) are managed automatically — never listed.
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
