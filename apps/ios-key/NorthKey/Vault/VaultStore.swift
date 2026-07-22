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
    func unlock(masterPassword: String) async {
        busy = true
        error = nil
        do {
            let blob = try await ApiClient.shared.getWrappedPasswordKey()
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
    }

    // MARK: - Sync

    func pull() async throws {
        guard let key = vaultKey else { return }
        if let (v, ct) = try await ApiClient.shared.getVault() {
            let doc = try await Task.detached(priority: .userInitiated) {
                try VaultCrypto.decodeSyncBlob(vaultKey: key, blob: ct, version: UInt64(v))
            }.value
            document = doc
            version = v
            items = doc.items.compactMap { b64 in
                guard let env = Data(base64Encoded: b64) else { return nil }
                return try? VaultCrypto.openItem(vaultKey: key, envelope: env)
            }
            .sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        } else {
            document = VaultDocument(format: 1, items: [], tombstones: [])
            version = 0
            items = []
        }
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
}
