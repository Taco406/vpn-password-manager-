// The phone's static P-256 key, generated in and non-exportable from the Secure
// Enclave. Every use (ECDH during an unlock) is gated by Face ID via SecAccessControl.

import Foundation
import CryptoKit
import LocalAuthentication

enum EnclaveError: Error { case unavailable, denied }

struct EnclaveKey {
    /// The persisted Secure-Enclave key. Created once at pairing.
    private let key: SecureEnclave.P256.KeyAgreement.PrivateKey

    /// Load an existing key from the Keychain, or create one gated by Face ID.
    static func loadOrCreate() throws -> EnclaveKey {
        guard SecureEnclave.isAvailable else { throw EnclaveError.unavailable }
        if let data = Keychain.read("sentinel.enclave.key") {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: data)
            return EnclaveKey(key: key)
        }
        let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet], nil)!
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        Keychain.write("sentinel.enclave.key", key.dataRepresentation)
        return EnclaveKey(key: key)
    }

    /// SEC1 uncompressed public key (65 bytes) — what the desktop pins.
    var publicSEC1: Data { key.publicKey.x963Representation }

    /// Perform ECDH with the desktop's ephemeral public key. Triggers Face ID.
    func agree(withDesktopSEC1 desktopPub: Data, reason: String) throws -> SharedSecret {
        let context = LAContext()
        context.localizedReason = reason
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: desktopPub)
        // `key` requires biometric auth on use because of the access-control flags.
        return try key.sharedSecretFromKeyAgreement(with: peer)
    }
}

/// Minimal Keychain wrapper (data-protection class = complete).
enum Keychain {
    static func read(_ account: String) -> Data? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
        ]
        var item: CFTypeRef?
        return SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess ? item as? Data : nil
    }

    static func write(_ account: String, _ data: Data) {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        SecItemDelete(q as CFDictionary)
        SecItemAdd(q as CFDictionary, nil)
    }
}
