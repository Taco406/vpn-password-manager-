// The end-to-end pairing channel. This mirrors the Rust `pairing::channel` byte for
// byte so the phone and desktop interoperate:
//   - P-256 ECDH (CryptoKit `P256.KeyAgreement`),
//   - transcript = qrPayload ‖ desktopPubSEC1 ‖ phonePubSEC1,
//   - per-direction keys = HKDF-SHA256(sharedSecret, salt = SHA256(transcript), info),
//   - IETF ChaCha20-Poly1305 in combined-box form (nonce ‖ ct ‖ tag).

import Foundation
import CryptoKit

enum Role { case desktop, phone }

// Info strings — identical to the Rust `Info` enum.
enum ChannelInfo {
    static let desktopToPhone = "sentinel/v1/pair/chan/desktop->phone"
    static let phoneToDesktop = "sentinel/v1/pair/chan/phone->desktop"
}

struct PairingChannel {
    private let sendKey: SymmetricKey
    private let recvKey: SymmetricKey

    /// Build the transcript that binds the QR payload and both public keys.
    static func transcript(qrPayload: Data, desktopPubSEC1: Data, phonePubSEC1: Data) -> Data {
        var t = Data()
        t.append(qrPayload)
        t.append(desktopPubSEC1)
        t.append(phonePubSEC1)
        return t
    }

    /// The 6-digit out-of-band verification code (first 4 bytes of SHA256, mod 1e6).
    static func verificationCode(transcript: Data) -> String {
        let d = SHA256.hash(data: transcript)
        let bytes = Array(d)
        let n = (UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16 | UInt32(bytes[2]) << 8 | UInt32(bytes[3])) % 1_000_000
        return String(format: "%06u", n)
    }

    init(role: Role, sharedSecret: SharedSecret, transcript: Data) {
        let salt = Data(SHA256.hash(data: transcript))
        let d2p = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: salt,
            sharedInfo: Data(ChannelInfo.desktopToPhone.utf8), outputByteCount: 32)
        let p2d = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: salt,
            sharedInfo: Data(ChannelInfo.phoneToDesktop.utf8), outputByteCount: 32)
        switch role {
        case .desktop: (sendKey, recvKey) = (d2p, p2d)
        case .phone:   (sendKey, recvKey) = (p2d, d2p)
        }
    }

    /// Seal a message for the peer. AAD = "pair", matching the Rust side.
    func seal(_ plaintext: Data) throws -> Data {
        let box = try ChaChaPoly.seal(plaintext, using: sendKey, authenticating: Data("pair".utf8))
        return box.combined // nonce ‖ ciphertext ‖ tag
    }

    /// Open a combined box from the peer.
    func open(_ combined: Data) throws -> Data {
        let box = try ChaChaPoly.SealedBox(combined: combined)
        return try ChaChaPoly.open(box, using: recvKey, authenticating: Data("pair".utf8))
    }
}
