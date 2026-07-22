// RFC 6238 TOTP, mirroring the Rust `totp` module (SHA-1/256/512, 6–8 digits).

import Foundation
import CryptoKit

enum TotpAlgo { case sha1, sha256, sha512 }

struct TotpEntry: Identifiable {
    let id = UUID()
    let title: String
    let secret: Data
    let algo: TotpAlgo
    let digits: Int
    let period: Int
}

enum Rfc6238 {
    static func code(secret: Data, algo: TotpAlgo, digits: Int, period: Int, at time: Date = Date()) -> String {
        var counter = UInt64(time.timeIntervalSince1970) / UInt64(period)
        var counterBytes = Data(count: 8)
        for i in (0..<8).reversed() { counterBytes[i] = UInt8(counter & 0xff); counter >>= 8 }
        let key = SymmetricKey(data: secret)
        let digest: [UInt8]
        switch algo {
        case .sha1:   digest = Array(HMAC<Insecure.SHA1>.authenticationCode(for: counterBytes, using: key))
        case .sha256: digest = Array(HMAC<SHA256>.authenticationCode(for: counterBytes, using: key))
        case .sha512: digest = Array(HMAC<SHA512>.authenticationCode(for: counterBytes, using: key))
        }
        let offset = Int(digest[digest.count - 1] & 0x0f)
        let bin = (UInt32(digest[offset] & 0x7f) << 24)
            | (UInt32(digest[offset + 1]) << 16)
            | (UInt32(digest[offset + 2]) << 8)
            | UInt32(digest[offset + 3])
        let mod = UInt32(pow(10.0, Double(digits)))
        return String(format: "%0\(digits)u", bin % mod)
    }

    static func remainingSeconds(period: Int, at time: Date = Date()) -> Int {
        period - Int(time.timeIntervalSince1970) % period
    }
}
