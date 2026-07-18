# SentinelKey — Xcode project settings

The sources in `SentinelKey/` are a complete SwiftUI app. Create the Xcode project
around them with these exact settings (there is no `.xcodeproj` in the repo because it
cannot be built without a Mac).

## Target

- **Product name:** SentinelKey
- **Bundle id:** `com.<you>.sentinelkey`
- **Deployment target:** iOS 16.0 (Secure Enclave `P256.KeyAgreement`, CryptoKit
  `hkdfDerivedSymmetricKey`).
- **Devices:** iPhone only. The Secure Enclave is **not** available in the simulator —
  build to a physical device.
- **Swift language version:** 5.9+.

## Capabilities / entitlements

- **Keychain Sharing** — for the Enclave key reference.
- **Push Notifications** — to wake the app for unlock approvals.
- **Background Modes → Remote notifications**.
- **Data Protection** — `NSFileProtectionComplete` (the app writes no vault data, but
  set the strictest default).

## Info.plist keys

- `NSCameraUsageDescription` = "Scan the pairing QR shown on your Mac."
- `NSFaceIDUsageDescription` = "Approve unlocks and release your vault key share."

## Signing

- Automatic signing with your Team.
- The App ID must have Push Notifications enabled; create an APNs auth key (.p8) and
  configure it on the sync API (`APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_P8`).

## Source → group mapping

| Group | Files |
|---|---|
| App | `SentinelKeyApp.swift`, `ContentView.swift` |
| Crypto | `Crypto/EnclaveKey.swift`, `Crypto/Channel.swift` |
| Pairing | `Pairing/PairingCeremony.swift`, `Pairing/QRScanner.swift` |
| Approvals | `Approvals/UnlockApprovalView.swift`, `Approvals/PushHandler.swift` |
| TOTP | `Totp/Rfc6238.swift`, `Totp/TotpViewer.swift` |

## Interop invariant

`Crypto/Channel.swift` must stay byte-compatible with the Rust `pairing::channel`
module: P-256 ECDH, transcript = `qr ‖ desktopPubSEC1 ‖ phonePubSEC1`, HKDF-SHA256
salted by `SHA256(transcript)` with the info strings in `ChannelInfo`, and IETF
ChaCha20-Poly1305 in CryptoKit's combined-box form. The Rust test
`full_ceremony_both_roles_agree` is the reference vector.
