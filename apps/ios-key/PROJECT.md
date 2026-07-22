# NorthKey iPhone — Xcode project

The Xcode project is **generated from [`project.yml`](project.yml)** with
[XcodeGen](https://github.com/yonyz/XcodeGen), so there's no `.xcodeproj` checked in (it can't be
produced or built without a Mac, and generating it keeps the repo free of `pbxproj` merge conflicts).

## Generate and open

```bash
brew install xcodegen                 # once
cd apps/ios-key && xcodegen generate  # writes NorthKey.xcodeproj (gitignored)
open NorthKey.xcodeproj
```

Then in Xcode → **Signing & Capabilities**, pick your **Team** and (if `com.northkey.app` is taken) a
unique bundle id. Build to a **physical iPhone** — the Secure Enclave is unavailable in the simulator.

## What `project.yml` sets

- **Product / bundle id:** NorthKey / `com.northkey.app`.
- **Deployment target:** iOS 16.0 (Secure Enclave `P256.KeyAgreement`, CryptoKit
  `hkdfDerivedSymmetricKey`).
- **Devices:** iPhone only (`TARGETED_DEVICE_FAMILY = 1`).
- **Info.plist:** [`Config/Info.plist`](Config/Info.plist) — camera + Face ID usage strings and the
  `remote-notification` background mode.
- **Entitlements:** [`Config/NorthKey.entitlements`](Config/NorthKey.entitlements) —
  `aps-environment` (push) and `com.apple.developer.default-data-protection = NSFileProtectionComplete`.

## One-time Apple setup

- Enable **Push Notifications** on the App ID in the developer portal and create an **APNs key**
  (`.p8`); wire it into the sync API's env (`APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_P8`).
- For TestFlight/App Store, switch `aps-environment` in the entitlements from `development` to
  `production`. The same Apple Team, Developer ID, and notarization credentials as the Mac app are
  reused — see [`docs/macos-signing.md`](../../docs/macos-signing.md).

## Source layout (`NorthKey/`)

| Group | Files |
|---|---|
| App | `NorthKeyApp.swift`, `ContentView.swift` |
| Onboarding | `Onboarding/ServerSetupView.swift` |
| Api | `Api/ApiClient.swift` (sync-server client + Keychain session) |
| Crypto | `Crypto/EnclaveKey.swift`, `Crypto/Channel.swift` |
| Pairing | `Pairing/PairingCeremony.swift`, `Pairing/QRScanner.swift` |
| Approvals | `Approvals/UnlockApprovalView.swift`, `Approvals/PushHandler.swift` |
| TOTP | `Totp/Rfc6238.swift`, `Totp/TotpViewer.swift` |

## Interop invariant

`Crypto/Channel.swift` must stay byte-compatible with the Rust `pairing::channel` module: P-256
ECDH, transcript = `qr ‖ desktopPubSEC1 ‖ phonePubSEC1`, HKDF-SHA256 salted by `SHA256(transcript)`
with the info strings in `ChannelInfo` (kept as the `sentinel/v1/pair/chan/*` protocol constants —
**do not rebrand them**), and IETF ChaCha20-Poly1305 in CryptoKit's combined-box form. The Rust test
`full_ceremony_both_roles_agree` is the reference vector; `just ios-docs-check` asserts the HKDF info
strings match across `Channel.swift` and `crates/core/src/crypto/kdf.rs`.
