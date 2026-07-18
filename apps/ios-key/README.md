# SENTINEL Key — iOS companion

A one-screen SwiftUI app that turns an iPhone into a hardware key for the SENTINEL
desktop vault: it holds a Secure-Enclave key share, approves unlocks after Face ID,
approves new devices, and shows a read-only pocket TOTP viewer.

> **Not built in CI.** This directory is complete SwiftUI source plus setup docs. It
> needs a Mac with Xcode and an Apple Developer account to build — there is no Swift
> toolchain in the SENTINEL CI environment. The crypto here mirrors the Rust
> `pairing` module exactly (P-256 ECDH, transcript-salted HKDF-SHA256, IETF
> ChaCha20-Poly1305 in CryptoKit's combined-box format), so the two interoperate.

## What it does

- **Pairing ceremony** — scan the QR shown by the desktop, verify the 6-digit code
  matches on both screens (out-of-band, no trust-on-first-use), and register the
  phone's pinned Secure-Enclave public key.
- **Unlock approvals** — a push arrives, Face ID gates it, and the key share is
  released over the pinned E2E channel. The desktop card shows the live approval state.
- **New-device approval** — approve a newly-enrolled desktop from the phone.
- **Pocket TOTP viewer** — a read-only mirror of the vault's TOTP entries, fetched
  per-open over the E2E channel. Nothing is stored at rest beyond the Enclave key.

## Security properties

- The Secure-Enclave private key is non-exportable and used only for ECDH; Face ID
  (`SecAccessControl` with `.biometryCurrentSet`) gates every use.
- The desktop's public key is pinned at pairing; a different key never decrypts
  (`pinned_key_mismatch` in the Rust tests).
- No vault data is written to disk — a filesystem audit finds only the Enclave key
  reference. TOTP entries are fetched per-open and held in memory.

## Building it (on a Mac)

1. **Apple Developer account** ($99/yr) — needed for the Secure Enclave, push
   notifications, and device provisioning. A free account can sideload but cannot use
   push.
2. Open `SentinelKey.xcodeproj` (create it from the sources per `PROJECT.md`) in Xcode.
3. Set your Team and a unique bundle id (e.g. `com.yourname.sentinelkey`).
4. Entitlements (see `PROJECT.md`): Keychain Sharing, Push Notifications, and the
   `com.apple.developer.default-data-protection` = `NSFileProtectionComplete`.
5. **Push certificates**: enable Push Notifications on the App ID in the developer
   portal and create an APNs key; wire it into the sync API's `.env` (`APNS_KEY_ID`,
   `APNS_TEAM_ID`, `APNS_P8`).
6. Build to a device (the Secure Enclave is unavailable in the simulator).
7. **TestFlight / sideload**: Archive → distribute via TestFlight for family, or
   sideload directly for personal use.

## Layout

```
SentinelKey/
  SentinelKeyApp.swift        app entry, push registration
  ContentView.swift           the single screen (paired state, approvals, TOTP)
  Crypto/EnclaveKey.swift      Secure-Enclave P-256 key, Face-ID gated
  Crypto/Channel.swift         E2E channel — mirrors Rust pairing::channel
  Pairing/PairingCeremony.swift  QR scan + verification-code check + registration
  Pairing/QRScanner.swift      AVFoundation QR scanner
  Approvals/UnlockApprovalView.swift  Face ID → release share
  Approvals/PushHandler.swift  APNs handling
  Totp/TotpViewer.swift        read-only TOTP list
  Totp/Rfc6238.swift           RFC 6238 codes (SHA-1/256/512)
PROJECT.md                    exact target/entitlement/capability settings
```
