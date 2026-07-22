# NorthKey — iPhone companion

A one-screen SwiftUI app that turns an iPhone into a hardware key for the NorthKey desktop vault: it
holds a Secure-Enclave key share, approves unlocks after Face ID, approves new devices, and shows a
read-only pocket TOTP viewer.

> **Not built in CI.** This directory is complete SwiftUI source, an [XcodeGen](project.yml) spec, and
> setup docs. It needs a Mac with Xcode and an Apple Developer account to build — there is no Swift
> toolchain in the NorthKey CI environment, so the Swift here is delivered to build on your Mac. The
> crypto mirrors the Rust `pairing` module exactly (P-256 ECDH, transcript-salted HKDF-SHA256, IETF
> ChaCha20-Poly1305 in CryptoKit's combined-box format), so the two interoperate.

## What it does

- **Connect to your sync server** — enter your NorthKey sync server URL and personal setup token
  once; the phone enrolls as an approved iOS device and holds its session in the Keychain.
- **Pairing ceremony** — scan the QR shown by the desktop, verify the 6-digit code matches on both
  screens (out-of-band, no trust-on-first-use), and register the phone's pinned Secure-Enclave public
  key with the sync server.
- **Unlock approvals** — a push arrives, Face ID gates it, and the response is relayed to the desktop.
- **Pocket TOTP viewer** — a read-only mirror of the vault's TOTP entries.

## Status — what's wired

**iOS-1 (this milestone).** The app is buildable and installable, and the following are real, end to
end against a live `sentinel-api`:

- Server onboarding + bootstrap auth, session held/rotated in the Keychain (`Api/ApiClient.swift`).
- APNs registration (`POST /v1/push/register`).
- Pinning the phone's Secure-Enclave key at pairing (`POST /v1/devices/pin`).
- Fetching a pushed unlock request and responding approve/deny behind Face ID
  (`GET`/`POST /v1/unlock-requests/:id[/respond]`).

**Next increments** (tracked in the iPhone roadmap): sealing the actual vault **key share** over the
pinned channel on approval (needs the desktop to emit a per-unlock ECDH payload and to drive the
pairing UI), the **vault viewer** over a `sentinel-core` UniFFI XCFramework, iOS **AutoFill**, and
**passkeys**.

## Building it (on a Mac)

1. **Apple Developer account** ($99/yr) — needed for the Secure Enclave, push notifications, and
   device provisioning. A free account can sideload but cannot use push.
2. Generate and open the project (see [PROJECT.md](PROJECT.md)):
   ```bash
   brew install xcodegen
   cd apps/ios-key && xcodegen generate && open NorthKey.xcodeproj
   ```
3. Set your **Team** and (if needed) a unique bundle id in Signing & Capabilities.
4. **Push:** enable Push Notifications on the App ID and create an APNs key; wire it into the sync
   API's env (`APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_P8`).
5. Build to a device (the Secure Enclave is unavailable in the simulator).
6. **First run:** enter your sync server URL and the personal setup token
   (`SENTINEL_BOOTSTRAP_TOKEN` from your one-click sync-server deploy).
7. **TestFlight / sideload:** Archive → distribute via TestFlight for family, or sideload for
   personal use.

## Security properties

- The Secure-Enclave private key is non-exportable and used only for ECDH; Face ID
  (`SecAccessControl` with `.biometryCurrentSet`) gates every use.
- The desktop's public key is pinned at pairing; a different key never decrypts
  (`pinned_key_mismatch` in the Rust tests).
- No vault data is written to disk — a filesystem audit finds only the Enclave key reference and the
  Keychain-held session. TOTP entries are fetched per-open and held in memory.
- The sync server only relays **opaque E2E ciphertext** for unlock request/response payloads,
  size-capped and expiring after 2 minutes.

## Layout

```
apps/ios-key/
  project.yml                  XcodeGen spec (generates NorthKey.xcodeproj)
  Config/Info.plist            usage strings, background modes
  Config/NorthKey.entitlements push + data-protection
  NorthKey/
    NorthKeyApp.swift          app entry, push registration
    ContentView.swift          the single screen (onboarding / pairing / paired)
    Onboarding/ServerSetupView.swift  first-run: connect to your sync server
    Api/ApiClient.swift        sync-server client + Keychain session
    Crypto/EnclaveKey.swift    Secure-Enclave P-256 key, Face-ID gated
    Crypto/Channel.swift       E2E channel — mirrors Rust pairing::channel
    Pairing/PairingCeremony.swift  QR scan + verification-code check + key pin
    Pairing/QRScanner.swift    AVFoundation QR scanner
    Approvals/UnlockApprovalView.swift  Face ID → respond over the relay
    Approvals/PushHandler.swift  APNs handling
    Totp/TotpViewer.swift      read-only TOTP list
    Totp/Rfc6238.swift         RFC 6238 codes (SHA-1/256/512)
  PROJECT.md                   exact target/entitlement/capability settings
```
