# Device pairing ceremony (desktop ⇄ iPhone)

Pairing establishes an end-to-end encrypted channel and pins the phone's public key so
later unlock approvals are authentic. There is **no trust-on-first-use**: a human
compares a 6-digit code out-of-band.

## Steps

1. **Desktop** generates an ephemeral P-256 keypair and shows a QR:
   `{ v, pairingId, relayUrl, desktopPub (SEC1 base64), expires }`.
2. **iPhone** scans the QR, loads/creates its Secure-Enclave P-256 key (Face-ID gated),
   and performs ECDH with the desktop's public key.
3. Both sides compute:
   - `transcript = qrPayload ‖ desktopPubSEC1 ‖ phonePubSEC1`
   - per-direction channel keys via `HKDF(ecdh_x, salt = SHA256(transcript), pair/chan/*)`
   - a **6-digit verification code** = `SHA256(transcript)[..4] mod 10^6`.
4. The user confirms the codes match on both screens. Only then does the desktop **pin**
   the phone's public key and the phone register as a wrapper.

## Why it's safe

If an attacker tampers with the QR or substitutes a public key, the transcript changes,
so the two verification codes won't match and the human aborts. And because the phone's
key is pinned, a later unlock attempt from a different key cannot decrypt — proven by
the Rust tests `tampered_transcript_breaks_the_channel` and
`pinned_key_mismatch_is_detectable`.

## Unlock flow (after pairing)

1. Desktop creates an unlock request (`POST /v1/unlock-requests`) carrying an opaque
   E2E ciphertext; the server relays it and fires an APNs push.
2. iPhone wakes, Face ID gates the approval, and it releases the key share sealed over
   the pinned channel (`POST /v1/unlock-requests/:id/respond`).
3. Desktop long-polls, receives the opaque response verbatim, decrypts the share, and
   unwraps the vault key.

The server only moves opaque blobs — request and response payloads are E2E ciphertext,
size-capped, and expire after 2 minutes.

## Interop

`apps/ios-key/SentinelKey/Crypto/Channel.swift` is byte-compatible with
`crates/core/pairing/channel.rs`. The reference vector is the Rust test
`full_ceremony_both_roles_agree`; `just ios-docs-check` asserts the HKDF info strings
match.
