# SENTINEL crypto specification (normative)

This is the authoritative parameter table. Code in `crates/core` must match it; several
tests pin these values (`argon2_production_profile`, golden envelope layouts).

## Primitives

| Purpose | Algorithm / parameters |
|---|---|
| Vault key | 32 random bytes (`OsRng`). Plaintext only in RAM inside `VaultSession`; zeroized on lock. |
| AEAD (vault, wrappers, export) | **XChaCha20-Poly1305**, 24-byte random nonce (fresh per seal), 16-byte tag. |
| AEAD (pairing channel) | **IETF ChaCha20-Poly1305**, 12-byte nonce, CryptoKit combined-box form (`nonce ‖ ct ‖ tag`) for iOS interop. |
| Key separation | HKDF-SHA256, 32-byte output. |
| Slow KDF | Argon2id, **m = 65536 KiB (64 MiB), t = 3, p = 4**, 32-byte output, 16-byte random salt. Test profile m=8192, t=1, p=1 is gated to non-live builds. |

## HKDF `info` strings

```
sentinel/v1/wrap/platform
sentinel/v1/wrap/phone-share
sentinel/v1/wrap/recovery
sentinel/v1/vault/item
sentinel/v1/vault/outer
sentinel/v1/pair/chan/desktop->phone
sentinel/v1/pair/chan/phone->desktop
sentinel/v1/export
```

## Wrapped-key blob

```
"SNTL"(4) | ver=0x01 | wrapper_type u8 {1=platform,2=phone,3=recovery}
         | params_len u16 LE | params | nonce(24) | ct(48)
```
- ct = the 32-byte vault key sealed under the wrapper's KEK (32 + 16 tag = 48).
- AAD = the entire header (magic … params).
- Platform/phone: `params_len = 0` (80 bytes total). Recovery: `params = argon2 salt(16)` (96 bytes).
- KEKs: platform = hardware key; phone = `HKDF(share_b, salt = pairing_id, wrap/phone-share)`;
  recovery = `HKDF(Argon2id(recovery_key, salt), wrap/recovery)`.

## Vault item envelope

```
0x01 | item_id(16) | updated_at i64 LE (8) | nonce(24) | ct
```
- Item key = `HKDF(vault_key, salt = item_id, vault/item)`.
- AAD = the first 25 bytes (binds ciphertext to its id and timestamp).

## Sync blob (server-stored vault)

```
"SVLT"(4) | 0x01 | 0x00 0x00 0x00 | nonce(24) | ct
```
- Plaintext = zstd(level 3, JSON of the vault document).
- Outer key = `HKDF(vault_key, vault/outer)`.
- AAD = header(8) ‖ **server version u64 LE** — binds the ciphertext to the server's
  monotonic version so a rollback/replay fails to open.

## Encrypted export

```
"SEXP"(4) | ver=0x01 | salt(16) | nonce(24) | ct
```
- KEK = `HKDF(Argon2id(passphrase, salt), export)`; plaintext = JSON of the items.

## Recovery key

- 128-bit key (`OsRng`).
- Crockford Base32 alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`; decode folds I/L→1, O→0.
- 30 data chars: `[0]` version (`A`=v1); `[1..27]` = 130 bits (2 zero pad + 128 key,
  big-endian); `[27..30]` = 15-bit checksum = top 15 bits of `SHA-256("SNTL-RK-v1" ‖ key)`.
- Displayed `SNTL-` + six hyphenated groups of five. Entropy 128 bits.

## Provisioning callback

- Single-use bearer token (32 random bytes hex), 90s window.
- Server pubkey authenticity = `HMAC-SHA256(callback_hmac_key, pubkey ‖ ip)`, key
  delivered only in the instance's cloud-init `user_data` (over the provider's TLS API).

## Pairing channel

- P-256 ECDH (desktop ephemeral ⇄ phone Secure-Enclave static, pinned).
- transcript = QR payload ‖ desktop pub (SEC1) ‖ phone pub (SEC1).
- Per-direction keys = `HKDF(ecdh_x, salt = SHA256(transcript), pair/chan/*)`.
- 6-digit verification code = `SHA-256(transcript)[..4] as u32 mod 10^6`, compared
  out-of-band by the human (no TOFU).

## Account (server-side)

- TOTP: RFC 6238 SHA-1, 6 digits, 30s. Secret at rest under the server's
  `SENTINEL_TOTP_ENC_KEY` (the one secret the server necessarily holds — it protects
  the account/2FA, not the vault; see DECISIONS D8).
- Access token: ES256 JWT, 10-minute lifetime. Refresh token: 32 random bytes, stored
  as SHA-256, 30-day lifetime, rotation with reuse-detection.
