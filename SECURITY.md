# SECURITY.md — SENTINEL threat model & invariants

SENTINEL is a personal security suite: an on-demand ephemeral WireGuard VPN and a
zero-knowledge password manager. This document states what it protects, against whom,
and the invariants that make those guarantees hold — each mapped to an automated test.

## Assets

1. **Vault plaintext** — passwords, TOTP secrets, notes, cards, identities.
2. **The 256-bit vault key** — decrypts the vault. Never stored unwrapped.
3. **VPN control credentials** — the user's Linode token (OS keychain only).
4. **Account/2FA** — Google identity + TOTP secret (gate sync, not the vault).

## Trust boundaries

- **The vault key exists in plaintext only in RAM**, inside `VaultSession`, and only
  while unlocked. On lock / idle / OS-sleep it is zeroized (`zeroize`).
- **The desktop is the crypto authority.** The Chrome extension and iOS app never hold
  the vault key; they receive decrypted fields per-use (extension) or a wrapped key
  share (phone), and only after the desktop authorizes.
- **The sync server is untrusted for confidentiality.** It stores opaque AEAD blobs and
  an encrypted TOTP secret. It is trusted only for availability and for enforcing
  version monotonicity / rate limits.

## Threat scenarios (and the invariant + test that covers each)

### T1 — Attacker downloads or copies the app binary
The shipped binary contains **no secrets** — no keys, tokens, or vault data are baked
in. Configuration and the Linode token live in the OS keychain on the user's machine,
never in the bundle.
→ Guard: `scripts/plaintext-audit.sh` (CI, **blocking**) greps the tree for PEM private
keys, Linode/Google secret patterns, and seeded plaintext canaries in any `vault.db`/`*.vault`
artifact; `platform::secrets` stores only in the keychain (mock = in-memory, test-only).

### T2 — Attacker steals the vault file / app-data directory
The local vault (`vault.db`) holds only per-item AEAD ciphertext. Without the vault key
— which is not in the file, and is itself only stored wrapped by a TPM/Secure-Enclave,
the paired iPhone, or the recovery kit — nothing decrypts. Auto-lock + zeroize mean a
grabbed-while-running memory image has a narrow window.
→ Tests: `vault::envelope` tamper/wrong-key tests (AEAD open fails); `keyring` wrap/
unwrap round-trip proves the key is recoverable *only* with a wrapper;
`security_gate::locking_prevents_access` proves a locked session yields no plaintext, and
`Key32`/`SecretBytes` are `ZeroizeOnDrop`.

### T3 — Full server database dump **plus** compromised Google account
The brief's hard requirement. The server never holds any unwrap material. A dump gives
the attacker wrapped-key blobs and vault ciphertext; Google gives them the account.
Neither yields the vault key.
→ Test: `structural_zero_knowledge` in `crates/core` assembles a simulated server dump
+ valid Google/TOTP state and asserts no vault item can be decrypted; API-side
`schema_guard` asserts no plaintext-suspect columns exist.

### T4 — Malicious website tries to exfiltrate credentials via the extension
Autofill is offered only for entries whose saved URL matches the page's registrable
domain (PSL), never cross-domain, never in cross-origin iframes, never auto-on-load
(user gesture required), and https-saved entries never fill on http.
→ Tests: `apps/extension/src/matching.test.ts` (table-driven origin cases: subdomain,
suffix-confusion, https-downgrade, ports, cross-origin iframe); desktop-side `origin_matches`
is the authoritative check before any field is released (re-checked in `nmhost` for search /
fields / totp).

### T5 — Locked desktop, attacker drives the extension / native channel
When the desktop is locked, every `vault.*` native-messaging request returns
`err: LOCKED` and the extension caches zero credential data.
→ Test: `nmhost::credential_requests_are_locked_without_vault` asserts every credential
request answers `LOCKED` with **no payload** when the vault can't be opened.

### T6 — MITM on VPN provisioning
A fresh Linode presents its WireGuard pubkey over self-signed TLS; authenticity is an
HMAC over the pubkey keyed by material delivered only in the instance `user_data`.
Single-use token, 90s window.
→ Test: `provision::callback` negative tests reject tampered pubkeys/MACs.

### T7 — Crash leaves a billing VPN instance
Instance id is persisted before create returns; every FSM failure edge destroys; launch
sweep removes anything tagged `sentinel-ephemeral`; server-side dead-man `shutdown -h`.
→ Test: `vpn::session` property test (all failure paths call delete); `orphan_sweep`.

### T8 — Secrets leak into logs
No secret material is ever logged. `CoreError` Display never carries key/plaintext;
`Key32`/`TotpSecret` Debug is redacted.
→ Tests: `security_gate::debug_never_leaks_secrets` (redacted `Debug` for key/secret types)
and `security_gate::errors_never_carry_plaintext` (`CoreError` Display carries no key/plaintext).
Handlers log via `tracing` with no secret-valued fields.

### T9 — Brute force against the account / TOTP
Sensitive endpoints are rate-limited by a sliding-window limiter (`services/api/ratelimit.rs`)
keyed off the **real peer IP** (not a spoofable `X-Forwarded-For` header, unless the server is
explicitly configured to trust a proxy — v0.1.10); TOTP verify has a per-account lockout after
5 failures for 15 min; refresh tokens are stored SHA-256-hashed with rotation + reuse-detection
(a replayed token revokes the whole chain).
→ Tests: `ratelimit::allows_up_to_max_then_blocks`; `integration::refresh_reuse_revokes_chain`.

## Non-goals (v1)

Multi-user sharing, Android, custom/multi-hop protocols, a standalone extension vault,
and billing/payments are out of scope. Losing **all** wrappers means the vault is
unrecoverable — this is by design, and onboarding forces the user to prove they saved
the recovery kit before the vault activates.

## Reporting

This is a personal-use project. Security issues: open a private advisory on the repo.
