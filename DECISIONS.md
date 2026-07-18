# DECISIONS.md

Running log of architecture/security decisions. Per the build brief's working
agreement: **when a choice is ambiguous, take the more secure option and record it
here.** Newest entries at the bottom of each section.

## Crypto & key model

- **D1 — No memorized master password.** A random 256-bit vault key is generated at
  setup and only ever stored *wrapped*. Rationale: eliminates the weakest link
  (human-chosen passwords) from the confidentiality boundary. Wrappers A (platform
  biometric/TPM), B (iPhone Secure-Enclave share), C (128-bit recovery kit).
- **D2 — AEAD = XChaCha20-Poly1305** (24-byte random nonce). Chosen over AES-GCM for
  the larger nonce space (random nonces are safe without a counter) and misuse
  resistance. Nonce always from `OsRng`.
- **D3 — KDF split.** HKDF-SHA256 for fast key separation from high-entropy inputs
  (the vault key, ECDH outputs); Argon2id (m=64MiB, t=3, p=4) only where the input is
  lower-entropy and attacker-grindable (the recovery key, export passphrases). Never
  use a fast KDF on a human passphrase.
- **D4 — Per-item keys.** Each vault item is sealed under
  `HKDF(vault_key, salt=item_id, info="sentinel/v1/vault/item")`, not the vault key
  directly. Limits blast radius and binds ciphertext to its item id via AAD.
- **D5 — Recovery key encoding.** 128-bit key, Crockford Base32 (ambiguous chars
  I/L/O folded), 15-bit SHA-256 checksum, versioned first char. Displayed as
  `SNTL-XXXXX-...` in six groups so a human can transcribe it from the printed kit.
- **D6 — Argon2id Test profile.** Tests and CI use m=8MiB, t=1, p=1 for speed. A
  `const` assertion test pins the *production* profile to the brief's exact params so
  the fast profile can never silently ship. The Test profile is refused when the crate
  is built `--release` with any `live-*` feature.

## Server / zero-knowledge

- **D7 — Server holds only opaque blobs.** `wrapped_keys.blob` and `vaults.ciphertext`
  are AEAD outputs; no server-side column can hold a plaintext secret. A migration-time
  assertion + a `cargo test` enforce "no plaintext-suspect columns". A full server dump
  plus a compromised Google account still cannot decrypt any vault item (structural
  test in `crates/core`).
- **D8 — Account TOTP secret is the one server-side secret.** The API must verify TOTP,
  so it stores the TOTP secret encrypted (AES-256-GCM) under `SENTINEL_TOTP_ENC_KEY`,
  which the server necessarily knows. This protects *the account/2FA*, not the vault.
  Vault confidentiality does not depend on it. Documented so the asymmetry is explicit.
- **D9 — Vault version monotonicity is a DB constraint,** not just app logic: a
  `BEFORE UPDATE` trigger requires `new.version = old.version + 1`. Prevents rollback
  and lost-update attacks even if the app or a client misbehaves.

## VPN

- **D10 — Delete-on-any-failure.** The connect state machine persists the instance id
  to disk *before* the create call can return, and every failure edge routes through
  `Destroying`. Combined with a launch-time orphan sweep (tag `sentinel-ephemeral`) and
  a server-side dead-man `shutdown -h`, a crash cannot leave a billing instance for
  more than the dead-man window.
- **D11 — Provisioning pubkey authenticity.** The fresh server presents its WireGuard
  pubkey over a self-signed TLS callback; authenticity comes from an HMAC over the
  pubkey using a key delivered only inside the Linode `user_data` (over Linode's TLS
  API). The callback token is single-use with a 90s window. Avoids TOFU on the pubkey.

## Platform / build

- **D12 — `src-tauri` excluded from Cargo `default-members`.** All logic lives in the
  headless, fully-tested `sentinel-core`; the Tauri crate is 1-line-per-command glue so
  `cargo test` never needs a GUI toolchain. (webkit2gtk *is* installable here, so the
  real desktop build is also exercised, but tests never depend on it.)
- **D13 — Custom d3-geo 2D-canvas globe, WebGL rejected.** react-globe.gl / three.js
  need WebGL, which falls back to slow/blank SwiftShader in headless Chromium, making
  screenshots flaky and adding ~600KB. A 2D-canvas orthographic globe is deterministic,
  cheap, and screenshots pixel-stably.
- **D14 — Mock bridge is the demo substrate.** The frontend targets a `SentinelBridge`
  interface with two impls: a real Tauri `invoke` bridge and a deterministic in-browser
  mock seeded from Rust (`sentinel-cli seed --json`). Everything is buildable,
  testable, and screenshottable in headless Chromium without a desktop binary.
- **D15 — zxcvbn runs in two places.** The Rust `zxcvbn` crate is authoritative for the
  health audit; the JS `@zxcvbn-ts` port drives only the live UI strength meter. They
  can disagree at the margins; the audit result is the source of truth.

## API implementation

- **D17 — sqlx runtime queries, not the `query!` macros.** The API uses
  `sqlx::query`/`query_as` (checked at run time against the live schema by integration
  tests) rather than compile-time-checked macros. This removes the need for a live DB
  at build time and the committed `.sqlx` offline cache, eliminating a whole class of
  CI friction (stale-cache failures). Coverage comes from integration tests that run
  every query against a real Postgres 16.
- **D18 — ES256 JWT keys are generated, never committed.** The server loads its signing
  key from `SENTINEL_JWT_ES256_PEM`; if unset (dev/test), it generates an ephemeral
  P-256 keypair at boot. No private key is ever committed (the plaintext-audit gate
  would reject one anyway).

## Vault

- **D19 — Curated passphrase wordlist, entropy from the real list size.** Rather than
  vendoring the full 7776-word EFF list as a binary asset, the generator ships a
  curated list of common, easy-to-type words and reports passphrase entropy as
  `words × log2(list_len)` from the *actual* deduplicated list size — never an inflated
  constant. The default word count is raised to compensate, and the zxcvbn meter gives
  the real-world strength on top. Swapping in the full EFF list later only increases
  entropy and requires no format change.

## Local-first (user requirement)

- **D16 — The app works fully offline with no account.** Onboarding can skip Google
  entirely; the local vault (rusqlite) and VPN (with the user's own Linode token) work
  with zero server contact. The sync API is optional and only needed for multi-device
  sync, new-device approval, and iPhone-unlock relay. A stolen app binary contains no
  secrets; a stolen vault file is opaque ciphertext with the key held only in
  hardware/phone/recovery-kit wrappers.
