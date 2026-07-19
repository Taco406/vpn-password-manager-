# SENTINEL — Security review (2026-07)

_Reviewer: automated pass (Claude) · Version reviewed: v0.1.9 → fixes land in v0.1.10 ·
Scope: desktop app (`apps/desktop`), core crypto (`crates/core`), sync server (`services/api`),
browser extension (`apps/extension`), CI/supply-chain._

## Summary

SENTINEL's cryptographic core is strong and well-tested: XChaCha20-Poly1305 AEAD with a fresh
random nonce per seal, HKDF-SHA256 with purpose-separated `info` strings, Argon2id for low-entropy
inputs, `ZeroizeOnDrop` secret types with redacted `Debug`, per-item AAD binding (ciphertext bound
to item id + timestamp), and a **structurally-tested zero-knowledge** sync model (a simulated full
server dump plus a compromised Google account still decrypts nothing). VPN provisioning authenticates
the node's WireGuard pubkey with an HMAC (not TLS trust), and cloud-init hardens the node
(default-drop firewall, SSH disabled, dead-man switch).

The review found **no plaintext-leak or key-exposure defects** in the core. The material findings
were in the **optional sync server's operational safety**, one **dependency advisory**, and
**documentation that over-claimed test coverage**. The high/medium items are fixed in v0.1.10.

## Findings

| # | Severity | Area | Finding | Status (v0.1.10) |
|---|---|---|---|---|
| 1 | High | Deps | `react-router-dom` pulled `@remix-run/router ≤1.23.1` — GHSA-2w69-qvjg-hvjx (XSS via open redirect). Low real-world impact in a Tauri webview, but a real advisory. | **Fixed** — pinned `@remix-run/router` to `1.23.3` via pnpm override; CI now fails on any HIGH/CRITICAL prod advisory. |
| 2 | High (ops) | Server | The server silently fell back to a **mock Google verifier** (accepts any identity) and an **ephemeral JWT key** when env vars were unset — only a `warn!`. A misconfigured production deploy would accept forged logins. | **Fixed** — with `SENTINEL_ENV=production` the server **refuses to boot** unless `GOOGLE_OAUTH_CLIENT_ID`, `SENTINEL_JWT_ES256_PEM`, and `SENTINEL_TOTP_ENC_KEY` are all set (unit-tested). |
| 3 | Medium | Server | Rate limiting keyed off the client-controllable `X-Forwarded-For` header, so a client could spoof its way past the limiter (or share a bucket). | **Fixed** — keys off the **real peer IP** (`ConnectInfo`); `X-Forwarded-For` is honored only when `SENTINEL_TRUST_FORWARDED_FOR` is set (behind a trusted proxy). |
| 4 | Medium | Server | No CORS policy and no request tracing were wired, despite the deps being present. | **Fixed** — `CorsLayer` (locked to `SENTINEL_CORS_ALLOWED_ORIGINS` in production; permissive in dev) + `TraceLayer` added. The desktop client is native (CORS-exempt); this hardens any browser surface. |
| 5 | Medium | Docs/integrity | `SECURITY.md` cited ~4 tests by name that **do not exist** (`no_secrets_in_artifacts`, `zeroize_on_lock`, `log_hygiene`, a "Playwright autofill e2e") and mis-described the rate limiter (`tower_governor`). Over-claiming coverage is itself a risk. | **Fixed** — every threat's test reference now points to a test/guard that actually exists. |
| 6 | Low | Supply chain | The CI "Security audit" job ran `cargo audit` / `pnpm audit` non-blocking (`|| true`); only the bespoke `plaintext-audit.sh` was enforcing. | **Partially fixed** — `pnpm audit --prod --audit-level high` is now **blocking**; `plaintext-audit.sh` remains blocking. `cargo audit` stays advisory pending a vetted baseline (see Recommendations). |
| 7 | Info | Extension | The extension requests broad `host_permissions` (`*://*/*`). | **Accepted (documented)** — autofill must be offerable on any site; a page only ever receives credentials whose saved URL origin-matches it, enforced desktop-side before any field is released. Narrowing would break general autofill without adding real protection. |
| 8 | Info | Desktop | The vault key sits in the OS keychain and the app auto-unlocks on launch, so any process running as the user can read it. | **Accepted (by design)** — this is the documented trust model (the OS login guards the keychain); **Windows Hello** (opt-in) adds a per-unlock check. |

## What was changed in v0.1.10

- **Dependency:** `@remix-run/router` pinned to `1.23.3` (root `package.json` pnpm override).
- **Server (`services/api`):** production boot-gate (`config::check_production_secrets`, unit-tested);
  rate limiting off the real peer IP with an opt-in trusted-proxy mode; `CorsLayer` + `TraceLayer`.
- **CI (`.github/workflows/ci.yml`):** blocking `pnpm audit --prod --audit-level high`.
- **Docs:** `SECURITY.md` test references corrected to reality; this report added.

## Residual risk / accepted

- **Local attacker running as the user** can read the keychain-stored vault key while the app is
  unlocked (finding 8) — mitigated by Windows Hello and auto-lock, not eliminated. This is the
  stated model.
- **Two moderate JS advisories** remain in the dependency tree (below the blocking threshold);
  tracked, low impact in a native webview.
- **The Tauri desktop layer** (kill switch, WireGuard controller, live Linode) has no automated
  coverage — it can't run in headless CI; it ships opt-in and labeled experimental.

## Recommendations (future)

- Promote `cargo audit` to blocking once a clean baseline is confirmed (add explicit `--ignore`
  entries for any unfixable transitive advisory rather than a blanket `|| true`), or adopt
  `cargo-deny` with a committed `deny.toml`.
- Add `gitleaks` with an allowlist tuned for the repo's public keys (extension `key`, updater
  pubkey) and test fixtures — the existing `plaintext-audit.sh` already covers private-key/secret
  patterns, so this is defense-in-depth.
- Add a capturing-`tracing`-subscriber log-hygiene test to make the T8 guarantee executable.
- Consider a paid Authenticode/notarization cert to drop the first-run SmartScreen/Gatekeeper
  warning (integrity is already guaranteed by the updater signature).

## Method

Static review of the crypto, key model, server routes/auth, VPN provisioning, and extension
messaging; dependency audit (`pnpm audit`, `cargo audit`); verification that the fixes compile and
pass unit/integration tests (`cargo test -p sentinel-api`, `cargo test -p sentinel-core`, the
`nmhost` suite) plus typecheck/build. Live Windows/Linode paths were not exercised (no such host in
CI); they remain documented experimental field-tests.
