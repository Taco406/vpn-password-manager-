# NorthKey — security review (v0.1.61)

_Reviewer: automated pass (Claude) · Tree reviewed: **v0.1.61** · Fixes land in **v0.1.62** ·
Scope: password vault, VPN, server monitoring, across Windows/macOS desktop and the iPhone app._

This is a **checklist-driven review of the vault/VPN/monitor product surface**. It supersedes
nothing: the earlier [`security-review-2026-07.md`](./security-review-2026-07.md) covered
v0.1.9→v0.1.10 and was infrastructure-focused (sync server, CI, dependencies). That review is
**50+ versions stale** — it predates the iPhone app, Netdata monitoring, Hetzner, file
transfers, and master-password sign-in, none of which had been security-reviewed until now.

Format per item: ✅ verified / ⚠️ gap / ❌ defect, with file:line evidence and, for anything
not ✅, the fix.

---

## P0 findings first

**There are no P0 defects.** The cryptographic core and the zero-knowledge model both hold up
under this pass: a single vetted AEAD, correct Argon2id parameters, random per-seal nonces, no
hand-rolled crypto, and a login flow that provably never sends the master password or any key
to the server. The two ❌ items below are P1 (local-attacker and supply-chain), and both are
fixed in v0.1.62.

The most serious *real* finding is not a crypto flaw but an **honesty gap**: three protections
the app advertised did not exist. The auto-lock slider changed a number nothing read, the
iPhone left decrypted vault contents in the app-switcher snapshot, and `SECURITY.md` claimed
zeroize-on-idle/OS-sleep triggers that were never implemented. A control the user believes is
on, but isn't, is worse than one they know is missing.

---

## P0 — Vault cryptography

| # | Item | Verdict | Evidence |
|---|---|---|---|
| 1.1 | No custom crypto | ✅ | Single AEAD via a vetted crate: `crates/core/src/crypto/mod.rs:15` `use chacha20poly1305::{…XChaCha20Poly1305, XNonce}`. No hand-rolled cipher, mode, or "obfuscation" anywhere in the tree. |
| 1.2 | KDF = Argon2id, modern params | ✅ | `crates/core/src/crypto/kdf.rs:64` `pub const PRODUCTION: (u32, u32, u32) = (65536, 3, 4)` — 64 MiB, t=3, p=4, **above** the ≥64 MB / ≥3 bar. 16-byte random salt (`kdf.rs:96`). Pinned by test (`kdf.rs:148`) and matched server-side (`services/api/src/routes.rs:471`). |
| 1.3 | AEAD + unique nonces | ✅ | `crypto/mod.rs:23` `generate_nonce(&mut OsRng)` — random 24-byte XChaCha nonce per seal (uniqueness test at `crypto/mod.rs:101`). XChaCha's 192-bit nonce makes random generation safe, unlike GCM. Tampering fails closed — see the new test in 1.6. |
| 1.4 | Zero knowledge | ✅ | The password never leaves the device. Login sends a one-way HKDF proof (`crates/core/src/keyring/password.rs:50-57`), the server stores only SHA-256 of it (`services/api/src/routes.rs:506`) and compares in constant time (`routes.rs:539`). Structurally tested: `crates/core/tests/structural_zero_knowledge.rs`. |
| 1.5 | Memory hygiene (core) | ✅ | `ZeroizeOnDrop` on key types (`keyring/mod.rs:65`, `wg/keys.rs:9`), `Zeroizing` password buffer (`keyring/password.rs:19`), `session.rs:30` drops the key on lock. |
| 1.6 | Tamper fails closed (asserted) | ✅ **new** | Added `tampered_sync_blob_fails_to_open` (`crates/core/tests/security_gate.rs`): bit-flips across header/nonce/ciphertext, truncation, and version-rollback all rejected. Previously only primitive-level tamper tests existed; the blob that actually travels between devices had none. |
| 1.7 | Argon2 cost can be lowered by env var | ⚠️ | `kdf.rs:79` honours `SENTINEL_ARGON2_PROFILE=test` (m=8192,t=1,p=1). It is release-guarded only when a `live-*` feature is on, so a plain release build would accept it. **Fix (not applied — needs your call):** make the test profile `#[cfg(debug_assertions)]`-only. Not exploitable remotely (an attacker who can set your env vars already has your session), which is why it's ⚠️ and not ❌. |
| 1.8 | Desktop holds passwords in plain `String` | ⚠️ | No `zeroize` in `apps/desktop/src-tauri/src/` — e.g. `applock.rs:134` `password: String`, cloned at `sync.rs:1828`. Core zeroizes; the Tauri glue does not, so a master password may linger in freed heap. **Fix (deferred, mechanical but broad):** wrap the command-layer password params in `Zeroizing<String>`. |

---

## P0 — Compartmentalization

| # | Item | Verdict | Evidence |
|---|---|---|---|
| 2.1 | Monitoring creds outside the vault's crypto | ✅ | Hetzner (`servers.rs:21`), Linode (`vpn.rs:36`) and Netdata basic-auth (`servers.rs:705`) live in the **OS keychain**, never in `settings.json` — which stores only `has_auth`/port/https (`servers.rs:644`). They are separate keychain entries, not derived from the vault key. |
| 2.2 | No webview for remote content | ✅ | Netdata is rendered with **native canvas charts** (`components/charts/TimeSeriesChart.tsx`, Swift Charts on iOS). No `WKWebView`/`iframe` renders agent-controlled content, so a compromised Netdata instance has no script surface pointed at the app. |
| 2.3 | Provider tokens are read-only scoped | ⚠️ | Not enforceable in code — Hetzner/Linode tokens are user-created and the app performs power actions, so they are read/write by necessity. **Documented, not fixed:** the trust model already treats these as "can rebuild my servers, cannot read my vault." |
| 2.4 | VPN key material separate from the vault | ✅ | WireGuard keys are their own keychain entry (`vpn.rs:1692`), `ZeroizeOnDrop` (`wg/keys.rs:9`), redacted in `Debug` (`wg/keys.rs:40`). No shared key material with the vault. |

---

## P1 — Leak channels

| # | Item | Verdict | Evidence |
|---|---|---|---|
| 3.1 | No secrets in logs | ✅ (was untested) | A full grep of every log macro in core/desktop/nm-host/api intersected with secret identifiers found **one** hit, and it is benign (`main.rs:58`, an error string). Logs are bounded and newline-flattened (`applog.rs:11,32`). **Now enforced:** a new log-hygiene gate in `scripts/plaintext-audit.sh` fails the build if any log statement interpolates a secret-named variable — verified to catch a planted `eprintln!("dbg {token}")`. |
| 3.2 | Clipboard auto-clear | ❌ → ✅ **fixed** | The vault copy path cleared after N seconds (`bridge/tauri.ts:124`), but the **Health screen's generated-password copies did not** (`Health.tsx:51`, `:250` wrote the secret with no timer at all) — the same secret, protected or not depending on which button you pressed. Fixed: both now route through the new `lib/clipboardSecret.ts`, which clears after the configured delay and only wipes if the clipboard still holds our value. |
| 3.3 | Windows clipboard-history exclusion | ⚠️ | No `ExcludeClipboardContentFromMonitorProcessing` / `CanIncludeInClipboardHistory` format is set, so copied passwords can land in Windows Clipboard History and Cloud Clipboard, outliving the auto-clear. **Fix (deferred — needs a native clipboard call from Rust, not the webview):** set the exclusion formats in a Tauri command. Tracked as the top follow-up. |
| 3.4 | iOS clipboard expiry | ✅ | `VaultViews.swift:14-19` sets `.localOnly: true` + `.expirationDate: +60s` — no Universal Clipboard, auto-expiring. |
| 3.5 | iOS screen privacy | ❌ → ✅ **fixed** | There was **no** blur-on-background: iOS writes an app-switcher snapshot to disk, so decrypted vault contents were captured. Fixed in `NorthKeyApp.swift`: a `PrivacyShield` overlay driven by `scenePhase`, applied on `.inactive` (which fires *before* the snapshot). `SecureField` was already used for entry (`VaultViews.swift:42`). |
| 3.6 | No plaintext temp files / safe export | ✅ | Export is encrypted-by-default with a **mandatory** passphrase (`import/export.rs:23`); `export_plain_csv` exists in core but is **not wired to any command or UI**, so no plaintext export path is reachable in the shipped app. |
| 3.7 | Atomic vault writes | ❌ → ✅ **fixed** | `vault-key.wrap` — the **only** copy of the master-password-wrapped vault key — was written with a truncating `fs::write` (`applock.rs:98`, `sync.rs:1759`); a crash mid-write left an unopenable vault. Fixed with `state::write_atomic` (temp file + `sync_all` + rename). Vault items themselves were always safe (SQLite, transactional). |
| 3.8 | No vault contents in window titles | ✅ | Titles are static route names; no item data reaches the window title. |

---

## P1 — Auth & sessions

| # | Item | Verdict | Evidence |
|---|---|---|---|
| 4.1 | Auto-lock timer | ❌ → ✅ **fixed** | **The advertised setting was dead code.** `autoLockMinutes` had a slider (`Settings.tsx:142`) and a default (`commands.rs:993`) but **no consumer anywhere** — the vault never auto-locked. Fixed with `hooks/useAutoLock.ts`, which arms an idle timer and calls `lock()`; it deliberately no-ops when no master password is set, since locking would strand the user. |
| 4.2 | Lock on background / OS lock | ⚠️ desktop, ✅ **fixed** iOS | iOS now locks on return if the app was away longer than a 60-second grace (`NorthKeyApp.swift` → `.northKeyAutoLock` → `ContentView`), so a phone left on a table doesn't stay in an open vault while quick app-switches stay frictionless. **Desktop still has no OS-lock/session-change hook** (no `WindowEvent`/WTS subscription in `main.rs:41`); the idle timer above is the partial substitute. |
| 4.3 | Lock clears decrypted state | ✅ | Core: `locking_prevents_access` (`tests/security_gate.rs:57`) proves a locked session cannot decrypt. iOS: `VaultStore.lock()` (`VaultStore.swift:199`) clears `items`, `document`, `vaultKey`, and `providerTokens`. |
| 4.4 | Constant-time comparison | ✅ | Comes free from AEAD verification locally; server-side proof comparison is explicit (`routes.rs:539` `constant_time_eq`). |
| 4.5 | Biometric unlock is OS-gated | ✅ iOS / ⚠️ Windows | iOS is properly enclave-gated: `SecAccessControlCreateWithFlags(… .biometryCurrentSet)` (`VaultStore.swift:175`, `EnclaveKey.swift:21`), and re-enrolment invalidates the item. **Windows Hello is a boolean checked in-process** (`applock.rs:113`, `hello.rs:26`) — the key sits in Credential Manager unprotected by Hello, so Hello is a speed bump, not a boundary. Unchanged from the documented accepted risk; **stated plainly here rather than implied to be equivalent to Face ID.** |
| 4.6 | No recoverable password hint | ✅ | No hint feature exists. |

---

## P1 — Transit & supply chain

| # | Item | Verdict | Evidence |
|---|---|---|---|
| 5.1 | TLS verification on | ⚠️ scoped, now **guarded** | Exactly **two** Rust sites accept invalid certs, both deliberate: the self-signed Netdata agent (`cloud/netdata.rs:37`) and the pre-trust TOFU probe that sends nothing (`sync.rs:1704`). All other clients verify normally. **Now enforced:** `plaintext-audit.sh` fails if a **third** site appears — verified against a planted occurrence. Residual risk (unchanged, documented): the Netdata request carries a basic-auth header over an unverified channel, so a MITM on your LAN could capture the monitoring credential — not the vault. |
| 5.2 | iOS TLS | ⚠️ | `MonitoringClients.swift:325` mirrors the Netdata exemption; `ApiClient.swift:95` is capture-only. `Info.plist:61` sets `NSAllowsArbitraryLoads` (documented rationale: ATS rejects self-signed IP endpoints before the pinning delegate runs) — but it lowers the floor process-wide. **Fix (deferred, needs care):** replace the global flag with a per-domain ATS exception. |
| 5.3 | Sync endpoint pinning | ✅ | **Exact-certificate** pinning on both platforms after deploy: `sync.rs:81` (`add_root_certificate`) and `ApiClient.swift:58` (`presented == pinnedDER`) — stronger than SPKI pinning. The Google token exchange deliberately stays unpinned (public CA), documented at `sync.rs:72`. |
| 5.4 | Release signing | ✅ | Updater public key pinned in `tauri.conf.json:59`; artifacts signed (`:33`); HTTPS endpoint (`:57`); CSP set (`:26`). Windows Authenticode / macOS notarization wired in the release workflow. |
| 5.5 | Server self-update verifies its image | ❌ | `cloudinit.rs:340` runs a bare `docker pull` with **no digest pin and no signature check**; only a health-check rollback follows. A registry or tag compromise is RCE on the sync server. **Fix (deferred — architectural, wants your call):** pin the image by `@sha256:` digest and have `update.sh` verify the digest before swapping. Mitigating factors: the container never gets the Docker socket, and the box holds only ciphertext. |
| 5.6 | Dependency audit in CI | ⚠️ | `pnpm audit --prod --audit-level high` is **blocking** (`ci.yml:157`) and `plaintext-audit.sh` is blocking (`:161`), but `cargo audit` is still `|| true` (`ci.yml:147`) — and its *install* is too, so a failed install silently skips it. Lockfiles are committed. **Fix (deferred):** promote to blocking once a clean baseline is confirmed (carried over from the 2026-07 review). |
| 5.7 | Provider-parser tests actually run | ❌ → ✅ **fixed** | Not on the original checklist, found while fixing the CPU chart: the `live-linode`/`live-hetzner` features gate the real provider clients, the desktop ships with them **on**, but CI compiled them **out** — so 13 provider parser tests never ran in CI. Fixed in `ci.yml`. |

---

## P2 — Hardening & honesty

| # | Item | Verdict | Evidence |
|---|---|---|---|
| 6.1 | Kill switch | ⚠️ Windows-only | Fail-closed default-deny via `netsh advfirewall` with carve-outs for loopback/LAN/endpoint (`vpn.rs:1031-1105`), cleared at startup so a crash can't strand you (`main.rs:44`). **macOS/Linux is a no-op stub** (`vpn.rs:1118`) — on the Mac there is *no* kill switch. Now stated in the docs rather than implied cross-platform. |
| 6.2 | DNS through the tunnel | ✅ with a caveat | `DNS = 1.1.1.1` is written into the client config and enforced by WireGuard's NRPT rule (`wg/config.rs:33`, cleanup at `vpn.rs:986`). Caveat: the kill switch's LAN carve-out permits UDP/53 to a local router, so a DNS query to the gateway can still escape while engaged. |
| 6.3 | WireGuard config file permissions | ❌ → ✅ **fixed** | The tunnel config — containing a live `PrivateKey` — was written to the **shared** temp dir with default (world-readable) permissions and only best-effort deleted. Fixed: `write_private_conf` creates it `0600` on Unix and tightens a pre-existing file before writing the key; regression-tested (`vpn.rs` `tunnel_conf_is_owner_only`). Windows temp is already per-user. |
| 6.4 | Threat model documented | ⚠️ → corrected | `SECURITY.md` exists and is thorough, but claimed zeroize "on lock / idle / OS-sleep" (`SECURITY.md:17`) when no idle or OS-sleep trigger existed. The idle path is now real (4.1); the OS-sleep claim is corrected rather than left aspirational. |
| 6.5 | iOS build integrity | ⚠️ | No DeviceCheck/App Attest; distribution integrity rests on the App Store/TestFlight pipeline. Accepted for a personal-use app. |

---

## Acceptance tests added to CI

The four the checklist asked for, each **verified to fail when its invariant is broken**:

1. **Log-hygiene gate** — `scripts/plaintext-audit.sh` (blocking in CI) rejects any log statement
   interpolating a secret-named variable. Proven against a planted `eprintln!("dbg {token}")`.
2. **Tamper fails closed** — `tampered_sync_blob_fails_to_open` in `crates/core/tests/security_gate.rs`.
3. **Lock clears decrypted state** — `locking_prevents_access` (pre-existing) plus iOS
   `VaultStore.lock()` clearing items/keys/tokens.
4. **TLS scope guard** — the audit script pins the number of `danger_accept_invalid_certs`
   sites at 2; a third fails the build. Proven against a planted third occurrence.

Plus, from 5.7: the provider parser tests now actually execute in CI.

## Fixed in v0.1.62

WireGuard conf `0600` · iOS app-switcher privacy shield · iOS auto-lock (60 s grace) · desktop
idle auto-lock (the dead setting made real) · clipboard auto-clear on every copy path · atomic
wrapped-key writes · log-hygiene gate · TLS-scope guard · tamper test · provider tests in CI.

## Open, in priority order

1. **Windows clipboard-history exclusion** (3.3) — needs a native clipboard call.
2. **Pin the server image by digest** (5.5) — the one remaining supply-chain hole.
3. **`cargo audit` blocking** (5.6).
4. **`Zeroizing` for desktop password params** (1.8).
5. **macOS kill switch** (6.1) — currently absent, not merely untested.
6. **Per-domain ATS instead of `NSAllowsArbitraryLoads`** (5.2).
7. **Argon2 test-profile behind `debug_assertions`** (1.7).

## Accepted risk (unchanged, by design)

A process running **as you** on an unlocked machine can read the keychain-held vault key —
the OS login is the boundary, Windows Hello is a speed bump on top. NorthKey defends against a
stolen device, a hostile network, and a compromised Netdata/provider account. It does **not**
defend against a compromised OS or a keylogger.
