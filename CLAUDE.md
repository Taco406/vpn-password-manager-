# NorthKey — operating manual for agents

NorthKey is a personal security suite: ephemeral WireGuard VPN (Linode), a zero-knowledge
password vault, a self-hosted sync server, a Chrome extension, and an iPhone app. One user,
their own server, three apps that must feel like ONE product.

## The product invariant (do not regress this)

**One login everywhere: connect → sign in → master password → vault.** Identical on Windows,
Mac, and iPhone. Every new feature must fit this front door — never add a second onboarding
path, a second place to set the master password, or a settings screen outside Account & Sync /
Settings. The QR on the desktop ("Add a device") and the master password are the entire
device-joining story; everything else lives under collapsed "Advanced" sections.

**Zero-knowledge**: the server stores only ciphertext and hashes. If a change would let the
server read a vault, a key, or a password — it's wrong, redesign it.

## Device & state ledger — READ FIRST, and update it when anything changes

Three apps, three versions, three delivery paths. Most wasted time on this project comes from
mixing them up: a symptom on ONE device gets debugged as if it were everywhere. Before
diagnosing anything, say which device you mean.

| Device | Delivery path | Version (as of 2026-07-26) | Confirmed by the user |
|---|---|---|---|
| Windows desktop | NSIS `-setup.exe` (per-user, no admin prompt) | **0.1.58** confirmed on device; **0.1.62 released** (0.1.60/61/62 installs all unconfirmed) | Servers screen lists **both** Linode and Hetzner. Settings → Hetzner Cloud = "Connected". |
| iPhone | TestFlight | **0.1.57** confirmed on device; **0.1.60, 0.1.61 and the 0.1.62 fix build uploaded** (runs #20, #21, #23) | Servers tab lists **only** the Linode `sentinel-sync` box. Additive-merge sync fix shipped in 0.1.61 — unverified on hardware. |
| Mac | `.dmg` | — | not in active use |

**Three releases are stacked up unconfirmed on both devices.** Nothing in 0.1.60–0.1.62 has been
seen working by the user; treat all of it as "built and delivered to the store", not "shipped".

The iOS TestFlight workflow auto-prunes stale **development** certificates (they, not
distribution certs, fill Apple's cap) — that's what broke every upload from 1.58 to 1.59.

**The phone build compiles only in the TestFlight job** (no Swift toolchain in CI), and the
Release workflow dispatches that job *after* publishing — so a Swift error ships a green desktop
release with a broken phone build (exactly what 0.1.62 did with an iOS-17-only `onChange`).
`scripts/interop-check.sh` now guards the iOS-16 API surface; extend that guard rather than
relying on the TestFlight job to catch API-availability mistakes.

### Rules that stop the churn (these are lessons, not suggestions)

1. **"Shipped" means the user saw it on their device.** Green CI, a merged PR, and a published
   GitHub release are NOT delivery. Never say shipped / fixed / verified until they confirm it
   on hardware. Multiple releases were called "shipped" while the user's app never updated.
2. **Never re-ask a fact the user already gave**, including in a screenshot. Re-read this ledger
   and the recent messages before asking. Asking "what does the Servers screen show?" three
   times is how you burn someone's trust.
3. **Name the device in every diagnosis.** "Hetzner isn't showing" cost two days because it was
   missing on the *phone* while working on the *desktop* — two completely different fixes.
4. **A phone problem is usually not a phone-build problem.** Check the data path first (does the
   token actually reach it?) before assuming a stale version or an unimplemented feature.
5. **Delivery breaks silently — check it explicitly.** The iOS build can fail at Apple signing
   (e.g. the "maximum number of certificates" cap) and the desktop updater can fail to apply;
   both leave the user on an old build with no error. After any release, verify the artifact
   actually reached the device before moving on.
6. **Silent `let _ = …` / swallowed errors are a bug class here**, not a style choice. A
   fire-and-forget push that reports success is indistinguishable from a working one until the
   user notices data missing on another device.

## Component map

| Path | What | Language |
|---|---|---|
| `crates/core` | crypto, vault model, provisioning templates — the source of truth | Rust |
| `apps/desktop` | Tauri v2 app (Windows/macOS/Linux): React front, `src-tauri` glue | TS + Rust |
| `services/api` | sync server (`sentinel-api`): Axum + Postgres, ships as a ghcr image | Rust |
| `apps/ios-key` | iPhone app — **not built in CI** (no Swift toolchain); user builds in Xcode | Swift + vendored C |
| `apps/extension` | Chrome extension + native-messaging host | TS |

## Cross-component contracts (change BOTH sides or neither)

These cross a language boundary, so no compiler catches drift. Each has a tripwire; if a check
fails, fix the other side of the contract — **never loosen the check**.

| Contract | Sides | Guard |
|---|---|---|
| HKDF info strings `sentinel/v1/*` (protocol constants — never rebrand) | `crates/core/src/crypto/kdf.rs` ↔ `apps/ios-key/NorthKey/Crypto/{Channel,VaultCrypto}.swift` | `scripts/interop-check.sh` (CI "guards") |
| Argon2id production params (65536 KiB, t=3, p=4) | `kdf.rs` ↔ `VaultCrypto.swift` | interop-check + CI release-mode tests |
| Byte formats: SNTL wrapped key, SVLT sync blob, item envelope | `crates/core/src/keyring` + `vault` ↔ `VaultCrypto.swift` | golden fixture (below) |
| Golden fixture `apps/ios-key/NorthKeyTests/Fixtures/golden-vault.json` | generated by Rust, decoded by both | Rust: `cargo test -p sentinel-core --test ios_golden_vectors` (+ ignored Argon2 test in CI). Swift: `NorthKeyTests` (⌘U) |
| Add-a-device QR payload `{v:2, ip, cert, enroll, ts}` | `apps/desktop/src-tauri/src/sync.rs` ↔ `ScanSetupView.swift` | interop-check |
| Phone HTTP paths + JSON fields | `ApiClient.swift` ↔ `services/api/src/routes.rs` | interop-check (paths); field names are policy (below) |
| Chrome extension ID (derived from `manifest.json` `"key"`) | `apps/extension/manifest.json` ↔ `nmhost.rs EXTENSION_ID` | interop-check (derives + compares) |
| Keychain service/account for the vault key | `sync.rs KC_*` ↔ `state.rs KEYCHAIN_*` | interop-check |
| NM host name `com.sentinel.host` + wire-type strings | `nmhost.rs` ↔ `packages/shared/nmProtocol.ts` ↔ host manifest tmpl ↔ `crates/core/src/nm/protocol.rs` | interop-check |
| Bundle id `com.sentinel.desktop` (app-data dir + keychain service) | `tauri.conf.json` ↔ `nmhost.rs`/`state.rs`/`applog.rs` | interop-check |
| Container uid 10001 + `/opt/sentinel/migrations` | `services/api/Dockerfile` ↔ `cloudinit.rs` ↔ `main.rs` | interop-check |
| ghcr image owner + updater endpoint (hardcoded repo identity) | `sync.rs`/`tauri.conf.json` ↔ this repo's owner/name | interop-check (repo-aware) |
| VPN callback HMAC (`pubkey‖ip`, hex, JSON keys) | embedded Python in `cloudinit.rs` ↔ `callback.rs::verify_callback` | cloudinit template test |
| Shipped SQL migrations (byte-frozen) | `services/api/migrations/*.sql` ↔ every deployed server's `_sqlx_migrations` checksums | `scripts/migrations-check.sh` + manifest |
| Desktop bridge command names + arg keys (~120 commands, camelCase↔snake_case) | `apps/desktop/src/bridge` ↔ `src-tauri` `#[tauri::command]` registrations | interop-check (names, since 0.1.61); arg-key casing still by hand |

**Wire-format policy (unguardable by grep, so it's a rule)**: server JSON field names
(`ciphertext_b64`, `blob_b64`, `access_token`, …) are read stringly by Swift and re-declared by
the desktop — treat every shipped field as frozen, additive-only. Same for native-messaging
wire types and the `CAPS` list in `nmhost.rs`: append, never rename or remove.

**Changing a byte format**: regenerate the fixture
(`cargo test -p sentinel-core --test ios_golden_vectors -- --ignored generate`), update the
Swift side, and confirm the user runs ⌘U in Xcode before release. A format change also breaks
already-deployed phones — version the format instead of mutating it whenever possible.

## Account model (this bit us once — keep it true)

One personal server = ONE account row, regardless of sign-in method. `auth_google` re-keys a
lone `bootstrap:local` account to the real Google identity; `auth_bootstrap` adopts the single
existing account; multi-account servers refuse ambiguity. Enroll codes land the phone on the
**minter's** account. Covered by `services/api/tests/account_unification.rs` (separate binary,
serialized — don't merge it into the main integration test file). The vault auto-pushes after
sign-in/deploy/join; never reintroduce a sign-in path that leaves the server empty.

## Update paths (three of them — keep all three working)

- **Desktop**: Tauri updater reads `latest.json` from the latest GitHub release; pubkey pinned
  in `tauri.conf.json`. Never rotate the signing key casually — installed apps reject other keys.
- **Server**: self-updates via host-side systemd (daily timer + flag-file path unit written by
  cloud-init in `crates/core/src/provision/cloudinit.rs`); the app's "Update server" button hits
  `POST /v1/admin/update`. The API container must NEVER get the Docker socket.
- **iPhone**: via TestFlight — the `iOS TestFlight` workflow builds/signs/uploads (cloud signing
  from the App Store Connect API key secrets; see `docs/ios-testflight.md`). The Release finalize
  job dispatches it explicitly after publishing — its `release: published` trigger never fires
  because GitHub suppresses events created by a workflow's own token; don't "simplify" the chain
  away. Xcode-from-source (`cd apps/ios-key && xcodegen generate`) remains the fallback. The
  golden-vector tests stay the crypto compatibility gate either way.

**Compatibility rules**: the `/v1` API is additive-only (old desktops talk to newer self-updated
servers). Migrations are append-only — never edit a shipped `services/api/migrations/*.sql`
(`scripts/migrations-check.sh` enforces it; after ADDING one, run it with `--update` and commit
the manifest). New desktop features against old servers must degrade with a clear message (see
the enroll-code fallback in `sync.rs` for the pattern).

**Update-path safeties (don't remove)**: the release workflow gates all publishing on a test
job, publishes as a DRAFT, verifies `latest.json` covers all three platforms, then flips it
live. The server's `update.sh` health-checks the new container and rolls back to the previous
image if `/healthz` doesn't answer (servers have no SSH — rollback is the only recovery).
The updater signing key has a two-step rotation ceremony — see `docs/releasing.md` before
touching it. Open backlog: re-register the native-messaging host manifest on app startup
(today it's written once at install and can go stale if the install path changes).

## Release runbook

1. Bump `apps/desktop/src-tauri/tauri.conf.json` AND `apps/desktop/package.json` to the same
   X.Y.Z, add a `## [X.Y.Z]` section at the top of `CHANGELOG.md` (the release notes and the
   in-app "What's new" both parse it). `scripts/version-check.sh` enforces this in CI.
2. PR → all CI jobs green → squash-merge.
3. Dispatch the **Release** workflow on `main` with a blank tag (it reads the version from
   `tauri.conf.json`). It builds all three OS installers, signs `latest.json`, and publishes the
   `sentinel-api` image.
4. Verify: the GitHub release has `.msi` + `.dmg` + `.deb`/`.rpm`/`.AppImage` + `.sig` files, and
   `latest.json` reports the new version. Only then tell the user it shipped.

## Test gates (run before any PR)

```
cargo fmt --all --check && cargo clippy --all-targets -- -D warnings
cargo test -p sentinel-core -p sentinel-cli -p sentinel-nm-host
cargo test -p sentinel-api          # needs Postgres: see .github/workflows/ci.yml api job
pnpm -r typecheck && pnpm --filter @sentinel/desktop build && pnpm --filter @sentinel/desktop e2e
bash scripts/interop-check.sh && bash scripts/version-check.sh
```

Gotchas:
- CI sets `SENTINEL_ARGON2_PROFILE=test` globally; production-cost crypto tests are `#[ignore]`
  and run explicitly in release mode (see the `rust` job). Real blobs ALWAYS use Production.
- The desktop crate doesn't build on Linux CI (webkit2gtk) — macOS job covers it; don't move
  desktop-only logic into paths the Linux jobs need.
- e2e asserts screenshots, not text; regenerate deliberately, review the diff visually.
- The extension must be built and staged (`stage-extension.mjs`) before the desktop Rust crate
  compiles.

## Communication with the user

The user is non-expert and tests on real devices (Windows PC, MacBook, iPhone). Ship with a
click-path test script (`docs/morning-test.md` is the model): exact button labels, one command
per line for terminal steps (their shell chokes on `&&` chains and placeholders), and honest
failure notes. Never paste secrets into chat; Apple/updater secrets go directly into GitHub
Settings → Secrets.
