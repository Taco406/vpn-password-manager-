# Changelog

All notable changes to **SENTINEL** are recorded here. The app shows this list under
**Settings → Updates → What's new**, and each GitHub release uses its section below as the
release notes.

The format follows [Keep a Changelog](https://keepachangelog.com/). Versions are
[semantic](https://semver.org/). **Add a new `## [x.y.z]` section at the top in the same PR
that bumps the app version** — that's how "the changelog updates on every merge."

## [0.1.9] — 2026-07-19

### Added
- **Browser autofill is now built in and easy to install.** The extension ships inside the
  installer. Settings → Browser autofill → **"Get the extension"** copies it to a folder and
  registers the browser host; you just point Chrome/Edge's "Load unpacked" at the shown path
  (with Copy-path / Open-folder buttons). Previously the extension wasn't shipped to users at all.
- **One consolidated Setup & required-downloads guide** (`docs/setup.md`), linked from the app
  (Settings) and the README: what each feature needs (WireGuard, Linode, sync server), with costs.
- Chrome Web Store submission is prepped (`docs/chrome-web-store.md` + listing/privacy copy); the
  native-messaging host already accepts both the unpacked and future store extension ids.

### Fixed
- Corrected a stale doc note that claimed the shipped VPN was always a simulation (real VPN has
  been available since v0.1.2 when a Linode token is set).

## [0.1.8] — 2026-07-19

### Fixed
- **Auto-update actually works now.** The in-app updater was throwing
  `Cannot read properties of null (reading 'available')` on every check, so updates never
  installed. Cause: the JavaScript updater plugin (`2.3.0`) had drifted out of sync with the
  Rust updater crate (`2.10.1`), which changed the "no update" response to `null`. Aligned
  `@tauri-apps/plugin-updater`, `@tauri-apps/plugin-process`, and `@tauri-apps/api` to their
  matching versions. (You need to install this version manually one last time; from here on it
  self-updates.)
- **Real VPN no longer falls back to the simulation after adding a token mid-session.** The
  app decided sim-vs-real once at startup and cached it, so saving a Linode token didn't take
  effect until a restart. Connecting (and opening the region picker) now re-checks the token
  live — no restart needed.

### Added
- This changelog, viewable in-app under **Settings → Updates → What's new**.

## [0.1.7] — 2026-07-19

### Added
- **VPN kill switch (Windows).** While connected, blocks outbound traffic except the tunnel,
  loopback, and local subnet, so a dropped tunnel can't leak. Fail-safe: rules clear on
  disconnect, on any failure, on every launch, and on exit, plus a manual "Clear kill-switch
  rules" button.
- **Auto-connect on untrusted Wi-Fi.** Brings the tunnel up automatically when you join a
  network that isn't on your trusted-SSID list; never fires on trusted networks.
- **Live region latency.** The region picker measures real round-trip time to each Linode
  region in parallel.

## [0.1.6] — 2026-07-19

### Added
- **Windows Hello unlock.** Optional biometric/PIN prompt to unlock the vault instead of
  auto-unlocking from the OS keychain.

## [0.1.5] — 2026-07-19

### Added
- **Browser autofill (Chrome/Edge).** The desktop app registers itself as a native-messaging
  host so the SENTINEL extension can fill logins, gated by per-site origin matching.

## [0.1.4] — 2026-07-19

### Added
- **Import existing passwords** from Chrome (CSV), Bitwarden (CSV/JSON), and 1Password.
- **Live breach check.** The health audit checks each password against Have I Been Pwned using
  k-anonymity, so full passwords never leave your device.

## [0.1.3] — 2026-07-19

### Added
- **Google sign-in + zero-knowledge sync (opt-in).** PKCE OAuth sign-in and end-to-end
  encrypted vault sync through a self-hostable server (Axum + Postgres, Docker deploy included).
  The server only ever stores ciphertext.

## [0.1.2] — 2026-07-19

### Added
- **Real ephemeral VPN via Linode (opt-in).** Paste a Linode API token and Connect spins up a
  throwaway WireGuard exit node, routes all traffic through it, and destroys it on disconnect.
  Includes a dead-man switch, an orphan-sweep on launch, and a running cost estimate so a bug
  can't quietly run up a bill.

## [0.1.1] — 2026-07-18

### Added
- **Real local vault.** Persistent encrypted storage (SQLite, XChaCha20-Poly1305) with the
  vault key held in the OS keychain for auto-unlock. Full item CRUD (logins, notes, cards),
  TOTP codes, password/passphrase generator, and copy-with-auto-clear.

## [0.1.0] — 2026-07-18

### Added
- First installable Windows build with **signed self-updates** (Tauri updater + GitHub
  Releases). Local-first vault UI, command palette, generator, and health audit. VPN screen
  runs a built-in simulation until a Linode token is added.

[0.1.9]: https://github.com/Taco406/vpn-password-manager-/releases/tag/v0.1.9
[0.1.8]: https://github.com/Taco406/vpn-password-manager-/releases/tag/v0.1.8
[0.1.7]: https://github.com/Taco406/vpn-password-manager-/releases/tag/v0.1.7
[0.1.6]: https://github.com/Taco406/vpn-password-manager-/releases/tag/v0.1.6
[0.1.5]: https://github.com/Taco406/vpn-password-manager-/releases/tag/v0.1.5
[0.1.4]: https://github.com/Taco406/vpn-password-manager-/releases/tag/v0.1.4
[0.1.3]: https://github.com/Taco406/vpn-password-manager-/releases/tag/v0.1.3
[0.1.2]: https://github.com/Taco406/vpn-password-manager-/releases/tag/v0.1.2
[0.1.1]: https://github.com/Taco406/vpn-password-manager-/releases/tag/v0.1.1
[0.1.0]: https://github.com/Taco406/vpn-password-manager-/releases/tag/v0.1.0
