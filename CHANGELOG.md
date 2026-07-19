# Changelog

All notable changes to **SENTINEL** are recorded here. The app shows this list under
**Settings → Updates → What's new**, and each GitHub release uses its section below as the
release notes.

The format follows [Keep a Changelog](https://keepachangelog.com/). Versions are
[semantic](https://semver.org/). **Add a new `## [x.y.z]` section at the top in the same PR
that bumps the app version** — that's how "the changelog updates on every merge."

## [0.1.12] — 2026-07-19

### Added
- **Multi-hop VPN ("bounce").** Real-VPN only. Under **Settings → Multi-hop (bounce)** you can
  route traffic through **2–3 exit nodes in a row** (entry → exit). Your device keeps one tunnel to
  the entry hop; each hop forwards to the next server-side, and only the last node egresses to the
  internet — so no single server sees both who you are and where you're going.
- **Cost/latency are surfaced up front:** cost is **N× a single node** and latency compounds, so
  the UI says so and caps chains at 3 hops.

### Fixed
- **NAT on exit nodes.** The provisioning cloud-init now installs a masquerade rule so forwarded
  client traffic actually egresses — this also hardens the regular single-hop VPN.

_Experimental and Windows-first; the live multi-hop path can't be exercised in CI, so the config
generation is golden-tested and any failed connect destroys every provisioned node (no orphan bills)._

## [0.1.11] — 2026-07-19

### Added
- **VPN node management (power off vs destroy + manage the fleet).** Real-VPN only. Under
  **Settings → VPN exit nodes** you can now list every exit node with its live state, **stop**
  (power off) vs **destroy** (delete), **start**, **reboot**, and **Destroy all**. A running
  **cost meter** shows the hourly total across all nodes.
- **Cost safety:** a stopped Linode *still bills* — only destroying it stops the meter, and the
  UI says so plainly. Kept/stopped nodes are recorded in a registry so the launch and pre-connect
  orphan-sweep no longer reaps them, and there's a **max of 5 kept nodes** so a bug can't rack up
  an unbounded bill.

_Note: one tunnel is active at a time; running traffic through several nodes at once (multi-hop)
is the next phase. Windows-first and experimental — the live Linode path can't be exercised in CI._

## [0.1.10] — 2026-07-19

### Security
- **Full security review** (see `docs/security-review-2026-07.md`). The crypto core came out
  clean; the fixes below address dependency, server-hardening, and doc-integrity findings.
- **Fixed a high-severity dependency advisory** (`@remix-run/router` XSS via open redirect,
  GHSA-2w69-qvjg-hvjx) by pinning it to a patched version. CI now fails on any high/critical
  advisory in production dependencies.
- **Sync server (self-hosted) hardening:** with `SENTINEL_ENV=production` the server refuses to
  boot on insecure dev fallbacks (mock Google verifier / ephemeral JWT key / missing TOTP key);
  rate limiting now keys off the real client IP instead of a spoofable header; added CORS and
  request-tracing layers.
- Corrected `SECURITY.md` so every threat maps to a test/guard that actually exists.

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

[0.1.12]: https://github.com/Taco406/vpn-password-manager-/releases/tag/v0.1.12
[0.1.11]: https://github.com/Taco406/vpn-password-manager-/releases/tag/v0.1.11
[0.1.10]: https://github.com/Taco406/vpn-password-manager-/releases/tag/v0.1.10
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
