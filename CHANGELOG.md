# Changelog

All notable changes to **SENTINEL** are recorded here. The app shows this list under
**Settings → Updates → What's new**, and each GitHub release uses its section below as the
release notes.

The format follows [Keep a Changelog](https://keepachangelog.com/). Versions are
[semantic](https://semver.org/). **Add a new `## [x.y.z]` section at the top in the same PR
that bumps the app version** — that's how "the changelog updates on every merge."

## [0.1.27] — 2026-07-20

### Fixed
- **The sync server now actually starts.** This is the real reason a one-click sync server would
  show *Running* but never sign this device in (so Reconnect could never finish): the server was
  started in production mode **without one of its required secrets** (the TOTP encryption key), so it
  refused to boot and the container crash-looped forever — nothing ever answered the health check.
  Redeploying couldn't help because every deploy hit the same missing secret. The deploy now generates
  and passes that key (like it already does for the others), so a freshly deployed server comes up
  healthy and this device signs in on its own. **If you have a stuck server, Destroy it and Deploy
  once more** — the new one will work.
- **The Devices page no longer shows fake demo content.** The device list and the "Pair a new iPhone"
  card at the top were leftover placeholders wired to sample data (there's no iOS companion app behind
  them), which made the whole page look broken. They're removed — the page now shows only the real
  sync server and vault-sync controls, and your actual signed-in devices already appear under **Vault
  sync → Signed-in devices**.

## [0.1.26] — 2026-07-20

### Fixed
- **No more flashing black windows.** On Windows, every WireGuard/network command the app ran
  (`wg`, `net`, `ping`) popped a console window for a split second — and because the throughput
  counter polls `wg show` every 2 seconds while connected, and opening the **VPN** tab checks
  elevation with `net session`, it flashed constantly on the VPN screen and throughout a connection.
  Every one of those calls now runs hidden (`CREATE_NO_WINDOW`), so nothing flashes anymore.

### Added
- **Always-on VPN (optional).** Alongside the disposable per-session VPN, you can now deploy a
  **dedicated exit node that stays running** for a stable connection — find it under **VPN → Always-on
  VPN**. Pick a region and size, **Deploy**, and it provisions its own WireGuard node (with the same
  exit-node fixes as the regular VPN), connects, and — unlike a throwaway node — **keeps running**
  when you disconnect, so reconnecting is instant and your exit IP stays the same. It survives an app
  restart (the tunnel key is stored in your OS keychain, never on disk in the clear), and if
  auto-connect-on-untrusted-Wi-Fi is on it reconnects to *this* node instead of spinning up a second
  one. It's a **different privacy tradeoff** from the default VPN (the IP is stable, not rotated, and
  tied to this box) and it **bills continuously** until you **Destroy** it — its live cost and a
  Destroy button are always shown. A normal **Disconnect** now clearly says it *keeps* the always-on
  node; only **Destroy** tears it down. Like the sync server, it's excluded from the automatic
  cleanup that reaps leftover throwaway nodes, so it's never destroyed behind your back. Money-safety
  is careful throughout: the node is recorded the instant it's created so it's always visible with a
  Destroy button (never a hidden billing box), **Destroy only reports success once Linode confirms the
  node is gone** (if your token is missing or the call fails it keeps the node listed so you can retry,
  rather than silently orphaning it), and if you turned on the kill switch it now protects the
  always-on tunnel too.

## [0.1.25] — 2026-07-20

### Added
- **Add another computer to your sync server with one code — no IP, cert, or Google needed.** On the
  device that has your one-click sync server, open **Devices → Sync server → Add a device** to get a
  one-time join code. On the new computer (fresh install, empty vault), choose **Join it with a device
  code**, paste, and it instantly connects to the same server and pulls your vault down. The code
  carries everything the new device needs (the server address, its pinned certificate, the login, and
  your vault key) so there's nothing to type by hand. Treat the code like a password — it's shown once.
  Joining only ever runs on a fresh, empty vault so it can never overwrite what's already on a device,
  and a device can **Reconnect** (finish an interrupted sign-in) or **Disconnect / forget the server**
  at any time to start over cleanly.

### Fixed
- **"I deployed a sync server but my vault isn't syncing."** A one-click deploy that finished creating
  the server but whose sign-in step didn't complete (first boot installs Docker, pulls the image, and
  migrates — which can take longer than the app waited) used to leave you stuck: the server was up and
  billing, but this device was never signed in, and there was no way to finish without destroying and
  redeploying. New **Reconnect / finish setup** button completes the sign-in against your existing
  server — no re-deploy, no lost billing.
- **The "Cross-device sync" panel no longer nags for a Google client id you don't need.** If you used
  the one-click server, that panel used to still show an empty "Google client id" field and copy
  claiming sync "needs" one — misleading, since one-click uses no Google account. The sync area now
  reflects what you actually set up: the account actions when you're signed in, a pointer to Reconnect
  if setup is unfinished, and the bring-your-own-server + Google path tucked behind an **Advanced**
  toggle for the few who want it.

## [0.1.24] — 2026-07-20

### Fixed
- **The VPN connects but pages don't load / downloads stall.** The exit node now NATs your return
  traffic reliably. Two bugs caused the connect-but-no-internet symptom (upload worked, download was
  zero): the node's masquerade rule was pinned to a hardcoded network interface name (`eth0`) that not
  every Linode host actually uses, and the throughput MSS-clamp rule was bundled into the same atomic
  firewall load — so on any host where that clamp expression was rejected, the **entire** NAT ruleset
  failed to apply and no return traffic was ever masqueraded. NAT is now interface-agnostic
  (masquerade everything leaving except the client tunnel, so it works no matter what the provider
  names the public NIC, and covers the multi-hop egress too), and the MSS clamp is applied
  best-effort *after* the firewall is up so it can never take NAT down with it. New exit nodes route
  return traffic, so pages load and downloads flow.

### Added
- **Passkeys can now be stored in your vault (groundwork).** SENTINEL now understands a new
  **passkey** item type and can securely generate and store a passkey's keys — the private key is
  minted on-device (P-256 / ES256) and sealed with the same per-item encryption as everything else,
  so it's never shown or copyable. You'll see stored passkeys in the vault with their site, username,
  and credential id, clearly marked read-only. This is foundational plumbing: actually **using** a
  passkey to register with or sign in to a website (through the browser) arrives in the next updates.

## [0.1.23] — 2026-07-20

### Added
- **First-run setup wizard.** On first launch SENTINEL now greets you with a short, fully skippable
  guide instead of leaving the optional extras buried in Settings. It walks through securing the vault
  with a master password, turning on the real (Linode) VPN — with a live WireGuard prerequisite check
  and a **Download WireGuard** shortcut — and enabling browser autofill for Chrome and Edge. Every step
  shows a live ✓/✗ status and can be skipped; the app is fully usable without any of it. You can replay
  the guide anytime from **Settings → General → Run setup guide again**.

## [0.1.22] — 2026-07-20

### Added
- **Split tunneling.** The VPN still routes **all** your traffic by default (full tunnel, nothing
  changes). New in **Settings → VPN → Split tunneling**, you can switch to **Split** mode and list the
  destinations — as CIDRs like `10.0.0.0/8` or `192.168.0.0/16` — that should go through the VPN;
  everything else uses your normal connection. Add and remove routes as chips, and if you leave the
  list empty (or an entry is invalid) SENTINEL safely falls back to full tunnel so you're never left
  routing nothing. The mode takes effect on your next Connect and works for single- and multi-hop.

## [0.1.21] — 2026-07-20

### Changed
- **Settings is no longer one endless scroll.** It's now split into tabs — **General**, **Security**,
  **VPN**, and **About** — so each area is a short, focused page.
- **Features moved out of Settings to where you actually use them.** The **VPN exit-node fleet** now
  lives on the **VPN** screen, **cross-device sync** and **one-click sync-server deploy** moved to the
  **Devices** screen, and **password import** moved into the **Vault**.
- **New "Experimental" section** in the sidebar gathers the beta, Windows-first features —
  **multi-hop (bounce)**, **auto-connect on untrusted Wi-Fi**, and **browser autofill** — behind a
  clear "these may change" banner, so the main screens stay focused on what's stable.

## [0.1.20] — 2026-07-19

### Fixed
- **Websites load over the VPN again.** After a connect, pages could hang or the connection felt
  dead even though the tunnel was up — the classic WireGuard full-tunnel MTU problem (small packets
  like DNS get through, large ones are silently dropped). The client tunnel now sets **MTU = 1420**
  and the exit node **clamps TCP MSS to the path MTU**, so full-size responses get through instead of
  stalling.
- **The throughput graph no longer overflows the page.** The live chart is now responsive and scales
  to fit its panel instead of spilling past the edge on narrower windows.

### Added
- **A headless VPN self-test** so the app can prove the real tunnel works end-to-end. Running
  `SENTINEL --vpn-selftest [region]` from an Administrator terminal spins up a throwaway Linode,
  brings a tunnel up with **minimal routing** (only the tunnel subnet — it never touches your default
  route or DNS, so it can't disrupt your internet), verifies a **real WireGuard handshake**, then
  **destroys the node** — printing each stage plus a PASS/FAIL (also saved to the errors log). It's
  the first way to *see* the live handshake succeed instead of inferring it, and it's what a future
  automated test runner will drive.

### Changed
- The WireGuard client config now omits the `DNS` line when no DNS is set (used by the self-test's
  no-hijack routing). Normal VPN connects are unchanged.

### Internal
- Added a regression test pinning the v0.1.19 fix: a connect must pin the server key baked into the
  node's config, never the key the node reports over its callback — so that class of "silent
  no-handshake" bug can't come back unnoticed.

## [0.1.19] — 2026-07-19

### Fixed
- **The real VPN now actually completes its handshake.** Single-hop connects were failing every time
  with *"no WireGuard handshake within 60s/120s"* because of a key mismatch: the exit node ran the
  server key SENTINEL generated, but the client was pinning a *different*, unrelated key the node
  reported back over its setup callback — so every handshake was sealed to a key the server didn't
  hold and was silently dropped. The client now pins the correct server key directly (the same way
  multi-hop "bounce" already did), so a real Connect can reach **tunnel up**. The node's callback is
  kept purely as an authenticated "I've finished booting" signal.

### Changed
- If a connect ever still times out at the handshake, the error now reports the tunnel's byte counters
  and says whether your PC never sent traffic (a local WireGuard/driver issue) or sent it but the node
  never replied (a server-side issue), and the full `wg show` dump is written to the errors log — so a
  failure points at the cause instead of being a blind guess.

## [0.1.18] — 2026-07-19

### Fixed
- **A dropped VPN can no longer leave your PC without internet.** When a WireGuard full-tunnel is torn
  down uncleanly it can leave behind "capture-all" routes and a DNS policy that even a full
  `netsh int ip reset` + reboot won't clear — which could strand your connection. SENTINEL now scrubs
  those leftovers (the two `0.0.0.0/1` + `128.0.0.0/1` routes, the WireGuard DNS policy, and the DNS
  cache) **automatically on disconnect, on any failed connect, and on every launch** — so the app
  self-heals a stranded connection the next time you open it.

### Changed
- The **Settings → WireGuard** recovery button is now **"Restore internet"** and does the full scrub
  (leftover tunnel + firewall rules + routes + DNS) in one click, with a note that the last-resort fix
  for a truly stuck adapter is to uninstall WireGuard and reboot.

## [0.1.17] — 2026-07-19

### Added
- **One-click "Deploy my sync server."** **Settings → Sync server → Deploy** now provisions your
  *own* encrypted sync server on Linode in one click — it reuses your Real VPN token, spins up a
  durable node, installs everything (Docker + a prebuilt image + Postgres), generates its own keys
  and a **self-signed TLS certificate the app pins**, and signs this device in automatically. **No
  Google account, no OAuth client id, and no domain required.** The vault stays end-to-end encrypted
  (the server only ever sees ciphertext). The panel shows the running cost and a one-click
  **Destroy** to stop billing.
  - It authenticates with a generated **bootstrap token** instead of Google (a new
    `/v1/auth/bootstrap` endpoint on the server). The old "Sign in with Google" remains for advanced
    setups under **Cross-device sync**.
  - **One-time setup:** the server image is published to GitHub Container Registry; make that package
    **Public** once so the deploy can pull it (see the setup guide — the deploy tells you if this is
    the holdup).
  - **Heads-up on cost:** unlike the ephemeral VPN, a sync server is **always-on and bills ~$5/month**
    until you Destroy it. The UI says so up front.

### Changed
- The sync server can now serve **HTTPS directly** from a provided certificate (no reverse proxy
  needed) and **self-migrate** its database on first boot, which is what makes the one-click deploy
  possible. Durable sync nodes are tagged so the VPN's orphan-sweep never touches them.

## [0.1.16] — 2026-07-19

### Changed
- **The app now opens unlocked by default.** SENTINEL is a personal-use tool, so there's no login
  wall on launch anymore — it opens straight to your vault. You opt into a lock only if you want one.

### Added
- **Optional master password (real encryption).** Under **Settings → App lock** you can set a master
  password. Unlike before, this genuinely protects the vault: your key is wrapped with Argon2id and
  the plaintext copy is removed from the OS keychain, so the password becomes a real factor (not just
  a screen lock). Change or remove it any time — removing it returns to unlocked-by-default. Nothing
  in your vault is re-encrypted, so it's safe to turn on with data already saved.
- **Sign in with your authenticator app (Google Authenticator, Authy, …).** Add a 6-digit
  **2-step unlock** under **Settings → App lock**: scan the shown **QR code** into your authenticator
  app (the code is now actually rendered), confirm once, and SENTINEL asks for a code at unlock. Fully
  local — no Google account or server required.
- A gentle nudge to add a master password when you set up the real VPN.

### Fixed
- **The Google sign-in that "looked fake" is clearer now.** The old "Sign in with Google" lives under
  a relabeled **Cross-device sync (advanced)** card and is plainly marked as an optional,
  self-hosted-server feature — *not* how you log into the app. Logging in is now App lock (above).

## [0.1.15] — 2026-07-19

### Fixed
- **A failed VPN connect can no longer take your internet down.** When the tunnel came up but the
  exit node never completed a handshake, SENTINEL destroyed the server but left the tunnel installed
  — and because it routes *all* traffic, the PC was left with no internet until you removed the
  tunnel by hand. The tunnel is now torn down automatically on a failed handshake, restoring normal
  internet before the error is shown.
- **More time for the tunnel to come up.** The handshake wait went from 60s to 120s, since a fresh
  exit node's WireGuard can take longer than a minute to answer the first handshake.

### Added
- **"Remove stuck tunnel (restore internet)" button** under **Settings → WireGuard**. One click
  removes any leftover SENTINEL tunnel and clears kill-switch firewall rules — your escape hatch if
  a connection ever leaves you offline.

## [0.1.14] — 2026-07-19

### Added
- **WireGuard monitor (Settings → WireGuard).** A live check of the two things the real VPN needs
  on your PC: whether **WireGuard is installed** (with the detected path) and, on Windows, whether
  **SENTINEL is running as administrator**. If WireGuard is missing, a **Download WireGuard** button
  opens the install page; a **Re-check** button re-runs the check after you install or relaunch.

### Fixed
- **Connect checks your PC *before* spending money.** SENTINEL now verifies WireGuard is installed
  (and, on Windows, that it's running as administrator) **before** creating a Linode — so a missing
  prerequisite fails instantly with a clear message instead of spinning up a paid server that then
  dies at the tunnel step.
- **"Access is denied" is now explained.** When the tunnel can't be installed because SENTINEL
  isn't elevated, the error now says exactly that — *"run as administrator, then Connect again"* —
  instead of a raw `wireguard.exe … Access is denied`.
- **Key exchange no longer times out on a slow provision.** The new server installs faster (it now
  pulls `wireguard-tools`, using the WireGuard module already in Linode's kernel instead of
  compiling one), and the app waits longer (~3 min) for the new node to finish setup before giving
  up — fixing *"provisioning failed at callback: server pubkey not retrieved"* on a cold start.

## [0.1.13] — 2026-07-19

### Added
- **Diagnostics error log.** **Settings → Diagnostics** shows a running log of errors and notable
  events (no passwords or secrets), with **Copy**, **Open folder**, and **Clear**. The file lives at
  `%APPDATA%\com.sentinel.desktop\logs\sentinel.log` and self-caps in size. When something like a
  VPN connect fails, you can copy the log and send it over.

### Fixed
- **VPN connect no longer times out before the server even boots.** The boot-wait loop polled
  Linode with no delay between checks, so it burned through every attempt in a few seconds and gave
  up with *"instance did not reach Running in time"* — even though the server was still coming up
  normally (a Linode takes ~1 minute). It now waits ~3s between polls and allows up to ~3 minutes,
  matching real provisioning time. This fixes the connect that failed right after the node appeared
  on the Linode dashboard.
- **VPN connect now tells you *why* it failed.** When Linode rejects a request (creating,
  booting, or managing an exit node), the app used to show only a bare HTTP status. It now
  surfaces Linode's actual reason — e.g. "Account must be activated", an invalid token scope, or
  an unsupported region — so a failed **Connect** is diagnosable instead of silent (and it's
  written to the new diagnostics log).

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

[0.1.18]: https://github.com/Taco406/vpn-password-manager-/releases/tag/v0.1.18
[0.1.17]: https://github.com/Taco406/vpn-password-manager-/releases/tag/v0.1.17
[0.1.16]: https://github.com/Taco406/vpn-password-manager-/releases/tag/v0.1.16
[0.1.15]: https://github.com/Taco406/vpn-password-manager-/releases/tag/v0.1.15
[0.1.14]: https://github.com/Taco406/vpn-password-manager-/releases/tag/v0.1.14
[0.1.13]: https://github.com/Taco406/vpn-password-manager-/releases/tag/v0.1.13
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
