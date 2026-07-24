# Changelog

All notable changes to **SENTINEL** are recorded here. The app shows this list under
**Settings → Updates → What's new**, and each GitHub release uses its section below as the
release notes.

The format follows [Keep a Changelog](https://keepachangelog.com/). Versions are
[semantic](https://semver.org/). **Add a new `## [x.y.z]` section at the top in the same PR
that bumps the app version** — that's how "the changelog updates on every merge."

## [0.1.59] — 2026-07-24

### Added
- **Lock a transfer with a password.** When you send a file (or a bundle) you can now add a password
  on top of the automatic encryption. The receiving device has to type that password to open it — so
  even someone who somehow had your vault key still couldn’t read the file without it. It uses the
  same strong key-stretching (Argon2id) your master password does.
- **Enter the password to open a protected file.** On any device — computer, iPhone, or iPad — a
  password-protected file asks for the password when you go to save it, and won’t open without it.

### Notes
- **The password can’t be recovered.** It’s never stored anywhere and never sent to the server, so if
  it’s forgotten the file can’t be opened — that’s the point. Share it separately from the file (not
  in the same place), and don’t forget it. The app warns you about this when you set one.
- This is a *second* lock on top of the usual encryption, not a replacement: every file is still
  sealed with your vault key first, and your server still only ever stores ciphertext. Files sent
  without a password behave exactly as before.

## [0.1.58] — 2026-07-24

### Added
- **Send several files — or a whole folder — as one transfer.** Pick more than one file at once, or
  just drag the files (or a folder) straight onto the Send card, and they travel together as a
  single encrypted bundle. On the receiving device you save the whole set in one go. (Your files are
  already compressed automatically before they're sealed, so this is about sending them *together*,
  not squeezing them smaller — that was already handled.)
- **Drag and drop.** Drop files onto the Transfers screen instead of hunting through the file picker.
  Dropped files are sealed with your vault key on this device first, exactly like the picker — no
  file leaves your computer unencrypted, and no file path is exposed to the app.
- **iPhone & iPad open bundles.** A multi-file bundle sent from a computer arrives on the phone and
  unpacks into its individual files, ready to save to Files/Photos.

### Notes
- Still zero-knowledge, still 25 MB per transfer: the whole bundle is encrypted on your device
  before it leaves, and your server only ever stores ciphertext and a size. Nothing about the
  encryption changed — single files use the exact same format as before, so transfers from older
  versions keep working.

## [0.1.57] — 2026-07-24

### Added
- **Sign in on a new computer and everything is already there.** Until now a fresh device only got
  your passwords and provider tokens back — the rest of your setup stayed on the old machine. Now
  your whole configuration rides your encrypted vault and rehydrates on first sign-in: your VPN
  preferences (split-tunnel routes, kill-switch default, auto-connect on untrusted Wi-Fi and your
  trusted-Wi-Fi list), your server monitoring (watchdog CPU/disk alerts **and** the logins for any
  password-protected Netdata servers), your always-on VPN server (so a new device can see, connect
  to, and shut it down instead of it being invisible and billing in the background), and the small
  stuff — theme, auto-lock timeout, clipboard-clear time, default region. Nothing to re-enter.
- **A new device now asks for your master password.** If you’ve set a master password, a computer
  you’ve just signed in on will require it on every launch from then on — instead of opening
  straight into your vault. A device that just downloaded your whole vault should be locked behind
  your password, and now it is. (If you don’t use a master password, nothing changes — it still
  opens by default.)
- **iPhone & iPad: password-protected server dashboards now load.** If a server’s Netdata is behind
  a username/password, the phone used to skip it; now it uses the login that rides your vault, the
  same as your computer.

### Notes
- All of this stays zero-knowledge: every setting travels inside the same end-to-end-encrypted vault
  item your passwords do — including the secret bits (a Netdata login, the always-on node’s key) —
  so your server still only ever stores ciphertext. Nothing about the encryption changed.
- Your recovery-code restore is unchanged and still opens straight in — it’s the one path that
  never asks for a master password, on purpose, so a forgotten password can’t lock you out of a
  recovery.

## [0.1.56] — 2026-07-23

### Added
- **Choose how long a sent file sticks around.** When you send a file to your devices you now pick,
  right on the Send card, how it’s kept: **for a few days** (with the exact number of days up to
  you), **until downloaded** (it’s deleted the moment one of your devices grabs it — nothing left
  behind), or **permanently** (filed on your own server until you delete it). This is the space
  saver you asked for: keep only what you want to keep, and let the rest clean itself up. The same
  three choices are on the iPhone and iPad.
- **Every transfer now shows how it’s being kept.** Each row in Incoming/Sent tells you whether it’s
  kept, deletes on download, or when it expires — so nothing disappears as a surprise.

### Fixed
- **Transfers showed the wrong size and no sender.** Sent/received files were displaying “0 B” with
  a blank sender and time on the computer; they now show the real size, who it’s from, and the age —
  the same details the phone already showed. (The files themselves always transferred correctly;
  only these labels were wrong.)
- **iPhone Servers tab: “Linode: cancelled” and the fleet vanishing after a sync.** The Servers tab
  re-synced the vault while it was still loading your servers, which cancelled the in-flight request
  and blanked the list with a scary “cancelled” error. It now lists your servers from the tokens it
  already has first — so they show immediately and can’t be wiped by a sync — and quietly ignores a
  cancelled refresh instead of clearing everything. Your Linode was never actually removed; only the
  on-screen list was clearing.

### Notes
- Files are still sealed on your device with your vault key before they leave — the server only ever
  stores ciphertext and a size. “Permanently” kept files count against your account’s transfer
  storage; if you run out of room, the app tells you to clear some space rather than failing
  quietly. Nothing about the encryption changed.

## [0.1.55] — 2026-07-23

### Added
- **iPhone & iPad: a full server dashboard, matching your computer.** Tapping a server on the
  Servers tab now opens a live dashboard with the whole tile grid — CPU, RAM, Swap, Disk, Load
  (1/5/15 min), CPU steal, processes, uptime, and CPU/memory/disk “pressure” — plus live Network,
  Disk I/O, and Load charts and your server’s active alarms. It reads Netdata directly, the same
  numbers the desktop shows.
- **Power your servers from your phone.** Start, reboot, or stop any Linode or Hetzner server right
  from its dashboard (with a confirmation), using the tokens that already ride your encrypted vault.

### Notes
- The monitoring math on the phone is the same as the desktop’s, checked by unit tests so the two
  always agree. If a server’s Netdata is behind a username/password, the phone skips it (set that up
  from the computer); if the port is firewalled, open it from the desktop’s one-click button.

## [0.1.54] — 2026-07-23

### Added
- **A “Getting started” checklist.** A new screen (and a sidebar item that shows your progress)
  lays out everything you can set up — protect your vault, add your first login, sync across
  devices, add another device, browser autofill, VPN, servers — each with a one-click button that
  takes you straight to it. It marks items done as you go and tucks itself away once the essentials
  are handled. Finishing the first-run setup now drops you here instead of an empty vault.
- **The iPhone app runs full-screen on iPad.** It’s now a proper iPad app (not a blown-up phone
  window): full-screen, works in any orientation, and the vault shows a side-by-side list and
  detail on the larger screen. The iPhone layout is unchanged.

### Changed
- **Clearer feedback everywhere.** Actions that used to fail silently now tell you what happened —
  most importantly the VPN **Connect/Disconnect** buttons, which previously gave no error if
  WireGuard wasn’t installed or the app wasn’t run as administrator. Success and error messages now
  appear as small notifications, and a screen that hits an unexpected error shows a “try again” card
  instead of going blank.
- **A friendlier empty vault.** A brand-new vault now shows an “Add your first login” button and an
  import hint, instead of “select an item” pointing at nothing.
- **The monthly report works and is easy to find.** You can reach it from the command palette
  (Ctrl/⌘-K) and the VPN screen, flip between months, and its **Export PNG** button now actually
  saves a shareable image of the report.

### Fixed
- Settings and unlock screens no longer flash blank while loading, and the browser-autofill card is
  hidden on macOS (where its helper isn’t supported yet) instead of showing a button that can’t work.
- **iPhone: Face ID unlock is instant again.** It was asking for your face several times before
  opening because the unlock screen re-checked “is Face ID set up?” by reading the protected key —
  which triggered a Face ID scan on every keystroke. The check now uses a lightweight flag, so your
  face is scanned exactly once, when you tap **Unlock with Face ID**.
- **Your servers now follow you to every device reliably.** The shared settings that ride your vault
  now back-fill themselves — if one computer has a token (e.g. Hetzner) that your shared settings
  were missing, it’s added and synced automatically. Previously it only propagated when you happened
  to change a setting, which is why a second computer or your phone could show your Linode server but
  not your Hetzner one. The phone’s Servers tab also refreshes these tokens when you open it.

## [0.1.53] — 2026-07-23

### Added
- **A real server dashboard.** The live-monitoring panel is now a full grid: CPU, RAM, Swap,
  Disk, Load (1/5/15 min), CPU steal (how much a noisy neighbour is stealing on a shared box),
  running processes, uptime, and “pressure” health for CPU/memory/disk — plus live charts for
  network in/out and disk read/write. Every tile loads on its own, so one missing number never
  blanks the rest.
- **Send files to your devices.** A new **Transfers** screen: pick a file, choose a device (or
  “all my devices”), and it’s encrypted on this computer before it leaves. Your other computers
  and your iPhone can save it. The server only ever holds the scrambled file and deletes it after
  24 hours — it can never read the contents or even the file name. Up to 25 MB per file.
- **One-click Hetzner firewall.** When your server’s monitoring can’t be reached because a
  Hetzner Cloud Firewall is blocking the port, there’s now a button to open it right from the
  app — no more digging through the Hetzner website. It defaults to opening the port to any
  address (right for a home internet connection whose IP changes, like Starlink), with an option
  to lock it to your current IP.
- **The iPhone caught up with the computer.** The phone now has its own **Servers** tab (live
  Netdata tiles for each of your servers) and **Transfers** tab, in addition to the vault. Your
  server API tokens ride your encrypted vault to the phone, so it talks to Linode/Hetzner/Netdata
  directly — the sync server still only ever stores scrambled data.

### Changed
- **Signing in now brings your servers with you.** After you sign in on a new computer, your
  saved server settings apply automatically and the Servers screen fills itself in — no more
  hunting for a “Sync now” button. Syncing runs quietly in the background. A new **Shared
  settings** panel under Account & Sync shows what’s shared across your devices (Linode, Hetzner,
  Google, monitoring) and when — without ever showing the secret values.
- **Your Hetzner token now syncs too.** Previously only the Linode and Google settings followed
  you to a second device, which is why a second computer never showed your Hetzner servers. Now
  it does.
- **The Mac app is signed and notarized.** This is the first Mac build signed with a Developer ID
  certificate, so macOS opens it without the “unidentified developer” warning.

## [0.1.52] — 2026-07-23

### Fixed
- **The iPhone can sign in to your server again.** iOS was blocking the connection to a
  self-signed personal server before the app's own certificate check could accept it (the
  "TLS error / secure connection failed" you saw). The app pins your exact server certificate
  itself — stronger than the check iOS was enforcing — so that check is now handed fully to the
  app. The desktop was never affected.
- **Server live-monitoring: RAM, Load, and Disk now show real numbers.** They were stuck on "—"
  because the app asked Netdata for the root-disk chart by an outdated name, and that one failed
  request blanked the other two along with it. The disk chart name is corrected and each reading
  is now independent, so one missing metric never hides the rest. (A richer server dashboard is
  coming next.)

## [0.1.50] — 2026-07-23

### Added
- **The iPhone works without a connection now.** After the first successful sync, the phone
  keeps an encrypted copy of your vault (the same unreadable-without-your-master-password bytes
  the server stores). No signal, server rebooting, plane mode — unlock still works and your
  passwords still show, with an "Offline" note; editing switches back on when the server is
  reachable again.

### Fixed
- **The "Add a device" QR shows a live countdown and refreshes with one click.** QRs are only
  good for ~5 minutes; the desktop now counts that down, swaps the dead QR for an "expired —
  press New QR" notice instead of leaving it on screen, and clears it when minting fails.
- **The phone tells you what actually went wrong when it can't connect.** Connection failures
  now show the full technical reason (so a screenshot is enough to diagnose), and the misleading
  "codes expire after ~5 minutes" hint only appears when the code is actually the problem.
- **A failed first connection no longer strands the phone.** Previously, if scanning the QR or
  the address sign-in failed part-way, the phone remembered the half-configured server and
  reopened onto an unlock screen for a server it never joined (until you tapped "forget" — the
  extra step several first logins hit). Failed attempts now roll back cleanly.
- After pressing "Trust this server", a server without master-password sign-in shows a clear
  what-to-do-next card (with a "Check again" button) instead of a small message that was easy
  to miss.

## [0.1.49] — 2026-07-23

### Added
- **Your app configuration now syncs too.** Signing in on a new computer no longer leaves it
  half-set-up: the Linode API token and the Google sign-in credentials travel inside your
  encrypted vault (a hidden system entry — never shown in your password list on any device) and
  are applied automatically on sync. Change a token on one device and every device has it after
  the next sync. Same zero-knowledge guarantee as your passwords: the server carries the tokens
  but can never read them.
- The device that already has the tokens shares them automatically on its next sync — no manual
  export step.

### Fixed
- The iPhone app has a proper app icon (required for TestFlight; previously a blank tile).

## [0.1.48] — 2026-07-22

### Changed
- **The login is now exactly what it should have been all along: server address + master
  password (+ your 6-digit code if 2-step is on).** On any device — Windows, Mac, or iPhone —
  signing in means typing your server's address and your master password. That's the whole
  flow. Google sign-in, setup tokens, and device join codes still work but move out of the way;
  the QR is now just a shortcut that fills in the address for the phone's camera.
- **First-contact trust check.** The first time a device connects to your server by address, it
  shows the server's identity code; your signed-in computer displays the same code under
  Account & Sync — matching codes rule out a man-in-the-middle, then the certificate is pinned
  forever. (Scanning the QR skips even this, since the QR carries the certificate.)
- **Turn on master-password sign-in** (Account & Sync → Advanced) replaces "Enable
  master-password unlock": one action escrows your wrapped key AND registers a one-way sign-in
  proof. Still zero-knowledge — the server stores a hash of an HKDF derivation and can verify
  your password without ever being able to unwrap your vault. Unlocking a fresh device with the
  master password auto-enrolls it too.
- The signed-in Account & Sync card now shows your server's address + identity code — the two
  things you read to another device to sign it in.

### Notes
- Sign-in and vault unwrap share one Argon2id derivation (same salt), so the phone signs in and
  opens the vault with a single ~1s computation. The login proof is locked cross-platform by
  the golden-vector tests. New endpoints are additive; older apps and servers keep working
  (a clear message tells you if the server needs its one-click update first).

## [0.1.47] — 2026-07-22

### Added
- **One login on every device.** The whole multi-device story is now a single mental model:
  *connect → sign in → master password → your vault*. The Devices screen is one **Account &
  Sync** experience — status, **Add a device**, **Sync now** — with server management, the
  attack monitor, and recovery tooling folded into collapsed **Advanced** sections instead of
  five overlapping cards.
- **Add a device now shows a QR.** The desktop mints a one-time enrollment code (5-minute,
  single-use, hashed at rest) and renders it as a QR carrying the server address + certificate
  pin — the iPhone scans it and is enrolled with **no tokens to type**. The copyable text code
  for computers sits right next to it; both connect to the *same account*.
- **The iPhone is a real vault app.** Scan the QR, enter the same master password you use on
  the desktop, and your passwords are there: browse, search, copy (auto-expiring clipboard),
  live TOTP codes, add/edit logins and notes, delete — synced end-to-end-encrypted through the
  same `PUT /v1/vault` the desktops use. Face ID unlock is an optional toggle. The crypto
  (Argon2id, XChaCha20-Poly1305, HKDF, zstd) is vendored reference C + CryptoKit, proven
  byte-identical to the desktop by golden-vector unit tests (⌘U) generated from the Rust core.
- **Sync servers update themselves.** New deploys install a host-side updater (daily timer + an
  **Update server to the latest version** button under Advanced) with no Docker socket exposed
  to the API container. Servers deployed before v0.1.47 need one last manual redeploy — the
  morning-test script (docs/morning-test.md) walks through it.

### Fixed
- **"0 passwords synced" on a second computer — the root cause.** Google sign-in and the
  built-in login used to create *two different accounts* on your own server, so a joined device
  looked at an empty vault. One personal server is now **one account** regardless of how each
  device signs in (covered by integration tests in both orders), the vault auto-pushes after
  sign-in/deploy/join instead of waiting for a manual backup, and vault edits auto-sync
  (debounced) so "Sync now" is a refresh, not a chore.
- The unlock screen no longer shows "Approve on iPhone" / "Recovery kit" rows that silently
  ignored input and unlocked from the OS keychain — only real unlock methods are listed.
- Removed a dead second onboarding flow that contradicted the setup wizard, and the recovery
  kit PDF is now named `northkey-recovery-kit.pdf`.

## [0.1.46] — 2026-07-22

### Added
- **Unlock your vault on a new device with just your master password.** No more device-code or
  recovery-code dance for multi-device sync: on a device that has your vault, **Vault sync → "Enable
  master-password unlock"** escrows your master-password-wrapped key (Argon2id, still zero-knowledge —
  the server holds no key material and can never unwrap it) and pushes your vault. Then on a new
  device, **Sign in + Vault sync → "Unlock this device with your master password"** downloads the key,
  unwraps it locally, and pulls your vault. Same account, same master password, nothing new to create.
- **File-transfer relay (backend).** The sync server can now hold an opaque, size-capped (25 MiB),
  24h-expiring encrypted blob addressed to one of your devices — the plumbing for a "send a file to
  my other device" feature. The desktop send/receive UI lands next; the server half ships now.

### Notes
- The file the transfer relay stores is encrypted client-side (XChaCha20-Poly1305) and the server
  never sees the file, its name, or any key. The password key-escrow reuses the exact wrapper the
  local master-password unlock already uses, so the same password works on disk and across devices.

## [0.1.45] — 2026-07-22

### Added
- **NorthKey for iPhone is a real, buildable app (iOS-1).** The companion in `apps/ios-key` now has
  a generated Xcode project (`xcodegen generate` from `project.yml`), an Info.plist, and hardened
  entitlements, so it builds and installs on an iPhone. On first run you connect it to your sync
  server with your personal setup token; it then enrolls as an approved iOS device, registers for
  push, and pins its Secure-Enclave key to the account — all against a live sync server. Renamed
  SentinelKey → NorthKey throughout (the `sentinel/…` pairing-protocol strings are unchanged so the
  desktop and phone still interoperate byte-for-byte).
- **Sync-server endpoints the phone needs.** `POST /v1/devices/pin` lets an iOS device register its
  pinned P-256 key; `GET /v1/devices` now returns that key so the desktop can seal to it; and
  `GET /v1/unlock-requests/:id` now also returns the opaque request payload so the phone can approve.

### Notes
- The desktop and Windows/Linux/macOS installers are unchanged in this release — its substance is the
  iPhone companion plus the sync-server (`sentinel-api`) relay endpoints, which ship in the published
  server image. Sealing the actual vault **key share** on approval, the desktop-side pairing UI, and
  the on-phone vault viewer are the next iPhone increments.

## [0.1.44] — 2026-07-22

### Added
- **NorthKey.app for macOS — signed & notarized.** The macOS build is now wired for Apple
  Developer ID code signing + notarization, so once the signing certificate is in place the `.dmg`
  opens with a normal double-click (no more right-click → Open past Gatekeeper). See
  `docs/macos-signing.md` for the one-time Apple setup. Windows and Linux builds are unchanged.

### Changed
- **Honest about what works on macOS.** On macOS the app now hides controls it can't back up: the
  VPN **kill switch** and **auto-connect on untrusted Wi-Fi** are labeled Windows-only (they were
  silently doing nothing on macOS), and the lock screen no longer shows a biometric button unless
  the OS actually has a verifier — so nothing pretends to protect you when it can't. Basic VPN
  connect still works on macOS via WireGuard (`brew install wireguard-tools`), and split-tunnel is
  fully supported.

### Notes
- macOS is now built and tested on every pull request (previously only at release time), so
  platform-specific regressions are caught earlier. Real Touch ID unlock is the next macOS step.

## [0.1.43] — 2026-07-21

### Added
- **Passkeys that actually sign in — Stage B + C (WebAuthn).** NorthKey can now **create** a
  passkey for a website and **sign in** with it, through the browser extension. When a site offers
  "create a passkey" or "sign in with a passkey," NorthKey asks whether to use it; on yes, the
  desktop does the P-256 signing and hands the browser a valid WebAuthn credential. Passkeys you
  create show up in your vault like any other item and sync end-to-end encrypted. The private key
  never leaves the desktop, and the desktop enforces that a site can only use a passkey scoped to
  its own domain.
- **Non-hijacking by design.** The extension only steps in when you say yes and NorthKey has (or
  makes) a matching passkey — otherwise it gets out of the way, so your hardware security keys and
  built-in platform passkeys keep working exactly as before.

### Notes
- Requires the NorthKey browser extension (Chrome/Edge) connected to the unlocked desktop app.
- This is the software-authenticator path (no hardware attestation) — sites see a standard "none"
  attestation, which is what password-manager passkeys use.

## [0.1.42] — 2026-07-21

### Added
- **Manage your servers, not just watch them.** Expand any server on the Servers screen →
  **Manage server** for a full lifecycle drawer that works across both Linode and Hetzner Cloud:
  - **Snapshots** — take a named snapshot before risky work and see your existing ones. (Hetzner
    snapshots bill per GB/month; Linode manual snapshots need the Backups add-on enabled.)
  - **Delete protection** (Hetzner) — turn on delete/rebuild protection so the provider refuses to
    destroy the box until you turn it back off.
  - **Reverse DNS** — set the PTR record for a server's IP (handy for mail servers).
  - **Recent activity** — the last several provider actions (reboots, snapshots, …) with status
    and time.
  - **Access** — a copy-paste `ssh root@<ip>`, a one-click **Open terminal** button (launches
    Windows Terminal into SSH, or falls back to PowerShell), and copy-paste one-line installers for
    free tools you can add to a box (Netdata, Uptime Kuma, Dozzle, fail2ban).

### Notes
- NorthKey never stores an SSH password — the terminal button just launches your own `ssh`, and
  the install one-liners are copy-paste you run on the server yourself.

## [0.1.41] — 2026-07-21

### Added
- **Attack monitor for your sync server.** A new **Attack monitor** panel on the Devices screen
  shows what's happening at your sign-in door: a 24-hour tally of **failed sign-ins**, **token
  replays**, **blocked IPs**, and successful **sign-ins**, plus a live feed of recent attempts
  (each with its outcome, source IP, and time). The server now records the outcome of every
  sign-in attempt — a wrong bootstrap token, a rejected Google token, a bad 2FA code, a
  rate-limit trip, or a **refresh-token replay** (a strong signal that a session token was
  stolen). Nothing sensitive is stored: no passwords and no vault data, only the outcome, the IP,
  and the timestamp — and your vault stays end-to-end encrypted exactly as before.
- **Block / unblock IPs.** Paste an address to block it (permanently, or type nothing to keep it
  simple), or hit **Block** next to any suspicious entry in the feed. Unblock the same way. A
  blocked IP is turned away before it ever reaches the password check.
- **Opt-in auto-ban.** Set `SENTINEL_AUTOBAN_THRESHOLD` on the server (e.g. `20`) and it will
  automatically, temporarily ban an IP that racks up that many failed attempts in a short window
  — with a built-in guard that never bans an address that has signed in successfully in the last
  day, so you can't lock yourself out by fat-fingering a code. Off by default (detection only);
  the panel shows which mode your server is in.

### Notes
- Servers deployed before this release don't have the monitor yet — the panel says so; redeploy
  (Destroy, then Deploy) to enable it. Your vault is untouched and re-uploads after you sign back
  in.

## [0.1.40] — 2026-07-21

### Added
- **Server watchdog with Windows notifications.** Turn it on at the bottom of the Servers screen
  and NorthKey checks all your servers in the background (every 2 minutes by default): a toast
  fires when a server goes **down** (and again when it **recovers**), when **CPU stays pegged**
  past your threshold, when a **disk runs full**, or when **Netdata raises an alarm**. Alerts are
  latched — one notification per incident, not one per check — and also collect in a "Recent
  alerts" feed on the screen. (Alerts fire only while NorthKey is running.)
- **Netdata live monitoring.** Expand a server row → **Live monitoring**: if the server runs the
  free Netdata agent, you get a per-second live CPU chart, RAM/load/disk gauges, and Netdata's
  own active alarms as badges — the same data Netdata's dashboard shows, inside NorthKey. A
  one-click check tells you whether the agent is reachable; if it isn't, you get copy-paste
  commands to install Netdata and open port 19999 **to your IP only** (plus an SSH-tunnel
  alternative), and fields for a custom port or proxy auth.

## [0.1.39] — 2026-07-21

### Added
- **New Servers screen — manage every server you own, in one place.** All your Linode instances
  (including NorthKey's own VPN and sync nodes, labeled so you can tell them apart) **and your
  Hetzner Cloud servers**, together: live state, IPs (click to copy), specs, and monthly cost per
  provider (in each provider's own currency).
  - **Start / Stop / Reboot** any server, with confirmations. The node carrying your active VPN
    connection is protected — the app points you at the VPN screen instead of yanking your tunnel.
  - **Real utilization graphs** — CPU and network in/out over 1h / 6h / 24h, straight from each
    provider's metrics API (no simulated data). Expand any server row to see them; they refresh
    every minute while open.
  - **Hetzner Cloud token** field under Settings → VPN (stored only in Windows Credential
    Manager, like the Linode one).
  - This is stage 1 of the server manager. Coming next: background watchdog with Windows
    notifications (server down / CPU pegged / disk full), per-second live graphs and alarms from
    Netdata on servers that run it, snapshots, and more.

## [0.1.38] — 2026-07-21

### Changed
- **SENTINEL is now NorthKey.** New name, new mountain‑and‑keyhole logo, new motto — *Your
  network. Your passwords. Your control.* The app window, installer, sidebar, browser extension,
  and all icons carry the new brand. Everything under the hood is unchanged: your vault, settings,
  sync server, devices, and sign‑ins all carry over — the update installs over the old SENTINEL
  version like any other update (the installer keeps the same upgrade identity). Two cosmetic
  notes: Start‑menu/desktop shortcuts are recreated under the new name, and if you use browser
  autofill the extension shows its new name after the app restages it.

## [0.1.37] — 2026-07-20

### Fixed
- **"Set up 2‑step unlock" (App lock → Authenticator app) did nothing when clicked.** The QR/setup
  screen was being cleared the instant it loaded, so there was no way to turn on the authenticator
  second step. It now opens properly: scan the QR (or type the key), enter the 6‑digit code, done —
  from then on unlocking SENTINEL takes your master password *and* a Google Authenticator code.
- **The Updates card showed the wrong version.** The version badge was a leftover hardcoded
  "v0.1.32" no matter what was actually installed. It now reads the running app's real version.
- **"What's new" no longer starts with a garbled entry.** The changelog viewer mistakenly rendered
  part of the file's own intro text as a fake "vx.y.z" release at the top.

## [0.1.36] — 2026-07-20

### Fixed
- **The Google sign‑in's authenticator step now shows an actual QR code.** The message said
  "scan the QR" but the screen only showed the typed setup key. Enrollment now displays a
  scannable QR (same as the app‑lock 2‑step setup), with the typed key still there as a fallback.

## [0.1.35] — 2026-07-20

### Fixed
- **Google sign‑in failed at the last step with "token endpoint returned HTTP 400."** For
  Desktop‑app OAuth clients, Google requires the **client secret** (shown next to the Client ID in
  Google Cloud → Credentials) in the final token exchange — even with PKCE — and the app wasn't
  sending one. There's now a **Client secret** field wherever you set up Google sign‑in (deploy,
  switch, and right above the "Sign in with Google" button if it isn't saved yet). The secret is
  stored in the Windows keychain and never leaves your PC — the sync server itself doesn't need it.
  Token‑exchange failures now also show Google's actual error text instead of just the HTTP code.

## [0.1.34] — 2026-07-20

### Fixed
- **"Sign in with Google" opened File Explorer instead of your browser.** On Windows the app
  launched URLs via `explorer`, which handles plain links but silently opens a File Explorer
  window for any URL with a query string — and the Google sign‑in URL is exactly that. All links
  the app opens (Google sign‑in, password‑reset pages, download links) now go through a launcher
  that passes the full URL to your default browser intact.

## [0.1.33] — 2026-07-20

### Added
- **Fix a password in one click (Vault health).** Every weak, reused, or breached entry now has a
  **Fix** button: it generates a fresh strong password, copies it to your clipboard, and opens that
  site's password‑change page (via the web‑standard `/.well-known/change-password`, which the major
  sites redirect to their real reset form) so you can paste the new one straight in.
- **A way to switch a running sync server to "Sign in with Google."** Previously the Google option
  only appeared while first deploying a server, so anyone who'd already deployed the built‑in‑login
  server had no path to it. The Sync server card now shows your current sign‑in method and a
  **Switch to "Sign in with Google"** action (it redeploys a fresh, Google‑enabled server — your
  local vault is untouched and re‑uploads after you sign in).

### Changed
- **Vault health opens instantly.** The tab used to sit blank for a few seconds while it ran the
  online breach check. It now renders immediately from the local audit (reused / weak / old) and
  fills in the "Breached" count a moment later, with a small spinner while that online check runs.

## [0.1.32] — 2026-07-20

### Added
- **Network tools** (new **Tools** tab):
  - **My IP & location** — shows the public IP and rough location the internet currently sees you
    at. With the VPN connected it should read your *exit server's* location, not your real one — the
    fastest way to confirm the tunnel is actually working. (Uses a public HTTPS geo‑IP service;
    nothing from your vault is sent.)
  - **Ping** — round‑trip latency to any host, measured by timing a TCP connection (no admin rights
    or raw sockets needed, so it behaves the same everywhere).
  - **DNS lookup** — resolve a hostname to its IP addresses.

## [0.1.31] — 2026-07-20

### Added
- **Sign in with Google for the one-click sync server.** When deploying your sync server you can
  now choose **"Sign in with Google"** and paste a Google OAuth **Client ID** (the deploy screen
  has the ~10-minute, one-time setup steps for creating a "Desktop app" client in Google Cloud —
  no client secret needed). The server is provisioned to validate real Google logins, and this
  device finishes sign-in with Google + a TOTP code from your authenticator app. Leave it off to
  keep the original zero-setup personal server.

### Fixed
- **Google sign-in now actually reaches a one-click server.** The Google sign-in call used the
  un-pinned HTTP client, so it couldn't complete the TLS handshake against a self-signed one-click
  server (it only worked against a public-CA custom server). It now uses the pinned client — the
  same trust/cert path the rest of sync uses — and reports the real device platform instead of
  always "windows".

## [0.1.30] — 2026-07-20

### Fixed
- **The VPN now actually passes traffic — connects *and* browses.** The exit node's firewall
  ruleset was silently failing to load, which took its NAT down with it, so a connected tunnel
  handshaked (looked "connected", counters flickered) but no real traffic ever got a reply —
  pages just hung. Root cause: the node loads its firewall *before* the WireGuard interface
  exists, and one rule referenced that interface by kernel index (`iif "wg0"`), which errors
  "interface does not exist" and — because the load is all-or-nothing — **rejected the entire
  ruleset, including the masquerade/NAT that makes your traffic routable.** Without NAT, your
  packets left the server with a private address and never came back. Fixed by matching the
  interface by name (`iifname`), which loads cleanly before the tunnel comes up. Reproduced and
  verified with the real firewall tool. New connections use the fixed node automatically —
  update and reconnect; no manual server cleanup needed.
- **Lowered the tunnel MTU to a universally safe value (1280).** On connections with a smaller
  underlying MTU (PPPoE, mobile/LTE, DS-Lite, nested VPNs) the old 1420 could blackhole large
  packets — the handshake and small requests work but page data stalls. 1280 (the IPv6 minimum)
  survives those paths.

## [0.1.29] — 2026-07-20

### Changed
- **Browser autofill overhaul — it now fills *and* offers to save.** The extension was missing
  its whole save path and the autofill was easy to miss. Now:
  - **Save works.** When you sign in on a site, an in-page **"Save password to SENTINEL?"** bar
    appears; saving creates a new login (or updates the existing one for that site) directly in
    your vault. Previously the extension asked the app to save but the app had no handler, so
    nothing ever happened.
  - **Autofill is visible.** A small key badge appears inside the focused username/password field
    — click it for a menu of your matching logins, a **Generate password** action, and a clear
    "Unlock SENTINEL" hint when the app is locked (instead of silently doing nothing). Login forms
    that load later (single-page apps) are detected too.
  - **Nicer popup.** Redesigned with per-item **Fill** (fills the active tab), copy username /
    password, and a one-click generate-and-copy — plus a real toolbar icon.
  - Nothing changed about the security model: credentials are still released only on an explicit
    click, only for a matching origin, and only while the app is unlocked.
  - **After updating**, re-open **Settings → Experimental → Browser autofill → Get the extension**,
    then in `chrome://extensions` press **Reload** on the SENTINEL card so the browser picks up the
    new version.

## [0.1.28] — 2026-07-20

### Fixed
- **The sync server now actually starts (the second and final crash cause).** v0.1.27 fixed a
  missing startup secret, but that only exposed a second crash hiding right behind it: the moment the
  server tried to bring up its own HTTPS, it hit an internal TLS mix-up (two cryptography backends
  were compiled in and the library refused to pick one) and **panicked on boot** — so the container
  still crash-looped and the health check still never answered, which is why a fresh Delete + Deploy
  on v0.1.27 *still* showed *Running · not signed in*. The server now picks its crypto backend
  explicitly, so it boots, serves its health check, and this device signs itself in. Verified
  end-to-end by running the real server through its exact production startup (migrate → HTTPS →
  health check → sign-in). **If your server is stuck, Destroy it and Deploy once more** — the new box
  pulls the fixed server and comes up on its own.

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
