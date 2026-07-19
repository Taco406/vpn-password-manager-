# SENTINEL — Setup & required downloads

Everything you need to get SENTINEL working, from "just the vault" to "the whole suite." Start at
the top; each optional feature says exactly what it needs and what (if anything) it costs.

## At a glance — what needs what

| Feature | Extra downloads / accounts | Cost | Admin? |
|---|---|---|---|
| **Vault, generator, breach check** | none (works offline) | free | no |
| **Browser autofill** (Chrome/Edge) | the bundled extension (2-click load) | free | no |
| **Real VPN** (ephemeral exit nodes) | WireGuard for Windows + a Linode account | ~1¢/hour while connected | **yes** |
| **Sync across devices** | a self-hosted sync server (Docker) | your hosting (~$5/mo) | no |
| **Windows Hello unlock** | none (uses built-in Windows Hello) | free | no |
| **iPhone companion** | a Mac + Xcode | Apple dev acct ($99/yr) | no |

You never need all of it. The vault is fully useful on its own.

---

## 1. Install the app (required)

1. Go to the [Releases page](https://github.com/Taco406/vpn-password-manager-/releases/latest).
2. Download **`SENTINEL_x.y.z_x64_en-US.msi`** (Windows). *(macOS `.dmg` and Linux `.AppImage`/`.deb`
   are published too.)*
3. Run it. Windows **SmartScreen** will warn "unknown publisher" (SENTINEL isn't code-signed with a
   paid certificate) → **More info → Run anyway** → finish.
4. Launch **SENTINEL** from the Start menu.

**Updates install themselves** from here on (v0.1.8+). You can also check manually in
**Settings → Updates → Check for updates**, and see what changed under **What's new**.

Your data lives in your Windows user profile (`%APPDATA%\com.sentinel.desktop`), so reinstalling or
updating never wipes your vault.

---

## 2. Core features — no extra downloads

Work immediately, fully offline, nothing leaves your device:

- **Vault** — logins, secure notes, cards. Encrypted with XChaCha20-Poly1305; the key lives in the
  Windows Credential Manager and never in a file.
- **Generator** — strong passwords and passphrases.
- **Health / breach check** — flags weak, reused, and **breached** passwords. The breach check uses
  Have I Been Pwned via *k-anonymity*: only a 5-character hash prefix is sent, never your password.
- **Import** — bring in passwords from Chrome (CSV), Bitwarden (CSV/JSON), or 1Password.

---

## 3. Browser autofill (optional, free)

Fill logins straight into Chrome or Edge. SENTINEL is its own native-messaging host — there's no
separate program to install, and the extension now ships **inside** the app.

1. **Settings → Browser autofill → "Get the extension."** This copies the extension to a folder and
   registers SENTINEL as the browser host. The folder path is shown, with **Copy path** and
   **Open folder** buttons.
2. In your browser, open **`chrome://extensions`** (or `edge://extensions`).
3. Turn on **Developer mode** (top-right).
4. Click **Load unpacked** and select the folder from step 1.

A site only ever receives *its own* credentials, and nothing is available while the vault is locked.
(A one-click Chrome Web Store install is coming — see [`chrome-web-store.md`](./chrome-web-store.md).)

---

## 4. Real VPN — ephemeral exit nodes (optional, paid, needs admin)

By default the VPN screen runs a **simulation**. To route real traffic through a throwaway server
you create and destroy on demand, you need three things:

1. **WireGuard for Windows** — install from
   [wireguard.com/install](https://www.wireguard.com/install/). SENTINEL drives it to bring the
   tunnel up.
2. **A Linode account + API token** — sign up at [linode.com](https://www.linode.com/), add a
   payment method, then create a **Personal Access Token** with **Read/Write** on **Linodes**
   (Cloud Manager → profile → API Tokens). A Nanode costs **~$0.0075/hour** and you're only billed
   while a node exists — SENTINEL destroys it on disconnect, with a dead-man switch + orphan-sweep so
   a crash can't run up a bill.
3. **Run SENTINEL as Administrator** — creating a tunnel is privileged. Right-click SENTINEL →
   *Run as administrator* (or set it permanently in the shortcut's Properties → Compatibility).

Then: **Settings → Real VPN (Linode)** → paste the token → **Save**. Go to the **VPN** screen, pick a
region, **Connect**. Full details, verification steps, kill switch, and auto-connect are in
[`real-vpn.md`](./real-vpn.md).

> If Connect fails, the VPN screen names the stage that failed — that's usually a quick fix.

---

## 5. Sync across devices (optional)

SENTINEL is local-first; sync is opt-in and **zero-knowledge** (the server only ever stores
ciphertext). You run the server yourself. See [`self-hosting.md`](./self-hosting.md) for the Docker
setup, the environment variables, TLS, and the Google sign-in (PKCE) configuration.

---

## 6. Windows Hello unlock (optional, free)

Require a fingerprint / face / PIN each time the vault unlocks, instead of auto-unlocking from the
keychain: **Settings → Security → "Require Windows Hello."** Uses the Windows Hello you already have.

---

## 7. iPhone companion (optional)

A SwiftUI companion exists in source (`apps/ios-key`) but isn't distributed as a build. Compiling it
needs a **Mac + Xcode** (and an Apple Developer account, $99/yr, to run on a real phone). See
`apps/ios-key/README.md`.

---

## Troubleshooting

- **"unknown publisher" / SmartScreen** — expected without a paid code-signing cert. *More info →
  Run anyway.* Update integrity is still guaranteed by the updater's own signature.
- **Autofill does nothing** — make sure the vault is unlocked, you loaded the folder from step 3.1,
  and you restarted the browser after loading the extension.
- **VPN "Connect" errors** — check WireGuard is installed and SENTINEL is running as Administrator;
  the error names the failing stage.
- **Updates say "Couldn't check"** — fixed in v0.1.8; if you're older, install the latest `.msi` once
  by hand and auto-update will work from then on.
