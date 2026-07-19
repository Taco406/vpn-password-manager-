# Browser autofill (experimental)

Fill logins straight into Chrome and Edge from the SENTINEL vault. This is **opt-in**,
**experimental**, and **Windows-first** — it works on macOS and Linux too, but Windows is
the primary, tested target.

## How it works

Chrome's autofill extension talks to the desktop over
[Chrome native messaging](./native-messaging.md) (u32-LE length prefix + JSON
`NmEnvelope`, 1 MiB cap). Normally that needs a separate host binary.

Instead, **the SENTINEL desktop binary is its own native-messaging host.** When Chrome or
Edge launch the configured host, they exec the binary and pass the requesting extension
origin (`chrome-extension://…`) as an argument. At the very top of `main()` the app checks
for that (`nmhost::is_host_mode()`); if present, it runs a short stdio loop
(`nmhost::run()`) that speaks the wire protocol and exits — it never builds the UI. A
normal double-click launch never takes that path.

Nothing extra ships and there are no release-pipeline changes: the same installed
`sentinel-desktop.exe` is both the app and the browser host.

```
Chrome/Edge  ──native messaging (stdio)──►  sentinel-desktop.exe --nm-host
   ▲                                              │  opens <app_data_dir>/vault.db
   │  chrome-extension://<pinned id>              │  unlocked with the OS-keychain key
   └──────────────────  JSON replies  ◄───────────┘
```

The host serves: `hello` (`{caps, appVersion, locked}`), `vault.search`
(`{items:[…]}`), `vault.fields.get` (decrypted `username` / `password` / `totp`),
`vault.totp.get` (`{code}`), and `vault.generate` (`{password}`). It opens the exact same
vault the app uses — DB at `<app_data_dir>/vault.db`, key from the OS keychain
(`com.sentinel.desktop` / `vault-key`).

## User steps (the app does the hard part)

The extension now **ships inside the installer** (bundled via `bundle.resources` in
`tauri.conf.json`), so there's no repo checkout to find.

1. **Settings → Browser autofill → "Get the extension."** The app copies the bundled
   extension to a stable, writable folder — `<app_data_dir>/extension` (Windows:
   `%APPDATA%\com.sentinel.desktop\extension`) — registers itself as the browser host, and
   shows that folder path with **Copy path** and **Open folder** buttons.
2. **Load it in the browser.** Open `chrome://extensions` (or `edge://extensions`) → enable
   **Developer mode** → **Load unpacked** → select the folder from step 1. The extension's id
   is pinned (via a fixed `"key"` in the manifest) to `pbcngnmfielibgghcofedjmojogohcdf`, so it
   stays stable across reloads and the host allow-lists exactly this extension. (A Chrome Web
   Store build — a true one-click install — is prepped in [`chrome-web-store.md`](./chrome-web-store.md);
   the host already accepts both the unpacked and store ids.)

The "Get the extension" step also writes the host manifest and registers the binary as
`com.sentinel.host`:
   - **Windows:** `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.sentinel.host`
     and `HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.sentinel.host` (default
     value = the manifest path).
   - **macOS:** a `com.sentinel.host.json` file under
     `~/Library/Application Support/{Google/Chrome, Microsoft Edge, Chromium}/NativeMessagingHosts/`.
   - **Linux:** `~/.config/{google-chrome, chromium, microsoft-edge}/NativeMessagingHosts/com.sentinel.host.json`.

   **Disable** removes those keys/files. The installed state is read back with
   `autofill_status`.

Restart the browser after loading the extension so it picks up the new host registration.

## Safety — a site only ever gets its own credentials

The desktop is the authority. On every credential request the host re-checks the page
`origin` against each item's saved URL with `sentinel_core::vault::session::origin_matches`
**before** releasing any field, and refuses with `BAD_ORIGIN` otherwise. The same rules
apply as everywhere else in SENTINEL:

- an `https`-saved credential never fills on a plain-`http` page (no downgrade);
- non-default ports must match exactly;
- host-exact URLs need an exact host; domain URLs match the registrable domain only;
- there is never a match into an unrelated origin.

If the vault can't be opened (locked, no keychain, first run), `hello` reports
`locked: true` and every credential request answers `LOCKED` with **no payload** — the
extension receives zero secret data. Password generation is the only request that works
while locked, because it touches no vault data.

## Scope / caveats

- Experimental and Windows-first; treat macOS/Linux as best-effort.
- The extension ships in the installer and is loaded unpacked (Developer mode). A Chrome Web
  Store listing (one-click, no Developer mode) is prepped but not yet published.
- "Get the extension" copies the files + registers the OS host manifest; the browser's
  **Load unpacked** (step 2) is the one manual action that remains.
