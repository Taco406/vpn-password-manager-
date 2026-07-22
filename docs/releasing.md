# Releasing & auto-update

SENTINEL desktop installs are built by CI and update themselves. This is Tauri's
built-in updater: each release publishes signed installers **and** a `latest.json`
manifest; installed apps check that manifest on launch and apply signed updates.

## One-time setup

1. **Generate the updater signing keypair** (on your machine):
   ```bash
   pnpm --filter @sentinel/desktop exec tauri signer generate -w ~/.sentinel-updater.key
   ```
   This prints a **public** key and writes the **private** key to the file.

2. **Paste the public key** into `apps/desktop/src-tauri/tauri.conf.json` →
   `plugins.updater.pubkey` (replacing `REPLACE_WITH_YOUR_UPDATER_PUBLIC_KEY`), commit it.

3. **Add the private key as repo secrets** (GitHub → Settings → Secrets and variables →
   Actions):
   - `TAURI_SIGNING_PRIVATE_KEY` = the contents of `~/.sentinel-updater.key`
   - `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` = the password you set (empty string if none)

4. **Make Releases downloadable by the app.** The updater endpoint
   (`releases/latest/download/latest.json`) must be reachable without auth. The repo can
   stay private, but its **Releases/assets must be public** — or host `latest.json` +
   the artifacts somewhere the app can fetch unauthenticated and point
   `plugins.updater.endpoints` there. (If everything is private, the updater can't fetch
   and you'd update manually by downloading a new installer.)

## Cutting a release

```bash
just release 0.2.0
```

That bumps the version in `tauri.conf.json`, `apps/desktop/package.json`, and the
desktop `Cargo.toml`, commits, tags `v0.2.0`, and pushes the tag. The
[`Release`](../.github/workflows/release.yml) workflow then:

- runs the test gate (server + core tests, interop/version/migration guards) — nothing
  publishes if it's red, because deployed sync servers auto-pull the `:latest` image,
- builds installers on Windows, macOS (universal), and Linux runners,
- signs the update artifacts with your private key,
- assembles everything on a **draft** release, verifies `latest.json` covers all three
  platforms (each with a signature), and only then flips the release public — a failed
  platform build can never publish a partial "latest" that strands one OS.

You can also trigger it manually from the Actions tab (workflow_dispatch).

## Protecting the updater signing key

Installed apps only accept updates signed by the private key matching the `pubkey` pinned
in `tauri.conf.json`. Two failure modes to respect:

- **Loss**: if `TAURI_SIGNING_PRIVATE_KEY` is lost, no future release can be signed in a
  way installed apps accept — auto-update dies permanently and every user must manually
  reinstall. Keep an offline backup of the key file and its password (password manager,
  printed copy — anywhere that isn't only the GitHub secret).
- **Rotation is a TWO-step ceremony.** Never swap the key and the pinned pubkey in one
  release — installed apps verify the new release with the OLD pubkey and reject it,
  stranding everyone. Instead:
  1. Ship a transitional release **signed with the old key** whose only relevant change is
     the new `pubkey` in `tauri.conf.json`. Wait for the fleet to update.
  2. Swap the repo secrets to the new key; subsequent releases are signed with it.

## What the user experiences

- **First install:** download the installer for their OS from the Release page and run
  it. Without an OS code-signing certificate, Windows SmartScreen shows an "unknown
  publisher" prompt and macOS Gatekeeper needs a right-click → Open the first time.
  (That's OS code-signing, which is separate from — and not required by — the updater.)
- **Every launch after that:** the app silently checks `latest.json`; if a newer signed
  version exists it downloads, verifies the signature, installs, and relaunches. There's
  also a **Check for updates** button in Settings.

## Building locally (optional)

On the matching OS you can build an installer without CI:
```bash
pnpm --filter @sentinel/desktop exec tauri build
# → apps/desktop/src-tauri/target/release/bundle/…
```
Linux produces `.deb`/AppImage, Windows `.exe`/`.msi`, macOS `.dmg`/`.app`. Requires the
[Tauri prerequisites](https://tauri.app/start/prerequisites/) for that OS.

## Note on the VPN

The VPN screen runs a built-in **simulation until a Linode API token is added**; once a token
is saved (Settings → Real VPN), Connect provisions a real ephemeral Linode + WireGuard tunnel
and destroys it on disconnect. See [`real-vpn.md`](./real-vpn.md). (Real VPN, real breach check,
browser autofill, Windows Hello, and sync are all wired in the shipped app and gated per-feature;
Windows-specific/live paths ship as documented experimental field-tests since headless CI can't
exercise them.)
