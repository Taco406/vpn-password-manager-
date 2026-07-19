# SENTINEL

**Personal security suite — on-demand ephemeral WireGuard VPN + zero-knowledge password
manager.** One desktop app, one Chrome extension, one iPhone companion key, one
lightweight sync backend. Single-user / family. Local-first: the vault and VPN work
fully offline with no account; the server is optional.

> This repository is a from-scratch build against the SENTINEL v1 brief. The crypto,
> vault, VPN control plane, and sync API are real and tested. Platform integrations that
> require hardware/cloud/OS access the CI box doesn't have (biometrics, WireGuard kernel,
> Linode, Apple Secure Enclave) sit behind traits with a real implementation coded to the
> actual API **and** a deterministic mock used for tests and the in-browser demo. See
> [`DECISIONS.md`](DECISIONS.md) and [`SECURITY.md`](SECURITY.md).

## What it does

- **Vault** — logins, secure notes, cards, identities. Per-item XChaCha20-Poly1305,
  keys separated by HKDF from a random 256-bit vault key that is **never** stored
  unwrapped. Command-palette-first UI, password generator (charset + EFF passphrase),
  health audit (reused / weak / old + HIBP k-anonymity breach check), clipboard
  auto-clear, auto-lock, Bitwarden/Chrome import, encrypted export.
- **VPN** — pick a region, an ephemeral Linode is created on connect and destroyed on
  disconnect (nothing left billing). WireGuard only. Kill switch, connection profiles,
  live throughput + server-vitals charts, session history, monthly report card. Real exit
  nodes are **opt-in** (paste a Linode token in Settings) — see
  [`docs/real-vpn.md`](docs/real-vpn.md); without a token the VPN runs a built-in simulation.
- **No master password** — the vault key is wrapped by (A) your device's biometric /
  TPM, (B) your paired iPhone's Secure Enclave, and (C) a one-time printable recovery
  kit. Lose all three and the vault is gone — by design.

## The key model in one picture

```
        256-bit vault key (random, in RAM only while unlocked)
                 │  wrapped, never stored in the clear
      ┌──────────┼───────────────┬─────────────────────────┐
  Wrapper A               Wrapper B                    Wrapper C
  platform biometric      iPhone Secure Enclave        recovery kit (printed)
  (TPM / Secure Enclave)  share, released after         SNTL-XXXXX-… + QR
  daily unlock            Face ID over E2E channel      break-glass
```

The sync server stores only wrapped blobs and opaque vault ciphertext. A full server
dump plus a compromised Google account still cannot decrypt anything — enforced
structurally and tested (`structural_zero_knowledge`).

## Repository layout

```
crates/core        sentinel-core — ALL crypto & orchestration (headless, fully tested)
crates/cli         sentinel-cli  — seed demo data, render recovery PDF, run mock flows
crates/nm-host     native-messaging host bridging Chrome ⇄ desktop
services/api       sentinel-api  — Axum + Postgres sync backend (zero-knowledge schema)
apps/desktop       Tauri + React/TS UI (runs standalone in a browser via a mock bridge)
apps/extension     Chrome MV3 extension
apps/ios-key       SwiftUI companion (source + build docs; not compiled in CI)
packages/shared    TypeScript types + the SentinelBridge contract + seeded demo data
docs/              architecture, crypto spec, native-messaging, pairing ceremony
showcase/          full-resolution screenshots of every app (seeded data, both themes)
```

## Quickstart (development)

Prerequisites: Rust 1.94, Node 22 + pnpm 10, PostgreSQL 16, and [`just`](https://github.com/casey/just).

```bash
just setup            # pnpm install + cargo fetch
just db-up            # local Postgres dev cluster on 127.0.0.1:5433
just db-migrate       # apply the schema
just test-rust        # crypto/vault/vpn unit tests (no GUI, no network)
just test-api         # API tests against the local cluster
just dev-web          # the desktop UI in a browser, driven by the mock bridge
just screenshots      # regenerate /showcase (both themes, seeded data)
just ci               # everything CI runs
```

The desktop UI opens against the **mock bridge** by default in a browser, so you can
click through onboarding, the vault, and the VPN connect sequence with realistic seeded
data without any cloud account or the Tauri binary. Build the real desktop app with
`pnpm --filter @sentinel/desktop tauri build` (needs the platform WebView + toolchain).

## Install & auto-update

**New here?** Start with the [**Setup & required-downloads guide**](docs/setup.md) — one page
covering the installer plus what each optional feature needs (WireGuard, Linode, the browser
extension, sync server), with costs and admin requirements.

Installers (Windows `.exe`/`.msi`, macOS `.dmg`, Linux `.deb`/AppImage) are built by CI
and attached to GitHub Releases. Push a tag and the [`Release`](.github/workflows/release.yml)
workflow builds all three on their own runners:

```bash
just release 0.2.0     # bumps version, tags v0.2.0, pushes → CI publishes the Release
```

Installed apps **update themselves**: SENTINEL uses Tauri's signed updater, so on launch
it checks the latest Release's `latest.json`, and applies any newer signed version
(there's also a *Check for updates* button in Settings). One-time setup (generating the
updater signing key + adding it as a repo secret) is in
[`docs/releasing.md`](docs/releasing.md).

## Running the sync server (optional)

The app is local-first; you only need the server for multi-device sync, new-device
approval, and iPhone-unlock relay. See [`docs/self-hosting.md`](docs/self-hosting.md)
for running `services/api` on a small VPS or home box (systemd + Postgres).

## iOS companion

`apps/ios-key` is complete SwiftUI source plus setup docs. Building it needs a Mac, Xcode,
and an Apple Developer account ($99/yr) for push + device provisioning — see
[`apps/ios-key/README.md`](apps/ios-key/README.md).

## Security

Read [`SECURITY.md`](SECURITY.md) for the full threat model. Short version: a stolen app
binary has no secrets in it, a stolen vault file is opaque ciphertext, and the server
plus your Google account together still can't decrypt your vault.

## License

MIT — see [`LICENSE`](LICENSE).
