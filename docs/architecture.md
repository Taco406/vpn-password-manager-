# SENTINEL architecture

## Components

```
┌──────────────────────────────────────────────────────────────────────┐
│  Desktop app (Tauri)                                                   │
│  ┌───────────────────────────┐   ┌────────────────────────────────┐   │
│  │ React/TS webview (UI)      │◄─►│ Rust core (sentinel-core)      │   │
│  │  - screens, globe, charts  │   │  - crypto, keyring, vault      │   │
│  │  - SentinelBridge contract │   │  - VPN FSM, provisioning       │   │
│  └───────────────────────────┘   │  - pairing, native messaging   │   │
│         Tauri commands (glue) ────►                                 │   │
│                                    └───────────┬────────────────────┘   │
└────────────────────────────────────────────────┼──────────────────────┘
       ▲ native messaging          ▲ IPC socket   │ HTTPS
       │                           │              ▼
┌──────┴───────┐        ┌──────────┴───────┐   ┌──────────────┐   ┌──────────────┐
│ Chrome ext   │        │ nm-host (stdio)  │   │ Linode API   │   │ sync API     │
│ (MV3)        │        │                  │   │ (ephemeral)  │   │ (Axum + PG)  │
└──────────────┘        └──────────────────┘   └──────────────┘   └──────┬───────┘
                                                                          │ push/relay
                                                                   ┌──────┴───────┐
                                                                   │ iPhone Key   │
                                                                   │ (SwiftUI)    │
                                                                   └──────────────┘
```

## Trust boundaries

- **The desktop Rust core is the crypto authority.** The vault key exists in plaintext
  only inside its `VaultSession`, only while unlocked, and is zeroized on lock.
- **The webview never sees the vault key** — it calls Tauri commands that return only
  the fields it needs (masked by default).
- **The Chrome extension never sees the vault key** — it receives decrypted fields
  per-use, and only after the desktop validates the page origin. While locked it gets
  a `LOCKED` error and holds zero credential data.
- **The sync server is untrusted for confidentiality** — it stores opaque AEAD blobs
  and an encrypted TOTP secret; it can never derive vault plaintext.
- **The iPhone holds a Secure-Enclave key share**, released only after Face ID over
  the pinned E2E pairing channel.

## Local-first

The desktop app and local vault (`crates/core/vault/store.rs`, SQLite) work with **no
account and no server**. The sync API is optional and needed only for multi-device
sync, new-device approval, and iPhone-unlock relay. Onboarding can skip Google entirely.

## The mock substrate

Every OS/cloud/hardware integration is a Rust trait with a real implementation coded to
the actual API (cfg/feature-gated) and a deterministic mock (default). The frontend
targets a `SentinelBridge` interface with a real Tauri bridge and an in-browser mock
seeded from Rust. This is what makes the whole system buildable, testable, and
screenshottable headlessly.

## Platform integrations (real impls documented)

- **Kill switch** — WFP (Windows) / pf (macOS). Blocks all egress except the WG
  endpoint. `crates/core/platform/killswitch.rs`.
- **Biometric wrappers** — Windows Hello (NCrypt/TPM) / Touch ID (Secure Enclave via
  `SecAccessControl`). `crates/core/keyring/platform.rs` (cfg-gated).
- **Secret storage** — OS keychain via the Tauri secure-storage plugin.
- **WireGuard control** — WireGuardNT (Windows) / wireguard-go (macOS).
