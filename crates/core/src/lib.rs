//! # sentinel-core
//!
//! All of SENTINEL's security-critical logic: authenticated encryption, the wrapped
//! vault-key model, the vault item format, TOTP, password generation, health audit,
//! WireGuard config, ephemeral-VPN orchestration, device pairing, and the native
//! messaging protocol. Fully headless and testable — every OS/cloud/hardware
//! integration is a trait with a real implementation and a deterministic mock.
//!
//! See `SECURITY.md` for the threat model and `docs/crypto-spec.md` for the
//! normative parameter table.

pub mod auth;
pub mod cloud;
pub mod crypto;
pub mod error;
pub mod generator;
pub mod health;
pub mod import;
pub mod keyring;
pub mod platform;
pub mod provision;
pub mod recovery_kit;
pub mod seed;
pub mod totp;
pub mod vault;
pub mod vpn;
pub mod wg;

pub use error::{CoreError, Result};
