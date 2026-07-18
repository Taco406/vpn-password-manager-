//! Crate-wide error type.
//!
//! Invariant (SECURITY.md T8): a `CoreError` must never carry secret material in
//! its `Display`. Variants hold only non-sensitive context (algorithm names, sizes,
//! item ids), never keys, passwords, or plaintext.

use thiserror::Error;

/// The result type used throughout `sentinel-core`.
pub type Result<T> = std::result::Result<T, CoreError>;

#[derive(Debug, Error)]
pub enum CoreError {
    /// AEAD open failed: wrong key or tampered ciphertext. Deliberately opaque —
    /// callers must not be able to distinguish the two (padding-oracle hygiene).
    #[error("decryption failed (wrong key or corrupted data)")]
    Decrypt,

    /// A serialized blob did not match the expected magic/version/length.
    #[error("malformed {what}: {detail}")]
    Format { what: &'static str, detail: String },

    /// A recovery key / code failed its checksum or challenge.
    #[error("invalid recovery key")]
    InvalidRecoveryKey,

    /// A wrapper could not release the key (e.g. biometric declined, phone denied).
    #[error("key unwrap was not authorized: {0}")]
    Unauthorized(&'static str),

    /// Requested item / entity does not exist.
    #[error("not found: {0}")]
    NotFound(String),

    /// A precondition on state was violated (e.g. operating on a locked vault).
    #[error("invalid state: {0}")]
    State(&'static str),

    /// A VPN provisioning step failed. `stage` is a non-secret label.
    #[error("provisioning failed at {stage}: {detail}")]
    Provision { stage: &'static str, detail: String },

    /// Input validation failure (bad URL, out-of-range parameter, …).
    #[error("invalid input: {0}")]
    Invalid(String),

    /// Wrapped I/O error.
    #[error("io error: {0}")]
    Io(String),

    /// Wrapped serialization error.
    #[error("serialization error: {0}")]
    Serde(String),

    /// Wrapped storage (SQLite) error.
    #[error("storage error: {0}")]
    Storage(String),

    /// Wrapped network error (never includes request bodies).
    #[error("network error: {0}")]
    Network(String),
}

impl From<std::io::Error> for CoreError {
    fn from(e: std::io::Error) -> Self {
        CoreError::Io(e.to_string())
    }
}

impl From<serde_json::Error> for CoreError {
    fn from(e: serde_json::Error) -> Self {
        CoreError::Serde(e.to_string())
    }
}

impl From<rusqlite::Error> for CoreError {
    fn from(e: rusqlite::Error) -> Self {
        CoreError::Storage(e.to_string())
    }
}
