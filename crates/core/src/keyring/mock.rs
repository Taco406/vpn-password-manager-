//! Wrapper A (mock) — a deterministic stand-in for a platform biometric / TPM /
//! Secure-Enclave-backed key, used by tests and the in-browser demo.
//!
//! The real implementation (see `platform.rs`, cfg-gated to Windows/macOS) wraps the
//! vault key with a non-exportable hardware key released by Windows Hello / Touch ID.
//! This mock models the *authorization gate*: a KEK is held in memory (as a real TPM
//! key would be), but `unwrap` fails with `Unauthorized` unless a biometric approval
//! has been simulated — exactly the state machine the UI drives.

use super::{KeyWrapper, VaultKey, WrappedBlob, WrapperType};
use crate::crypto::Key32;
use crate::error::{CoreError, Result};
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A mock platform wrapper. Clone-shares the approval flag and KEK so the UI/tests can
/// call [`MockBiometricWrapper::approve`] on one handle and unwrap on another.
#[derive(Clone)]
pub struct MockBiometricWrapper {
    kek: Arc<Key32>,
    approved: Arc<AtomicBool>,
    /// If true, `unwrap` consumes the approval (single-use, like a real prompt).
    consume: bool,
}

impl Default for MockBiometricWrapper {
    fn default() -> Self {
        Self::new()
    }
}

impl MockBiometricWrapper {
    /// New wrapper with a random device-bound KEK and no standing approval.
    pub fn new() -> Self {
        MockBiometricWrapper {
            kek: Arc::new(Key32::random()),
            approved: Arc::new(AtomicBool::new(false)),
            consume: true,
        }
    }

    /// Simulate a successful biometric prompt (the user touched the sensor).
    pub fn approve(&self) {
        self.approved.store(true, Ordering::SeqCst);
    }

    /// Simulate a declined / cancelled prompt.
    pub fn deny(&self) {
        self.approved.store(false, Ordering::SeqCst);
    }

    /// For tests: pre-authorize and keep the approval (don't consume on unwrap).
    pub fn always_approved() -> Self {
        MockBiometricWrapper {
            kek: Arc::new(Key32::random()),
            approved: Arc::new(AtomicBool::new(true)),
            consume: false,
        }
    }

    fn check_authorized(&self) -> Result<()> {
        let ok = if self.consume {
            self.approved.swap(false, Ordering::SeqCst)
        } else {
            self.approved.load(Ordering::SeqCst)
        };
        if ok {
            Ok(())
        } else {
            Err(CoreError::Unauthorized("biometric prompt not approved"))
        }
    }
}

#[async_trait]
impl KeyWrapper for MockBiometricWrapper {
    fn wrapper_type(&self) -> WrapperType {
        WrapperType::Platform
    }

    async fn wrap(&self, vk: &VaultKey) -> Result<WrappedBlob> {
        // Enrolling a biometric wrapper requires a live user presence too.
        self.check_authorized()?;
        Ok(WrappedBlob::seal(WrapperType::Platform, &self.kek, &[], vk))
    }

    async fn unwrap(&self, blob: &WrappedBlob) -> Result<VaultKey> {
        self.check_authorized()?;
        blob.open(&self.kek)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn approved_round_trip() {
        let w = MockBiometricWrapper::always_approved();
        let vk = VaultKey::generate();
        let blob = w.wrap(&vk).await.unwrap();
        let got = w.unwrap(&blob).await.unwrap();
        assert_eq!(got.key().as_bytes(), vk.key().as_bytes());
    }

    #[tokio::test]
    async fn unwrap_requires_approval() {
        let w = MockBiometricWrapper::new();
        w.approve();
        let vk = VaultKey::generate();
        let blob = w.wrap(&vk).await.unwrap(); // consumes the approval

        // No standing approval now → unwrap must be Unauthorized.
        assert!(matches!(
            w.unwrap(&blob).await,
            Err(CoreError::Unauthorized(_))
        ));

        // Approve again → unwrap succeeds.
        w.approve();
        let got = w.unwrap(&blob).await.unwrap();
        assert_eq!(got.key().as_bytes(), vk.key().as_bytes());
    }

    #[tokio::test]
    async fn denied_prompt_blocks_unwrap() {
        let w = MockBiometricWrapper::always_approved();
        let vk = VaultKey::generate();
        let blob = w.wrap(&vk).await.unwrap();
        w.deny();
        assert!(w.unwrap(&blob).await.is_err());
    }
}
