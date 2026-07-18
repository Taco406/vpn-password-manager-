//! Wrapper B — the iPhone companion. The vault key is wrapped with a KEK derived
//! from a 256-bit *share* that lives in the phone's Secure Enclave and is released
//! only after Face ID, delivered over the E2E channel established at pairing.
//!
//! The desktop never persists the share: it generates one at pairing, wraps with it,
//! sends it to the phone, and forgets it. To unlock later it asks the phone (via the
//! [`UnlockRelay`]) to release the share again. Here the relay is abstracted; the mock
//! models the phone's Enclave + Face ID gate. The real relay (HTTP long-poll to the
//! sync API + the pinned pairing channel) lands in Phase 6.

use super::{KeyWrapper, VaultKey, WrappedBlob, WrapperType};
use crate::crypto::{hkdf32, Info, SecretBytes};
use crate::error::{CoreError, Result};
use async_trait::async_trait;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Abstracts the phone side of the share lifecycle. In production every payload is
/// opaque E2E ciphertext; the relay just moves bytes.
#[async_trait]
pub trait UnlockRelay: Send + Sync {
    /// Pairing/enroll: hand a freshly generated share to the phone to hold in its
    /// Secure Enclave. Called once per wrap.
    async fn provision_share(&self, pairing_id: &[u8; 16], share: &[u8; 32]) -> Result<()>;

    /// Unlock: ask the phone to release the share (push → Face ID → E2E). Returns the
    /// share bytes, or [`CoreError::Unauthorized`] if denied or timed out.
    async fn request_share(&self, pairing_id: &[u8; 16]) -> Result<SecretBytes>;
}

/// Phone-companion key wrapper. `params` in the blob carries the 16-byte pairing id.
pub struct PhoneShareWrapper {
    pairing_id: [u8; 16],
    relay: Arc<dyn UnlockRelay>,
}

impl PhoneShareWrapper {
    pub fn new(pairing_id: [u8; 16], relay: Arc<dyn UnlockRelay>) -> Self {
        PhoneShareWrapper { pairing_id, relay }
    }

    fn derive_kek(&self, share: &[u8]) -> crate::crypto::Key32 {
        hkdf32(share, Some(&self.pairing_id), Info::WrapPhoneShare)
    }
}

#[async_trait]
impl KeyWrapper for PhoneShareWrapper {
    fn wrapper_type(&self) -> WrapperType {
        WrapperType::Phone
    }

    async fn wrap(&self, vk: &VaultKey) -> Result<WrappedBlob> {
        let mut share = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut share);
        self.relay.provision_share(&self.pairing_id, &share).await?;
        let kek = self.derive_kek(&share);
        let blob = WrappedBlob::seal(WrapperType::Phone, &kek, &self.pairing_id, vk);
        // The desktop must not retain the share.
        use zeroize::Zeroize;
        share.zeroize();
        Ok(blob)
    }

    async fn unwrap(&self, blob: &WrappedBlob) -> Result<VaultKey> {
        let params = blob.params()?;
        if params.as_slice() != self.pairing_id {
            return Err(CoreError::Format {
                what: "phone blob",
                detail: "pairing id mismatch".into(),
            });
        }
        let share = self.relay.request_share(&self.pairing_id).await?;
        let kek = self.derive_kek(share.as_slice());
        blob.open(&kek)
    }
}

/// A deterministic in-memory relay modeling the phone's Enclave + Face ID gate. Used
/// by tests and the demo. `approved` mirrors "the user completed Face ID".
#[derive(Clone, Default)]
pub struct MockRelay {
    store: Arc<Mutex<HashMap<[u8; 16], [u8; 32]>>>,
    approved: Arc<AtomicBool>,
}

impl MockRelay {
    /// A relay that auto-approves unlock requests (Face ID always succeeds).
    pub fn approving() -> Self {
        MockRelay {
            store: Arc::new(Mutex::new(HashMap::new())),
            approved: Arc::new(AtomicBool::new(true)),
        }
    }

    /// A relay that denies unlock requests (Face ID declined / phone unavailable).
    pub fn denying() -> Self {
        MockRelay {
            store: Arc::new(Mutex::new(HashMap::new())),
            approved: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn set_approved(&self, v: bool) {
        self.approved.store(v, Ordering::SeqCst);
    }
}

#[async_trait]
impl UnlockRelay for MockRelay {
    async fn provision_share(&self, pairing_id: &[u8; 16], share: &[u8; 32]) -> Result<()> {
        self.store.lock().unwrap().insert(*pairing_id, *share);
        Ok(())
    }

    async fn request_share(&self, pairing_id: &[u8; 16]) -> Result<SecretBytes> {
        if !self.approved.load(Ordering::SeqCst) {
            return Err(CoreError::Unauthorized("phone denied the unlock request"));
        }
        let guard = self.store.lock().unwrap();
        let share = guard
            .get(pairing_id)
            .ok_or_else(|| CoreError::NotFound("no share for this pairing".into()))?;
        Ok(SecretBytes::new(share.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid() -> [u8; 16] {
        [0x5A; 16]
    }

    #[tokio::test]
    async fn phone_round_trip_when_approved() {
        let relay = Arc::new(MockRelay::approving());
        let w = PhoneShareWrapper::new(pid(), relay);
        let vk = VaultKey::generate();
        let blob = w.wrap(&vk).await.unwrap();
        assert_eq!(blob.params().unwrap(), pid());
        let got = w.unwrap(&blob).await.unwrap();
        assert_eq!(got.key().as_bytes(), vk.key().as_bytes());
    }

    #[tokio::test]
    async fn denied_face_id_blocks_unwrap() {
        let relay = Arc::new(MockRelay::approving());
        let w = PhoneShareWrapper::new(pid(), relay.clone());
        let vk = VaultKey::generate();
        let blob = w.wrap(&vk).await.unwrap();
        relay.set_approved(false);
        assert!(matches!(
            w.unwrap(&blob).await,
            Err(CoreError::Unauthorized(_))
        ));
    }

    #[tokio::test]
    async fn pairing_id_is_bound() {
        let relay = Arc::new(MockRelay::approving());
        let w = PhoneShareWrapper::new(pid(), relay.clone());
        let vk = VaultKey::generate();
        let blob = w.wrap(&vk).await.unwrap();

        // A wrapper for a different pairing must refuse this blob.
        let other = PhoneShareWrapper::new([0x11; 16], relay);
        assert!(other.unwrap(&blob).await.is_err());
    }
}
