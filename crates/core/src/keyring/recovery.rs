//! Wrapper C — the printed recovery kit. The KEK is derived from the 128-bit
//! recovery key with Argon2id (slow, since the recovery key is the one low-entropy
//! input an attacker could grind) then HKDF for domain separation.

use super::{KeyWrapper, VaultKey, WrappedBlob, WrapperType};
use crate::crypto::{argon2id_kek, hkdf32, Argon2Profile, Info};
use crate::error::Result;
use crate::recovery_kit::RecoveryKey;
use async_trait::async_trait;
use rand::RngCore;

/// Wraps/unwraps the vault key using a recovery key. The Argon2 salt is stored in the
/// blob's `params`, so a fresh salt is used per wrap and recovery only needs the key.
pub struct RecoveryWrapper {
    key: RecoveryKey,
    profile: Argon2Profile,
}

impl RecoveryWrapper {
    /// Build with the environment-selected Argon2 profile (Production unless a test
    /// explicitly opts into the fast profile).
    pub fn new(key: RecoveryKey) -> Self {
        RecoveryWrapper {
            key,
            profile: Argon2Profile::from_env_or_production(),
        }
    }

    /// Build with an explicit profile (used by fast unit tests).
    pub fn with_profile(key: RecoveryKey, profile: Argon2Profile) -> Self {
        RecoveryWrapper { key, profile }
    }

    fn derive_kek(&self, salt: &[u8; 16]) -> crate::crypto::Key32 {
        let stretched = argon2id_kek(self.key.as_bytes(), salt, self.profile);
        hkdf32(stretched.as_bytes(), None, Info::WrapRecovery)
    }
}

#[async_trait]
impl KeyWrapper for RecoveryWrapper {
    fn wrapper_type(&self) -> WrapperType {
        WrapperType::Recovery
    }

    async fn wrap(&self, vk: &VaultKey) -> Result<WrappedBlob> {
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let kek = self.derive_kek(&salt);
        Ok(WrappedBlob::seal(WrapperType::Recovery, &kek, &salt, vk))
    }

    async fn unwrap(&self, blob: &WrappedBlob) -> Result<VaultKey> {
        let params = blob.params()?;
        let mut salt = [0u8; 16];
        if params.len() != 16 {
            return Err(crate::error::CoreError::Format {
                what: "recovery blob",
                detail: "params must be a 16-byte salt".into(),
            });
        }
        salt.copy_from_slice(&params);
        let kek = self.derive_kek(&salt);
        blob.open(&kek)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn recovery_round_trip() {
        let rk = RecoveryKey::random();
        let vk = VaultKey::generate();
        let w = RecoveryWrapper::with_profile(rk.clone(), Argon2Profile::Test);
        let blob = w.wrap(&vk).await.unwrap();
        let got = w.unwrap(&blob).await.unwrap();
        assert_eq!(got.key().as_bytes(), vk.key().as_bytes());
    }

    #[tokio::test]
    async fn wrong_recovery_key_fails() {
        let vk = VaultKey::generate();
        let good = RecoveryWrapper::with_profile(RecoveryKey::random(), Argon2Profile::Test);
        let blob = good.wrap(&vk).await.unwrap();
        let bad = RecoveryWrapper::with_profile(RecoveryKey::random(), Argon2Profile::Test);
        assert!(bad.unwrap(&blob).await.is_err());
    }

    #[tokio::test]
    async fn each_wrap_uses_fresh_salt() {
        let rk = RecoveryKey::random();
        let vk = VaultKey::generate();
        let w = RecoveryWrapper::with_profile(rk, Argon2Profile::Test);
        let a = w.wrap(&vk).await.unwrap();
        let b = w.wrap(&vk).await.unwrap();
        assert_ne!(a.params().unwrap(), b.params().unwrap(), "salt must differ");
        assert_ne!(a.bytes, b.bytes);
    }
}
