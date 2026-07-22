//! Wrapper D — a user master password. The KEK is derived from the password with Argon2id (slow,
//! since a password is the low-entropy input an attacker would grind); the 16-byte salt travels in
//! the blob's `params`, so a fresh salt is used per wrap and only the password is needed to unwrap.
//!
//! This derivation is **byte-identical to the desktop app's local master-password wrap**
//! (`apps/desktop/.../applock.rs`): `KEK = argon2id_kek(password, salt)` used directly, with no
//! extra HKDF step. That means the very same blob works both on local disk and escrowed on the sync
//! server, so a second device can unwrap it with the same master password (multi-device unlock).

use super::{KeyWrapper, VaultKey, WrappedBlob, WrapperType};
use crate::crypto::{argon2id_kek, Argon2Profile, Key32};
use crate::error::{CoreError, Result};
use async_trait::async_trait;
use rand::RngCore;
use zeroize::Zeroizing;

/// Wraps/unwraps the vault key using a master password.
pub struct PasswordWrapper {
    password: Zeroizing<Vec<u8>>,
    profile: Argon2Profile,
}

impl PasswordWrapper {
    /// Build with the environment-selected Argon2 profile (Production unless a test opts into fast).
    pub fn new(password: &str) -> Self {
        PasswordWrapper {
            password: Zeroizing::new(password.as_bytes().to_vec()),
            profile: Argon2Profile::from_env_or_production(),
        }
    }

    /// Build with an explicit profile (used by fast unit tests).
    pub fn with_profile(password: &str, profile: Argon2Profile) -> Self {
        PasswordWrapper {
            password: Zeroizing::new(password.as_bytes().to_vec()),
            profile,
        }
    }

    fn derive_kek(&self, salt: &[u8; 16]) -> Key32 {
        // Argon2id output used directly as the KEK — matches applock.rs (no HKDF), so blobs interop.
        argon2id_kek(self.password.as_slice(), salt, self.profile)
    }
}

#[async_trait]
impl KeyWrapper for PasswordWrapper {
    fn wrapper_type(&self) -> WrapperType {
        WrapperType::Password
    }

    async fn wrap(&self, vk: &VaultKey) -> Result<WrappedBlob> {
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let kek = self.derive_kek(&salt);
        Ok(WrappedBlob::seal(WrapperType::Password, &kek, &salt, vk))
    }

    async fn unwrap(&self, blob: &WrappedBlob) -> Result<VaultKey> {
        let params = blob.params()?;
        if params.len() != 16 {
            return Err(CoreError::Format {
                what: "password blob",
                detail: "params must be a 16-byte salt".into(),
            });
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&params);
        let kek = self.derive_kek(&salt);
        blob.open(&kek)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn password_round_trip() {
        let vk = VaultKey::generate();
        let w = PasswordWrapper::with_profile("correct horse battery staple", Argon2Profile::Test);
        let blob = w.wrap(&vk).await.unwrap();
        assert_eq!(blob.wrapper, WrapperType::Password);
        assert_eq!(blob.bytes[5], WrapperType::Password.code()); // 4
        let got = w.unwrap(&blob).await.unwrap();
        assert_eq!(got.key().as_bytes(), vk.key().as_bytes());
    }

    #[tokio::test]
    async fn wrong_password_fails() {
        let vk = VaultKey::generate();
        let good = PasswordWrapper::with_profile("hunter2", Argon2Profile::Test);
        let blob = good.wrap(&vk).await.unwrap();
        let bad = PasswordWrapper::with_profile("hunter3", Argon2Profile::Test);
        assert!(bad.unwrap(&blob).await.is_err());
    }

    #[tokio::test]
    async fn each_wrap_uses_fresh_salt() {
        let vk = VaultKey::generate();
        let w = PasswordWrapper::with_profile("pw", Argon2Profile::Test);
        let a = w.wrap(&vk).await.unwrap();
        let b = w.wrap(&vk).await.unwrap();
        assert_ne!(a.params().unwrap(), b.params().unwrap(), "salt must differ");
        assert_ne!(a.bytes, b.bytes);
    }

    /// The blob is the canonical 96-byte SNTL envelope the server escrow accepts (80..512 bound).
    #[tokio::test]
    async fn blob_is_canonical_shape() {
        let vk = VaultKey::generate();
        let w = PasswordWrapper::with_profile("pw", Argon2Profile::Test);
        let blob = w.wrap(&vk).await.unwrap();
        assert_eq!(blob.bytes.len(), 8 + 16 + 24 + 48);
        assert_eq!(&blob.bytes[0..4], b"SNTL");
    }
}
