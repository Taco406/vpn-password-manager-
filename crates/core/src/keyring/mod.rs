//! The wrapped vault-key model (D1). A random 256-bit vault key is generated once
//! and only ever stored *wrapped* by one or more [`KeyWrapper`]s. The key exists in
//! plaintext only in RAM, inside a `VaultSession`, and is zeroized on lock.
//!
//! Wrapped-blob format (normative, docs/crypto-spec.md):
//! ```text
//! "SNTL"(4) | ver=0x01 | wrapper_type u8 | params_len u16 LE | params | nonce(24) | ct(48)
//! ```
//! `ct` is the 32-byte vault key sealed with XChaCha20-Poly1305 (32 + 16 tag = 48),
//! with the entire header (magic … params) as AEAD associated data. Each wrapper
//! derives its 32-byte KEK differently (platform hardware, phone share, recovery key)
//! but the envelope is identical, so blobs are opaque and interchangeable at rest.

pub mod mock;
pub mod phone;
pub mod recovery;

use crate::crypto::{self, Key32};
use crate::error::{CoreError, Result};
use async_trait::async_trait;
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAGIC: &[u8; 4] = b"SNTL";
const VERSION: u8 = 0x01;

/// Which wrapper produced a blob. Encoded as the `wrapper_type` byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapperType {
    /// Wrapper A — platform biometric / TPM / Secure Enclave (daily unlock).
    Platform,
    /// Wrapper B — iPhone companion Secure-Enclave share.
    Phone,
    /// Wrapper C — printed recovery kit (break-glass).
    Recovery,
}

impl WrapperType {
    pub fn code(self) -> u8 {
        match self {
            WrapperType::Platform => 1,
            WrapperType::Phone => 2,
            WrapperType::Recovery => 3,
        }
    }

    pub fn from_code(b: u8) -> Result<Self> {
        match b {
            1 => Ok(WrapperType::Platform),
            2 => Ok(WrapperType::Phone),
            3 => Ok(WrapperType::Recovery),
            other => Err(CoreError::Format {
                what: "wrapped blob",
                detail: format!("unknown wrapper_type {other}"),
            }),
        }
    }
}

/// The 256-bit vault key. Plaintext lives only here, only while unlocked.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultKey(Key32);

impl VaultKey {
    pub fn generate() -> Self {
        VaultKey(Key32::random())
    }

    pub fn from_key(k: Key32) -> Self {
        VaultKey(k)
    }

    pub fn key(&self) -> &Key32 {
        &self.0
    }
}

impl std::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultKey(<redacted>)")
    }
}

/// A serialized wrapped-key blob (the exact bytes stored at rest / synced).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedBlob {
    pub wrapper: WrapperType,
    pub bytes: Vec<u8>,
}

impl WrappedBlob {
    /// Assemble the header (magic … params) that is both a prefix of the blob and the
    /// AEAD associated data.
    fn header(wrapper: WrapperType, params: &[u8]) -> Vec<u8> {
        let mut h = Vec::with_capacity(8 + params.len());
        h.extend_from_slice(MAGIC);
        h.push(VERSION);
        h.push(wrapper.code());
        h.extend_from_slice(&(params.len() as u16).to_le_bytes());
        h.extend_from_slice(params);
        h
    }

    /// Seal a vault key under `kek`, embedding `params` in the header/AAD.
    pub fn seal(wrapper: WrapperType, kek: &Key32, params: &[u8], vk: &VaultKey) -> WrappedBlob {
        let header = Self::header(wrapper, params);
        let (nonce, ct) = crypto::seal(kek, &header, vk.key().as_bytes());
        let mut bytes = header;
        bytes.extend_from_slice(nonce.as_bytes());
        bytes.extend_from_slice(&ct);
        WrappedBlob { wrapper, bytes }
    }

    /// Parse and validate the envelope, returning `(params, nonce, ciphertext)`.
    fn parse(&self) -> Result<(&[u8], crypto::Nonce24, &[u8])> {
        let b = &self.bytes;
        if b.len() < 8 {
            return Err(CoreError::Format {
                what: "wrapped blob",
                detail: "too short".into(),
            });
        }
        if &b[0..4] != MAGIC {
            return Err(CoreError::Format {
                what: "wrapped blob",
                detail: "bad magic".into(),
            });
        }
        if b[4] != VERSION {
            return Err(CoreError::Format {
                what: "wrapped blob",
                detail: format!("unsupported version {}", b[4]),
            });
        }
        let wt = WrapperType::from_code(b[5])?;
        if wt != self.wrapper {
            return Err(CoreError::Format {
                what: "wrapped blob",
                detail: "wrapper_type mismatch".into(),
            });
        }
        let params_len = u16::from_le_bytes([b[6], b[7]]) as usize;
        let header_end = 8 + params_len;
        // header + 24 nonce + 48 ct
        if b.len() != header_end + 24 + 48 {
            return Err(CoreError::Format {
                what: "wrapped blob",
                detail: "bad length".into(),
            });
        }
        let params = &b[8..header_end];
        let mut nb = [0u8; 24];
        nb.copy_from_slice(&b[header_end..header_end + 24]);
        let nonce = crypto::Nonce24::from_bytes(nb);
        let ct = &b[header_end + 24..];
        Ok((params, nonce, ct))
    }

    /// Return the `params` bytes embedded in the header (e.g. the Argon2 salt).
    pub fn params(&self) -> Result<Vec<u8>> {
        let (params, _, _) = self.parse()?;
        Ok(params.to_vec())
    }

    /// Open the blob given the KEK the wrapper derived. AAD is the header prefix.
    pub fn open(&self, kek: &Key32) -> Result<VaultKey> {
        let (_, nonce, ct) = self.parse()?;
        let header_end = self.bytes.len() - 24 - 48;
        let header = &self.bytes[..header_end];
        let pt = crypto::open(kek, header, &nonce, ct)?;
        let mut arr = [0u8; 32];
        if pt.as_slice().len() != 32 {
            return Err(CoreError::Format {
                what: "wrapped blob",
                detail: "unwrapped key not 32 bytes".into(),
            });
        }
        arr.copy_from_slice(pt.as_slice());
        Ok(VaultKey::from_key(Key32::from_bytes(arr)))
    }
}

/// A means of wrapping/unwrapping the vault key. Every OS/hardware/phone integration
/// implements this; tests and the demo use deterministic mocks. Object-safe so the
/// keyring can hold `Arc<dyn KeyWrapper>`.
#[async_trait]
pub trait KeyWrapper: Send + Sync {
    fn wrapper_type(&self) -> WrapperType;

    /// Wrap the vault key. May prompt hardware / the phone (hence async).
    async fn wrap(&self, vk: &VaultKey) -> Result<WrappedBlob>;

    /// Unwrap a previously produced blob. Returns [`CoreError::Unauthorized`] if the
    /// user declines a biometric / the phone denies the request.
    async fn unwrap(&self, blob: &WrappedBlob) -> Result<VaultKey>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trip_and_shape() {
        let kek = Key32::random();
        let vk = VaultKey::generate();
        let params = [7u8; 16];
        let blob = WrappedBlob::seal(WrapperType::Recovery, &kek, &params, &vk);

        // Shape: 8 header + 16 params + 24 nonce + 48 ct = 96 bytes.
        assert_eq!(blob.bytes.len(), 8 + 16 + 24 + 48);
        assert_eq!(&blob.bytes[0..4], MAGIC);
        assert_eq!(blob.bytes[5], WrapperType::Recovery.code());
        assert_eq!(blob.params().unwrap(), params);

        let got = blob.open(&kek).unwrap();
        assert_eq!(got.key().as_bytes(), vk.key().as_bytes());
    }

    #[test]
    fn wrong_kek_fails_to_open() {
        let kek = Key32::random();
        let vk = VaultKey::generate();
        let blob = WrappedBlob::seal(WrapperType::Platform, &kek, &[], &vk);
        assert_eq!(blob.bytes.len(), 8 + 24 + 48);
        assert!(matches!(
            blob.open(&Key32::random()),
            Err(CoreError::Decrypt)
        ));
    }

    #[test]
    fn tampered_params_fail_aead() {
        let kek = Key32::random();
        let vk = VaultKey::generate();
        let mut blob = WrappedBlob::seal(WrapperType::Recovery, &kek, &[1u8; 16], &vk);
        blob.bytes[8] ^= 0xFF; // flip a params byte → AAD mismatch
        assert!(matches!(blob.open(&kek), Err(CoreError::Decrypt)));
    }

    #[test]
    fn rejects_bad_magic_and_length() {
        let bad = WrappedBlob {
            wrapper: WrapperType::Recovery,
            bytes: b"XXXX".to_vec(),
        };
        assert!(bad.open(&Key32::random()).is_err());
    }
}
