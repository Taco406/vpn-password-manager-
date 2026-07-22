//! File-transfer blobs: a file sealed as one opaque, self-describing ciphertext for the
//! "send to my devices" relay. The server only ever stores and expires these bytes — it
//! never sees the plaintext, the filename, or any key.
//!
//! File blob (normative):
//! ```text
//! "SFIL"(4) | 0x01 | 0x00 0x00 0x00 | salt(16) | nonce(24) | ct
//! ```
//! - plaintext = `meta_len(u32 LE) | meta_json | file_bytes`, then zstd(level 3).
//! - `meta_json` = JSON of [`FileMeta`] (filename + mime — themselves sensitive, so sealed
//!   inside the blob, never sent as cleartext columns).
//! - AAD = header(8) ‖ salt(16); key = `HKDF(vault_key, salt, "sentinel/v1/file/blob")`.
//!
//! The salt is random per file and travels in the blob, so every transfer gets a distinct
//! key with no key exchange: any of the user's devices holding the same `vault_key` opens it.

use crate::crypto::{self, hkdf32, Info, Nonce24};
use crate::error::{CoreError, Result};
use crate::keyring::VaultKey;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};

const MAGIC: &[u8; 4] = b"SFIL";
const VERSION: u8 = 0x01;
const HDR_LEN: usize = 8;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

/// Non-secret-to-the-owner file metadata, sealed inside the blob (the server never sees it).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMeta {
    pub filename: String,
    pub mime: String,
}

fn header() -> Vec<u8> {
    let mut h = Vec::with_capacity(HDR_LEN);
    h.extend_from_slice(MAGIC);
    h.push(VERSION);
    h.extend_from_slice(&[0, 0, 0]);
    h
}

/// Seal a file (with its metadata) into a transfer blob under the vault key.
pub fn seal_file(vk: &VaultKey, meta: &FileMeta, data: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);

    let meta_json = serde_json::to_vec(meta)?;
    let mut plaintext = Vec::with_capacity(4 + meta_json.len() + data.len());
    plaintext.extend_from_slice(&(meta_json.len() as u32).to_le_bytes());
    plaintext.extend_from_slice(&meta_json);
    plaintext.extend_from_slice(data);

    let compressed =
        zstd::encode_all(plaintext.as_slice(), 3).map_err(|e| CoreError::Io(e.to_string()))?;

    let hdr = header();
    let mut aad = hdr.clone();
    aad.extend_from_slice(&salt);

    let key = hkdf32(vk.key().as_bytes(), Some(&salt), Info::FileTransfer);
    let (nonce, ct) = crypto::seal(&key, &aad, &compressed);

    let mut out = hdr;
    out.extend_from_slice(&salt);
    out.extend_from_slice(nonce.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a transfer blob back into its metadata and file bytes.
pub fn open_file(vk: &VaultKey, bytes: &[u8]) -> Result<(FileMeta, Vec<u8>)> {
    if bytes.len() < HDR_LEN + SALT_LEN + NONCE_LEN {
        return Err(CoreError::Format {
            what: "file blob",
            detail: "too short".into(),
        });
    }
    if &bytes[0..4] != MAGIC || bytes[4] != VERSION {
        return Err(CoreError::Format {
            what: "file blob",
            detail: "bad magic/version".into(),
        });
    }
    let hdr = &bytes[..HDR_LEN];
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[HDR_LEN..HDR_LEN + SALT_LEN]);
    let mut nb = [0u8; NONCE_LEN];
    nb.copy_from_slice(&bytes[HDR_LEN + SALT_LEN..HDR_LEN + SALT_LEN + NONCE_LEN]);
    let nonce = Nonce24::from_bytes(nb);
    let ct = &bytes[HDR_LEN + SALT_LEN + NONCE_LEN..];

    let mut aad = hdr.to_vec();
    aad.extend_from_slice(&salt);

    let key = hkdf32(vk.key().as_bytes(), Some(&salt), Info::FileTransfer);
    let pt = crypto::open(&key, &aad, &nonce, ct)?;
    let plain = zstd::decode_all(pt.as_slice()).map_err(|e| CoreError::Io(e.to_string()))?;

    if plain.len() < 4 {
        return Err(CoreError::Format {
            what: "file blob",
            detail: "no metadata length".into(),
        });
    }
    let meta_len = u32::from_le_bytes([plain[0], plain[1], plain[2], plain[3]]) as usize;
    if plain.len() < 4 + meta_len {
        return Err(CoreError::Format {
            what: "file blob",
            detail: "metadata truncated".into(),
        });
    }
    let meta: FileMeta = serde_json::from_slice(&plain[4..4 + meta_len])?;
    let data = plain[4 + meta_len..].to_vec();
    Ok((meta, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> FileMeta {
        FileMeta {
            filename: "report.pdf".into(),
            mime: "application/pdf".into(),
        }
    }

    #[test]
    fn round_trip() {
        let vk = VaultKey::generate();
        let data = vec![7u8; 4096];
        let blob = seal_file(&vk, &meta(), &data).unwrap();
        let (m, back) = open_file(&vk, &blob).unwrap();
        assert_eq!(m, meta());
        assert_eq!(back, data);
    }

    #[test]
    fn empty_and_large_files_round_trip() {
        let vk = VaultKey::generate();
        for len in [0usize, 1, 1024, 1_000_003] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let blob = seal_file(&vk, &meta(), &data).unwrap();
            let (_m, back) = open_file(&vk, &blob).unwrap();
            assert_eq!(back.len(), len);
            assert_eq!(back, data);
        }
    }

    #[test]
    fn wrong_key_fails() {
        let vk = VaultKey::generate();
        let blob = seal_file(&vk, &meta(), b"hello").unwrap();
        assert!(open_file(&VaultKey::generate(), &blob).is_err());
    }

    #[test]
    fn tamper_fails() {
        let vk = VaultKey::generate();
        let mut blob = seal_file(&vk, &meta(), b"hello").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(matches!(open_file(&vk, &blob), Err(CoreError::Decrypt)));
    }

    #[test]
    fn distinct_salts_per_seal() {
        // Two seals of the same file must carry different salts (and thus different keys).
        let vk = VaultKey::generate();
        let a = seal_file(&vk, &meta(), b"x").unwrap();
        let b = seal_file(&vk, &meta(), b"x").unwrap();
        assert_ne!(
            &a[HDR_LEN..HDR_LEN + SALT_LEN],
            &b[HDR_LEN..HDR_LEN + SALT_LEN]
        );
    }

    #[test]
    fn truncated_blob_is_rejected() {
        let vk = VaultKey::generate();
        let blob = seal_file(&vk, &meta(), b"hello").unwrap();
        assert!(open_file(&vk, &blob[..HDR_LEN + 4]).is_err());
    }
}
