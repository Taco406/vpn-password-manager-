//! The sync document: the whole vault sealed as one opaque blob for the server,
//! with the server's monotonic version bound into the AEAD associated data so a
//! rolled-back or swapped ciphertext fails to open.
//!
//! Sync blob (normative):
//! ```text
//! "SVLT"(4) | 0x01 | 0x00 0x00 0x00 | nonce(24) | ct
//! ```
//! plaintext = zstd(level 3, JSON of VaultDocument); AAD = header(8) | version u64 LE.

use super::envelope::ItemEnvelope;
use crate::crypto::{self, hkdf32, Info, Nonce24};
use crate::error::{CoreError, Result};
use crate::keyring::VaultKey;
use serde::{Deserialize, Serialize};

const MAGIC: &[u8; 4] = b"SVLT";
const VERSION: u8 = 0x01;

/// The serialized set of sealed items plus tombstones for deletions.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultDocument {
    pub format: u8,
    /// base64 of each item envelope (envelopes are already ciphertext).
    pub items: Vec<String>,
    /// (item_id, deleted_at) tombstones so deletions propagate on merge.
    pub tombstones: Vec<(uuid::Uuid, i64)>,
}

impl VaultDocument {
    pub fn from_envelopes(envs: &[ItemEnvelope], tombstones: Vec<(uuid::Uuid, i64)>) -> Self {
        use base64::Engine as _;
        VaultDocument {
            format: 1,
            items: envs
                .iter()
                .map(|e| base64::engine::general_purpose::STANDARD.encode(&e.0))
                .collect(),
            tombstones,
        }
    }

    pub fn envelopes(&self) -> Result<Vec<ItemEnvelope>> {
        use base64::Engine as _;
        self.items
            .iter()
            .map(|s| {
                base64::engine::general_purpose::STANDARD
                    .decode(s)
                    .map(ItemEnvelope)
                    .map_err(|_| CoreError::Format {
                        what: "vault document",
                        detail: "item not base64".into(),
                    })
            })
            .collect()
    }
}

fn header(version: u64) -> Vec<u8> {
    let mut h = Vec::with_capacity(8);
    h.extend_from_slice(MAGIC);
    h.push(VERSION);
    h.extend_from_slice(&[0, 0, 0]);
    // AAD extends the header with the version; the on-wire header is just the 8 bytes.
    let _ = version;
    h
}

/// Seal a document for the server at a given version.
pub fn encode_sync_blob(vk: &VaultKey, doc: &VaultDocument, version: u64) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(doc)?;
    let compressed =
        zstd::encode_all(json.as_slice(), 3).map_err(|e| CoreError::Io(e.to_string()))?;
    let hdr = header(version);
    let mut aad = hdr.clone();
    aad.extend_from_slice(&version.to_le_bytes());

    let key = hkdf32(vk.key().as_bytes(), None, Info::VaultOuter);
    let (nonce, ct) = crypto::seal(&key, &aad, &compressed);

    let mut out = hdr;
    out.extend_from_slice(nonce.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a server blob, verifying it was sealed for `expected_version`.
pub fn decode_sync_blob(
    vk: &VaultKey,
    bytes: &[u8],
    expected_version: u64,
) -> Result<VaultDocument> {
    if bytes.len() < 8 + 24 {
        return Err(CoreError::Format {
            what: "sync blob",
            detail: "too short".into(),
        });
    }
    if &bytes[0..4] != MAGIC || bytes[4] != VERSION {
        return Err(CoreError::Format {
            what: "sync blob",
            detail: "bad magic/version".into(),
        });
    }
    let hdr = &bytes[..8];
    let mut nb = [0u8; 24];
    nb.copy_from_slice(&bytes[8..32]);
    let nonce = Nonce24::from_bytes(nb);
    let ct = &bytes[32..];

    let mut aad = hdr.to_vec();
    aad.extend_from_slice(&expected_version.to_le_bytes());

    let key = hkdf32(vk.key().as_bytes(), None, Info::VaultOuter);
    let pt = crypto::open(&key, &aad, &nonce, ct)?;
    let json = zstd::decode_all(pt.as_slice()).map_err(|e| CoreError::Io(e.to_string()))?;
    Ok(serde_json::from_slice(&json)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::envelope::seal_item;
    use crate::vault::model::Item;

    fn doc(vk: &VaultKey) -> VaultDocument {
        let a = seal_item(vk, &Item::new_login("A", 1)).unwrap();
        let b = seal_item(vk, &Item::new_login("B", 2)).unwrap();
        VaultDocument::from_envelopes(&[a, b], vec![])
    }

    #[test]
    fn sync_round_trip() {
        let vk = VaultKey::generate();
        let d = doc(&vk);
        let blob = encode_sync_blob(&vk, &d, 7).unwrap();
        let back = decode_sync_blob(&vk, &blob, 7).unwrap();
        assert_eq!(d, back);
        assert_eq!(back.envelopes().unwrap().len(), 2);
    }

    #[test]
    fn wrong_version_fails() {
        // A blob sealed for version 7 must not open as version 8 (rollback/replay).
        let vk = VaultKey::generate();
        let blob = encode_sync_blob(&vk, &doc(&vk), 7).unwrap();
        assert!(matches!(
            decode_sync_blob(&vk, &blob, 8),
            Err(CoreError::Decrypt)
        ));
    }

    #[test]
    fn wrong_key_fails() {
        let vk = VaultKey::generate();
        let blob = encode_sync_blob(&vk, &doc(&vk), 1).unwrap();
        assert!(decode_sync_blob(&VaultKey::generate(), &blob, 1).is_err());
    }
}
