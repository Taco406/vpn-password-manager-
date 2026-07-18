//! Per-item encryption. Each item is sealed under a key derived from the vault key
//! and the item id (D4), so ciphertext is bound to its item and blast radius is
//! minimal.
//!
//! Item envelope (normative):
//! ```text
//! 0x01 | item_id(16) | updated_at i64 LE (8) | nonce(24) | ct
//! ```
//! AAD = the first 25 bytes (version | item_id | updated_at), so a ciphertext cannot
//! be replayed under a different id or moved backwards in time.

use super::model::Item;
use crate::crypto::{self, hkdf32, Info, Key32, Nonce24};
use crate::error::{CoreError, Result};
use crate::keyring::VaultKey;

const ITEM_VERSION: u8 = 0x01;

/// A sealed item (the exact bytes stored per-row in the local vault).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemEnvelope(pub Vec<u8>);

fn item_key(vk: &VaultKey, item_id: &[u8; 16]) -> Key32 {
    hkdf32(vk.key().as_bytes(), Some(item_id), Info::VaultItem)
}

/// Seal an item under the vault key.
pub fn seal_item(vk: &VaultKey, item: &Item) -> Result<ItemEnvelope> {
    let id_bytes = *item.id.as_bytes();
    let mut header = Vec::with_capacity(25);
    header.push(ITEM_VERSION);
    header.extend_from_slice(&id_bytes);
    header.extend_from_slice(&item.updated_at.to_le_bytes());

    let plaintext = serde_json::to_vec(item)?;
    let key = item_key(vk, &id_bytes);
    let (nonce, ct) = crypto::seal(&key, &header, &plaintext);

    let mut out = header;
    out.extend_from_slice(nonce.as_bytes());
    out.extend_from_slice(&ct);
    Ok(ItemEnvelope(out))
}

/// Open a sealed item under the vault key.
pub fn open_item(vk: &VaultKey, env: &ItemEnvelope) -> Result<Item> {
    let b = &env.0;
    if b.len() < 25 + 24 + 16 {
        return Err(CoreError::Format {
            what: "item envelope",
            detail: "too short".into(),
        });
    }
    if b[0] != ITEM_VERSION {
        return Err(CoreError::Format {
            what: "item envelope",
            detail: format!("unsupported version {}", b[0]),
        });
    }
    let mut id_bytes = [0u8; 16];
    id_bytes.copy_from_slice(&b[1..17]);
    let header = &b[..25];
    let mut nb = [0u8; 24];
    nb.copy_from_slice(&b[25..49]);
    let nonce = Nonce24::from_bytes(nb);
    let ct = &b[49..];

    let key = item_key(vk, &id_bytes);
    let pt = crypto::open(&key, header, &nonce, ct)?;
    let item: Item = serde_json::from_slice(pt.as_slice())?;

    // Bind the decoded item to the header (defense in depth against a mismatched blob).
    if item.id.as_bytes() != &id_bytes {
        return Err(CoreError::Format {
            what: "item envelope",
            detail: "item id mismatch".into(),
        });
    }
    Ok(item)
}

/// Extract the `(item_id, updated_at)` from an envelope header without decrypting —
/// used for conflict resolution / merge without unlocking every item.
pub fn envelope_meta(env: &ItemEnvelope) -> Result<(uuid::Uuid, i64)> {
    let b = &env.0;
    if b.len() < 25 {
        return Err(CoreError::Format {
            what: "item envelope",
            detail: "too short for meta".into(),
        });
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&b[1..17]);
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&b[17..25]);
    Ok((uuid::Uuid::from_bytes(id), i64::from_le_bytes(ts)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::model::Login;

    fn sample() -> Item {
        let mut it = Item::new_login("GitHub", 1_700_000_000);
        it.login = Some(Login {
            username: Some("octocat".into()),
            password: Some("hunter2-reused".into()),
            totp: None,
        });
        it
    }

    #[test]
    fn round_trip() {
        let vk = VaultKey::generate();
        let item = sample();
        let env = seal_item(&vk, &item).unwrap();
        let back = open_item(&vk, &env).unwrap();
        assert_eq!(item, back);
    }

    #[test]
    fn ciphertext_hides_plaintext() {
        let vk = VaultKey::generate();
        let env = seal_item(&vk, &sample()).unwrap();
        // The password must not appear in the sealed bytes.
        assert!(
            !env.0.windows(14).any(|w| w == b"hunter2-reused"),
            "plaintext leaked into item envelope"
        );
    }

    #[test]
    fn wrong_key_fails() {
        let vk = VaultKey::generate();
        let env = seal_item(&vk, &sample()).unwrap();
        assert!(matches!(
            open_item(&VaultKey::generate(), &env),
            Err(CoreError::Decrypt)
        ));
    }

    #[test]
    fn tampered_updated_at_fails() {
        let vk = VaultKey::generate();
        let mut env = seal_item(&vk, &sample()).unwrap();
        env.0[20] ^= 0xFF; // flip a byte inside updated_at (AAD) → open fails
        assert!(matches!(open_item(&vk, &env), Err(CoreError::Decrypt)));
    }

    #[test]
    fn meta_matches_without_decrypt() {
        let vk = VaultKey::generate();
        let item = sample();
        let env = seal_item(&vk, &item).unwrap();
        let (id, ts) = envelope_meta(&env).unwrap();
        assert_eq!(id, item.id);
        assert_eq!(ts, item.updated_at);
    }

    #[test]
    fn golden_envelope_layout() {
        // Fixed key + item → assert the header layout is exactly as specified.
        let vk = VaultKey::from_key(Key32::from_bytes([0x11; 32]));
        let mut item = Item::new_login("x", 0x0102030405060708);
        item.id = uuid::Uuid::from_bytes([0xAB; 16]);
        let env = seal_item(&vk, &item).unwrap();
        assert_eq!(env.0[0], ITEM_VERSION);
        assert_eq!(&env.0[1..17], &[0xAB; 16]);
        assert_eq!(&env.0[17..25], &0x0102030405060708i64.to_le_bytes());
    }
}
