//! The vault: item model, per-item encryption, the sync document, the local encrypted
//! store, and the unlocked session.

pub mod document;
pub mod envelope;
pub mod model;
pub mod passkey;
pub mod session;
pub mod store;
pub mod webauthn;

pub use document::{decode_sync_blob, encode_sync_blob, VaultDocument};
pub use envelope::{open_item, seal_item, ItemEnvelope};
pub use model::{
    Card, CustomField, Identity, Item, ItemId, ItemType, Login, Passkey, UrlMatch, UrlMode,
};
pub use passkey::{mint_passkey, public_key_sec1, signing_key};
pub use session::{origin_matches, rank_matches, VaultSession};
pub use store::{LocalVault, MergeReport};
pub use webauthn::{assertion, registration_attestation};
