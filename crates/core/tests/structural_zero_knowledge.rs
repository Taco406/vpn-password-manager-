//! SECURITY.md T3 — the brief's hard requirement, at the key-model layer.
//!
//! Assemble everything the sync server stores for an account (wrapped-key blobs,
//! encrypted TOTP secret, Google tokens) into a simulated "full server dump", then
//! assert that the vault key cannot be recovered from it. The vault-ciphertext half
//! of this test is added in Phase 2 once the vault format exists.

use sentinel_core::crypto::{Argon2Profile, Key32};
use sentinel_core::keyring::mock::MockBiometricWrapper;
use sentinel_core::keyring::phone::{MockRelay, PhoneShareWrapper};
use sentinel_core::keyring::recovery::RecoveryWrapper;
use sentinel_core::keyring::{KeyWrapper, VaultKey, WrappedBlob};
use sentinel_core::recovery_kit::RecoveryKey;
use sentinel_core::vault::model::{Item, Login};
use sentinel_core::vault::{encode_sync_blob, seal_item, VaultDocument};
use std::sync::Arc;

/// Everything the server holds for an account. By construction, no field is unwrap
/// material — the server never sees a wrapper secret.
struct ServerDump {
    wrapped_blobs: Vec<WrappedBlob>,
    vault_ciphertext: Vec<u8>,
    totp_secret_ciphertext: Vec<u8>,
    google_id_token: Vec<u8>,
    google_access_token: Vec<u8>,
}

impl ServerDump {
    /// All server-held byte strings an attacker could try as key material.
    fn candidate_material(&self) -> Vec<Vec<u8>> {
        let mut v = vec![
            self.vault_ciphertext.clone(),
            self.totp_secret_ciphertext.clone(),
            self.google_id_token.clone(),
            self.google_access_token.clone(),
        ];
        for b in &self.wrapped_blobs {
            v.push(b.bytes.clone());
        }
        v
    }
}

#[tokio::test]
async fn full_server_dump_plus_google_cannot_decrypt_vault_key() {
    // The user's real vault key, and the three wrappers protecting it.
    let vault_key = VaultKey::generate();

    let recovery = RecoveryWrapper::with_profile(RecoveryKey::random(), Argon2Profile::Test);
    let platform = MockBiometricWrapper::always_approved();
    let phone = PhoneShareWrapper::new([0x33; 16], Arc::new(MockRelay::approving()));

    let blobs = vec![
        recovery.wrap(&vault_key).await.unwrap(),
        platform.wrap(&vault_key).await.unwrap(),
        phone.wrap(&vault_key).await.unwrap(),
    ];

    // Seal a real vault (a login with a recognizable password) into the sync blob the
    // server would store.
    let mut item = Item::new_login("Bank of Example", 1);
    item.login = Some(Login {
        username: Some("jackson".into()),
        password: Some("PLAINTEXT-CANARY-PASSWORD-9931".into()),
        totp: None,
    });
    let doc = VaultDocument::from_envelopes(&[seal_item(&vault_key, &item).unwrap()], vec![]);
    let vault_ciphertext = encode_sync_blob(&vault_key, &doc, 1).unwrap();

    // The server stores the blobs, the vault ciphertext, and account/2FA state — but
    // NO wrapper secret and NO vault key.
    let dump = ServerDump {
        wrapped_blobs: blobs,
        vault_ciphertext,
        totp_secret_ciphertext: b"aead(totp-secret-under-server-key)".to_vec(),
        google_id_token: b"eyJ.google.id.token.payload".to_vec(),
        google_access_token: b"ya29.google-access-token".to_vec(),
    };

    // 1) The raw vault key never appears verbatim anywhere in the dump.
    let vk_bytes = vault_key.key().as_bytes();
    for field in dump.candidate_material() {
        assert!(
            !field.windows(32).any(|w| w == vk_bytes),
            "vault key leaked into the server dump"
        );
    }

    // 1b) The vault plaintext (the item password) never appears in the dump.
    let canary = b"PLAINTEXT-CANARY-PASSWORD-9931";
    for field in dump.candidate_material() {
        assert!(
            !field.windows(canary.len()).any(|w| w == canary),
            "vault plaintext leaked into the server dump"
        );
    }

    // 2) No server-held byte string, used directly as a KEK, opens any wrapped blob.
    //    (A real attacker has nothing better — the KEKs derive from the recovery key,
    //    the hardware key, and the phone share, none of which the server ever holds.)
    for blob in &dump.wrapped_blobs {
        for material in dump.candidate_material() {
            if material.len() >= 32 {
                let mut k = [0u8; 32];
                k.copy_from_slice(&material[..32]);
                assert!(
                    blob.open(&Key32::from_bytes(k)).is_err(),
                    "a server-held value unexpectedly opened a wrapped blob"
                );
            }
        }
    }
}

#[tokio::test]
async fn each_wrapper_independently_recovers_the_same_key() {
    // Sanity dual of the above: WITH a wrapper secret, recovery works and yields the
    // exact same vault key regardless of which wrapper is used.
    let vault_key = VaultKey::generate();

    let rk = RecoveryKey::random();
    let recovery = RecoveryWrapper::with_profile(rk.clone(), Argon2Profile::Test);
    let platform = MockBiometricWrapper::always_approved();
    let relay = Arc::new(MockRelay::approving());
    let phone = PhoneShareWrapper::new([0x44; 16], relay);

    let rb = recovery.wrap(&vault_key).await.unwrap();
    let pb = platform.wrap(&vault_key).await.unwrap();
    let hb = phone.wrap(&vault_key).await.unwrap();

    let via_recovery = RecoveryWrapper::with_profile(rk, Argon2Profile::Test)
        .unwrap(&rb)
        .await
        .unwrap();
    let via_platform = platform.unwrap(&pb).await.unwrap();
    let via_phone = phone.unwrap(&hb).await.unwrap();

    assert_eq!(via_recovery.key().as_bytes(), vault_key.key().as_bytes());
    assert_eq!(via_platform.key().as_bytes(), vault_key.key().as_bytes());
    assert_eq!(via_phone.key().as_bytes(), vault_key.key().as_bytes());
}
