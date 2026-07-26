//! SECURITY.md gate tests: secret material must never appear in Debug output, error
//! messages, or after a lock; and the AEAD/format invariants hold.

use sentinel_core::crypto::{Key32, SecretBytes};
use sentinel_core::keyring::mock::MockBiometricWrapper;
use sentinel_core::keyring::{KeyWrapper, VaultKey};
use sentinel_core::recovery_kit::RecoveryKey;
use sentinel_core::totp::TotpSecret;
use sentinel_core::vault::model::{Item, Login};
use sentinel_core::vault::VaultSession;
use sentinel_core::wg::WgKeypair;

const CANARY: &str = "hunter2-reused";

#[test]
fn debug_never_leaks_secrets() {
    // Every secret-bearing type must redact its Debug output.
    let key = Key32::from_bytes([0x42; 32]);
    assert!(format!("{key:?}").contains("redacted"));
    assert!(!format!("{key:?}").contains("4242"));

    let vk = VaultKey::from_key(Key32::from_bytes([0x7; 32]));
    assert!(format!("{vk:?}").contains("redacted"));

    let sb = SecretBytes::new(CANARY.as_bytes().to_vec());
    assert!(!format!("{sb:?}").contains(CANARY));

    let rk = RecoveryKey::from_bytes([0x9; 16]);
    assert!(format!("{rk:?}").contains("redacted"));

    let totp = TotpSecret::parse("JBSWY3DPEHPK3PXP").unwrap();
    assert!(!format!("{totp:?}").contains("JBSWY3DP"));

    let wg = WgKeypair::generate();
    assert!(format!("{wg:?}").contains("redacted"));
    assert!(!format!("{wg:?}").contains(&wg.private_base64()));
}

#[test]
fn errors_never_carry_plaintext() {
    // A decrypt failure error must not echo any input.
    let vk = VaultKey::generate();
    let mut item = Item::new_login("Bank", 1);
    item.login = Some(Login {
        username: Some("jackson".into()),
        password: Some(CANARY.into()),
        totp: None,
    });
    let env = sentinel_core::vault::seal_item(&vk, &item).unwrap();
    let err = sentinel_core::vault::open_item(&VaultKey::generate(), &env).unwrap_err();
    let msg = format!("{err}");
    assert!(!msg.contains(CANARY));
    assert!(!msg.contains("jackson"));
}

#[tokio::test]
async fn locking_prevents_access() {
    // After lock(), the session must refuse to decrypt — the key is dropped/zeroized.
    let vk = VaultKey::generate();
    let mut item = Item::new_login("Secret", 1);
    item.login = Some(Login {
        username: None,
        password: Some(CANARY.into()),
        totp: None,
    });
    let mut session = VaultSession::unlocked(vk);
    let env = session.seal(&item).unwrap();
    assert!(session.open(&env).is_ok());

    session.lock();
    assert!(session.is_locked());
    assert!(
        session.open(&env).is_err(),
        "locked session must not decrypt"
    );
}

#[tokio::test]
async fn wrapped_blobs_are_opaque_at_rest() {
    // A stolen wrapped-key blob reveals nothing without the wrapper secret.
    let wrapper = MockBiometricWrapper::always_approved();
    let vk = VaultKey::generate();
    let blob = wrapper.wrap(&vk).await.unwrap();
    // The vault key bytes never appear in the blob.
    assert!(
        !blob.bytes.windows(32).any(|w| w == vk.key().as_bytes()),
        "vault key leaked into wrapped blob"
    );
}

/// T-tamper: the vault file that actually travels between devices (the SVLT sync blob) must
/// FAIL CLOSED on any modification — no partial decrypt, no garbage document. Exercised at
/// every byte region: the header, the nonce, and the ciphertext body.
#[test]
fn tampered_sync_blob_fails_to_open() {
    use sentinel_core::vault::document::{decode_sync_blob, encode_sync_blob, VaultDocument};

    let vk = VaultKey::generate();
    let session = VaultSession::unlocked(vk.clone());
    let mut item = Item::new_login("Bank", 1);
    item.login = Some(Login {
        username: Some("me@example.com".into()),
        password: Some(CANARY.into()),
        totp: None,
    });
    let env = session.seal(&item).expect("seal");
    let doc = VaultDocument::from_envelopes(&[env], vec![]);
    let blob = encode_sync_blob(&vk, &doc, 7).expect("encode");

    // Sanity: the untampered blob opens.
    assert!(decode_sync_blob(&vk, &blob, 7).is_ok());

    // Single-bit flips sampled across header / nonce / ciphertext must all be rejected.
    for pos in [0, 4, 8, 20, 31, blob.len() / 2, blob.len() - 1] {
        let mut bad = blob.clone();
        bad[pos] ^= 0x01;
        assert!(
            decode_sync_blob(&vk, &bad, 7).is_err(),
            "tampered byte {pos} was accepted — AEAD must fail closed"
        );
    }

    // Truncation must fail too, not decode a shorter "valid" document.
    assert!(decode_sync_blob(&vk, &blob[..blob.len() - 4], 7).is_err());

    // A blob sealed for another version must not open as this one (rollback protection).
    assert!(decode_sync_blob(&vk, &blob, 8).is_err());
}
