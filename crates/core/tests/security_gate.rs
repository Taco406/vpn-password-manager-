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
