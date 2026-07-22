//! Generates the byte-compat fixtures the iOS app's unit tests decode
//! (`apps/ios-key/NorthKeyTests/Fixtures/golden-vault.json`). The Swift vault crypto
//! (Argon2id KEK → SNTL unwrap → SVLT sync-blob decode → item envelopes) must reproduce these
//! bytes exactly — that is the interop guarantee between desktop and phone.
//!
//! Regenerate (rarely — only on a format change) with:
//!   cargo test -p sentinel-core --test ios_golden_vectors -- --ignored generate
//! then commit the JSON. Uses the PRODUCTION Argon2 profile on purpose: the fixture must match
//! what real escrowed blobs use (the Swift test takes ~1s on-device for the 64 MiB derivation).

use base64::Engine as _;
use sentinel_core::crypto::{Argon2Profile, Key32};
use sentinel_core::keyring::password::PasswordWrapper;
use sentinel_core::keyring::{KeyWrapper, VaultKey, WrappedBlob, WrapperType};
use sentinel_core::vault::model::{Item, Login};
use sentinel_core::vault::{
    decode_sync_blob, encode_sync_blob, open_item, seal_item, ItemEnvelope, VaultDocument,
};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../apps/ios-key/NorthKeyTests/Fixtures/golden-vault.json"
);

fn read_fixture() -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(FIXTURE).expect(
        "committed fixture missing — regenerate with \
         `cargo test -p sentinel-core --test ios_golden_vectors -- --ignored generate`",
    ))
    .unwrap()
}

fn b64d(v: &serde_json::Value, key: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(v[key].as_str().unwrap())
        .unwrap()
}

/// The committed fixture must stay decodable by the CURRENT Rust core. This is the desktop half
/// of the desktop↔iPhone interop guarantee (the Swift half is NorthKeyTests/VaultCryptoTests):
/// if a change to the SVLT/envelope formats or the vault JSON model breaks this test, that same
/// change just broke every deployed iPhone — fix the change or regenerate the fixture AND
/// re-verify the Swift tests, never loosen this.
#[test]
fn committed_fixture_blob_and_items_decode() {
    let f = read_fixture();
    let vk_bytes: [u8; 32] = b64d(&f, "vault_key_b64").try_into().unwrap();
    let vk = VaultKey::from_key(Key32::from_bytes(vk_bytes));
    let blob = b64d(&f, "vault_blob_b64");
    let version = f["vault_version"].as_u64().unwrap();

    let doc = decode_sync_blob(&vk, &blob, version).expect("SVLT decode changed incompatibly");
    let expected = f["items"].as_array().unwrap();
    assert_eq!(doc.items.len(), expected.len());

    let mut opened: std::collections::HashMap<String, Item> = doc
        .items
        .iter()
        .map(|b64| {
            let env = ItemEnvelope(
                base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .unwrap(),
            );
            let item = open_item(&vk, &env).expect("item envelope decode changed incompatibly");
            (item.id.to_string(), item)
        })
        .collect();
    for want in expected {
        let item = opened
            .remove(want["id"].as_str().unwrap())
            .expect("fixture item missing");
        let login = item.login.expect("fixture item lost its login");
        assert_eq!(item.title, want["title"].as_str().unwrap());
        assert_eq!(login.username.as_deref(), want["username"].as_str());
        assert_eq!(login.password.as_deref(), want["password"].as_str());
    }

    // The version is authenticated (AAD) — rollback protection both platforms rely on.
    assert!(decode_sync_blob(&vk, &blob, version + 1).is_err());
}

/// Same guarantee for the master-password wrapped key (Argon2id at PRODUCTION cost — run in
/// release mode; CI runs it in the production-profile step).
#[test]
#[ignore = "production-cost Argon2; CI runs it explicitly in release mode"]
fn committed_fixture_wrapped_key_unwraps() {
    let f = read_fixture();
    let blob = WrappedBlob {
        wrapper: WrapperType::Password,
        bytes: b64d(&f, "wrapped_key_b64"),
    };
    let wrapper =
        PasswordWrapper::with_profile(f["password"].as_str().unwrap(), Argon2Profile::Production);
    let vk = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(wrapper.unwrap(&blob))
        .expect("password KEK/SNTL unwrap changed incompatibly — this breaks every iPhone");
    assert_eq!(
        base64::engine::general_purpose::STANDARD.encode(vk.key().as_bytes()),
        f["vault_key_b64"].as_str().unwrap()
    );
    // The sign-in proof must stay stable too — a drift here locks every phone out of login.
    let salt: [u8; 16] = blob.params().unwrap().try_into().unwrap();
    assert_eq!(
        base64::engine::general_purpose::STANDARD.encode(wrapper.login_proof(&salt).as_bytes()),
        f["login_proof_b64"].as_str().unwrap()
    );
}

#[test]
#[ignore = "writes the committed iOS fixture; run explicitly to regenerate"]
fn generate() {
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let password = "morning-test-master-password";
    let vk = VaultKey::from_key(Key32::from_bytes([0x42; 32]));

    let wrapper = PasswordWrapper::with_profile(password, Argon2Profile::Production);
    let wrapped = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(wrapper.wrap(&vk))
        .unwrap();
    // The sign-in proof for the same salt (one derivation covers login AND unwrap on clients).
    let salt: [u8; 16] = wrapped.params().unwrap().try_into().unwrap();
    let login_proof = wrapper.login_proof(&salt);

    let mut a = Item::new_login("GitHub", 1_750_000_000);
    a.id = uuid::Uuid::from_bytes([0xA1; 16]);
    a.login = Some(Login {
        username: Some("octocat".into()),
        password: Some("hunter2-golden".into()),
        totp: None,
    });
    let mut b = Item::new_login("Example Bank", 1_750_000_100);
    b.id = uuid::Uuid::from_bytes([0xB2; 16]);
    b.login = Some(Login {
        username: Some("jackson".into()),
        password: Some("s3cure-golden".into()),
        totp: None,
    });

    let envs = vec![seal_item(&vk, &a).unwrap(), seal_item(&vk, &b).unwrap()];
    let doc = VaultDocument::from_envelopes(&envs, vec![]);
    let version = 3u64;
    let blob = encode_sync_blob(&vk, &doc, version).unwrap();

    let fixture = serde_json::json!({
        "comment": "generated by crates/core/tests/ios_golden_vectors.rs — do not hand-edit",
        "password": password,
        "vault_key_b64": b64(vk.key().as_bytes()),
        "wrapped_key_b64": b64(&wrapped.bytes),
        "login_proof_b64": b64(login_proof.as_bytes()),
        "argon2": { "m_kib": 65536, "t": 3, "p": 4 },
        "vault_version": version,
        "vault_blob_b64": b64(&blob),
        "items": [
            { "id": a.id.to_string(), "title": "GitHub", "username": "octocat", "password": "hunter2-golden" },
            { "id": b.id.to_string(), "title": "Example Bank", "username": "jackson", "password": "s3cure-golden" },
        ],
    });
    let out = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../apps/ios-key/NorthKeyTests/Fixtures/golden-vault.json"
    );
    std::fs::create_dir_all(std::path::Path::new(out).parent().unwrap()).unwrap();
    std::fs::write(out, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();
    println!("wrote {out}");
}
