//! Vault export. Encrypted export is passphrase-wrapped (Argon2id + AEAD); plaintext
//! CSV is available only behind an explicit, scary confirmation in the UI.

use super::csv;
use crate::crypto::{self, argon2id_kek, hkdf32, Argon2Profile, Info, Nonce24};
use crate::error::{CoreError, Result};
use crate::vault::model::Item;
use rand::RngCore;

const MAGIC: &[u8; 4] = b"SEXP";
const VERSION: u8 = 0x01;

/// Encrypt a set of items under a passphrase. Format:
/// `"SEXP" | ver | salt(16) | nonce(24) | ct` where the key is
/// `HKDF(Argon2id(passphrase, salt), Export)` and the plaintext is the items JSON.
pub fn export_encrypted(
    items: &[Item],
    passphrase: &str,
    profile: Argon2Profile,
) -> Result<Vec<u8>> {
    if passphrase.is_empty() {
        return Err(CoreError::Invalid("export passphrase required".into()));
    }
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let kek = hkdf32(
        argon2id_kek(passphrase.as_bytes(), &salt, profile).as_bytes(),
        None,
        Info::Export,
    );
    let json = serde_json::to_vec(items)?;

    let mut header = Vec::with_capacity(5 + 16);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&salt);
    let (nonce, ct) = crypto::seal(&kek, &header, &json);

    let mut out = header;
    out.extend_from_slice(nonce.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt an encrypted export.
pub fn import_encrypted(
    bytes: &[u8],
    passphrase: &str,
    profile: Argon2Profile,
) -> Result<Vec<Item>> {
    if bytes.len() < 5 + 16 + 24 {
        return Err(CoreError::Format {
            what: "encrypted export",
            detail: "too short".into(),
        });
    }
    if &bytes[0..4] != MAGIC || bytes[4] != VERSION {
        return Err(CoreError::Format {
            what: "encrypted export",
            detail: "bad magic/version".into(),
        });
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&bytes[5..21]);
    let header = &bytes[..21];
    let mut nb = [0u8; 24];
    nb.copy_from_slice(&bytes[21..45]);
    let nonce = Nonce24::from_bytes(nb);
    let ct = &bytes[45..];

    let kek = hkdf32(
        argon2id_kek(passphrase.as_bytes(), &salt, profile).as_bytes(),
        None,
        Info::Export,
    );
    let pt = crypto::open(&kek, header, &nonce, ct)?;
    Ok(serde_json::from_slice(pt.as_slice())?)
}

/// Export to plaintext CSV. This is dangerous (no encryption) and the UI gates it
/// behind an explicit confirmation; kept here so the format is well-defined.
pub fn export_plain_csv(items: &[Item]) -> String {
    let mut rows = vec![vec![
        "name".to_string(),
        "url".to_string(),
        "username".to_string(),
        "password".to_string(),
        "totp".to_string(),
        "notes".to_string(),
    ]];
    for it in items {
        let (user, pass, totp) = it
            .login
            .as_ref()
            .map(|l| {
                (
                    l.username.clone().unwrap_or_default(),
                    l.password.clone().unwrap_or_default(),
                    l.totp.clone().unwrap_or_default(),
                )
            })
            .unwrap_or_default();
        rows.push(vec![
            it.title.clone(),
            it.urls.first().map(|u| u.url.clone()).unwrap_or_default(),
            user,
            pass,
            totp,
            it.notes.clone().unwrap_or_default(),
        ]);
    }
    csv::write(&rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::model::{Item, Login};

    fn items() -> Vec<Item> {
        let mut a = Item::new_login("GitHub", 1);
        a.login = Some(Login {
            username: Some("octocat".into()),
            password: Some("Tr0ub4dour-canary".into()),
            totp: None,
        });
        a.urls = vec![crate::vault::model::UrlMatch {
            url: "https://github.com".into(),
            mode: crate::vault::model::UrlMode::Domain,
        }];
        vec![a]
    }

    #[test]
    fn encrypted_export_round_trip() {
        let its = items();
        let blob = export_encrypted(&its, "correct horse", Argon2Profile::Test).unwrap();
        assert_eq!(&blob[0..4], b"SEXP");
        let back = import_encrypted(&blob, "correct horse", Argon2Profile::Test).unwrap();
        assert_eq!(its, back);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let blob = export_encrypted(&items(), "right", Argon2Profile::Test).unwrap();
        assert!(import_encrypted(&blob, "wrong", Argon2Profile::Test).is_err());
    }

    #[test]
    fn encrypted_export_hides_plaintext() {
        let blob = export_encrypted(&items(), "pw", Argon2Profile::Test).unwrap();
        assert!(
            !blob.windows(17).any(|w| w == b"Tr0ub4dour-canary"),
            "plaintext leaked into encrypted export"
        );
    }

    #[test]
    fn plain_csv_has_header_and_row() {
        let out = export_plain_csv(&items());
        assert!(out.starts_with("name,url,username,password,totp,notes\n"));
        assert!(out.contains("GitHub"));
        assert!(out.contains("Tr0ub4dour-canary")); // plaintext by design (gated in UI)
    }
}
