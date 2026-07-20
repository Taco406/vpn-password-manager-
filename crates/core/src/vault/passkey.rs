//! Passkey (WebAuthn / FIDO2) credential minting and key access.
//!
//! Stage A: mint a P-256 (ES256) discoverable credential and hold its material inside a
//! vault [`Passkey`] item. Because the whole item is sealed by the per-item envelope, the
//! secret scalar is encrypted at rest for free. Later stages build on the exact formats
//! established here:
//!   - Stage B (registration) COSE-encodes the SEC1 public key from [`public_key_sec1`];
//!   - Stage C (assertion) signs `authenticatorData || clientDataHash` with [`signing_key`].
//!
//! Key formats (normative):
//!   - `private_key`  = base64 (std)          of the 32-byte P-256 secret scalar.
//!   - `credential_id`= base64url (no pad)    of 16 random bytes.
//!   - `user_handle`  = base64url (no pad)    of the opaque user-handle bytes.
//!   - public key     = 65-byte uncompressed SEC1 point (`0x04 || x || y`).

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore as _;

use super::model::Passkey;
use crate::error::{CoreError, Result};

/// COSE algorithm identifier for ES256 (ECDSA over P-256 with SHA-256).
pub const ALG_ES256: i32 = -7;

/// Mint a fresh ES256 passkey for a relying party. Generates a new P-256 key and a random
/// 16-byte credential id; `sign_count` starts at 0. No I/O — the caller seals + stores it.
pub fn mint_passkey(
    rp_id: &str,
    rp_name: Option<String>,
    user_name: &str,
    user_display_name: Option<String>,
    user_handle: &[u8],
) -> Passkey {
    let signing_key = SigningKey::random(&mut OsRng);
    // `to_bytes()` yields the 32-byte big-endian secret scalar.
    let private_key = STANDARD.encode(signing_key.to_bytes());

    let mut cred = [0u8; 16];
    OsRng.fill_bytes(&mut cred);

    Passkey {
        rp_id: rp_id.to_string(),
        rp_name,
        user_name: user_name.to_string(),
        user_display_name,
        user_handle: URL_SAFE_NO_PAD.encode(user_handle),
        credential_id: URL_SAFE_NO_PAD.encode(cred),
        private_key,
        algorithm: ALG_ES256,
        sign_count: 0,
    }
}

/// Restore the ES256 [`SigningKey`] from a stored passkey. This is what Stage C uses to
/// sign assertions. Fails cleanly (no secret in the error) if the stored key is malformed.
pub fn signing_key(pk: &Passkey) -> Result<SigningKey> {
    let raw = STANDARD
        .decode(pk.private_key.as_bytes())
        .map_err(|_| CoreError::Format {
            what: "passkey private key",
            detail: "not valid base64".into(),
        })?;
    if raw.len() != 32 {
        return Err(CoreError::Format {
            what: "passkey private key",
            detail: format!("expected 32 bytes, got {}", raw.len()),
        });
    }
    let field = p256::FieldBytes::from_slice(&raw);
    SigningKey::from_bytes(field).map_err(|_| CoreError::Format {
        what: "passkey private key",
        detail: "not a valid P-256 scalar".into(),
    })
}

/// The 65-byte uncompressed SEC1 public point (`0x04 || x || y`) for a stored passkey.
/// Stage B COSE-encodes this into the attested credential data.
pub fn public_key_sec1(pk: &Passkey) -> Result<Vec<u8>> {
    let sk = signing_key(pk)?;
    let vk = VerifyingKey::from(&sk);
    Ok(vk.to_encoded_point(false).as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{
        signature::{Signer, Verifier},
        Signature,
    };

    #[test]
    fn mint_round_trips_to_a_usable_signing_key() {
        // The stored scalar must restore to a key that produces a signature its own
        // public key verifies — proof the private_key encoding is a real, usable ES256 key.
        let pk = mint_passkey(
            "example.com",
            Some("Example".into()),
            "alice",
            Some("Alice A.".into()),
            b"\x01\x02\x03\x04",
        );
        let sk = signing_key(&pk).expect("restore signing key");
        let msg = b"authenticatorData||clientDataHash";
        let sig: Signature = sk.sign(msg);
        let vk = VerifyingKey::from(&sk);
        assert!(
            vk.verify(msg, &sig).is_ok(),
            "round-tripped key must verify"
        );
    }

    #[test]
    fn mint_sets_the_expected_metadata() {
        let pk = mint_passkey("example.com", None, "bob", None, b"handle-bytes");
        assert_eq!(pk.algorithm, ALG_ES256);
        assert_eq!(pk.sign_count, 0);
        assert_eq!(pk.rp_id, "example.com");
        assert_eq!(pk.user_name, "bob");
        // user_handle is base64url (no pad) of the raw bytes.
        assert_eq!(
            URL_SAFE_NO_PAD.decode(pk.user_handle.as_bytes()).unwrap(),
            b"handle-bytes"
        );
    }

    #[test]
    fn credential_id_decodes_to_16_bytes() {
        let pk = mint_passkey("example.com", None, "carol", None, b"h");
        let raw = URL_SAFE_NO_PAD
            .decode(pk.credential_id.as_bytes())
            .expect("credential id is base64url");
        assert_eq!(raw.len(), 16);
    }

    #[test]
    fn public_key_is_uncompressed_sec1() {
        let pk = mint_passkey("example.com", None, "dave", None, b"h");
        let sec1 = public_key_sec1(&pk).unwrap();
        assert_eq!(sec1.len(), 65, "uncompressed SEC1 point is 65 bytes");
        assert_eq!(sec1[0], 0x04, "uncompressed point tag");
    }

    #[test]
    fn two_mints_differ_in_id_and_key() {
        let a = mint_passkey("example.com", None, "erin", None, b"h");
        let b = mint_passkey("example.com", None, "erin", None, b"h");
        assert_ne!(a.credential_id, b.credential_id);
        assert_ne!(a.private_key, b.private_key);
    }
}
