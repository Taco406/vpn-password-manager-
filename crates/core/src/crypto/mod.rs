//! Authenticated encryption and key derivation primitives.
//!
//! One AEAD everywhere: XChaCha20-Poly1305 (D2). One fast KDF: HKDF-SHA256, with
//! purpose-separated `info` strings (D3). Argon2id lives in [`kdf`] for the
//! low-entropy inputs only.

pub mod kdf;
pub mod types;

pub use kdf::{argon2id_kek, hkdf32, Argon2Profile, Info};
pub use types::{Key32, Nonce24, SecretBytes};

use crate::error::{CoreError, Result};
use chacha20poly1305::aead::Aead as _;
use chacha20poly1305::{AeadCore as _, KeyInit as _, XChaCha20Poly1305, XNonce};

/// Seal `plaintext` under `key` with associated data `aad`.
///
/// Returns `(nonce, ciphertext‖tag)`. A fresh random 24-byte nonce is generated
/// per call, so callers never manage nonces themselves.
pub fn seal(key: &Key32, aad: &[u8], plaintext: &[u8]) -> (Nonce24, Vec<u8>) {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut rand::rngs::OsRng);
    let ct = cipher
        .encrypt(
            &nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        // Encryption failure here is only possible on absurd input sizes; treat as a
        // programming error rather than a recoverable condition.
        .expect("XChaCha20-Poly1305 encryption");
    let mut nb = [0u8; 24];
    nb.copy_from_slice(nonce.as_slice());
    (Nonce24::from_bytes(nb), ct)
}

/// Open `ciphertext` (with appended tag) under `key`, `nonce`, and `aad`.
///
/// Returns [`CoreError::Decrypt`] on wrong key *or* tamper — the two are
/// indistinguishable to the caller by design.
pub fn open(key: &Key32, aad: &[u8], nonce: &Nonce24, ciphertext: &[u8]) -> Result<SecretBytes> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let xn = XNonce::from_slice(nonce.as_bytes());
    let pt = cipher
        .decrypt(
            xn,
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CoreError::Decrypt)?;
    Ok(SecretBytes::new(pt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let k = Key32::random();
        let (n, ct) = seal(&k, b"aad", b"top secret");
        let pt = open(&k, b"aad", &n, &ct).unwrap();
        assert_eq!(pt.as_slice(), b"top secret");
    }

    #[test]
    fn wrong_key_fails() {
        let k = Key32::random();
        let (n, ct) = seal(&k, b"", b"secret");
        let other = Key32::random();
        assert!(matches!(
            open(&other, b"", &n, &ct),
            Err(CoreError::Decrypt)
        ));
    }

    #[test]
    fn tamper_fails() {
        let k = Key32::random();
        let (n, mut ct) = seal(&k, b"", b"secret");
        ct[0] ^= 0x01;
        assert!(matches!(open(&k, b"", &n, &ct), Err(CoreError::Decrypt)));
    }

    #[test]
    fn wrong_aad_fails() {
        let k = Key32::random();
        let (n, ct) = seal(&k, b"aad-a", b"secret");
        assert!(matches!(
            open(&k, b"aad-b", &n, &ct),
            Err(CoreError::Decrypt)
        ));
    }

    #[test]
    fn nonces_are_unique_across_seals() {
        let k = Key32::random();
        let (n1, _) = seal(&k, b"", b"x");
        let (n2, _) = seal(&k, b"", b"x");
        assert_ne!(n1.as_bytes(), n2.as_bytes());
    }
}
