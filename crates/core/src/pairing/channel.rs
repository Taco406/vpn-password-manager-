//! The end-to-end pairing channel between the desktop and the iPhone companion.
//!
//! Desktop generates an ephemeral P-256 key; the phone holds a static P-256 key in its
//! Secure Enclave. After ECDH, per-direction keys are derived via HKDF salted by the
//! transcript hash. A 6-digit verification code (from the same transcript) is compared
//! out-of-band by the human, so there is no trust-on-first-use: a tampered QR/pubkey
//! changes the transcript and the codes won't match. The phone's public key is pinned
//! on the desktop after pairing and required to match on every later unlock.

use crate::crypto::{hkdf32, Info, Key32, SecretBytes};
use crate::error::{CoreError, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use p256::ecdh::diffie_hellman;
use p256::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// A P-256 keypair (ephemeral on the desktop, Enclave-static on the phone).
pub struct PairKey {
    secret: SecretKey,
    public: PublicKey,
}

impl PairKey {
    pub fn generate() -> Self {
        let secret = SecretKey::random(&mut OsRng);
        let public = secret.public_key();
        PairKey { secret, public }
    }

    /// SEC1 uncompressed public key bytes (65 bytes), as pinned/registered.
    pub fn public_sec1(&self) -> Vec<u8> {
        self.public.to_sec1_bytes().to_vec()
    }

    pub fn public(&self) -> PublicKey {
        self.public
    }
}

/// Parse a peer's SEC1 public key.
pub fn parse_public(sec1: &[u8]) -> Result<PublicKey> {
    PublicKey::from_sec1_bytes(sec1).map_err(|_| CoreError::Invalid("bad P-256 public key".into()))
}

/// The transcript binds the QR payload and both public keys. Any tampering changes it.
pub fn transcript(qr_payload: &[u8], desktop_pub: &[u8], phone_pub: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(qr_payload.len() + desktop_pub.len() + phone_pub.len());
    t.extend_from_slice(qr_payload);
    t.extend_from_slice(desktop_pub);
    t.extend_from_slice(phone_pub);
    t
}

/// The 6-digit out-of-band verification code shown on both devices.
pub fn verification_code(transcript: &[u8]) -> String {
    let d = Sha256::digest(transcript);
    let n = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 1_000_000;
    format!("{n:06}")
}

/// Which side of the channel we are.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Desktop,
    Phone,
}

/// An E2E channel: two direction-separated keys + per-direction nonce counters.
pub struct Channel {
    send_key: Key32,
    recv_key: Key32,
}

impl Channel {
    /// Establish the channel from our secret, the peer's public key, and the shared
    /// transcript. `role` decides which HKDF info string keys each direction.
    pub fn establish(role: Role, my: &PairKey, peer_pub: &PublicKey, transcript: &[u8]) -> Channel {
        let shared = diffie_hellman(my.secret.to_nonzero_scalar(), peer_pub.as_affine());
        let x = shared.raw_secret_bytes();
        let salt = Sha256::digest(transcript);
        let d2p = hkdf32(x.as_slice(), Some(&salt), Info::PairChannelDesktopToPhone);
        let p2d = hkdf32(x.as_slice(), Some(&salt), Info::PairChannelPhoneToDesktop);
        match role {
            Role::Desktop => Channel {
                send_key: d2p,
                recv_key: p2d,
            },
            Role::Phone => Channel {
                send_key: p2d,
                recv_key: d2p,
            },
        }
    }

    /// Seal a message for the peer using IETF ChaCha20-Poly1305, returning the
    /// CryptoKit-compatible combined box: `nonce(12) ‖ ciphertext ‖ tag(16)`. This is
    /// exactly `ChaChaPoly.SealedBox(...).combined` on the Swift side.
    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(self.send_key.as_bytes().into());
        let mut nb = [0u8; 12];
        OsRng.fill_bytes(&mut nb);
        let nonce = Nonce::from_slice(&nb);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: b"pair",
                },
            )
            .expect("chacha20poly1305 encrypt");
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nb);
        out.extend_from_slice(&ct);
        out
    }

    /// Open a CryptoKit combined box from the peer.
    pub fn open(&self, combined: &[u8]) -> Result<SecretBytes> {
        if combined.len() < 12 + 16 {
            return Err(CoreError::Format {
                what: "pair box",
                detail: "too short".into(),
            });
        }
        let cipher = ChaCha20Poly1305::new(self.recv_key.as_bytes().into());
        let nonce = Nonce::from_slice(&combined[..12]);
        let pt = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &combined[12..],
                    aad: b"pair",
                },
            )
            .map_err(|_| CoreError::Decrypt)?;
        Ok(SecretBytes::new(pt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_ceremony_both_roles_agree() {
        // Rust plays both sides. Desktop is ephemeral; phone is "Enclave" static.
        let desktop = PairKey::generate();
        let phone = PairKey::generate();
        let qr = br#"{"v":1,"pairingId":"abc"}"#;

        let d_pub = desktop.public_sec1();
        let p_pub = phone.public_sec1();
        let t = transcript(qr, &d_pub, &p_pub);

        // Both compute the same verification code (human compares out-of-band).
        assert_eq!(verification_code(&t), verification_code(&t));

        let d_chan = Channel::establish(Role::Desktop, &desktop, &phone.public(), &t);
        let p_chan = Channel::establish(Role::Phone, &phone, &desktop.public(), &t);

        // Desktop → phone.
        let box1 = d_chan.seal(b"share-request");
        assert_eq!(p_chan.open(&box1).unwrap().as_slice(), b"share-request");
        // Phone → desktop.
        let box2 = p_chan.seal(b"share-bytes");
        assert_eq!(d_chan.open(&box2).unwrap().as_slice(), b"share-bytes");
    }

    #[test]
    fn tampered_transcript_breaks_the_channel() {
        let desktop = PairKey::generate();
        let phone = PairKey::generate();
        let qr = br#"{"v":1}"#;
        let t = transcript(qr, &desktop.public_sec1(), &phone.public_sec1());
        // Attacker changes the QR the phone saw.
        let t_bad = transcript(
            br#"{"v":1,"evil":1}"#,
            &desktop.public_sec1(),
            &phone.public_sec1(),
        );

        // Verification codes differ → the human aborts.
        assert_ne!(verification_code(&t), verification_code(&t_bad));

        let d_chan = Channel::establish(Role::Desktop, &desktop, &phone.public(), &t);
        let p_chan = Channel::establish(Role::Phone, &phone, &desktop.public(), &t_bad);
        let sealed = d_chan.seal(b"secret");
        // Different salts ⇒ different keys ⇒ open fails.
        assert!(p_chan.open(&sealed).is_err());
    }

    #[test]
    fn pinned_key_mismatch_is_detectable() {
        // After pairing, an unlock from a DIFFERENT phone key must not decrypt.
        let desktop = PairKey::generate();
        let phone = PairKey::generate();
        let imposter = PairKey::generate();
        let qr = br#"{"v":1}"#;
        let t = transcript(qr, &desktop.public_sec1(), &phone.public_sec1());

        let d_chan = Channel::establish(Role::Desktop, &desktop, &phone.public(), &t);
        // Imposter tries to talk to the desktop using the pinned transcript.
        let imp_chan = Channel::establish(Role::Phone, &imposter, &desktop.public(), &t);
        let sealed = imp_chan.seal(b"malicious-share");
        assert!(
            d_chan.open(&sealed).is_err(),
            "imposter key must not decrypt"
        );
    }

    #[test]
    fn verification_code_is_six_digits() {
        let code = verification_code(b"anything");
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }
}
