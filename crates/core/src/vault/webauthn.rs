//! WebAuthn (FIDO2) attestation/assertion assembly for the passkey virtual authenticator —
//! Stage B (registration) and Stage C (authentication), built on the P-256 key material minted
//! in [`super::passkey`]. Pure functions with fixture tests; no I/O and no vault access.
//!
//! NorthKey is a *software* authenticator, so it uses the **"none"** attestation statement (no
//! device attestation — a password manager attests nothing about hardware). We emit exactly what
//! a relying party consumes:
//!   - **registration** → `attestationObject = CBOR{ fmt:"none", attStmt:{}, authData }`, where
//!     `authData` carries the attested credential data (AAGUID, credential id, COSE public key).
//!   - **assertion** → `authenticatorData` plus an ECDSA(P-256/SHA-256) signature over
//!     `authenticatorData || SHA-256(clientDataJSON)`, DER-encoded as WebAuthn requires.
//!
//! The CBOR we need is tiny and fixed-shape (two small maps), so a minimal *canonical* writer is
//! hand-rolled here rather than pulling in a general CBOR dependency — fewer moving parts to audit,
//! and the byte layout is pinned by tests.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use sha2::{Digest, Sha256};

use super::model::Passkey;
use super::passkey::{public_key_sec1, signing_key};
use crate::error::{CoreError, Result};

/// AAGUID of the NorthKey software authenticator. All-zero is the conventional value for a
/// credential created under the "none" attestation path — it identifies no hardware model, which
/// is deliberate for privacy (a self-attesting software key reveals nothing to track across sites).
const AAGUID: [u8; 16] = [0u8; 16];

// authenticatorData flag bits (WebAuthn §6.1).
const FLAG_UP: u8 = 0x01; // user present
const FLAG_UV: u8 = 0x04; // user verified
const FLAG_AT: u8 = 0x40; // attested credential data included

// --- minimal canonical CBOR writer (only the shapes WebAuthn needs) ----------

/// Write a CBOR head: major type (0..7) and its argument, using the shortest encoding (canonical).
fn cbor_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let mt = major << 5;
    if arg < 24 {
        out.push(mt | arg as u8);
    } else if arg < 0x100 {
        out.push(mt | 24);
        out.push(arg as u8);
    } else if arg < 0x1_0000 {
        out.push(mt | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg < 0x1_0000_0000 {
        out.push(mt | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

/// A CBOR integer (positive → major 0, negative → major 1).
fn cbor_int(out: &mut Vec<u8>, v: i64) {
    if v < 0 {
        cbor_head(out, 1, (-1 - v) as u64);
    } else {
        cbor_head(out, 0, v as u64);
    }
}

fn cbor_bytes(out: &mut Vec<u8>, b: &[u8]) {
    cbor_head(out, 2, b.len() as u64);
    out.extend_from_slice(b);
}

fn cbor_text(out: &mut Vec<u8>, s: &str) {
    cbor_head(out, 3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

fn cbor_map_head(out: &mut Vec<u8>, entries: u64) {
    cbor_head(out, 5, entries);
}

/// COSE_Key (RFC 8152) for an ES256 public key, from a 65-byte uncompressed SEC1 point.
/// Keys are emitted in CTAP2 canonical order (1, 3, -1, -2, -3).
fn cose_es256_key(sec1: &[u8]) -> Result<Vec<u8>> {
    if sec1.len() != 65 || sec1[0] != 0x04 {
        return Err(CoreError::Format {
            what: "passkey public key",
            detail: "expected 65-byte uncompressed SEC1 point".into(),
        });
    }
    let x = &sec1[1..33];
    let y = &sec1[33..65];
    let mut out = Vec::with_capacity(77);
    cbor_map_head(&mut out, 5);
    cbor_int(&mut out, 1); // kty
    cbor_int(&mut out, 2); //   = EC2
    cbor_int(&mut out, 3); // alg
    cbor_int(&mut out, -7); //   = ES256
    cbor_int(&mut out, -1); // crv
    cbor_int(&mut out, 1); //   = P-256
    cbor_int(&mut out, -2); // x
    cbor_bytes(&mut out, x);
    cbor_int(&mut out, -3); // y
    cbor_bytes(&mut out, y);
    Ok(out)
}

// --- authenticatorData + attestation object ----------------------------------

/// SHA-256 of the RP id — the first 32 bytes of authenticatorData.
fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

/// `rpIdHash(32) || flags(1) || signCount(4 BE) || [attestedCredentialData]`.
fn authenticator_data(rp_id: &str, flags: u8, sign_count: u32, attested: Option<&[u8]>) -> Vec<u8> {
    let mut d = Vec::with_capacity(37 + attested.map_or(0, <[u8]>::len));
    d.extend_from_slice(&rp_id_hash(rp_id));
    d.push(flags);
    d.extend_from_slice(&sign_count.to_be_bytes());
    if let Some(a) = attested {
        d.extend_from_slice(a);
    }
    d
}

/// `aaguid(16) || credIdLen(2 BE) || credId || cosePublicKey`.
fn attested_credential_data(cred_id: &[u8], cose_key: &[u8]) -> Vec<u8> {
    let mut d = Vec::with_capacity(18 + cred_id.len() + cose_key.len());
    d.extend_from_slice(&AAGUID);
    d.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
    d.extend_from_slice(cred_id);
    d.extend_from_slice(cose_key);
    d
}

/// `attestationObject = CBOR{ "fmt":"none", "attStmt":{}, "authData": <bytes> }` (canonical order).
fn attestation_object(auth_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(auth_data.len() + 24);
    cbor_map_head(&mut out, 3);
    cbor_text(&mut out, "fmt");
    cbor_text(&mut out, "none");
    cbor_text(&mut out, "attStmt");
    cbor_map_head(&mut out, 0); // empty map
    cbor_text(&mut out, "authData");
    cbor_bytes(&mut out, auth_data);
    out
}

/// Decode a passkey's base64url credential id to raw bytes.
fn credential_id_bytes(pk: &Passkey) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(pk.credential_id.as_bytes())
        .map_err(|_| CoreError::Format {
            what: "passkey credential id",
            detail: "not valid base64url".into(),
        })
}

/// Registration (Stage B): returns `(authenticatorData, attestationObject)` for a freshly minted
/// passkey. `sign_count` is taken from the passkey (0 for a new one). No signature is produced —
/// "none" attestation has an empty statement.
pub fn registration_attestation(pk: &Passkey) -> Result<(Vec<u8>, Vec<u8>)> {
    let sec1 = public_key_sec1(pk)?;
    let cose = cose_es256_key(&sec1)?;
    let cred_id = credential_id_bytes(pk)?;
    let acd = attested_credential_data(&cred_id, &cose);
    let auth_data = authenticator_data(
        &pk.rp_id,
        FLAG_UP | FLAG_UV | FLAG_AT,
        pk.sign_count,
        Some(&acd),
    );
    let att = attestation_object(&auth_data);
    Ok((auth_data, att))
}

/// Authentication (Stage C): build `authenticatorData` at the given (already-incremented)
/// `sign_count` and sign `authenticatorData || SHA-256(clientDataJSON)` with the passkey's key.
/// Returns `(authenticatorData, DER-encoded ECDSA signature)`.
pub fn assertion(
    pk: &Passkey,
    sign_count: u32,
    client_data_json: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let auth_data = authenticator_data(&pk.rp_id, FLAG_UP | FLAG_UV, sign_count, None);
    let client_hash = Sha256::digest(client_data_json);
    let mut signed = Vec::with_capacity(auth_data.len() + 32);
    signed.extend_from_slice(&auth_data);
    signed.extend_from_slice(&client_hash);

    let sk: SigningKey = signing_key(pk)?;
    // ECDSA over P-256 hashing the message with SHA-256 (the ES256 contract), DER-encoded.
    let sig: Signature = sk.sign(&signed);
    Ok((auth_data, sig.to_der().to_bytes().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::passkey::mint_passkey;
    use p256::ecdsa::{signature::Verifier, VerifyingKey};

    /// Tiny CBOR reader — just enough to walk the fixed maps we emit and assert their contents.
    struct Cbor<'a> {
        b: &'a [u8],
        i: usize,
    }
    impl<'a> Cbor<'a> {
        fn new(b: &'a [u8]) -> Self {
            Cbor { b, i: 0 }
        }
        fn head(&mut self) -> (u8, u64) {
            let first = self.b[self.i];
            self.i += 1;
            let major = first >> 5;
            let info = first & 0x1f;
            let arg = match info {
                0..=23 => info as u64,
                24 => {
                    let v = self.b[self.i] as u64;
                    self.i += 1;
                    v
                }
                25 => {
                    let v = u16::from_be_bytes([self.b[self.i], self.b[self.i + 1]]) as u64;
                    self.i += 2;
                    v
                }
                _ => panic!("unexpected cbor arg {info}"),
            };
            (major, arg)
        }
        fn int(&mut self) -> i64 {
            let (major, arg) = self.head();
            match major {
                0 => arg as i64,
                1 => -1 - arg as i64,
                _ => panic!("expected int, got major {major}"),
            }
        }
        fn bytes(&mut self) -> Vec<u8> {
            let (major, len) = self.head();
            assert_eq!(major, 2, "expected byte string");
            let out = self.b[self.i..self.i + len as usize].to_vec();
            self.i += len as usize;
            out
        }
        fn text(&mut self) -> String {
            let (major, len) = self.head();
            assert_eq!(major, 3, "expected text string");
            let out = String::from_utf8(self.b[self.i..self.i + len as usize].to_vec()).unwrap();
            self.i += len as usize;
            out
        }
        fn map_len(&mut self) -> u64 {
            let (major, len) = self.head();
            assert_eq!(major, 5, "expected map");
            len
        }
    }

    fn sample() -> Passkey {
        mint_passkey(
            "example.com",
            Some("Example".into()),
            "alice",
            None,
            b"\x01\x02\x03\x04",
        )
    }

    #[test]
    fn cose_key_is_canonical_es256() {
        let pk = sample();
        let sec1 = public_key_sec1(&pk).unwrap();
        let cose = cose_es256_key(&sec1).unwrap();
        let mut r = Cbor::new(&cose);
        assert_eq!(r.map_len(), 5);
        assert_eq!(r.int(), 1); // kty label
        assert_eq!(r.int(), 2); //   EC2
        assert_eq!(r.int(), 3); // alg label
        assert_eq!(r.int(), -7); //   ES256
        assert_eq!(r.int(), -1); // crv label
        assert_eq!(r.int(), 1); //   P-256
        assert_eq!(r.int(), -2); // x label
        assert_eq!(r.bytes(), sec1[1..33], "x coordinate");
        assert_eq!(r.int(), -3); // y label
        assert_eq!(r.bytes(), sec1[33..65], "y coordinate");
        assert_eq!(r.i, cose.len(), "no trailing bytes");
    }

    #[test]
    fn authenticator_data_layout() {
        let d = authenticator_data("example.com", FLAG_UP | FLAG_UV, 7, None);
        assert_eq!(d.len(), 37, "rpIdHash + flags + signCount");
        assert_eq!(&d[..32], rp_id_hash("example.com"));
        assert_eq!(d[32], 0x05, "UP|UV, no AT");
        assert_eq!(&d[33..37], &7u32.to_be_bytes());
    }

    #[test]
    fn registration_attestation_parses_and_carries_the_key() {
        let pk = sample();
        let (auth_data, att) = registration_attestation(&pk).unwrap();
        // The standalone authenticatorData equals the one embedded in the attestation object.
        assert_eq!(auth_data[0..32], rp_id_hash("example.com"));
        let mut r = Cbor::new(&att);
        assert_eq!(r.map_len(), 3);
        assert_eq!(r.text(), "fmt");
        assert_eq!(r.text(), "none");
        assert_eq!(r.text(), "attStmt");
        assert_eq!(r.map_len(), 0);
        assert_eq!(r.text(), "authData");
        let auth = r.bytes();
        // rpIdHash | flags(AT set) | signCount | aaguid | credIdLen | credId | cose
        assert_eq!(&auth[..32], rp_id_hash("example.com"));
        assert_eq!(auth[32], FLAG_UP | FLAG_UV | FLAG_AT);
        assert_eq!(&auth[33..37], &0u32.to_be_bytes(), "fresh sign_count is 0");
        assert_eq!(&auth[37..53], &AAGUID, "none-attestation AAGUID is zero");
        let cred_len = u16::from_be_bytes([auth[53], auth[54]]) as usize;
        assert_eq!(cred_len, 16, "credential id length");
        let cred = &auth[55..55 + cred_len];
        assert_eq!(cred, credential_id_bytes(&pk).unwrap());
        // The remaining bytes are the COSE key; its map header is 0xA5.
        assert_eq!(auth[55 + cred_len], 0xA5, "COSE map of 5");
    }

    #[test]
    fn assertion_signature_verifies_against_the_passkey_public_key() {
        let pk = sample();
        let client_data =
            br#"{"type":"webauthn.get","challenge":"abc","origin":"https://example.com"}"#;
        let (auth_data, der_sig) = assertion(&pk, 1, client_data).unwrap();

        // Layout: assertion authData has no attested credential data (37 bytes), flags UP|UV.
        assert_eq!(auth_data.len(), 37);
        assert_eq!(auth_data[32], FLAG_UP | FLAG_UV);
        assert_eq!(&auth_data[33..37], &1u32.to_be_bytes());

        // An RP verifies ECDSA(P-256/SHA-256) over authData || SHA-256(clientDataJSON).
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(client_data));
        let sec1 = public_key_sec1(&pk).unwrap();
        let vk = VerifyingKey::from_sec1_bytes(&sec1).unwrap();
        let sig = Signature::from_der(&der_sig).expect("DER signature");
        assert!(
            vk.verify(&signed, &sig).is_ok(),
            "RP-side verification must pass"
        );
    }

    #[test]
    fn assertion_is_bound_to_the_client_data() {
        // A signature made for one clientDataJSON must not verify against a different one —
        // this is what stops a replay with a swapped challenge/origin.
        let pk = sample();
        let (auth_data, der_sig) = assertion(&pk, 2, b"clientdata-A").unwrap();
        let sig = Signature::from_der(&der_sig).unwrap();
        let vk = VerifyingKey::from_sec1_bytes(&public_key_sec1(&pk).unwrap()).unwrap();

        let mut wrong = auth_data.clone();
        wrong.extend_from_slice(&Sha256::digest(b"clientdata-B"));
        assert!(
            vk.verify(&wrong, &sig).is_err(),
            "must not verify against different client data"
        );
    }
}
