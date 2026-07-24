//! File-transfer blobs: a file sealed as one opaque, self-describing ciphertext for the
//! "send to my devices" relay. The server only ever stores and expires these bytes — it
//! never sees the plaintext, the filename, or any key.
//!
//! File blob (normative):
//! ```text
//! "SFIL"(4) | 0x01 | 0x00 0x00 0x00 | salt(16) | nonce(24) | ct
//! ```
//! - plaintext = `meta_len(u32 LE) | meta_json | file_bytes`, then zstd(level 3).
//! - `meta_json` = JSON of [`FileMeta`] (filename + mime — themselves sensitive, so sealed
//!   inside the blob, never sent as cleartext columns).
//! - AAD = header(8) ‖ salt(16); key = `HKDF(vault_key, salt, "sentinel/v1/file/blob")`.
//!
//! The salt is random per file and travels in the blob, so every transfer gets a distinct
//! key with no key exchange: any of the user's devices holding the same `vault_key` opens it.

use crate::crypto::{self, argon2id_kek, hkdf32, Argon2Profile, Info, Nonce24};
use crate::error::{CoreError, Result};
use crate::keyring::VaultKey;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};

const MAGIC: &[u8; 4] = b"SFIL";
const VERSION: u8 = 0x01;
const HDR_LEN: usize = 8;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

/// Non-secret-to-the-owner file metadata, sealed inside the blob (the server never sees it).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMeta {
    pub filename: String,
    pub mime: String,
}

fn header() -> Vec<u8> {
    let mut h = Vec::with_capacity(HDR_LEN);
    h.extend_from_slice(MAGIC);
    h.push(VERSION);
    h.extend_from_slice(&[0, 0, 0]);
    h
}

/// Seal a file (with its metadata) into a transfer blob under the vault key.
pub fn seal_file(vk: &VaultKey, meta: &FileMeta, data: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);

    let meta_json = serde_json::to_vec(meta)?;
    let mut plaintext = Vec::with_capacity(4 + meta_json.len() + data.len());
    plaintext.extend_from_slice(&(meta_json.len() as u32).to_le_bytes());
    plaintext.extend_from_slice(&meta_json);
    plaintext.extend_from_slice(data);

    let compressed =
        zstd::encode_all(plaintext.as_slice(), 3).map_err(|e| CoreError::Io(e.to_string()))?;

    let hdr = header();
    let mut aad = hdr.clone();
    aad.extend_from_slice(&salt);

    let key = hkdf32(vk.key().as_bytes(), Some(&salt), Info::FileTransfer);
    let (nonce, ct) = crypto::seal(&key, &aad, &compressed);

    let mut out = hdr;
    out.extend_from_slice(&salt);
    out.extend_from_slice(nonce.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a transfer blob back into its metadata and file bytes.
pub fn open_file(vk: &VaultKey, bytes: &[u8]) -> Result<(FileMeta, Vec<u8>)> {
    if bytes.len() < HDR_LEN + SALT_LEN + NONCE_LEN {
        return Err(CoreError::Format {
            what: "file blob",
            detail: "too short".into(),
        });
    }
    if &bytes[0..4] != MAGIC || bytes[4] != VERSION {
        return Err(CoreError::Format {
            what: "file blob",
            detail: "bad magic/version".into(),
        });
    }
    let hdr = &bytes[..HDR_LEN];
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[HDR_LEN..HDR_LEN + SALT_LEN]);
    let mut nb = [0u8; NONCE_LEN];
    nb.copy_from_slice(&bytes[HDR_LEN + SALT_LEN..HDR_LEN + SALT_LEN + NONCE_LEN]);
    let nonce = Nonce24::from_bytes(nb);
    let ct = &bytes[HDR_LEN + SALT_LEN + NONCE_LEN..];

    let mut aad = hdr.to_vec();
    aad.extend_from_slice(&salt);

    let key = hkdf32(vk.key().as_bytes(), Some(&salt), Info::FileTransfer);
    let pt = crypto::open(&key, &aad, &nonce, ct)?;
    let plain = zstd::decode_all(pt.as_slice()).map_err(|e| CoreError::Io(e.to_string()))?;

    if plain.len() < 4 {
        return Err(CoreError::Format {
            what: "file blob",
            detail: "no metadata length".into(),
        });
    }
    let meta_len = u32::from_le_bytes([plain[0], plain[1], plain[2], plain[3]]) as usize;
    if plain.len() < 4 + meta_len {
        return Err(CoreError::Format {
            what: "file blob",
            detail: "metadata truncated".into(),
        });
    }
    let meta: FileMeta = serde_json::from_slice(&plain[4..4 + meta_len])?;
    let data = plain[4 + meta_len..].to_vec();
    Ok((meta, data))
}

// ---------------------------------------------------------------------------
// Bundle archive (v0.1.58): pack several files into one byte string that then rides as the
// payload of a single ordinary SFIL blob (its `FileMeta.mime` = [`BUNDLE_MIME`]). There is NO
// crypto here — the SFIL seal still provides all confidentiality; this is only a container so that
// "send these five files" (or a whole folder) is ONE encrypted transfer instead of five. A client
// that doesn't recognise the mime just sees one opaque file (the ciphertext still opens); a new
// client unpacks it. Symmetric, self-describing, and unit- + golden-tested so the desktop (Rust)
// and phone (Swift) agree byte-for-byte.
//
// ```text
// "NKAR"(4) | 0x01 | count(u32 LE) | [ name_len(u32 LE) | name_utf8 | data_len(u64 LE) | data ]*
// ```

/// Mime marking a sealed file whose plaintext is a [`pack_bundle`] archive of several files.
pub const BUNDLE_MIME: &str = "application/x-northkey-bundle";

const NKAR_MAGIC: &[u8; 4] = b"NKAR";
const NKAR_VERSION: u8 = 0x01;

/// One file inside a bundle.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BundleEntry {
    pub name: String,
    pub data: Vec<u8>,
}

/// Pack several files into one self-describing archive (the plaintext payload of a bundle transfer).
pub fn pack_bundle(entries: &[BundleEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(NKAR_MAGIC);
    out.push(NKAR_VERSION);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        let name = e.name.as_bytes();
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&(e.data.len() as u64).to_le_bytes());
        out.extend_from_slice(&e.data);
    }
    out
}

/// Unpack a bundle archive back into its files, validating every length against the buffer so a
/// malformed or truncated archive is rejected rather than panicking.
pub fn unpack_bundle(bytes: &[u8]) -> Result<Vec<BundleEntry>> {
    let fmt = |detail: &str| CoreError::Format {
        what: "file bundle",
        detail: detail.to_string(),
    };
    let len = bytes.len();
    let fits = |pos: usize, n: usize| pos.checked_add(n).map(|end| end <= len).unwrap_or(false);
    if len < 9 || &bytes[0..4] != NKAR_MAGIC {
        return Err(fmt("bad magic"));
    }
    if bytes[4] != NKAR_VERSION {
        return Err(fmt("unsupported version"));
    }
    let count = u32::from_le_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) as usize;
    let mut pos = 9;
    let mut out = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        if !fits(pos, 4) {
            return Err(fmt("truncated (name length)"));
        }
        let nlen = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
            as usize;
        pos += 4;
        if !fits(pos, nlen) {
            return Err(fmt("truncated (name)"));
        }
        let name = String::from_utf8(bytes[pos..pos + nlen].to_vec())
            .map_err(|_| fmt("name not utf-8"))?;
        pos += nlen;
        if !fits(pos, 8) {
            return Err(fmt("truncated (data length)"));
        }
        let dlen = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap()) as usize;
        pos += 8;
        if !fits(pos, dlen) {
            return Err(fmt("truncated (data)"));
        }
        let data = bytes[pos..pos + dlen].to_vec();
        pos += dlen;
        out.push(BundleEntry { name, data });
    }
    if pos != len {
        return Err(fmt("trailing bytes"));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Passphrase envelope (SPAS) — v0.1.59: an OPTIONAL outer layer wrapping a finished SFIL blob under
// a user-supplied passphrase (Argon2id → XChaCha20-Poly1305). "Double encryption": the file is
// already sealed under the vault key (SFIL); this adds a second factor only the sender and recipient
// know, so even a device holding the vault key can't open the file without the passphrase. The
// passphrase is NEVER stored and is NOT recoverable — that is the point.
//
// ```text
// "SPAS"(4) | 0x01 | 0x00 0x00 0x00 | argon_salt(16) | nonce(24) | ct   (ct = sealed SFIL blob)
// ```
// key = argon2id_kek(passphrase, argon_salt, Production);  AAD = header(8) ‖ argon_salt(16).
// The Argon2 cost is FIXED at Production (like the master-password wrap) and NOT stored, so any of
// the user's devices derives the same key from the passphrase + the in-blob salt.

const PASS_MAGIC: &[u8; 4] = b"SPAS";
const PASS_VERSION: u8 = 0x01;

/// True when `bytes` is a passphrase-wrapped (SPAS) blob rather than a bare SFIL blob — so a
/// recipient can tell it needs a passphrase before trying to open it.
pub fn is_passphrase_wrapped(bytes: &[u8]) -> bool {
    bytes.len() >= 5 && &bytes[0..4] == PASS_MAGIC && bytes[4] == PASS_VERSION
}

fn pass_header() -> Vec<u8> {
    let mut h = Vec::with_capacity(HDR_LEN);
    h.extend_from_slice(PASS_MAGIC);
    h.push(PASS_VERSION);
    h.extend_from_slice(&[0, 0, 0]);
    h
}

/// Wrap a finished transfer blob under `passphrase`. `profile` is `Production` for real transfers;
/// tests pass `Test` for speed (seal and open must use the SAME profile — the cost isn't stored).
pub fn seal_passphrase(passphrase: &str, inner: &[u8], profile: Argon2Profile) -> Vec<u8> {
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let hdr = pass_header();
    let mut aad = hdr.clone();
    aad.extend_from_slice(&salt);
    let key = argon2id_kek(passphrase.as_bytes(), &salt, profile);
    let (nonce, ct) = crypto::seal(&key, &aad, inner);
    let mut out = hdr;
    out.extend_from_slice(&salt);
    out.extend_from_slice(nonce.as_bytes());
    out.extend_from_slice(&ct);
    out
}

/// Unwrap a passphrase-wrapped blob back to the inner SFIL blob. Wrong passphrase or tamper →
/// [`CoreError::Decrypt`] (the two are indistinguishable by design).
pub fn open_passphrase(passphrase: &str, bytes: &[u8], profile: Argon2Profile) -> Result<Vec<u8>> {
    if bytes.len() < HDR_LEN + SALT_LEN + NONCE_LEN {
        return Err(CoreError::Format {
            what: "passphrase blob",
            detail: "too short".into(),
        });
    }
    if &bytes[0..4] != PASS_MAGIC || bytes[4] != PASS_VERSION {
        return Err(CoreError::Format {
            what: "passphrase blob",
            detail: "bad magic/version".into(),
        });
    }
    let hdr = &bytes[..HDR_LEN];
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[HDR_LEN..HDR_LEN + SALT_LEN]);
    let mut nb = [0u8; NONCE_LEN];
    nb.copy_from_slice(&bytes[HDR_LEN + SALT_LEN..HDR_LEN + SALT_LEN + NONCE_LEN]);
    let nonce = Nonce24::from_bytes(nb);
    let ct = &bytes[HDR_LEN + SALT_LEN + NONCE_LEN..];
    let mut aad = hdr.to_vec();
    aad.extend_from_slice(&salt);
    let key = argon2id_kek(passphrase.as_bytes(), &salt, profile);
    let pt = crypto::open(&key, &aad, &nonce, ct)?;
    Ok(pt.as_slice().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> FileMeta {
        FileMeta {
            filename: "report.pdf".into(),
            mime: "application/pdf".into(),
        }
    }

    fn bundle() -> Vec<BundleEntry> {
        vec![
            BundleEntry {
                name: "a.txt".into(),
                data: b"hello".to_vec(),
            },
            BundleEntry {
                name: "nested/b.bin".into(),
                data: vec![0u8, 255, 7, 42, 7],
            },
            BundleEntry {
                name: "empty".into(),
                data: vec![],
            },
        ]
    }

    #[test]
    fn bundle_round_trip() {
        let packed = pack_bundle(&bundle());
        assert_eq!(&packed[0..4], NKAR_MAGIC);
        assert_eq!(unpack_bundle(&packed).unwrap(), bundle());
    }

    #[test]
    fn bundle_rejects_garbage_and_short() {
        assert!(unpack_bundle(b"not an archive").is_err());
        assert!(unpack_bundle(b"NKAR").is_err());
        assert!(unpack_bundle(&[]).is_err());
    }

    #[test]
    fn bundle_rejects_truncated_lengths() {
        let mut packed = pack_bundle(&bundle());
        packed.truncate(packed.len() - 2); // chop part of the last file's data
        assert!(unpack_bundle(&packed).is_err());
    }

    #[test]
    fn bundle_rides_a_normal_sealed_blob() {
        // The whole point: a bundle is just the plaintext of an ordinary SFIL blob.
        let vk = VaultKey::generate();
        let payload = pack_bundle(&bundle());
        let m = FileMeta {
            filename: "3 files.nkbundle".into(),
            mime: BUNDLE_MIME.into(),
        };
        let blob = seal_file(&vk, &m, &payload).unwrap();
        let (got, back) = open_file(&vk, &blob).unwrap();
        assert_eq!(got.mime, BUNDLE_MIME);
        assert_eq!(unpack_bundle(&back).unwrap(), bundle());
    }

    #[test]
    fn round_trip() {
        let vk = VaultKey::generate();
        let data = vec![7u8; 4096];
        let blob = seal_file(&vk, &meta(), &data).unwrap();
        let (m, back) = open_file(&vk, &blob).unwrap();
        assert_eq!(m, meta());
        assert_eq!(back, data);
    }

    #[test]
    fn empty_and_large_files_round_trip() {
        let vk = VaultKey::generate();
        for len in [0usize, 1, 1024, 1_000_003] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let blob = seal_file(&vk, &meta(), &data).unwrap();
            let (_m, back) = open_file(&vk, &blob).unwrap();
            assert_eq!(back.len(), len);
            assert_eq!(back, data);
        }
    }

    #[test]
    fn wrong_key_fails() {
        let vk = VaultKey::generate();
        let blob = seal_file(&vk, &meta(), b"hello").unwrap();
        assert!(open_file(&VaultKey::generate(), &blob).is_err());
    }

    #[test]
    fn tamper_fails() {
        let vk = VaultKey::generate();
        let mut blob = seal_file(&vk, &meta(), b"hello").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(matches!(open_file(&vk, &blob), Err(CoreError::Decrypt)));
    }

    #[test]
    fn distinct_salts_per_seal() {
        // Two seals of the same file must carry different salts (and thus different keys).
        let vk = VaultKey::generate();
        let a = seal_file(&vk, &meta(), b"x").unwrap();
        let b = seal_file(&vk, &meta(), b"x").unwrap();
        assert_ne!(
            &a[HDR_LEN..HDR_LEN + SALT_LEN],
            &b[HDR_LEN..HDR_LEN + SALT_LEN]
        );
    }

    #[test]
    fn truncated_blob_is_rejected() {
        let vk = VaultKey::generate();
        let blob = seal_file(&vk, &meta(), b"hello").unwrap();
        assert!(open_file(&vk, &blob[..HDR_LEN + 4]).is_err());
    }

    #[test]
    fn passphrase_round_trip() {
        // Test profile keeps Argon2 fast; real transfers use Production.
        let vk = VaultKey::generate();
        let inner = seal_file(&vk, &meta(), b"top secret").unwrap();
        assert!(!is_passphrase_wrapped(&inner));
        let wrapped = seal_passphrase("hunter2", &inner, Argon2Profile::Test);
        assert!(is_passphrase_wrapped(&wrapped));
        let back = open_passphrase("hunter2", &wrapped, Argon2Profile::Test).unwrap();
        assert_eq!(back, inner);
        // ...and the recovered inner blob still opens under the vault key.
        let (m, data) = open_file(&vk, &back).unwrap();
        assert_eq!(m, meta());
        assert_eq!(data, b"top secret");
    }

    #[test]
    fn passphrase_wrong_password_fails() {
        let vk = VaultKey::generate();
        let inner = seal_file(&vk, &meta(), b"x").unwrap();
        let wrapped = seal_passphrase("right", &inner, Argon2Profile::Test);
        assert!(matches!(
            open_passphrase("wrong", &wrapped, Argon2Profile::Test),
            Err(CoreError::Decrypt)
        ));
    }

    #[test]
    fn passphrase_tamper_fails() {
        let vk = VaultKey::generate();
        let inner = seal_file(&vk, &meta(), b"x").unwrap();
        let mut wrapped = seal_passphrase("pw", &inner, Argon2Profile::Test);
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0x01;
        assert!(matches!(
            open_passphrase("pw", &wrapped, Argon2Profile::Test),
            Err(CoreError::Decrypt)
        ));
    }
}
