//! The recovery kit (Wrapper C): a 128-bit break-glass key, encoded for a human to
//! transcribe from a printed page and verify with a 2-group challenge during
//! onboarding.
//!
//! Encoding (D5, normative in docs/crypto-spec.md):
//! - 128-bit key from `OsRng`.
//! - Crockford Base32 alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (decode folds the
//!   ambiguous glyphs I/L → 1 and O → 0, case-insensitive).
//! - 30 data characters: `[0]` = version (`A` = v1); `[1..27]` = 130 bits (2 zero pad
//!   bits + the 128-bit key, big-endian); `[27..30]` = a 15-bit checksum = the top 15
//!   bits of `SHA-256("SNTL-RK-v1" ‖ key)`.
//! - Displayed as `SNTL-` followed by six hyphen-separated groups of five characters.

pub mod pdf;

use crate::error::{CoreError, Result};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const VERSION_CHAR: char = 'A';
const CHECKSUM_DOMAIN: &[u8] = b"SNTL-RK-v1";

/// A 128-bit recovery key. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKey([u8; 16]);

impl RecoveryKey {
    /// Generate a fresh recovery key from the OS CSPRNG.
    pub fn random() -> Self {
        let mut b = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut b);
        RecoveryKey(b)
    }

    pub fn from_bytes(b: [u8; 16]) -> Self {
        RecoveryKey(b)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey(<redacted>)")
    }
}

/// 15-bit checksum over the domain-separated key.
fn checksum15(key: &[u8; 16]) -> u16 {
    let mut h = Sha256::new();
    h.update(CHECKSUM_DOMAIN);
    h.update(key);
    let d = h.finalize();
    // Top 15 bits: all of byte 0 and the top 7 bits of byte 1.
    (((d[0] as u16) << 7) | ((d[1] as u16) >> 1)) & 0x7FFF
}

/// Push `n` most-significant bits of `value` (big-endian) onto `bits`.
fn push_bits(bits: &mut Vec<u8>, value: u128, n: u32) {
    for i in (0..n).rev() {
        bits.push(((value >> i) & 1) as u8);
    }
}

/// Pack a big-endian bit sequence (length a multiple of 5) into Crockford chars.
fn bits_to_chars(bits: &[u8]) -> String {
    debug_assert_eq!(bits.len() % 5, 0);
    bits.chunks(5)
        .map(|c| {
            let idx = c.iter().fold(0u8, |acc, &b| (acc << 1) | b);
            CROCKFORD[idx as usize] as char
        })
        .collect()
}

/// Encode a recovery key into its full `SNTL-…` display form.
pub fn encode(rk: &RecoveryKey) -> String {
    let key = u128::from_be_bytes(rk.0);

    // 130-bit payload: 2 zero pad bits then 128 key bits → 26 chars.
    let mut payload_bits = Vec::with_capacity(130);
    push_bits(&mut payload_bits, 0, 2);
    push_bits(&mut payload_bits, key, 128);
    let payload = bits_to_chars(&payload_bits);

    // 15-bit checksum → 3 chars.
    let mut cs_bits = Vec::with_capacity(15);
    push_bits(&mut cs_bits, checksum15(&rk.0) as u128, 15);
    let checksum = bits_to_chars(&cs_bits);

    let data: String = format!("{VERSION_CHAR}{payload}{checksum}");
    debug_assert_eq!(data.chars().count(), 30);
    group(&data)
}

/// Split 30 data chars into `SNTL-` + six groups of five.
fn group(data: &str) -> String {
    let groups: Vec<String> = data
        .as_bytes()
        .chunks(5)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    format!("SNTL-{}", groups.join("-"))
}

/// Return the six five-character groups (without the `SNTL-` prefix).
pub fn groups(display: &str) -> Result<[String; 6]> {
    let data = normalize(display)?;
    let g: Vec<String> = data
        .as_bytes()
        .chunks(5)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    g.try_into()
        .map_err(|_| CoreError::Invalid("recovery key must have six groups".into()))
}

/// Normalize any user-entered form to the 30 canonical data characters:
/// strip the `SNTL` prefix, spaces and hyphens; uppercase; fold I/L → 1, O → 0.
///
/// The `SNTL` prefix must be removed *before* folding, otherwise its `L` would fold
/// to `1` and the prefix would no longer match.
fn normalize(input: &str) -> Result<String> {
    // 1) uppercase + drop separators (no glyph folding yet).
    let cleaned: String = input
        .chars()
        .filter(|c| !matches!(c, '-' | ' ' | '\t' | '\n' | '\r'))
        .map(|c| c.to_ascii_uppercase())
        .collect();
    // 2) strip an optional leading literal "SNTL" token.
    let body = cleaned.strip_prefix("SNTL").unwrap_or(&cleaned);
    // 3) fold the ambiguous glyphs in the data portion only.
    let out: String = body
        .chars()
        .map(|c| match c {
            'I' | 'L' => '1',
            'O' => '0',
            _ => c,
        })
        .collect();
    if out.chars().count() != 30 {
        return Err(CoreError::Invalid(format!(
            "recovery key must be 30 characters, got {}",
            out.chars().count()
        )));
    }
    Ok(out)
}

fn char_to_val(c: char) -> Result<u8> {
    CROCKFORD
        .iter()
        .position(|&b| b as char == c)
        .map(|p| p as u8)
        .ok_or_else(|| CoreError::Invalid(format!("invalid recovery character: {c}")))
}

/// Decode + checksum-verify a user-entered recovery key.
pub fn decode(display: &str) -> Result<RecoveryKey> {
    let data = normalize(display)?;
    let chars: Vec<char> = data.chars().collect();

    if chars[0] != VERSION_CHAR {
        return Err(CoreError::InvalidRecoveryKey);
    }

    // Chars 1..27 → 130 bits → drop top 2 pad bits → 128-bit key.
    let mut bits: Vec<u8> = Vec::with_capacity(130);
    for &c in &chars[1..27] {
        let v = char_to_val(c)?;
        for i in (0..5).rev() {
            bits.push((v >> i) & 1);
        }
    }
    // First two bits are pad and must be zero.
    if bits[0] != 0 || bits[1] != 0 {
        return Err(CoreError::InvalidRecoveryKey);
    }
    let mut key: u128 = 0;
    for &b in &bits[2..130] {
        key = (key << 1) | b as u128;
    }
    let key_bytes = key.to_be_bytes();

    // Chars 27..30 → 15-bit checksum.
    let mut cs: u16 = 0;
    for &c in &chars[27..30] {
        let v = char_to_val(c)?;
        cs = (cs << 5) | v as u16;
    }
    let expected = checksum15(&key_bytes);
    if cs.ct_eq(&expected).unwrap_u8() != 1 {
        return Err(CoreError::InvalidRecoveryKey);
    }

    Ok(RecoveryKey::from_bytes(key_bytes))
}

/// Onboarding verification: the user must re-enter two randomly chosen groups from
/// their printed kit. Compared in constant time.
pub fn verify_challenge(
    full_display: &str,
    indices: [usize; 2],
    entered: [&str; 2],
) -> Result<bool> {
    let want = groups(full_display)?;
    let mut ok = 1u8;
    for (slot, &idx) in indices.iter().enumerate() {
        if idx >= 6 {
            return Err(CoreError::Invalid("group index out of range".into()));
        }
        let entered_norm = entered[slot].trim().to_ascii_uppercase();
        let entered_folded: String = entered_norm
            .chars()
            .map(|c| match c {
                'I' | 'L' => '1',
                'O' => '0',
                _ => c,
            })
            .collect();
        ok &= want[idx]
            .as_bytes()
            .ct_eq(entered_folded.as_bytes())
            .unwrap_u8();
    }
    Ok(ok == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_encode_decode() {
        for _ in 0..100 {
            let rk = RecoveryKey::random();
            let disp = encode(&rk);
            let back = decode(&disp).unwrap();
            assert_eq!(rk.as_bytes(), back.as_bytes());
        }
    }

    #[test]
    fn display_shape() {
        let rk = RecoveryKey::from_bytes([0xAB; 16]);
        let disp = encode(&rk);
        assert!(disp.starts_with("SNTL-"));
        // SNTL + 6 groups → 7 hyphen-separated tokens.
        assert_eq!(disp.split('-').count(), 7);
        for tok in disp.split('-').skip(1) {
            assert_eq!(tok.len(), 5);
        }
    }

    #[test]
    fn checksum_rejects_single_char_typo() {
        let rk = RecoveryKey::random();
        let disp = encode(&rk);
        let mut chars: Vec<char> = disp.chars().collect();
        // Flip a data character in the first group (position 5 is inside "SNTL-XXXXX").
        let pos = 6;
        chars[pos] = if chars[pos] == '0' { '1' } else { '0' };
        let corrupted: String = chars.into_iter().collect();
        assert!(decode(&corrupted).is_err());
    }

    #[test]
    fn ambiguous_glyphs_are_folded() {
        // Build a key, get its canonical form, then substitute canonical chars with
        // ambiguous equivalents where the canonical char is 1 or 0.
        let rk = RecoveryKey::random();
        let disp = encode(&rk);
        let spoofed: String = disp
            .chars()
            .map(|c| match c {
                '1' => 'I',
                '0' => 'O',
                other => other,
            })
            .collect();
        let back = decode(&spoofed).unwrap();
        assert_eq!(rk.as_bytes(), back.as_bytes());
    }

    #[test]
    fn lowercase_and_spaces_accepted() {
        let rk = RecoveryKey::random();
        let disp = encode(&rk).to_lowercase().replace('-', " ");
        let back = decode(&disp).unwrap();
        assert_eq!(rk.as_bytes(), back.as_bytes());
    }

    #[test]
    fn challenge_verifies_correct_groups() {
        let rk = RecoveryKey::random();
        let disp = encode(&rk);
        let g = groups(&disp).unwrap();
        assert!(verify_challenge(&disp, [1, 4], [&g[1], &g[4]]).unwrap());
        assert!(!verify_challenge(&disp, [1, 4], [&g[1], "ZZZZZ"]).unwrap());
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(decode("SNTL-ABC").is_err());
    }
}
