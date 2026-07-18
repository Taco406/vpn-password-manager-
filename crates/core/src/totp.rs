//! Per-entry TOTP (RFC 6238) for vault items. Parses `otpauth://` URIs and bare
//! base32 secrets; computes codes for SHA-1/256/512, 6–8 digits.

use crate::error::{CoreError, Result};
use hmac::{Mac, SimpleHmac};
use zeroize::ZeroizeOnDrop;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TotpAlgo {
    Sha1,
    Sha256,
    Sha512,
}

/// A parsed TOTP secret + parameters. The raw secret zeroizes on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct TotpSecret {
    raw: Vec<u8>,
    #[zeroize(skip)]
    pub algo: TotpAlgo,
    #[zeroize(skip)]
    pub digits: u8,
    #[zeroize(skip)]
    pub period: u32,
}

impl std::fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TotpSecret(<redacted>, {:?}, {} digits, {}s)",
            self.algo, self.digits, self.period
        )
    }
}

impl TotpSecret {
    /// Parse either an `otpauth://totp/...` URI or a bare base32 secret.
    pub fn parse(input: &str) -> Result<Self> {
        if input.starts_with("otpauth://") {
            Self::parse_uri(input)
        } else {
            Ok(TotpSecret {
                raw: base32_decode(input)?,
                algo: TotpAlgo::Sha1,
                digits: 6,
                period: 30,
            })
        }
    }

    fn parse_uri(uri: &str) -> Result<Self> {
        let parsed =
            url::Url::parse(uri).map_err(|_| CoreError::Invalid("bad otpauth uri".into()))?;
        let mut secret = None;
        let mut algo = TotpAlgo::Sha1;
        let mut digits = 6u8;
        let mut period = 30u32;
        for (k, v) in parsed.query_pairs() {
            match k.as_ref() {
                "secret" => secret = Some(base32_decode(&v)?),
                "algorithm" => {
                    algo = match v.to_ascii_uppercase().as_str() {
                        "SHA256" => TotpAlgo::Sha256,
                        "SHA512" => TotpAlgo::Sha512,
                        _ => TotpAlgo::Sha1,
                    }
                }
                "digits" => digits = v.parse().unwrap_or(6),
                "period" => period = v.parse().unwrap_or(30),
                _ => {}
            }
        }
        Ok(TotpSecret {
            raw: secret.ok_or(CoreError::Invalid("otpauth uri missing secret".into()))?,
            algo,
            digits,
            period,
        })
    }

    /// The code at a unix timestamp.
    pub fn code_at(&self, unix: u64) -> String {
        let counter = unix / self.period as u64;
        let digest = self.hmac(&counter.to_be_bytes());
        let offset = (digest[digest.len() - 1] & 0x0f) as usize;
        let bin = ((digest[offset] as u32 & 0x7f) << 24)
            | ((digest[offset + 1] as u32) << 16)
            | ((digest[offset + 2] as u32) << 8)
            | (digest[offset + 3] as u32);
        let modulo = 10u32.pow(self.digits as u32);
        format!("{:0width$}", bin % modulo, width = self.digits as usize)
    }

    /// Milliseconds until the current code rolls over.
    pub fn remaining_ms(&self, unix_ms: u64) -> u64 {
        let period_ms = self.period as u64 * 1000;
        period_ms - (unix_ms % period_ms)
    }

    fn hmac(&self, msg: &[u8]) -> Vec<u8> {
        match self.algo {
            TotpAlgo::Sha1 => {
                let mut m = SimpleHmac::<sha1::Sha1>::new_from_slice(&self.raw).unwrap();
                m.update(msg);
                m.finalize().into_bytes().to_vec()
            }
            TotpAlgo::Sha256 => {
                let mut m = SimpleHmac::<sha2::Sha256>::new_from_slice(&self.raw).unwrap();
                m.update(msg);
                m.finalize().into_bytes().to_vec()
            }
            TotpAlgo::Sha512 => {
                let mut m = SimpleHmac::<sha2::Sha512>::new_from_slice(&self.raw).unwrap();
                m.update(msg);
                m.finalize().into_bytes().to_vec()
            }
        }
    }
}

fn base32_decode(s: &str) -> Result<Vec<u8>> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut buf = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for c in s.chars().filter(|c| *c != '=' && !c.is_whitespace()) {
        let up = c.to_ascii_uppercase();
        let val = ALPHABET
            .iter()
            .position(|&x| x as char == up)
            .ok_or_else(|| CoreError::Invalid("invalid base32 in TOTP secret".into()))?
            as u32;
        buf = (buf << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    if out.is_empty() {
        return Err(CoreError::Invalid("empty TOTP secret".into()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 test vectors, SHA-1, secret "12345678901234567890", 8 digits.
    #[test]
    fn rfc6238_sha1_vectors() {
        let secret = TotpSecret {
            raw: b"12345678901234567890".to_vec(),
            algo: TotpAlgo::Sha1,
            digits: 8,
            period: 30,
        };
        assert_eq!(secret.code_at(59), "94287082");
        assert_eq!(secret.code_at(1111111109), "07081804");
        assert_eq!(secret.code_at(1234567890), "89005924");
        assert_eq!(secret.code_at(2000000000), "69279037");
    }

    #[test]
    fn parses_otpauth_uri() {
        // base32("Hello!" style) — use a known secret. "JBSWY3DPEHPK3PXP" = "Hello!\xde..."
        let uri =
            "otpauth://totp/SENTINEL:me?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30";
        let t = TotpSecret::parse(uri).unwrap();
        assert_eq!(t.digits, 6);
        assert_eq!(t.period, 30);
        assert_eq!(t.code_at(0).len(), 6);
    }

    #[test]
    fn bare_base32_secret() {
        let t = TotpSecret::parse("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(t.code_at(0).len(), 6);
    }

    #[test]
    fn remaining_ms_bounds() {
        let t = TotpSecret::parse("JBSWY3DPEHPK3PXP").unwrap();
        let r = t.remaining_ms(1000);
        assert!(r > 0 && r <= 30_000);
    }

    #[test]
    fn debug_redacts_secret() {
        let t = TotpSecret::parse("JBSWY3DPEHPK3PXP").unwrap();
        let s = format!("{t:?}");
        assert!(s.contains("<redacted>"));
        assert!(!s.contains("JBSWY3DP"));
    }
}
