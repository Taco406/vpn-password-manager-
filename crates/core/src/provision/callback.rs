//! The one-time HTTPS callback that retrieves the fresh server's WireGuard public key.
//! Authenticity does not rely on the (self-signed) TLS cert: the server returns an
//! HMAC over `pubkey || ip` keyed by material delivered only inside the instance's
//! cloud-init user_data (over Linode's TLS API). A tampered pubkey fails the HMAC
//! (D11, SECURITY.md T6).

use crate::error::{CoreError, Result};
use hmac::{Mac, SimpleHmac};
use serde::Deserialize;
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// The JSON body the fresh server returns from its one-shot callback endpoint.
#[derive(Debug, Deserialize)]
pub struct CallbackBody {
    pub pubkey: String,
    pub ip: String,
    /// Hex HMAC-SHA256 over (pubkey || ip).
    pub mac: String,
}

/// Verify the callback body and return the authenticated server public key.
pub fn verify_callback(body: &CallbackBody, hmac_key_hex: &str) -> Result<String> {
    let key = hex_decode(hmac_key_hex)?;
    let mut mac = SimpleHmac::<Sha256>::new_from_slice(&key).map_err(|_| CoreError::Provision {
        stage: "callback",
        detail: "bad hmac key".into(),
    })?;
    mac.update(body.pubkey.as_bytes());
    mac.update(body.ip.as_bytes());
    let expected = mac.finalize().into_bytes();
    let got = hex_decode(&body.mac)?;

    if got.len() != expected.len() || got.ct_eq(&expected).unwrap_u8() != 1 {
        return Err(CoreError::Provision {
            stage: "callback",
            detail: "pubkey HMAC mismatch (possible MITM)".into(),
        });
    }
    Ok(body.pubkey.clone())
}

/// Compute the expected HMAC hex for a (pubkey, ip) — used to build the server side and
/// by tests.
pub fn compute_mac(pubkey: &str, ip: &str, hmac_key_hex: &str) -> Result<String> {
    let key = hex_decode(hmac_key_hex)?;
    let mut mac = SimpleHmac::<Sha256>::new_from_slice(&key).map_err(|_| CoreError::Provision {
        stage: "callback",
        detail: "bad hmac key".into(),
    })?;
    mac.update(pubkey.as_bytes());
    mac.update(ip.as_bytes());
    Ok(hex_encode(&mac.finalize().into_bytes()))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(CoreError::Provision {
            stage: "callback",
            detail: "odd hex length".into(),
        });
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| CoreError::Provision {
                stage: "callback",
                detail: "bad hex".into(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "00112233445566778899aabbccddeeff";

    #[test]
    fn accepts_authentic_pubkey() {
        let pubkey = "SERVERPUBKEYbase64=";
        let ip = "203.0.113.7";
        let mac = compute_mac(pubkey, ip, KEY).unwrap();
        let body = CallbackBody {
            pubkey: pubkey.into(),
            ip: ip.into(),
            mac,
        };
        assert_eq!(verify_callback(&body, KEY).unwrap(), pubkey);
    }

    #[test]
    fn rejects_tampered_pubkey() {
        let ip = "203.0.113.7";
        let mac = compute_mac("REAL", ip, KEY).unwrap();
        // Attacker swaps in their own pubkey but can't recompute the MAC without the key.
        let body = CallbackBody {
            pubkey: "ATTACKER".into(),
            ip: ip.into(),
            mac,
        };
        assert!(verify_callback(&body, KEY).is_err());
    }

    #[test]
    fn rejects_tampered_ip() {
        let mac = compute_mac("REAL", "203.0.113.7", KEY).unwrap();
        let body = CallbackBody {
            pubkey: "REAL".into(),
            ip: "203.0.113.99".into(),
            mac,
        };
        assert!(verify_callback(&body, KEY).is_err());
    }

    #[test]
    fn rejects_wrong_key() {
        let mac = compute_mac("REAL", "1.2.3.4", KEY).unwrap();
        let body = CallbackBody {
            pubkey: "REAL".into(),
            ip: "1.2.3.4".into(),
            mac,
        };
        assert!(verify_callback(&body, "ffffffffffffffffffffffffffffffff").is_err());
    }
}
