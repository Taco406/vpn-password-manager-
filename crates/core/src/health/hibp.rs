//! Have I Been Pwned range API via k-anonymity: hash the password with SHA-1, send
//! only the first 5 hex chars, and compare suffixes locally. The full hash never
//! leaves the device.

use crate::error::Result;
use async_trait::async_trait;
use sha1::{Digest, Sha1};

/// Returns the breach count for a password, or 0 if not found.
#[async_trait]
pub trait HibpClient: Send + Sync {
    async fn breach_count(&self, password: &str) -> Result<u32>;
}

/// Split a password into its (5-char prefix, uppercase-hex suffix) for the range API.
pub fn sha1_prefix_suffix(password: &str) -> (String, String) {
    let digest = Sha1::digest(password.as_bytes());
    let hex = digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<String>();
    (hex[..5].to_string(), hex[5..].to_string())
}

/// Parse a HIBP range response body ("SUFFIX:COUNT" per line) for a given suffix.
pub fn count_from_range(body: &str, suffix: &str) -> u32 {
    for line in body.lines() {
        if let Some((s, c)) = line.trim().split_once(':') {
            if s.eq_ignore_ascii_case(suffix) {
                return c.trim().parse().unwrap_or(0);
            }
        }
    }
    0
}

/// Deterministic mock: a seeded table of known-breached passwords (used by tests and
/// the demo health screen). No network.
#[derive(Default)]
pub struct MockHibp;

#[async_trait]
impl HibpClient for MockHibp {
    async fn breach_count(&self, password: &str) -> Result<u32> {
        // A few well-known breached passwords, plus the seeded demo canary.
        let count = match password {
            "password" => 9_659_365,
            "123456" => 37_359_195,
            "hunter2-reused" => 4_210, // seeded "known-breached" demo entry
            "qwerty" => 3_912_816,
            _ => 0,
        };
        Ok(count)
    }
}

/// A no-network HIBP client: always reports 0 breaches, instantly. Powers the *fast* local audit
/// so the Health tab renders immediately; the real (network) breach check runs separately after.
#[derive(Default)]
pub struct NoHibp;

#[async_trait]
impl HibpClient for NoHibp {
    async fn breach_count(&self, _password: &str) -> Result<u32> {
        Ok(0)
    }
}

/// The real HIBP client (behind `live-hibp`), using the k-anonymity range API with
/// `Add-Padding: true` so the response size doesn't leak which prefix was queried.
#[cfg(feature = "live-hibp")]
pub struct RealHibp {
    http: reqwest::Client,
}

#[cfg(feature = "live-hibp")]
impl Default for RealHibp {
    fn default() -> Self {
        RealHibp {
            http: reqwest::Client::new(),
        }
    }
}

#[cfg(feature = "live-hibp")]
#[async_trait]
impl HibpClient for RealHibp {
    async fn breach_count(&self, password: &str) -> Result<u32> {
        let (prefix, suffix) = sha1_prefix_suffix(password);
        let url = format!("https://api.pwnedpasswords.com/range/{prefix}");
        let body = self
            .http
            .get(&url)
            .header("Add-Padding", "true")
            .send()
            .await
            .map_err(|e| crate::error::CoreError::Network(e.to_string()))?
            .text()
            .await
            .map_err(|e| crate::error::CoreError::Network(e.to_string()))?;
        Ok(count_from_range(&body, &suffix))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_is_five_chars_suffix_rest() {
        let (p, s) = sha1_prefix_suffix("password");
        assert_eq!(p.len(), 5);
        assert_eq!(s.len(), 35); // 40 hex chars total
                                 // Known SHA-1("password") = 5BAA6...
        assert_eq!(p, "5BAA6");
    }

    #[test]
    fn parses_range_body() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\nAB1:2\r\nFEEDFACE:99";
        assert_eq!(count_from_range(body, "FEEDFACE"), 99);
        assert_eq!(count_from_range(body, "feedface"), 99);
        assert_eq!(count_from_range(body, "NOPE"), 0);
    }

    #[tokio::test]
    async fn mock_flags_known_breaches() {
        let h = MockHibp;
        assert!(h.breach_count("password").await.unwrap() > 0);
        assert_eq!(h.breach_count("a-unique-generated-one").await.unwrap(), 0);
    }
}
