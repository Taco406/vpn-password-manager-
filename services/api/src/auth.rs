//! Authentication primitives: ES256 access JWTs, TOTP (RFC 6238), refresh-token
//! rotation with reuse detection, and a pluggable Google id_token verifier.

use crate::config::JwtKeys;
use crate::error::{ApiError, ApiResult};
use hmac::{Mac, SimpleHmac};
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use uuid::Uuid;

const ACCESS_TTL_SECS: i64 = 600; // 10 minutes
const PENDING_TTL_SECS: i64 = 300; // 5 minutes, between Google and TOTP confirmation

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessClaims {
    pub sub: String, // account id
    pub dev: String, // device id
    pub iat: i64,
    pub exp: i64,
    pub tok: String, // "access" | "pending"
}

fn issue(
    keys: &JwtKeys,
    account: Uuid,
    device: Uuid,
    now: i64,
    ttl: i64,
    tok: &str,
) -> ApiResult<String> {
    let claims = AccessClaims {
        sub: account.to_string(),
        dev: device.to_string(),
        iat: now,
        exp: now + ttl,
        tok: tok.into(),
    };
    jsonwebtoken::encode(&Header::new(Algorithm::ES256), &claims, &keys.encoding)
        .map_err(|_| ApiError::Internal)
}

/// Issue a short-lived ES256 access token for (account, device).
pub fn issue_access(keys: &JwtKeys, account: Uuid, device: Uuid, now: i64) -> ApiResult<String> {
    issue(keys, account, device, now, ACCESS_TTL_SECS, "access")
}

/// Issue a 5-minute "pending" token bridging Google sign-in and TOTP confirmation.
pub fn issue_pending(keys: &JwtKeys, account: Uuid, device: Uuid, now: i64) -> ApiResult<String> {
    issue(keys, account, device, now, PENDING_TTL_SECS, "pending")
}

fn verify_with_kind(keys: &JwtKeys, token: &str, kind: &str) -> ApiResult<AccessClaims> {
    let mut v = Validation::new(Algorithm::ES256);
    v.set_required_spec_claims(&["exp", "sub"]);
    let data = jsonwebtoken::decode::<AccessClaims>(token, &keys.decoding, &v)
        .map_err(|_| ApiError::Unauthorized)?;
    if data.claims.tok != kind {
        return Err(ApiError::Unauthorized);
    }
    Ok(data.claims)
}

/// Verify an access token and return its claims.
pub fn verify_access(keys: &JwtKeys, token: &str) -> ApiResult<AccessClaims> {
    verify_with_kind(keys, token, "access")
}

/// Verify a pending token and return its claims.
pub fn verify_pending(keys: &JwtKeys, token: &str) -> ApiResult<AccessClaims> {
    verify_with_kind(keys, token, "pending")
}

// --- refresh tokens -------------------------------------------------------

/// A freshly minted refresh token: the opaque value goes to the client, the hash to
/// the DB.
pub struct NewRefresh {
    pub token: String,
    pub hash: Vec<u8>,
}

pub fn mint_refresh() -> NewRefresh {
    use base64::Engine as _;
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    let hash = Sha256::digest(token.as_bytes()).to_vec();
    NewRefresh { token, hash }
}

pub fn hash_refresh(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

// --- TOTP (RFC 6238, SHA-1, 6 digits, 30s) --------------------------------

type HmacSha1 = SimpleHmac<Sha1>;

/// Compute the 6-digit TOTP code for a secret at a given unix time.
pub fn totp_code(secret: &[u8], unix: i64) -> String {
    let counter = (unix / 30) as u64;
    let mut mac = HmacSha1::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let bin = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    format!("{:06}", bin % 1_000_000)
}

/// Verify a code against the secret, allowing a ±1 step (30s) clock skew.
pub fn totp_verify(secret: &[u8], code: &str, unix: i64) -> bool {
    let code = code.trim();
    for step in [-1i64, 0, 1] {
        if constant_time_eq(
            totp_code(secret, unix + step * 30).as_bytes(),
            code.as_bytes(),
        ) {
            return true;
        }
    }
    false
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Encode a secret as a base32 `otpauth://` provisioning URI for QR display.
pub fn otpauth_uri(secret: &[u8], account_email: &str, issuer: &str) -> String {
    let b32 = base32_encode(secret);
    format!(
        "otpauth://totp/{issuer}:{account_email}?secret={b32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    )
}

fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &b in data {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

// --- Google id_token verification -----------------------------------------

#[derive(Debug, Clone)]
pub struct GoogleClaims {
    pub sub: String,
    pub email: String,
}

/// Verifies a Google id_token. The real implementation checks the RS256 signature
/// against Google's JWKS and validates `aud`/`iss`/`exp`; the mock accepts a fixture.
#[async_trait::async_trait]
pub trait GoogleVerifier: Send + Sync {
    async fn verify(&self, id_token: &str) -> ApiResult<GoogleClaims>;
}

/// Test/dev verifier: accepts `id_token` of the form `fixture:<sub>:<email>`.
pub struct MockGoogleVerifier;

#[async_trait::async_trait]
impl GoogleVerifier for MockGoogleVerifier {
    async fn verify(&self, id_token: &str) -> ApiResult<GoogleClaims> {
        let parts: Vec<&str> = id_token.splitn(3, ':').collect();
        if parts.len() == 3 && parts[0] == "fixture" {
            Ok(GoogleClaims {
                sub: parts[1].to_string(),
                email: parts[2].to_string(),
            })
        } else {
            Err(ApiError::Unauthorized)
        }
    }
}

// --- real Google id_token verifier (RS256 against Google's JWKS) -----------

/// Where Google publishes the RSA public keys that sign id_tokens.
const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
/// The two `iss` values Google uses for id_tokens.
const GOOGLE_ISSUERS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];
/// How long a fetched JWKS is trusted before a routine refetch. An unknown `kid`
/// forces a refetch regardless of age (Google rotates keys and publishes the new
/// one before signing with it).
const JWKS_TTL: Duration = Duration::from_secs(3600);
/// Clock skew tolerated on `exp` (and `nbf`, if present), in seconds.
const CLOCK_LEEWAY_SECS: u64 = 60;

/// One entry of Google's JWKS (an RSA verifying key).
#[derive(Deserialize)]
struct Jwk {
    kid: String,
    n: String, // base64url-encoded modulus
    e: String, // base64url-encoded exponent
    #[serde(default)]
    kty: String,
    #[serde(default)]
    alg: Option<String>,
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

/// The in-memory JWKS cache: decoded keys by `kid`, plus when they were fetched.
struct JwksCache {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Instant,
}

/// The subset of id_token claims we read after signature/`aud`/`iss`/`exp` have
/// already been validated by `jsonwebtoken::decode`.
#[derive(Deserialize)]
struct GoogleIdClaims {
    sub: String,
    #[serde(default)]
    email: Option<String>,
}

/// Production verifier: checks the id_token's RS256 signature against Google's JWKS
/// and validates `aud` (== the configured OAuth client id), `iss`, and `exp`.
pub struct GoogleIdTokenVerifier {
    client_id: String,
    http: reqwest::Client,
    cache: RwLock<Option<JwksCache>>,
}

impl GoogleIdTokenVerifier {
    /// Build a verifier bound to a specific Google OAuth client id (the expected `aud`).
    pub fn new(client_id: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self {
            client_id,
            http,
            cache: RwLock::new(None),
        }
    }

    /// Resolve the RSA verifying key for `kid`, refetching the JWKS if the cache is
    /// empty, stale, or does not contain the key (rotation).
    async fn key_for(&self, kid: &str) -> ApiResult<DecodingKey> {
        {
            let guard = self.cache.read().await;
            if let Some(cache) = guard.as_ref() {
                if cache.fetched_at.elapsed() < JWKS_TTL {
                    if let Some(key) = cache.keys.get(kid) {
                        return Ok(key.clone());
                    }
                }
            }
        }
        // Cache missing, stale, or unknown kid → refetch once, then look up.
        self.refresh().await?;
        let guard = self.cache.read().await;
        guard
            .as_ref()
            .and_then(|c| c.keys.get(kid).cloned())
            .ok_or(ApiError::Unauthorized)
    }

    /// Fetch and decode Google's JWKS into the cache. A network/parse failure is a
    /// server-side condition (`Internal`), not a rejected token.
    async fn refresh(&self) -> ApiResult<()> {
        let set: JwkSet = self
            .http
            .get(GOOGLE_JWKS_URL)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| {
                tracing::error!(error = %e, "google JWKS fetch failed");
                ApiError::Internal
            })?
            .json()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "google JWKS parse failed");
                ApiError::Internal
            })?;

        let mut keys = HashMap::new();
        for jwk in set.keys {
            if !jwk.kty.is_empty() && jwk.kty != "RSA" {
                continue;
            }
            if let Some(alg) = &jwk.alg {
                if alg != "RS256" {
                    continue;
                }
            }
            match DecodingKey::from_rsa_components(&jwk.n, &jwk.e) {
                Ok(key) => {
                    keys.insert(jwk.kid, key);
                }
                Err(e) => tracing::warn!(error = %e, "skipping malformed JWK"),
            }
        }

        let mut guard = self.cache.write().await;
        *guard = Some(JwksCache {
            keys,
            fetched_at: Instant::now(),
        });
        Ok(())
    }
}

#[async_trait::async_trait]
impl GoogleVerifier for GoogleIdTokenVerifier {
    async fn verify(&self, id_token: &str) -> ApiResult<GoogleClaims> {
        let header = jsonwebtoken::decode_header(id_token).map_err(|_| ApiError::Unauthorized)?;
        if header.alg != Algorithm::RS256 {
            return Err(ApiError::Unauthorized);
        }
        let kid = header.kid.ok_or(ApiError::Unauthorized)?;
        let key = self.key_for(&kid).await?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.client_id]);
        validation.set_issuer(&GOOGLE_ISSUERS);
        validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
        validation.leeway = CLOCK_LEEWAY_SECS;
        // validate_exp is true by default.

        let data = jsonwebtoken::decode::<GoogleIdClaims>(id_token, &key, &validation)
            .map_err(|_| ApiError::Unauthorized)?;

        let email = data.claims.email.ok_or(ApiError::Unauthorized)?;
        Ok(GoogleClaims {
            sub: data.claims.sub,
            email,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_matches_and_rejects() {
        let secret = b"12345678901234567890";
        let t = 1_700_000_000i64;
        let code = totp_code(secret, t);
        assert_eq!(code.len(), 6);
        assert!(totp_verify(secret, &code, t));
        // adjacent window ok
        assert!(totp_verify(secret, &code, t + 20));
        // far away rejected
        assert!(!totp_verify(secret, &code, t + 300));
        assert!(!totp_verify(secret, "000000", t) || code == "000000");
    }

    #[test]
    fn jwt_round_trip_and_tamper() {
        let keys = JwtKeys::ephemeral();
        let acc = Uuid::new_v4();
        let dev = Uuid::new_v4();
        // Far-future issue time so the token is unexpired when verified.
        let tok = issue_access(&keys, acc, dev, 4_000_000_000).unwrap();
        let claims = verify_access(&keys, &tok).unwrap();
        assert_eq!(claims.sub, acc.to_string());
        assert_eq!(claims.dev, dev.to_string());

        // A different key must reject the token.
        let other = JwtKeys::ephemeral();
        assert!(verify_access(&other, &tok).is_err());
    }

    #[test]
    fn refresh_hash_is_stable() {
        let r = mint_refresh();
        assert_eq!(hash_refresh(&r.token), r.hash);
        assert_eq!(r.hash.len(), 32);
    }

    #[test]
    fn otpauth_uri_shape() {
        let uri = otpauth_uri(b"secretbytes", "user@example.com", "SENTINEL");
        assert!(uri.starts_with("otpauth://totp/SENTINEL:user@example.com?secret="));
        assert!(uri.contains("algorithm=SHA1"));
    }

    // The real verifier rejects malformed and wrong-algorithm tokens *before* any
    // network call, so these run offline (no JWKS fetch is reached).
    #[tokio::test]
    async fn real_verifier_rejects_garbage() {
        let v = GoogleIdTokenVerifier::new("client-abc".into());
        assert!(v.verify("not-a-jwt").await.is_err());
        assert!(v.verify("").await.is_err());
    }

    #[tokio::test]
    async fn real_verifier_rejects_non_rs256() {
        // An HS256 token: valid JWT shape, but the wrong signing algorithm. The
        // alg check fires before the JWKS is ever consulted.
        let hs = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &serde_json::json!({ "sub": "x", "aud": "client-abc", "exp": 9_999_999_999i64 }),
            &jsonwebtoken::EncodingKey::from_secret(b"secret"),
        )
        .unwrap();
        let v = GoogleIdTokenVerifier::new("client-abc".into());
        assert!(matches!(v.verify(&hs).await, Err(ApiError::Unauthorized)));
    }
}
