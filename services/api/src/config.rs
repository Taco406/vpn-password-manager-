//! Server configuration, loaded from the environment.

use jsonwebtoken::{DecodingKey, EncodingKey};

#[derive(Clone)]
pub struct Config {
    pub bind: String,
    pub database_url: String,
    /// Public Google OAuth client id used to validate the `aud` of id_tokens.
    pub google_client_id: Option<String>,
    /// Shared secret for the personal `/v1/auth/bootstrap` path (a one-click self-hosted deploy
    /// sets this so no Google OAuth client id is needed). `None` disables the endpoint.
    pub bootstrap_token: Option<String>,
    /// 32-byte key that encrypts account TOTP secrets at rest (D8). Generated if unset.
    pub totp_enc_key: [u8; 32],
    /// True when `SENTINEL_ENV=production`. In production the server refuses to boot with
    /// insecure fallbacks (mock Google verifier, ephemeral JWT key, generated TOTP key).
    pub production: bool,
    /// Trust the `X-Forwarded-For` header for the client IP (only when behind a proxy that
    /// sets it). Off by default; when off, rate limiting keys off the real peer address so a
    /// client can't spoof its way past the limiter. Set `SENTINEL_TRUST_FORWARDED_FOR=1`.
    pub trust_forwarded_for: bool,
    /// Browser origins allowed by CORS in production (comma-separated
    /// `SENTINEL_CORS_ALLOWED_ORIGINS`). Empty = allow no browser origin (the desktop app is a
    /// native client and is unaffected by CORS).
    pub cors_allowed_origins: Vec<String>,
}

/// The ES256 keypair used to sign/verify access JWTs (D18).
#[derive(Clone)]
pub struct JwtKeys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
}

impl JwtKeys {
    /// Load from a PKCS#8 PEM private key, deriving the public verifying key from it.
    pub fn from_private_pem(pem: &str) -> Result<Self, String> {
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};
        let signing = SigningKey::from_pkcs8_pem(pem).map_err(|e| e.to_string())?;
        let verifying = signing.verifying_key();
        let pub_pem = verifying
            .to_public_key_pem(Default::default())
            .map_err(|e| e.to_string())?;
        let encoding = EncodingKey::from_ec_pem(pem.as_bytes()).map_err(|e| e.to_string())?;
        let decoding = DecodingKey::from_ec_pem(pub_pem.as_bytes()).map_err(|e| e.to_string())?;
        Ok(JwtKeys { encoding, decoding })
    }

    /// Generate an ephemeral ES256 keypair (dev/test).
    pub fn ephemeral() -> Self {
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
        let signing = SigningKey::random(&mut rand::rngs::OsRng);
        let priv_pem = signing.to_pkcs8_pem(Default::default()).unwrap();
        let pub_pem = signing
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        JwtKeys {
            encoding: EncodingKey::from_ec_pem(priv_pem.as_bytes()).unwrap(),
            decoding: DecodingKey::from_ec_pem(pub_pem.as_bytes()).unwrap(),
        }
    }
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let database_url =
            std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL is required".to_string())?;
        let bind = std::env::var("SENTINEL_API_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into());
        let google_client_id = std::env::var("GOOGLE_OAUTH_CLIENT_ID")
            .ok()
            .filter(|s| !s.is_empty());
        let bootstrap_token = std::env::var("SENTINEL_BOOTSTRAP_TOKEN")
            .ok()
            .filter(|s| !s.is_empty());

        let totp_enc_key = match std::env::var("SENTINEL_TOTP_ENC_KEY")
            .ok()
            .filter(|s| !s.is_empty())
        {
            Some(b64) => {
                use base64::Engine as _;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|_| "SENTINEL_TOTP_ENC_KEY must be base64".to_string())?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| "SENTINEL_TOTP_ENC_KEY must decode to 32 bytes".to_string())?;
                arr
            }
            None => {
                use rand::RngCore;
                let mut k = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut k);
                k
            }
        };

        let production = std::env::var("SENTINEL_ENV")
            .map(|v| v.eq_ignore_ascii_case("production"))
            .unwrap_or(false);
        let trust_forwarded_for = std::env::var("SENTINEL_TRUST_FORWARDED_FOR")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let cors_allowed_origins = std::env::var("SENTINEL_CORS_ALLOWED_ORIGINS")
            .ok()
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        Ok(Config {
            bind,
            database_url,
            google_client_id,
            bootstrap_token,
            totp_enc_key,
            production,
            trust_forwarded_for,
            cors_allowed_origins,
        })
    }

    /// In production, refuse to run on insecure dev fallbacks. `jwt_pem_set` / `totp_key_set`
    /// report whether the corresponding secrets are present in the environment. Returns the
    /// list of missing required secrets (empty = OK). A no-op outside production.
    pub fn check_production_secrets(
        &self,
        jwt_pem_set: bool,
        totp_key_set: bool,
    ) -> Vec<&'static str> {
        if !self.production {
            return Vec::new();
        }
        // Identity provider: EITHER a Google OAuth client id OR a personal bootstrap token
        // satisfies "how do accounts get in" — a one-click self-hosted deploy uses the latter.
        let has_identity = self.google_client_id.is_some() || self.bootstrap_token.is_some();
        [
            ("SENTINEL_JWT_ES256_PEM", jwt_pem_set),
            (
                "GOOGLE_OAUTH_CLIENT_ID or SENTINEL_BOOTSTRAP_TOKEN",
                has_identity,
            ),
            ("SENTINEL_TOTP_ENC_KEY", totp_key_set),
        ]
        .into_iter()
        .filter_map(|(name, present)| if present { None } else { Some(name) })
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(production: bool, google: Option<&str>) -> Config {
        Config {
            bind: "127.0.0.1:0".into(),
            database_url: "postgres://x".into(),
            google_client_id: google.map(|s| s.to_string()),
            bootstrap_token: None,
            totp_enc_key: [0u8; 32],
            production,
            trust_forwarded_for: false,
            cors_allowed_origins: Vec::new(),
        }
    }

    #[test]
    fn non_production_never_requires_secrets() {
        assert!(cfg(false, None)
            .check_production_secrets(false, false)
            .is_empty());
    }

    #[test]
    fn production_requires_all_three_secrets() {
        let missing = cfg(true, None).check_production_secrets(false, false);
        assert!(missing.contains(&"SENTINEL_JWT_ES256_PEM"));
        assert!(missing.contains(&"GOOGLE_OAUTH_CLIENT_ID or SENTINEL_BOOTSTRAP_TOKEN"));
        assert!(missing.contains(&"SENTINEL_TOTP_ENC_KEY"));
    }

    #[test]
    fn production_with_all_secrets_is_ok() {
        assert!(cfg(true, Some("client-id"))
            .check_production_secrets(true, true)
            .is_empty());
    }

    #[test]
    fn bootstrap_token_satisfies_identity_without_google() {
        let mut c = cfg(true, None);
        c.bootstrap_token = Some("secret".into());
        // Identity now satisfied by the bootstrap token; only JWT+TOTP would remain if unset.
        assert!(c
            .check_production_secrets(true, true)
            .iter()
            .all(|m| !m.contains("BOOTSTRAP")));
        assert!(c.check_production_secrets(true, true).is_empty());
    }

    #[test]
    fn production_reports_only_the_missing_one() {
        let missing = cfg(true, Some("client-id")).check_production_secrets(true, false);
        assert_eq!(missing, vec!["SENTINEL_TOTP_ENC_KEY"]);
    }
}
