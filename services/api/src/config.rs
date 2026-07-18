//! Server configuration, loaded from the environment.

use jsonwebtoken::{DecodingKey, EncodingKey};

#[derive(Clone)]
pub struct Config {
    pub bind: String,
    pub database_url: String,
    /// Public Google OAuth client id used to validate the `aud` of id_tokens.
    pub google_client_id: Option<String>,
    /// 32-byte key that encrypts account TOTP secrets at rest (D8). Generated if unset.
    pub totp_enc_key: [u8; 32],
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

        Ok(Config {
            bind,
            database_url,
            google_client_id,
            totp_enc_key,
        })
    }
}
