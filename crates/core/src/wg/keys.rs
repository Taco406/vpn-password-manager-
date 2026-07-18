//! WireGuard key material (Curve25519), base64-encoded as WireGuard expects.

use crate::error::{CoreError, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::ZeroizeOnDrop;

/// A WireGuard keypair. The private key zeroizes on drop.
#[derive(ZeroizeOnDrop)]
pub struct WgKeypair {
    secret: StaticSecret,
    #[zeroize(skip)]
    public: PublicKey,
}

impl WgKeypair {
    /// Generate a fresh keypair from the OS CSPRNG.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        WgKeypair { secret, public }
    }

    /// Standard-base64 private key (WireGuard `PrivateKey =`).
    pub fn private_base64(&self) -> String {
        STANDARD.encode(self.secret.to_bytes())
    }

    /// Standard-base64 public key (WireGuard `PublicKey =`).
    pub fn public_base64(&self) -> String {
        STANDARD.encode(self.public.as_bytes())
    }
}

impl std::fmt::Debug for WgKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WgKeypair(pub={}, priv=<redacted>)",
            self.public_base64()
        )
    }
}

/// Validate that a string is a 32-byte base64 WireGuard key.
pub fn validate_key(b64: &str) -> Result<()> {
    let bytes = STANDARD
        .decode(b64)
        .map_err(|_| CoreError::Invalid("wireguard key is not base64".into()))?;
    if bytes.len() != 32 {
        return Err(CoreError::Invalid("wireguard key must be 32 bytes".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_valid_keys() {
        let kp = WgKeypair::generate();
        validate_key(&kp.private_base64()).unwrap();
        validate_key(&kp.public_base64()).unwrap();
        assert_ne!(kp.private_base64(), kp.public_base64());
    }

    #[test]
    fn keys_are_unique() {
        assert_ne!(
            WgKeypair::generate().public_base64(),
            WgKeypair::generate().public_base64()
        );
    }

    #[test]
    fn debug_redacts_private() {
        let s = format!("{:?}", WgKeypair::generate());
        assert!(s.contains("priv=<redacted>"));
    }

    #[test]
    fn rejects_bad_key() {
        assert!(validate_key("not-base64!!").is_err());
        assert!(validate_key(&STANDARD.encode([0u8; 16])).is_err());
    }
}
