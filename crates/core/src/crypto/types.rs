//! Core key/nonce newtypes with redacted `Debug` and zeroize-on-drop.

use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 256-bit symmetric key. Zeroized on drop; `Debug` never prints the bytes.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key32([u8; 32]);

impl Key32 {
    /// Wrap raw bytes as a key. Prefer [`Key32::random`] for fresh keys.
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Key32(b)
    }

    /// Generate a fresh key from the OS CSPRNG.
    pub fn random() -> Self {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        Key32(b)
    }

    /// Borrow the raw key bytes. Callers must not copy these into long-lived,
    /// non-zeroizing storage.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for Key32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key32(<redacted>)")
    }
}

/// A 192-bit (24-byte) XChaCha20-Poly1305 nonce. Not secret, but distinct type
/// to prevent mixing nonces and keys at call sites.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Nonce24([u8; 24]);

impl Nonce24 {
    /// Fresh random nonce from the OS CSPRNG. XChaCha's 192-bit nonce makes random
    /// generation collision-safe without a counter.
    pub fn random() -> Self {
        let mut b = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut b);
        Nonce24(b)
    }

    pub fn from_bytes(b: [u8; 24]) -> Self {
        Nonce24(b)
    }

    pub fn as_bytes(&self) -> &[u8; 24] {
        &self.0
    }
}

impl std::fmt::Debug for Nonce24 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Nonces are public; still keep it terse.
        write!(f, "Nonce24({} bytes)", self.0.len())
    }
}

/// A short-lived buffer of secret bytes that zeroizes on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(v: Vec<u8>) -> Self {
        SecretBytes(v)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes(<redacted {} bytes>)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let k = Key32::from_bytes([7u8; 32]);
        let s = format!("{k:?}");
        assert_eq!(s, "Key32(<redacted>)");
        assert!(!s.contains('7'));

        let sb = SecretBytes::new(vec![1, 2, 3]);
        assert_eq!(format!("{sb:?}"), "SecretBytes(<redacted 3 bytes>)");
    }

    #[test]
    fn random_keys_differ() {
        assert_ne!(Key32::random().as_bytes(), Key32::random().as_bytes());
        assert_ne!(Nonce24::random().as_bytes(), Nonce24::random().as_bytes());
    }
}
