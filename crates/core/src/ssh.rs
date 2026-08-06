//! SSH host-key fingerprinting and pin comparison — the security-critical
//! *decisions* behind the desktop app's embedded root terminal.
//!
//! The russh session, PTY and streaming plumbing lives in the desktop crate
//! (`apps/desktop/src-tauri/src/ssh.rs`), which cannot compile on the Linux CI
//! runners (webkit2gtk). The parts where a bug is a *security hole* — how a host
//! key is fingerprinted, and whether a freshly-presented key matches the one we
//! pinned on first connect — live here in the core crate instead, where they
//! compile and run under `cargo test` on every push. A silently-accepted host
//! key change is a man-in-the-middle, so this module is covered by tests.

use base64::Engine;
use sha2::{Digest, Sha256};

/// Format a raw SSH public-key blob (the RFC 4253 wire encoding of the host key)
/// as the OpenSSH SHA256 fingerprint: the literal `SHA256:` followed by the
/// **unpadded** base64 of the SHA-256 digest.
///
/// This is byte-for-byte what `ssh-keygen -lf` and the OpenSSH client print, so
/// the fingerprint the app shows the user on first connect can be eyeballed
/// against any other tool.
pub fn sha256_fingerprint(key_blob: &[u8]) -> String {
    let digest = Sha256::digest(key_blob);
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
    format!("SHA256:{b64}")
}

/// Whether a freshly-presented host-key fingerprint matches the pinned one.
///
/// Trimmed, exact, case-sensitive compare (base64 is case-sensitive — `a` and
/// `A` are different bytes, so a case-folding compare would accept keys that
/// aren't the pinned one). An empty pin means "nothing pinned yet" and never
/// matches: the caller must handle trust-on-first-use as its own explicit branch
/// (capture + persist + show the user), rather than this function silently
/// treating "no pin" as "any key is fine".
pub fn fingerprint_matches(pinned: &str, presented: &str) -> bool {
    let pinned = pinned.trim();
    let presented = presented.trim();
    !pinned.is_empty() && pinned == presented
}

#[cfg(test)]
mod tests {
    use super::*;

    // The SHA-256 of the empty input is a well-known constant; its unpadded
    // base64 is the fingerprint OpenSSH would print for a (degenerate) empty
    // blob. This pins the exact format — algorithm label, base64 alphabet, and
    // the crucial *no padding* — against a value that doesn't depend on this
    // code being correct.
    #[test]
    fn fingerprint_of_empty_is_known_vector() {
        assert_eq!(
            sha256_fingerprint(b""),
            "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
        );
    }

    #[test]
    fn fingerprint_is_deterministic_and_input_sensitive() {
        assert_eq!(
            sha256_fingerprint(b"host-key-a"),
            sha256_fingerprint(b"host-key-a")
        );
        assert_ne!(
            sha256_fingerprint(b"host-key-a"),
            sha256_fingerprint(b"host-key-b")
        );
    }

    #[test]
    fn fingerprint_never_carries_base64_padding() {
        // Any digest is 32 bytes → 43 base64 chars + one '=' if padded. We must
        // never emit the pad, or the string won't match `ssh-keygen` output.
        for input in [&b""[..], b"x", b"a longer host key blob here"] {
            assert!(!sha256_fingerprint(input).contains('='));
        }
    }

    #[test]
    fn matching_is_exact_and_case_sensitive() {
        let fp = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";
        assert!(fingerprint_matches(fp, fp));
        // whitespace on either side is tolerated (stored/wire may differ)
        assert!(fingerprint_matches(&format!("  {fp}  "), fp));
        // one flipped character must fail
        assert!(!fingerprint_matches(
            fp,
            "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFu"
        ));
    }

    #[test]
    fn empty_pin_never_matches() {
        // "nothing pinned yet" is the caller's trust-on-first-use branch, not a
        // silent accept here.
        assert!(!fingerprint_matches("", "SHA256:anything"));
        assert!(!fingerprint_matches("   ", "SHA256:anything"));
        assert!(!fingerprint_matches("", ""));
    }
}
