//! Password strength via zxcvbn. This is authoritative for the health audit (D15);
//! the UI runs the JS port only for the live meter.

use zxcvbn::zxcvbn;

/// A strength assessment for display.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Strength {
    /// zxcvbn score, 0 (weakest) .. 4 (strongest).
    pub score: u8,
    /// Human-readable crack-time estimate at 10k guesses/sec (an offline-ish attacker).
    pub crack_display: String,
}

/// Assess a password. `user_inputs` (site name, username, email) are penalized if the
/// password contains them.
pub fn assess(password: &str, user_inputs: &[&str]) -> Strength {
    let entropy = zxcvbn(password, user_inputs);
    Strength {
        score: u8::from(entropy.score()),
        crack_display: entropy
            .crack_times()
            .offline_slow_hashing_1e4_per_second()
            .to_string(),
    }
}

/// True if the password is weak enough to flag in a health audit (score < 3).
pub fn is_weak(password: &str, user_inputs: &[&str]) -> bool {
    assess(password, user_inputs).score < 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_passwords_score_low() {
        assert!(assess("password", &[]).score <= 1);
        assert!(assess("12345678", &[]).score <= 1);
        assert!(is_weak("hunter2", &[]));
    }

    #[test]
    fn strong_passwords_score_high() {
        let s = assess("Tr0ub4dour-canary-Xq7!vmZ2", &[]);
        assert!(s.score >= 3, "expected strong, got {}", s.score);
        assert!(!is_weak("Tr0ub4dour-canary-Xq7!vmZ2", &[]));
    }

    #[test]
    fn user_inputs_penalized() {
        // A password that is basically the username should be weak.
        assert!(is_weak("octocat123", &["octocat"]));
    }

    #[test]
    fn crack_display_present() {
        assert!(!assess("aVeryLong-passphrase-here-42", &[])
            .crack_display
            .is_empty());
    }
}
