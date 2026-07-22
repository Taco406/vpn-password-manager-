//! Key derivation: HKDF-SHA256 for key separation, Argon2id for low-entropy inputs.

use super::types::Key32;
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

/// Purpose labels for HKDF. Each maps to a fixed, versioned `info` string so keys
/// derived for one purpose can never be confused with another (D4). Changing any
/// string is a breaking format change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Info {
    WrapPlatform,
    WrapPhoneShare,
    WrapRecovery,
    VaultItem,
    VaultOuter,
    PairChannelDesktopToPhone,
    PairChannelPhoneToDesktop,
    Export,
    FileTransfer,
}

impl Info {
    pub fn as_str(self) -> &'static str {
        match self {
            Info::WrapPlatform => "sentinel/v1/wrap/platform",
            Info::WrapPhoneShare => "sentinel/v1/wrap/phone-share",
            Info::WrapRecovery => "sentinel/v1/wrap/recovery",
            Info::VaultItem => "sentinel/v1/vault/item",
            Info::VaultOuter => "sentinel/v1/vault/outer",
            Info::PairChannelDesktopToPhone => "sentinel/v1/pair/chan/desktop->phone",
            Info::PairChannelPhoneToDesktop => "sentinel/v1/pair/chan/phone->desktop",
            Info::Export => "sentinel/v1/export",
            Info::FileTransfer => "sentinel/v1/file/blob",
        }
    }
}

/// HKDF-SHA256 to a 32-byte key. `salt` may be empty; `info` is purpose separation.
pub fn hkdf32(ikm: &[u8], salt: Option<&[u8]>, info: Info) -> Key32 {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut out = [0u8; 32];
    hk.expand(info.as_str().as_bytes(), &mut out)
        .expect("32 is a valid HKDF-SHA256 output length");
    Key32::from_bytes(out)
}

/// Argon2id cost profiles. `Production` matches the brief exactly (m=64MiB, t=3,
/// p=4). `Test` is fast (m=8MiB, t=1, p=1) for CI. A const test pins Production.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Argon2Profile {
    Production,
    Test,
}

impl Argon2Profile {
    /// (memory KiB, iterations, parallelism)
    pub const PRODUCTION: (u32, u32, u32) = (65536, 3, 4);
    pub const TEST: (u32, u32, u32) = (8192, 1, 1);

    fn params(self) -> (u32, u32, u32) {
        match self {
            Argon2Profile::Production => Self::PRODUCTION,
            Argon2Profile::Test => Self::TEST,
        }
    }

    /// Resolve the profile from the environment for tests/tools. Defaults to
    /// `Production`. `SENTINEL_ARGON2_PROFILE=test` selects the fast profile, but is
    /// refused in release builds that enable a live feature — the fast profile must
    /// never protect real secrets.
    pub fn from_env_or_production() -> Self {
        match std::env::var("SENTINEL_ARGON2_PROFILE").ok().as_deref() {
            Some("test") => {
                if cfg!(all(
                    not(debug_assertions),
                    any(feature = "live-linode", feature = "live-hibp")
                )) {
                    panic!("SENTINEL_ARGON2_PROFILE=test refused in a live release build");
                }
                Argon2Profile::Test
            }
            _ => Argon2Profile::Production,
        }
    }
}

/// Derive a 32-byte KEK from a low-entropy secret (recovery key, export passphrase)
/// using Argon2id with the given profile and a 16-byte salt.
pub fn argon2id_kek(secret: &[u8], salt: &[u8; 16], profile: Argon2Profile) -> Key32 {
    let (m, t, p) = profile.params();
    let params = Params::new(m, t, p, Some(32)).expect("valid Argon2 params");
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    a2.hash_password_into(secret, salt, &mut out)
        .expect("Argon2id derivation");
    Key32::from_bytes(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_purpose_separation() {
        let ikm = [9u8; 32];
        let a = hkdf32(&ikm, None, Info::VaultItem);
        let b = hkdf32(&ikm, None, Info::VaultOuter);
        assert_ne!(
            a.as_bytes(),
            b.as_bytes(),
            "different info => different key"
        );

        // Same inputs are deterministic.
        let c = hkdf32(&ikm, None, Info::VaultItem);
        assert_eq!(a.as_bytes(), c.as_bytes());
    }

    #[test]
    fn hkdf_salt_matters() {
        let ikm = [1u8; 16];
        let a = hkdf32(&ikm, Some(b"salt-a"), Info::VaultItem);
        let b = hkdf32(&ikm, Some(b"salt-b"), Info::VaultItem);
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn argon2_test_profile_is_deterministic() {
        let salt = [3u8; 16];
        let a = argon2id_kek(b"recovery", &salt, Argon2Profile::Test);
        let b = argon2id_kek(b"recovery", &salt, Argon2Profile::Test);
        assert_eq!(a.as_bytes(), b.as_bytes());
        let c = argon2id_kek(b"recovery", &[4u8; 16], Argon2Profile::Test);
        assert_ne!(a.as_bytes(), c.as_bytes(), "salt changes the KEK");
    }

    #[test]
    fn production_profile_matches_brief_constants() {
        // The brief pins Argon2id to m=64MiB, t=3, p=4. This guards against a silent
        // downgrade of the parameters that protect the recovery key.
        assert_eq!(Argon2Profile::PRODUCTION, (65536, 3, 4));
    }

    // Runs the real 64MiB parameters once, to prove Production is usable. Ignored by
    // default (slow); CI runs it in a dedicated single-threaded step.
    #[test]
    #[ignore = "slow: exercises the real 64MiB Argon2id profile"]
    fn argon2_production_profile() {
        let salt = [5u8; 16];
        let k = argon2id_kek(b"correct horse", &salt, Argon2Profile::Production);
        assert_eq!(k.as_bytes().len(), 32);
    }
}
