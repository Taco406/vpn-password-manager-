//! Secure password + passphrase generation using the OS CSPRNG, with zxcvbn strength
//! assessment.

pub mod passphrase;
pub mod strength;

pub use passphrase::{passphrase, PassphraseSpec};
pub use strength::{assess, Strength};

use crate::error::{CoreError, Result};
use rand::seq::SliceRandom;
use rand::Rng;

/// Charset password specification.
#[derive(Clone, Debug)]
pub struct PasswordSpec {
    pub length: usize,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for PasswordSpec {
    fn default() -> Self {
        PasswordSpec {
            length: 20,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

const LOWER: &str = "abcdefghijkmnpqrstuvwxyz"; // no l, o
const LOWER_AMBIG: &str = "l o";
const UPPER: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // no I, O
const DIGITS: &str = "23456789"; // no 0, 1
const DIGITS_AMBIG: &str = "0 1";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?";

/// Generate a password meeting the spec. Guarantees at least one character from each
/// enabled class (rejection-free: places one of each, fills the rest, shuffles).
pub fn password(spec: &PasswordSpec) -> Result<String> {
    let mut classes: Vec<Vec<char>> = Vec::new();
    let mut push_class = |base: &str, ambiguous: &str| {
        let mut chars: Vec<char> = base.chars().collect();
        if !spec.exclude_ambiguous {
            for c in ambiguous.split_whitespace() {
                if let Some(ch) = c.chars().next() {
                    chars.push(ch);
                }
            }
        }
        classes.push(chars);
    };
    if spec.lower {
        push_class(LOWER, LOWER_AMBIG);
    }
    if spec.upper {
        push_class(UPPER, "I O");
    }
    if spec.digits {
        push_class(DIGITS, DIGITS_AMBIG);
    }
    if spec.symbols {
        push_class(SYMBOLS, "");
    }

    if classes.is_empty() {
        return Err(CoreError::Invalid("no character classes enabled".into()));
    }
    if spec.length < classes.len() {
        return Err(CoreError::Invalid(format!(
            "length {} too short for {} required classes",
            spec.length,
            classes.len()
        )));
    }

    let mut rng = rand::rngs::OsRng;
    let mut out: Vec<char> = Vec::with_capacity(spec.length);

    // One guaranteed char from each enabled class.
    for class in &classes {
        out.push(class[rng.gen_range(0..class.len())]);
    }
    // Fill the rest from the union.
    let union: Vec<char> = classes.iter().flatten().copied().collect();
    while out.len() < spec.length {
        out.push(union[rng.gen_range(0..union.len())]);
    }
    out.shuffle(&mut rng);
    Ok(out.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_length() {
        for len in [8usize, 16, 32, 64] {
            let spec = PasswordSpec {
                length: len,
                ..Default::default()
            };
            assert_eq!(password(&spec).unwrap().chars().count(), len);
        }
    }

    #[test]
    fn includes_each_enabled_class() {
        let spec = PasswordSpec {
            length: 24,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: true,
        };
        // Over many draws, every class should appear at least once.
        let p = password(&spec).unwrap();
        assert!(p.chars().any(|c| c.is_ascii_lowercase()));
        assert!(p.chars().any(|c| c.is_ascii_uppercase()));
        assert!(p.chars().any(|c| c.is_ascii_digit()));
        assert!(p.chars().any(|c| SYMBOLS.contains(c)));
    }

    #[test]
    fn exclude_ambiguous_removes_confusables() {
        let spec = PasswordSpec {
            length: 200,
            exclude_ambiguous: true,
            ..Default::default()
        };
        let p = password(&spec).unwrap();
        for bad in ['l', 'I', 'O', '0', '1', 'o'] {
            assert!(!p.contains(bad), "ambiguous char {bad} present");
        }
    }

    #[test]
    fn generates_distinct_passwords() {
        let spec = PasswordSpec::default();
        let a = password(&spec).unwrap();
        let b = password(&spec).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn errors_when_no_classes() {
        let spec = PasswordSpec {
            length: 10,
            lower: false,
            upper: false,
            digits: false,
            symbols: false,
            exclude_ambiguous: false,
        };
        assert!(password(&spec).is_err());
    }
}
