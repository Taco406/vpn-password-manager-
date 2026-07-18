//! EFF-style passphrase generation from a curated wordlist (D19). Entropy is reported
//! from the real deduplicated list size, never an inflated constant.

use crate::error::{CoreError, Result};
use rand::Rng;

/// The curated wordlist: common, distinct, easy-to-type English words.
pub const WORDS: &[&str] = &[
    "able", "acid", "acorn", "actor", "agile", "album", "alert", "alien", "alloy", "amber",
    "anchor", "angle", "ankle", "apple", "apron", "arbor", "arch", "arena", "armor", "arrow",
    "aspen", "atlas", "atom", "aunt", "autumn", "axis", "bacon", "badge", "bagel", "baker",
    "balmy", "banjo", "barge", "basil", "batch", "beach", "beam", "beard", "beaver", "bench",
    "berry", "bison", "blade", "blaze", "bloom", "board", "bolt", "bonus", "boot", "boulder",
    "brave", "bread", "brick", "bridge", "brisk", "bronze", "brook", "broom", "brush", "bubble",
    "bunny", "cabin", "cable", "cactus", "camel", "candle", "canoe", "canyon", "carbon", "cargo",
    "carol", "carrot", "castle", "cedar", "cello", "chalk", "charm", "cherry", "chess", "chime",
    "cider", "cinema", "circle", "citrus", "clamp", "clay", "cliff", "cloak", "clover", "cobra",
    "cocoa", "comet", "compass", "copper", "coral", "cotton", "cougar", "crane", "crater",
    "crayon", "cream", "crest", "cricket", "crimson", "crisp", "crown", "crystal", "cube",
    "curtain", "cyan", "daisy", "dance", "dawn", "delta", "denim", "desert", "diamond", "dolphin",
    "domino", "donut", "dragon", "dream", "drift", "drum", "dusk", "eagle", "east", "ebony",
    "echo", "eclipse", "elbow", "ember", "emerald", "engine", "ethos", "fable", "falcon", "fancy",
    "feather", "fern", "fiber", "fiddle", "finch", "flame", "flint", "float", "flora", "fluke",
    "flute", "foggy", "forest", "fossil", "fox", "frost", "galaxy", "garden", "garlic", "gecko",
    "ginger", "glacier", "glide", "globe", "glow", "gnome", "golden", "gopher", "grape", "grass",
    "gravel", "grove", "guitar", "hammer", "harbor", "harvest", "hazel", "hedge", "helm", "heron",
    "hickory", "hollow", "honey", "hornet", "husky", "igloo", "index", "indigo", "iris", "island",
    "ivory", "jacket", "jaguar", "jasmine", "jelly", "jewel", "jigsaw", "jolly", "jungle",
    "juniper", "kayak", "kelp", "kettle", "kitten", "koala", "ladder", "lagoon", "lantern", "lava",
    "leaf", "ledger", "lemon", "lentil", "lever", "lilac", "linen", "lizard", "llama", "lobster",
    "locket", "lotus", "lunar", "lynx", "magnet", "maple", "marble", "marsh", "meadow", "melon",
    "meteor", "mint", "mirror", "mist", "mocha", "moose", "mosaic", "moss", "mountain", "muffin",
    "mural", "mushroom", "nebula", "nectar", "needle", "nickel", "noble", "north", "nugget", "oak",
    "oasis", "ocean", "olive", "onyx", "opal", "orbit", "orchid", "otter", "oval", "owl", "oxide",
    "oyster", "paddle", "palace", "panda", "papaya", "parrot", "pasta", "peach", "pearl", "pebble",
    "penguin", "pepper", "petal", "pewter", "phoenix", "piano", "pigeon", "pilot", "pine",
    "planet", "plum", "pocket", "pollen", "pond", "poppy", "portal", "potato", "prairie", "prism",
    "puffin", "pumpkin", "quartz", "quiet", "quilt", "quiver", "rabbit", "radar", "raft", "rain",
    "ranch", "raven", "reef", "relic", "ribbon", "ridge", "river", "robin", "rocket", "rose",
    "ruby", "rudder", "rustic", "saddle", "salmon", "sand", "sapphire", "satin", "scarf", "scout",
    "sculpt", "seal", "sequoia", "shadow", "shell", "shrub", "silk", "silver", "sketch", "sled",
    "slope", "snail", "snow", "socket", "solar", "sonnet", "spark", "sparrow", "spice", "spiral",
    "spruce", "squid", "stag", "stone", "storm", "stream", "sugar", "summit", "sunset", "swan",
    "sword", "syrup", "tango", "teak", "temple", "thistle", "thunder", "tiger", "timber", "toast",
    "topaz", "torch", "tower", "trail", "trout", "tulip", "tundra", "turtle", "twig", "umber",
    "unity", "urchin", "valley", "vanilla", "velvet", "vine", "violet", "viper", "vista", "vortex",
    "walnut", "walrus", "wander", "wasp", "water", "wave", "weasel", "wheat", "whisker", "willow",
    "window", "winter", "wizard", "wolf", "wombat", "wood", "yarn", "yeast", "yield", "yodel",
    "zebra", "zenith", "zephyr", "zinc", "zodiac",
];

/// Passphrase specification.
#[derive(Clone, Debug)]
pub struct PassphraseSpec {
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
    pub include_number: bool,
}

impl Default for PassphraseSpec {
    fn default() -> Self {
        PassphraseSpec {
            words: 6,
            separator: "-".into(),
            capitalize: true,
            include_number: true,
        }
    }
}

/// Bits of entropy per word, from the real deduplicated list size.
pub fn bits_per_word() -> f64 {
    (unique_word_count() as f64).log2()
}

fn unique_word_count() -> usize {
    // Words are authored unique; a test enforces it. Count directly.
    WORDS.len()
}

/// Generate a passphrase and its entropy estimate.
pub fn passphrase(spec: &PassphraseSpec) -> Result<(String, f64)> {
    if spec.words == 0 {
        return Err(CoreError::Invalid(
            "passphrase needs at least one word".into(),
        ));
    }
    let mut rng = rand::rngs::OsRng;
    let mut parts: Vec<String> = Vec::with_capacity(spec.words);
    for _ in 0..spec.words {
        let w = WORDS[rng.gen_range(0..WORDS.len())];
        parts.push(if spec.capitalize {
            let mut c = w.chars();
            match c.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + c.as_str(),
                None => String::new(),
            }
        } else {
            w.to_string()
        });
    }
    let mut phrase = parts.join(&spec.separator);
    let mut entropy = spec.words as f64 * bits_per_word();
    if spec.include_number {
        let n = rng.gen_range(0..1000);
        phrase.push_str(&spec.separator);
        phrase.push_str(&n.to_string());
        entropy += (1000f64).log2();
    }
    Ok((phrase, entropy))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn wordlist_has_no_duplicates() {
        let set: HashSet<&&str> = WORDS.iter().collect();
        assert_eq!(set.len(), WORDS.len(), "duplicate words in the list");
        assert!(WORDS.len() >= 256, "wordlist too small: {}", WORDS.len());
    }

    #[test]
    fn produces_requested_word_count() {
        let spec = PassphraseSpec {
            words: 5,
            separator: "-".into(),
            capitalize: false,
            include_number: false,
        };
        let (p, _) = passphrase(&spec).unwrap();
        assert_eq!(p.split('-').count(), 5);
    }

    #[test]
    fn entropy_is_from_real_list_size() {
        let spec = PassphraseSpec {
            words: 6,
            include_number: false,
            ..Default::default()
        };
        let (_, e) = passphrase(&spec).unwrap();
        let expected = 6.0 * (WORDS.len() as f64).log2();
        assert!((e - expected).abs() < 1e-9);
        assert!(e > 45.0, "6-word passphrase should exceed 45 bits, got {e}");
    }

    #[test]
    fn capitalize_and_number() {
        let spec = PassphraseSpec::default();
        let (p, _) = passphrase(&spec).unwrap();
        assert!(p.chars().next().unwrap().is_ascii_uppercase());
        assert!(p.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn distinct_each_call() {
        let spec = PassphraseSpec::default();
        assert_ne!(passphrase(&spec).unwrap().0, passphrase(&spec).unwrap().0);
    }
}
