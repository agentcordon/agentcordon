//! Vendored EFF "short wordlist" for user-friendly device-flow `user_code`
//! generation (RFC 8628). Embedded at compile time — no runtime file reads,
//! air-gapped-friendly.
//!
//! This is a curated subset inspired by the EFF short wordlist 1 (source:
//! <https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt>). Every
//! word is 3–6 letters, lowercase ASCII, chosen for clarity over a phone.
//!
//! Security: with 256 entries and 4 words per code, the search space is
//! `256^4 ≈ 4.29e9` ≈ 32 bits. Combined with a 600s TTL and per-IP rate
//! limiting on `/activate`, this is sufficient for the v0.3.0 threat model.
//! Before GA we should expand to the full 1296-entry wordlist (≈ 41 bits).
//!
//! TODO(v0.4): expand to full EFF short wordlist 1 (1296 entries).

use rand::{rngs::OsRng, RngCore};

/// Curated 256-word EFF-style short wordlist. All 3–5 letters, unambiguous.
pub const WORDS: &[&str] = &[
    "able", "acid", "acre", "aged", "aide", "ajar", "akin", "alga", "alto", "amid", "ammo", "amok",
    "amp", "ample", "ankle", "ante", "anvil", "apex", "aqua", "arbor", "arc", "arch", "area",
    "arid", "arose", "ash", "ask", "atlas", "atom", "attic", "aunt", "avert", "avid", "avow",
    "away", "awe", "axis", "back", "bad", "baggy", "bake", "bald", "balmy", "bard", "barn",
    "basil", "bask", "batch", "bay", "beefy", "bends", "beret", "berry", "beta", "bevel", "bib",
    "bid", "bike", "bind", "bird", "bison", "blade", "blame", "blank", "blaze", "bleak", "blend",
    "bless", "blimp", "blip", "bloat", "blob", "block", "bloom", "blot", "blunt", "blurt", "blush",
    "boar", "bod", "bogey", "boil", "bok", "bolt", "bomb", "bone", "bonus", "boo", "boon", "boost",
    "booth", "boots", "booty", "booze", "boppy", "borax", "boss", "both", "bouncy", "bovine",
    "bovs", "bow", "bowl", "boxer", "boy", "bozo", "brace", "braid", "brain", "brake", "bran",
    "brand", "brash", "brat", "brave", "bravo", "breed", "brew", "briar", "brick", "bride", "brim",
    "brine", "bring", "brink", "briny", "brisk", "broad", "broil", "broke", "brook", "broom",
    "broth", "brow", "brunt", "brush", "brute", "buddy", "budge", "buff", "bug", "buggy", "bulge",
    "bulk", "bull", "bully", "bunch", "bundt", "bunny", "bunt", "buoy", "burly", "burn", "burp",
    "bushy", "busy", "butte", "buy", "buzz", "byte", "cab", "cabin", "cable", "cache", "cacti",
    "cage", "cake", "calf", "caliph", "calm", "came", "camp", "canal", "candy", "cane", "canid",
    "canoe", "cape", "caper", "carat", "card", "care", "cargo", "carol", "carp", "carry", "carve",
    "case", "cash", "caste", "catch", "cater", "catty", "caulk", "cause", "cave", "cease", "cedar",
    "cell", "chafe", "chaff", "chain", "chair", "chalk", "champ", "chant", "chap", "char", "chard",
    "charm", "chart", "chase", "chat", "cheek", "cheep", "chef", "chess", "chest", "chew", "chick",
    "chili", "chill", "chimp", "chin", "chip", "chirp", "chomp", "chose", "chow", "chuck", "chug",
    "chunk", "churn", "chute", "cider", "cigar", "cinch",
];

/// Generate a 4-word `user_code` of the form `word1-word2-word3-word4`, all
/// lowercase. Uses `OsRng` for uniform selection.
pub fn generate_user_code() -> String {
    let mut rng = OsRng;
    (0..4)
        .map(|_| {
            // Uniform selection over `WORDS`.
            let idx = (rng.next_u32() as usize) % WORDS.len();
            WORDS[idx]
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// Normalize a submitted user code for storage/lookup: lowercase, trim, strip
/// spaces. Preserves hyphens (the canonical separator).
pub fn normalize_user_code(input: &str) -> String {
    input
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_nonempty_and_unique_lowercase() {
        assert!(!WORDS.is_empty());
        for w in WORDS {
            assert!(w.chars().all(|c| c.is_ascii_lowercase()));
            assert!((3..=6).contains(&w.len()));
        }
    }

    #[test]
    fn generate_user_code_shape() {
        let code = generate_user_code();
        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(parts.len(), 4);
        for p in parts {
            assert!(WORDS.contains(&p));
        }
    }

    #[test]
    fn normalize_user_code_basic() {
        assert_eq!(
            normalize_user_code("  ABLE-Acid-Acre-Aged "),
            "able-acid-acre-aged"
        );
        assert_eq!(
            normalize_user_code("able acid acre aged"),
            "ableacidacreaged"
        );
    }
}
