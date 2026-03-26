use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::Rng;
use rand::RngCore;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Generate a cryptographically random session token (32 bytes, base64url-encoded).
pub fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate a cryptographically random CSRF token (32 alphanumeric characters).
pub fn generate_csrf_token() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rngs::OsRng;
    (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Hash a session token with HMAC-SHA256 using the provided session key,
/// returning a hex-encoded digest.
///
/// The hash is stored in the database; the raw token is given to the client.
/// Using HMAC (instead of plain SHA-256) means a database compromise does not
/// allow offline pre-image attacks without also knowing the HMAC key.
pub fn hash_session_token_hmac(token: &str, session_key: &[u8; 32]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(session_key).expect("HMAC-SHA256 accepts any key length");
    mac.update(token.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// Legacy SHA-256 hashing function — kept for reference and migration.
/// New code should use `hash_session_token_hmac` instead.
#[allow(dead_code)]
pub fn hash_session_token_sha256(token: &str) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session_key() -> [u8; 32] {
        [0xABu8; 32]
    }

    #[test]
    fn generated_token_is_valid_base64url() {
        let token = generate_session_token();
        let decoded = URL_SAFE_NO_PAD.decode(&token);
        assert!(decoded.is_ok(), "generated token must be valid base64url");
        assert_eq!(decoded.unwrap().len(), 32, "token must decode to 32 bytes");
    }

    #[test]
    fn generated_tokens_are_unique() {
        let t1 = generate_session_token();
        let t2 = generate_session_token();
        assert_ne!(t1, t2, "two generated tokens must differ");
    }

    #[test]
    fn hmac_hash_is_deterministic() {
        let key = test_session_key();
        let token = "test-session-token";
        let h1 = hash_session_token_hmac(token, &key);
        let h2 = hash_session_token_hmac(token, &key);
        assert_eq!(h1, h2, "same input must produce same hash");
    }

    #[test]
    fn hmac_hash_is_hex_encoded() {
        let key = test_session_key();
        let token = "test-session-token";
        let hash = hash_session_token_hmac(token, &key);
        // HMAC-SHA256 produces 32 bytes = 64 hex chars
        assert_eq!(
            hash.len(),
            64,
            "HMAC-SHA-256 hex digest must be 64 characters"
        );
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "hash must be valid hex"
        );
    }

    #[test]
    fn hmac_different_tokens_produce_different_hashes() {
        let key = test_session_key();
        let h1 = hash_session_token_hmac("token-a", &key);
        let h2 = hash_session_token_hmac("token-b", &key);
        assert_ne!(h1, h2, "different tokens must produce different hashes");
    }

    #[test]
    fn hmac_different_keys_produce_different_hashes() {
        let key1 = [0xABu8; 32];
        let key2 = [0xCDu8; 32];
        let token = "same-token";
        let h1 = hash_session_token_hmac(token, &key1);
        let h2 = hash_session_token_hmac(token, &key2);
        assert_ne!(h1, h2, "different keys must produce different hashes");
    }

    #[test]
    fn hmac_hash_differs_from_sha256_hash() {
        let key = test_session_key();
        let token = "test-session-token";
        let hmac_hash = hash_session_token_hmac(token, &key);
        let sha256_hash = hash_session_token_sha256(token);
        assert_ne!(
            hmac_hash, sha256_hash,
            "HMAC hash must differ from plain SHA-256 hash"
        );
    }

    #[test]
    fn roundtrip_generate_and_hmac_hash() {
        let key = test_session_key();
        let token = generate_session_token();
        let hash = hash_session_token_hmac(&token, &key);
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, hash_session_token_hmac(&token, &key));
    }

    #[test]
    fn csrf_token_length_and_charset() {
        let token = generate_csrf_token();
        assert_eq!(token.len(), 32, "CSRF token must be 32 characters");
        assert!(
            token.chars().all(|c| c.is_ascii_alphanumeric()),
            "CSRF token must be alphanumeric"
        );
    }

    #[test]
    fn csrf_tokens_are_unique() {
        let t1 = generate_csrf_token();
        let t2 = generate_csrf_token();
        assert_ne!(t1, t2, "two generated CSRF tokens must differ");
    }
}
