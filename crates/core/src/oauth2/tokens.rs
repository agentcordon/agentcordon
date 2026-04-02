//! OAuth 2.0 token generation and PKCE validation.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Generate a cryptographically random authorization code.
///
/// Returns `(raw_code, code_hash)` where the hash is SHA-256 hex-encoded.
pub fn generate_auth_code() -> (String, String) {
    let raw = generate_random_token();
    let hash = hash_token(&raw);
    (raw, hash)
}

/// Generate a cryptographically random access token.
///
/// Returns `(raw_token, token_hash)` where the hash is SHA-256 hex-encoded.
pub fn generate_access_token() -> (String, String) {
    let raw = generate_random_token();
    let hash = hash_token(&raw);
    (raw, hash)
}

/// Generate a cryptographically random refresh token.
///
/// Returns `(raw_token, token_hash)` where the hash is SHA-256 hex-encoded.
pub fn generate_refresh_token() -> (String, String) {
    let raw = generate_random_token();
    let hash = hash_token(&raw);
    (raw, hash)
}

/// Generate a client ID in `ac_cli_{16_hex_chars}` format.
pub fn generate_client_id() -> String {
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("ac_cli_{}", hex::encode(bytes))
}

/// Generate a client secret.
///
/// Returns `(raw_secret, secret_hash)` where the hash is SHA-256 hex-encoded.
pub fn generate_client_secret() -> (String, String) {
    let raw = generate_random_token();
    let hash = hash_token(&raw);
    (raw, hash)
}

/// SHA-256 hash a token string and return hex-encoded digest.
///
/// Plain SHA-256 (not HMAC) is appropriate here because OAuth tokens are
/// generated from 32 cryptographically random bytes (256 bits of entropy),
/// making offline brute-force infeasible regardless of keyed hashing.
/// Session tokens use HMAC-SHA256 because they may carry lower entropy.
pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Validate a PKCE code verifier against a code challenge (S256 method).
///
/// `code_challenge = base64url(SHA-256(code_verifier))`
///
/// Uses constant-time comparison to prevent timing attacks.
pub fn validate_pkce(code_verifier: &str, code_challenge: &str) -> bool {
    let digest = Sha256::digest(code_verifier.as_bytes());
    let expected = URL_SAFE_NO_PAD.encode(digest);
    bool::from(expected.as_bytes().ct_eq(code_challenge.as_bytes()))
}

/// Generate 32 random bytes, base64url-encoded (no padding).
fn generate_random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_auth_code() {
        let (raw, hash) = generate_auth_code();
        assert!(!raw.is_empty());
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, hash_token(&raw));
    }

    #[test]
    fn test_generate_access_token() {
        let (raw, hash) = generate_access_token();
        assert!(!raw.is_empty());
        assert_eq!(hash, hash_token(&raw));
    }

    #[test]
    fn test_generate_refresh_token() {
        let (raw, hash) = generate_refresh_token();
        assert!(!raw.is_empty());
        assert_eq!(hash, hash_token(&raw));
    }

    #[test]
    fn test_generate_client_id_format() {
        let id = generate_client_id();
        assert!(id.starts_with("ac_cli_"));
        assert_eq!(id.len(), 7 + 16); // "ac_cli_" + 16 hex chars
    }

    #[test]
    fn test_generate_client_secret() {
        let (raw, hash) = generate_client_secret();
        assert!(!raw.is_empty());
        assert_eq!(hash, hash_token(&raw));
    }

    #[test]
    fn test_hash_token_deterministic() {
        let h1 = hash_token("test-token");
        let h2 = hash_token("test-token");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_hash_token_different_inputs() {
        let h1 = hash_token("token-a");
        let h2 = hash_token("token-b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_validate_pkce_valid() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let digest = Sha256::digest(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(digest);
        assert!(validate_pkce(verifier, &challenge));
    }

    #[test]
    fn test_validate_pkce_invalid() {
        assert!(!validate_pkce("wrong-verifier", "wrong-challenge"));
    }

    #[test]
    fn test_token_uniqueness() {
        let tokens: std::collections::HashSet<String> =
            (0..100).map(|_| generate_random_token()).collect();
        assert_eq!(tokens.len(), 100);
    }

    #[test]
    fn test_constant_time_eq_via_subtle() {
        assert!(bool::from(b"hello".ct_eq(b"hello")));
        assert!(!bool::from(b"hello".ct_eq(b"world")));
        // Different lengths always return false
        assert!(!bool::from(b"hello".ct_eq(b"hell")));
    }
}
