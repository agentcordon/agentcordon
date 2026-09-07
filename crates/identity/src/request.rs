//! The request signature: what the CLI puts in `X-AC-PublicKey`,
//! `X-AC-Timestamp`, `X-AC-Nonce`, `X-AC-Signature`, and what the broker
//! checks.
//!
//! The nonce is 16 random bytes as lowercase hex, fresh per request. It is
//! inside the signed bytes, so a replay must reuse it verbatim; the broker
//! remembers every `(key, nonce)` it has accepted for the skew window and
//! refuses a second presentation. That check needs state and lives in the
//! broker; this module only fixes the format and the bytes.

use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

use ed25519_dalek::Verifier;
use rand::RngCore;

use crate::key::{parse_public_key, parse_signature, WorkspaceKey};

/// Maximum accepted difference between the signed timestamp and the
/// verifier's clock, in seconds.
pub const MAX_CLOCK_SKEW_SECS: i64 = 30;

/// Length of a nonce on the wire: 16 bytes as lowercase hex.
pub const NONCE_HEX_LEN: usize = 32;

/// Why a signature was rejected. Deliberately coarse: a caller turning this
/// into an HTTP response should not tell an attacker which check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// Not hex, not 32 bytes, or not a valid Ed25519 point.
    #[error("invalid public key")]
    InvalidPublicKey,
    /// Not hex or not 64 bytes.
    #[error("invalid signature")]
    InvalidSignature,
    /// Well-formed, but not a signature by this key over these bytes.
    #[error("signature verification failed")]
    SignatureMismatch,
    /// Timestamp unparsable or more than [`MAX_CLOCK_SKEW_SECS`] from now.
    #[error("timestamp out of range")]
    TimestampOutOfRange,
    /// Nonce is not exactly [`NONCE_HEX_LEN`] lowercase hex characters.
    #[error("invalid nonce")]
    InvalidNonce,
}

/// Headers to attach to a signed broker request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHeaders {
    /// `X-AC-PublicKey`: hex public key.
    pub public_key: String,
    /// `X-AC-Timestamp`: Unix seconds, decimal.
    pub timestamp: String,
    /// `X-AC-Nonce`: 16 random bytes, lowercase hex.
    pub nonce: String,
    /// `X-AC-Signature`: hex Ed25519 signature over [`signing_payload`].
    pub signature: String,
}

/// A fresh nonce: 16 bytes from the OS CSPRNG, lowercase hex.
pub fn generate_nonce() -> String {
    let mut bytes = [0u8; NONCE_HEX_LEN / 2];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Check that a nonce is exactly [`NONCE_HEX_LEN`] lowercase hex
/// characters. Both the CLI and the broker accept nothing else, so the
/// broker's seen-set holds fixed-size keys.
pub fn validate_nonce(nonce: &str) -> Result<(), VerifyError> {
    if nonce.len() == NONCE_HEX_LEN
        && nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(VerifyError::InvalidNonce)
    }
}

/// The exact bytes that are signed: `METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY`.
///
/// `path` must already be canonical (see
/// [`crate::canonicalise_path_and_query`]). `body` is the raw request body;
/// an empty body leaves the payload ending in the fourth `\n`.
pub fn signing_payload(
    method: &str,
    path: &str,
    timestamp: &str,
    nonce: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        method.len() + path.len() + timestamp.len() + nonce.len() + body.len() + 4,
    );
    payload.extend_from_slice(method.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(path.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(timestamp.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(nonce.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(body);
    payload
}

/// Sign a request with the current time as the timestamp and a fresh nonce.
///
/// Fails only if the system clock is before the Unix epoch.
pub fn sign_request(
    key: &WorkspaceKey,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<SignedHeaders, SystemTimeError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    Ok(sign_request_at(key, method, path, body, now))
}

/// Sign a request with an explicit timestamp (Unix seconds) and a fresh
/// nonce.
pub fn sign_request_at(
    key: &WorkspaceKey,
    method: &str,
    path: &str,
    body: &[u8],
    timestamp: i64,
) -> SignedHeaders {
    sign_request_with(key, method, path, body, timestamp, &generate_nonce())
}

/// Sign a request with an explicit timestamp and nonce. This is the
/// primitive the other two wrap; tests and vectors call it directly.
pub fn sign_request_with(
    key: &WorkspaceKey,
    method: &str,
    path: &str,
    body: &[u8],
    timestamp: i64,
    nonce: &str,
) -> SignedHeaders {
    let timestamp = timestamp.to_string();
    let signature = key.sign(&signing_payload(method, path, &timestamp, nonce, body));
    SignedHeaders {
        public_key: key.public_key_hex(),
        timestamp,
        nonce: nonce.to_string(),
        signature: hex::encode(signature.to_bytes()),
    }
}

/// Verify a signed request.
///
/// `now` is the verifier's clock in Unix seconds; the timestamp must be
/// within [`MAX_CLOCK_SKEW_SECS`] of it. `path` must be the canonical
/// form of the received request. Checks run in a fixed order — key,
/// timestamp, nonce form, signature encoding, signature — so a request
/// that fails several ways reports the first. Replay of an accepted nonce
/// is the caller's check.
#[allow(clippy::too_many_arguments)]
pub fn verify_request(
    public_key_hex: &str,
    timestamp_str: &str,
    nonce: &str,
    signature_hex: &str,
    method: &str,
    path: &str,
    body: &[u8],
    now: i64,
) -> Result<(), VerifyError> {
    let verifying_key = parse_public_key(public_key_hex)?;
    check_timestamp(timestamp_str, now)?;
    validate_nonce(nonce)?;

    let signature = parse_signature(signature_hex)?;
    let payload = signing_payload(method, path, timestamp_str, nonce, body);
    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| VerifyError::SignatureMismatch)
}

/// Parse a decimal Unix timestamp and check it against `now`.
pub(crate) fn check_timestamp(timestamp_str: &str, now: i64) -> Result<i64, VerifyError> {
    let timestamp: i64 = timestamp_str
        .parse()
        .map_err(|_| VerifyError::TimestampOutOfRange)?;
    if (now - timestamp).abs() > MAX_CLOCK_SKEW_SECS {
        return Err(VerifyError::TimestampOutOfRange);
    }
    Ok(timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn verify(
        h: &SignedHeaders,
        method: &str,
        path: &str,
        body: &[u8],
        now: i64,
    ) -> Result<(), VerifyError> {
        verify_request(
            &h.public_key,
            &h.timestamp,
            &h.nonce,
            &h.signature,
            method,
            path,
            body,
            now,
        )
    }

    #[test]
    fn sign_request_uses_current_time_and_a_fresh_nonce() {
        let key = WorkspaceKey::generate();
        let a = sign_request(&key, "GET", "/status", b"").unwrap();
        let b = sign_request(&key, "GET", "/status", b"").unwrap();
        let ts: i64 = a.timestamp.parse().unwrap();
        assert!((now() - ts).abs() <= 1);
        assert_eq!(a.nonce.len(), NONCE_HEX_LEN);
        assert_ne!(a.nonce, b.nonce, "two signatures must not share a nonce");
        assert_ne!(a.signature, b.signature);
        verify(&a, "GET", "/status", b"", now()).unwrap();
        verify(&b, "GET", "/status", b"", now()).unwrap();
    }

    #[test]
    fn generate_nonce_is_lowercase_hex_of_16_bytes() {
        let n = generate_nonce();
        assert_eq!(validate_nonce(&n), Ok(()));
        assert_eq!(hex::decode(&n).unwrap().len(), 16);
    }

    #[test]
    fn validate_nonce_rejects_wrong_length_uppercase_and_non_hex() {
        assert_eq!(validate_nonce(""), Err(VerifyError::InvalidNonce));
        assert_eq!(
            validate_nonce(&"a".repeat(31)),
            Err(VerifyError::InvalidNonce)
        );
        assert_eq!(
            validate_nonce(&"a".repeat(33)),
            Err(VerifyError::InvalidNonce)
        );
        assert_eq!(
            validate_nonce(&"A".repeat(32)),
            Err(VerifyError::InvalidNonce)
        );
        assert_eq!(
            validate_nonce(&"g".repeat(32)),
            Err(VerifyError::InvalidNonce)
        );
        assert_eq!(validate_nonce(&"0".repeat(32)), Ok(()));
    }

    #[test]
    fn verify_rejects_malformed_nonce_before_checking_signature() {
        let key = WorkspaceKey::generate();
        let t = now();
        let h = sign_request_with(&key, "GET", "/status", b"", t, "short");
        assert_eq!(
            verify(&h, "GET", "/status", b"", t),
            Err(VerifyError::InvalidNonce)
        );
    }

    #[test]
    fn verify_rejects_nonce_that_differs_from_the_signed_one() {
        let key = WorkspaceKey::generate();
        let t = now();
        let mut h = sign_request_at(&key, "GET", "/status", b"", t);
        h.nonce = generate_nonce();
        assert_eq!(
            verify(&h, "GET", "/status", b"", t),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn verify_rejects_body_that_differs() {
        let key = WorkspaceKey::generate();
        let t = now();
        let h = sign_request_at(&key, "POST", "/x", b"wrong body", t);
        assert_eq!(
            verify(&h, "POST", "/x", b"actual", t),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn verify_rejects_query_dropped_by_verifier() {
        let key = WorkspaceKey::generate();
        let t = now();
        let h = sign_request_at(&key, "GET", "/foo?a=1", b"", t);
        assert_eq!(
            verify(&h, "GET", "/foo", b"", t),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn verify_rejects_skew_past_limit_in_both_directions() {
        let key = WorkspaceKey::generate();
        let t = 1_700_000_000;
        let h = sign_request_at(&key, "GET", "/status", b"", t);
        let check = |now| verify(&h, "GET", "/status", b"", now);
        assert_eq!(check(t + MAX_CLOCK_SKEW_SECS), Ok(()));
        assert_eq!(check(t - MAX_CLOCK_SKEW_SECS), Ok(()));
        assert_eq!(
            check(t + MAX_CLOCK_SKEW_SECS + 1),
            Err(VerifyError::TimestampOutOfRange)
        );
        assert_eq!(
            check(t - MAX_CLOCK_SKEW_SECS - 1),
            Err(VerifyError::TimestampOutOfRange)
        );
    }

    #[test]
    fn verify_rejects_unparsable_timestamp() {
        let key = WorkspaceKey::generate();
        let mut h = sign_request_at(&key, "GET", "/status", b"", now());
        h.timestamp = "soon".into();
        assert_eq!(
            verify(&h, "GET", "/status", b"", now()),
            Err(VerifyError::TimestampOutOfRange)
        );
    }

    #[test]
    fn verify_rejects_malformed_key_and_signature() {
        let key = WorkspaceKey::generate();
        let t = now();
        let h = sign_request_at(&key, "GET", "/status", b"", t);
        let mut bad_key = h.clone();
        bad_key.public_key = "zz".into();
        assert_eq!(
            verify(&bad_key, "GET", "/status", b"", t),
            Err(VerifyError::InvalidPublicKey)
        );
        let mut bad_sig = h.clone();
        bad_sig.signature = "abcd".into();
        assert_eq!(
            verify(&bad_sig, "GET", "/status", b"", t),
            Err(VerifyError::InvalidSignature)
        );
    }

    #[test]
    fn verify_rejects_signature_from_another_key() {
        let a = WorkspaceKey::generate();
        let b = WorkspaceKey::generate();
        let t = now();
        let mut h = sign_request_at(&a, "GET", "/status", b"", t);
        h.public_key = b.public_key_hex();
        assert_eq!(
            verify(&h, "GET", "/status", b"", t),
            Err(VerifyError::SignatureMismatch)
        );
    }
}
