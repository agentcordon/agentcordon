//! The self-signature on `agentcordon register`.
//!
//! The CLI proves it holds the private key for the public key it is
//! registering by signing
//! `WORKSPACE_NAME\nPUBLIC_KEY_HEX\nSCOPES\nTIMESTAMP\nNONCE` where
//! `SCOPES` is the scope list joined by single spaces. The timestamp and
//! nonce give the register body the same replay protection as a signed
//! request: the broker checks the timestamp against its clock with
//! [`MAX_CLOCK_SKEW_SECS`] and remembers the nonce for the window.

use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

use ed25519_dalek::Verifier;

use crate::key::{parse_public_key, parse_signature, pk_hash_of, WorkspaceKey};
#[allow(unused_imports)] // referenced from docs
use crate::request::MAX_CLOCK_SKEW_SECS;
use crate::request::{check_timestamp, generate_nonce, validate_nonce, VerifyError};

/// The body of `POST /register` on the broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterPayload {
    pub workspace_name: String,
    /// Hex public key.
    pub public_key: String,
    pub scopes: Vec<String>,
    /// Unix seconds, decimal.
    pub timestamp: String,
    /// 16 random bytes, lowercase hex.
    pub nonce: String,
    /// Hex Ed25519 signature over [`register_payload`].
    pub signature: String,
}

/// The exact string that is signed:
/// `NAME\nPUBLIC_KEY_HEX\nSCOPE SCOPE ...\nTIMESTAMP\nNONCE`.
pub fn register_payload(
    workspace_name: &str,
    public_key_hex: &str,
    scopes: &[String],
    timestamp: &str,
    nonce: &str,
) -> String {
    format!(
        "{workspace_name}\n{public_key_hex}\n{}\n{timestamp}\n{nonce}",
        scopes.join(" ")
    )
}

/// Build and sign the register body with the current time and a fresh
/// nonce. Fails only if the system clock is before the Unix epoch.
pub fn sign_register(
    key: &WorkspaceKey,
    workspace_name: &str,
    scopes: &[String],
) -> Result<RegisterPayload, SystemTimeError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    Ok(sign_register_at(
        key,
        workspace_name,
        scopes,
        now,
        &generate_nonce(),
    ))
}

/// Build and sign the register body with an explicit timestamp and nonce.
pub fn sign_register_at(
    key: &WorkspaceKey,
    workspace_name: &str,
    scopes: &[String],
    timestamp: i64,
    nonce: &str,
) -> RegisterPayload {
    let public_key = key.public_key_hex();
    let timestamp = timestamp.to_string();
    let signature = key
        .sign(register_payload(workspace_name, &public_key, scopes, &timestamp, nonce).as_bytes());
    RegisterPayload {
        workspace_name: workspace_name.to_string(),
        public_key,
        scopes: scopes.to_vec(),
        timestamp,
        nonce: nonce.to_string(),
        signature: hex::encode(signature.to_bytes()),
    }
}

/// Verify a register body against the verifier's clock `now` (Unix
/// seconds). Returns the `pk_hash` of the registering key on success, so
/// the caller keys its state by a value it has checked. Replay of an
/// accepted nonce is the caller's check.
pub fn verify_register(
    public_key_hex: &str,
    workspace_name: &str,
    scopes: &[String],
    timestamp_str: &str,
    nonce: &str,
    signature_hex: &str,
    now: i64,
) -> Result<String, VerifyError> {
    let verifying_key = parse_public_key(public_key_hex)?;
    check_timestamp(timestamp_str, now)?;
    validate_nonce(nonce)?;
    let signature = parse_signature(signature_hex)?;
    let payload = register_payload(workspace_name, public_key_hex, scopes, timestamp_str, nonce);
    verifying_key
        .verify(payload.as_bytes(), &signature)
        .map_err(|_| VerifyError::SignatureMismatch)?;
    Ok(pk_hash_of(&verifying_key.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scopes() -> Vec<String> {
        vec!["credentials:discover".into(), "credentials:vend".into()]
    }

    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn verify(p: &RegisterPayload, now: i64) -> Result<String, VerifyError> {
        verify_register(
            &p.public_key,
            &p.workspace_name,
            &p.scopes,
            &p.timestamp,
            &p.nonce,
            &p.signature,
            now,
        )
    }

    #[test]
    fn sign_then_verify_round_trips_and_returns_pk_hash() {
        let key = WorkspaceKey::generate();
        let p = sign_register(&key, "ws", &scopes()).unwrap();
        let ts: i64 = p.timestamp.parse().unwrap();
        assert!((now() - ts).abs() <= 1);
        assert_eq!(validate_nonce(&p.nonce), Ok(()));
        assert_eq!(verify(&p, now()).unwrap(), key.pk_hash());
    }

    #[test]
    fn two_signatures_use_different_nonces() {
        let key = WorkspaceKey::generate();
        let a = sign_register(&key, "ws", &scopes()).unwrap();
        let b = sign_register(&key, "ws", &scopes()).unwrap();
        assert_ne!(a.nonce, b.nonce);
    }

    #[test]
    fn verify_rejects_changed_name_or_scopes() {
        let key = WorkspaceKey::generate();
        let t = now();
        let p = sign_register(&key, "ws", &scopes()).unwrap();
        let mut renamed = p.clone();
        renamed.workspace_name = "other".into();
        assert_eq!(verify(&renamed, t), Err(VerifyError::SignatureMismatch));
        let mut rescoped = p.clone();
        rescoped.scopes = vec!["mcp:invoke".into()];
        assert_eq!(verify(&rescoped, t), Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn verify_rejects_changed_timestamp_or_nonce() {
        let key = WorkspaceKey::generate();
        let t = now();
        let p = sign_register_at(&key, "ws", &scopes(), t, &generate_nonce());
        let mut later = p.clone();
        later.timestamp = (t + 1).to_string();
        assert_eq!(verify(&later, t), Err(VerifyError::SignatureMismatch));
        let mut renonced = p.clone();
        renonced.nonce = generate_nonce();
        assert_eq!(verify(&renonced, t), Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn verify_rejects_timestamp_outside_skew_and_malformed_nonce() {
        let key = WorkspaceKey::generate();
        let t = 1_700_000_000;
        let p = sign_register_at(&key, "ws", &scopes(), t, &generate_nonce());
        assert!(verify(&p, t + MAX_CLOCK_SKEW_SECS).is_ok());
        assert_eq!(
            verify(&p, t + MAX_CLOCK_SKEW_SECS + 1),
            Err(VerifyError::TimestampOutOfRange)
        );
        assert_eq!(
            verify(&p, t - MAX_CLOCK_SKEW_SECS - 1),
            Err(VerifyError::TimestampOutOfRange)
        );
        let bad = sign_register_at(&key, "ws", &scopes(), t, "nope");
        assert_eq!(verify(&bad, t), Err(VerifyError::InvalidNonce));
    }

    #[test]
    fn verify_rejects_key_not_matching_signature() {
        let key = WorkspaceKey::generate();
        let other = WorkspaceKey::generate();
        let mut p = sign_register(&key, "ws", &scopes()).unwrap();
        // The payload embeds the public key, so swapping it changes both the
        // key and the signed bytes; either way it must fail.
        p.public_key = other.public_key_hex();
        assert_eq!(verify(&p, now()), Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn verify_reports_malformed_inputs_distinctly() {
        let key = WorkspaceKey::generate();
        let p = sign_register(&key, "ws", &scopes()).unwrap();
        let mut bad_key = p.clone();
        bad_key.public_key = "abcd".into();
        assert_eq!(verify(&bad_key, now()), Err(VerifyError::InvalidPublicKey));
        let mut bad_sig = p.clone();
        bad_sig.signature = "abcd".into();
        assert_eq!(verify(&bad_sig, now()), Err(VerifyError::InvalidSignature));
    }
}
