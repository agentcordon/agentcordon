use super::*;
use agentcordon_identity::{generate_nonce, sign_request_at, sign_request_with, WorkspaceKey};

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn verify(
    h: &agentcordon_identity::SignedHeaders,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<(), AuthError> {
    verify_workspace_signature(
        &h.public_key,
        &h.timestamp,
        &h.nonce,
        &h.signature,
        method,
        path,
        body,
    )
}

#[test]
fn rejects_body_that_differs_from_signed() {
    let key = WorkspaceKey::generate();
    let h = sign_request_at(&key, "GET", "/status", b"wrong body", now());
    assert_eq!(
        verify(&h, "GET", "/status", b"actual body"),
        Err(AuthError::InvalidSignature)
    );
}

#[test]
fn rejects_malformed_nonce() {
    let key = WorkspaceKey::generate();
    let h = sign_request_with(&key, "GET", "/status", b"", now(), "not-a-nonce");
    assert_eq!(
        verify(&h, "GET", "/status", b""),
        Err(AuthError::InvalidNonce)
    );
}

// ---------------------------------------------------------------------------
// NonceCache
// ---------------------------------------------------------------------------

#[test]
fn nonce_cache_refuses_second_presentation_within_window() {
    let cache = NonceCache::default();
    let n = generate_nonce();
    assert!(cache.check_and_insert("pk", &n, 1_000));
    assert!(!cache.check_and_insert("pk", &n, 1_000));
    assert!(!cache.check_and_insert("pk", &n, 1_000 + NONCE_TTL_SECS - 1));
}

#[test]
fn nonce_cache_allows_reuse_once_the_window_has_passed() {
    let cache = NonceCache::default();
    let n = generate_nonce();
    assert!(cache.check_and_insert("pk", &n, 1_000));
    assert!(cache.check_and_insert("pk", &n, 1_000 + NONCE_TTL_SECS));
    assert_eq!(
        cache.len(),
        1,
        "the expired entry was dropped, the new one kept"
    );
}

#[test]
fn nonce_cache_scopes_nonces_to_the_key() {
    let cache = NonceCache::default();
    let n = generate_nonce();
    assert!(cache.check_and_insert("pk-a", &n, 1_000));
    assert!(cache.check_and_insert("pk-b", &n, 1_000));
    assert!(!cache.check_and_insert("pk-a", &n, 1_000));
}

#[test]
fn nonce_cache_evicts_oldest_at_capacity() {
    let cache = NonceCache::with_capacity(3);
    let nonces: Vec<String> = (0..4).map(|_| generate_nonce()).collect();
    for (i, n) in nonces.iter().enumerate() {
        assert!(cache.check_and_insert("pk", n, 1_000 + i as i64));
    }
    assert_eq!(cache.len(), 3);
    // The oldest was evicted and is accepted again; the newer ones still
    // count as replays.
    assert!(cache.check_and_insert("pk", &nonces[0], 1_004));
    assert!(!cache.check_and_insert("pk", &nonces[3], 1_004));
}

#[test]
fn nonce_cache_drops_expired_entries_on_insert() {
    let cache = NonceCache::default();
    for _ in 0..10 {
        assert!(cache.check_and_insert("pk", &generate_nonce(), 1_000));
    }
    assert_eq!(cache.len(), 10);
    assert!(cache.check_and_insert("pk", &generate_nonce(), 1_000 + NONCE_TTL_SECS));
    assert_eq!(cache.len(), 1);
}
