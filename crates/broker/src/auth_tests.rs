use super::*;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

#[test]
fn test_verify_valid_signature() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let pk_hex = hex::encode(verifying_key.as_bytes());

    let timestamp = chrono::Utc::now().timestamp().to_string();
    let method = "GET";
    let path = "/status";
    let body = b"";

    let mut payload = Vec::new();
    payload.extend_from_slice(method.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(path.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(timestamp.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(body);

    use ed25519_dalek::Signer;
    let sig = signing_key.sign(&payload);
    let sig_hex = hex::encode(sig.to_bytes());

    assert!(verify_workspace_signature(&pk_hex, &timestamp, &sig_hex, method, path, body,).is_ok());
}

#[test]
fn test_reject_expired_timestamp() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let pk_hex = hex::encode(verifying_key.as_bytes());

    let timestamp = (chrono::Utc::now().timestamp() - 60).to_string();
    let method = "GET";
    let path = "/status";
    let body = b"";

    let mut payload = Vec::new();
    payload.extend_from_slice(method.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(path.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(timestamp.as_bytes());
    payload.push(b'\n');

    use ed25519_dalek::Signer;
    let sig = signing_key.sign(&payload);
    let sig_hex = hex::encode(sig.to_bytes());

    assert!(matches!(
        verify_workspace_signature(&pk_hex, &timestamp, &sig_hex, method, path, body),
        Err(AuthError::TimestampOutOfRange)
    ));
}

#[test]
fn test_reject_invalid_signature() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let pk_hex = hex::encode(verifying_key.as_bytes());

    let timestamp = chrono::Utc::now().timestamp().to_string();

    // Sign with different body
    let mut payload = Vec::new();
    payload.extend_from_slice(b"GET\n/status\n");
    payload.extend_from_slice(timestamp.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(b"wrong body");

    use ed25519_dalek::Signer;
    let sig = signing_key.sign(&payload);
    let sig_hex = hex::encode(sig.to_bytes());

    assert!(matches!(
        verify_workspace_signature(
            &pk_hex,
            &timestamp,
            &sig_hex,
            "GET",
            "/status",
            b"actual body",
        ),
        Err(AuthError::InvalidSignature)
    ));
}

#[test]
fn test_pk_hash() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let pk_hex = hex::encode(verifying_key.as_bytes());
    let hash = pk_hash(&pk_hex).unwrap();
    assert_eq!(hash.len(), 64); // SHA-256 hex = 64 chars
}

#[test]
fn canonicalise_path_and_query_cases() {
    assert_eq!(canonicalise_path_and_query("/foo/bar", None), "/foo/bar");
    assert_eq!(canonicalise_path_and_query("/foo/bar/", None), "/foo/bar");
    assert_eq!(
        canonicalise_path_and_query("/foo/bar", Some("a=1&b=2")),
        "/foo/bar?a=1&b=2"
    );
    assert_eq!(
        canonicalise_path_and_query("/foo/bar/", Some("a=1&b=2")),
        "/foo/bar?a=1&b=2"
    );
    assert_eq!(canonicalise_path_and_query("/", None), "/");
    assert_eq!(canonicalise_path_and_query("/", Some("a=1")), "/?a=1");
    assert_eq!(canonicalise_path_and_query("/", Some("")), "/");
}

#[test]
fn test_verify_signature_with_query_string() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let pk_hex = hex::encode(verifying_key.as_bytes());

    let timestamp = chrono::Utc::now().timestamp().to_string();
    let method = "GET";
    // Canonical form the broker would reconstruct from a URI of
    // `/foo/bar/?a=1&b=2`: trailing slash stripped, query preserved.
    let signed_path = canonicalise_path_and_query("/foo/bar/", Some("a=1&b=2"));
    assert_eq!(signed_path, "/foo/bar?a=1&b=2");
    let body = b"";

    let mut payload = Vec::new();
    payload.extend_from_slice(method.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(signed_path.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(timestamp.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(body);

    use ed25519_dalek::Signer;
    let sig = signing_key.sign(&payload);
    let sig_hex = hex::encode(sig.to_bytes());

    assert!(
        verify_workspace_signature(&pk_hex, &timestamp, &sig_hex, method, &signed_path, body,)
            .is_ok()
    );
}

#[test]
fn test_reject_signature_when_query_dropped() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let pk_hex = hex::encode(verifying_key.as_bytes());

    let timestamp = chrono::Utc::now().timestamp().to_string();
    let method = "GET";
    let signed_path = "/foo?a=1";
    let verify_path = "/foo";

    let mut payload = Vec::new();
    payload.extend_from_slice(method.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(signed_path.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(timestamp.as_bytes());
    payload.push(b'\n');

    use ed25519_dalek::Signer;
    let sig = signing_key.sign(&payload);
    let sig_hex = hex::encode(sig.to_bytes());

    // Verifier reconstructs without the query → signature must fail.
    assert!(matches!(
        verify_workspace_signature(&pk_hex, &timestamp, &sig_hex, method, verify_path, b"",),
        Err(AuthError::InvalidSignature)
    ));
}
