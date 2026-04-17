//! Ed25519 request signature verification for CLI-to-broker authentication.

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::state::SharedState;

/// Error type for authentication failures.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("timestamp out of range")]
    TimestampOutOfRange,
}

/// Maximum clock skew tolerance in seconds.
const MAX_CLOCK_SKEW: i64 = 30;

/// Canonicalise a request path-and-query for inclusion in the signed payload.
///
/// Byte-identical copy of the helper in `crates/cli/src/signing.rs` — see
/// that file for the rationale (no shared workspace crate; two copies are
/// the explicit design choice).
///
/// - Strip a single trailing `/` from `path` unless `path == "/"`.
/// - If `query` is `Some(non-empty)`, append `"?"` + the query verbatim
///   (percent-encoding untouched, parameters NOT re-sorted).
/// - If `query` is `None` or `Some("")`, append nothing.
fn canonicalise_path_and_query(path: &str, query: Option<&str>) -> String {
    let trimmed: &str = if path.len() > 1 && path.ends_with('/') {
        &path[..path.len() - 1]
    } else {
        path
    };
    match query {
        Some(q) if !q.is_empty() => format!("{trimmed}?{q}"),
        _ => trimmed.to_string(),
    }
}

/// Verify an Ed25519 signature over the request payload.
pub fn verify_workspace_signature(
    public_key_hex: &str,
    timestamp_str: &str,
    signature_hex: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<(), AuthError> {
    // Parse public key
    let pk_bytes = hex::decode(public_key_hex).map_err(|_| AuthError::InvalidPublicKey)?;
    let pk_array: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| AuthError::InvalidPublicKey)?;
    let verifying_key =
        VerifyingKey::from_bytes(&pk_array).map_err(|_| AuthError::InvalidPublicKey)?;

    // Check timestamp
    let timestamp: i64 = timestamp_str
        .parse()
        .map_err(|_| AuthError::TimestampOutOfRange)?;
    let now = chrono::Utc::now().timestamp();
    if (now - timestamp).abs() > MAX_CLOCK_SKEW {
        return Err(AuthError::TimestampOutOfRange);
    }

    // Parse signature
    let sig_bytes = hex::decode(signature_hex).map_err(|_| AuthError::InvalidSignature)?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| AuthError::InvalidSignature)?;
    let signature = Signature::from_bytes(&sig_array);

    // Construct signed payload: METHOD \n PATH \n TIMESTAMP \n BODY
    let mut payload = Vec::new();
    payload.extend_from_slice(method.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(path.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(timestamp_str.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(body);

    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| AuthError::InvalidSignature)?;

    Ok(())
}

/// Compute SHA-256 hex hash of a public key hex string (hashes the raw bytes).
pub fn pk_hash(public_key_hex: &str) -> Result<String, AuthError> {
    let pk_bytes = hex::decode(public_key_hex).map_err(|_| AuthError::InvalidPublicKey)?;
    let hash = Sha256::digest(&pk_bytes);
    Ok(hex::encode(hash))
}

/// Axum middleware that verifies Ed25519 signatures on incoming requests.
///
/// Extracts `X-AC-PublicKey`, `X-AC-Timestamp`, `X-AC-Signature` headers,
/// verifies the signature, and checks that the workspace is registered.
/// On success, injects the `pk_hash` into request extensions.
pub async fn auth_middleware(
    State(state): State<SharedState>,
    request: Request,
    next: Next,
) -> Response {
    let headers = request.headers();

    let public_key = match headers.get("X-AC-PublicKey").and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_string(),
        None => return auth_error_response(),
    };
    let timestamp = match headers.get("X-AC-Timestamp").and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_string(),
        None => return auth_error_response(),
    };
    let signature = match headers.get("X-AC-Signature").and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_string(),
        None => return auth_error_response(),
    };

    let method = request.method().as_str().to_string();
    let path = canonicalise_path_and_query(request.uri().path(), request.uri().query());

    // Buffer the body so we can verify the signature and pass it downstream
    let (parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return auth_error_response(),
    };

    // Verify signature
    if verify_workspace_signature(
        &public_key,
        &timestamp,
        &signature,
        &method,
        &path,
        &body_bytes,
    )
    .is_err()
    {
        return auth_error_response();
    }

    // Compute pk_hash and check registration
    let hash = match pk_hash(&public_key) {
        Ok(h) => h,
        Err(_) => return auth_error_response(),
    };

    {
        let workspaces = state.workspaces.read().await;
        if !workspaces.contains_key(&hash) {
            // If the IdP returned an OAuth error during registration, surface
            // it instead of the generic "not registered" response so the CLI
            // can exit non-zero immediately rather than polling until timeout.
            let err_msg = {
                let errs = state.registration_errors.read().await;
                errs.get(&hash).cloned()
            };
            if let Some(msg) = err_msg {
                // One-shot: clear the error after surfacing it once so a
                // retry doesn't keep failing on stale state.
                state.registration_errors.write().await.remove(&hash);
                return registration_failed_response(&msg);
            }
            return reregistration_required_response();
        }
    }

    // Rebuild request with buffered body and inject pk_hash
    let mut request = Request::from_parts(parts, axum::body::Body::from(body_bytes));
    request
        .extensions_mut()
        .insert(AuthenticatedWorkspace { pk_hash: hash });

    next.run(request).await
}

/// Authenticated workspace identity extracted from verified request.
#[derive(Debug, Clone)]
pub struct AuthenticatedWorkspace {
    /// SHA-256 hex hash of the Ed25519 public key.
    pub pk_hash: String,
}

fn auth_error_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({
            "error": {
                "code": "unauthorized",
                "message": "Signature verification failed"
            }
        })),
    )
        .into_response()
}

fn registration_failed_response(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({
            "error": {
                "code": "registration_failed",
                "message": format!("OAuth authorization failed: {message}")
            }
        })),
    )
        .into_response()
}

fn reregistration_required_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({
            "error": {
                "code": "reregistration_required",
                "message": "Workspace not registered with this broker. Run: agentcordon setup <server_url>"
            }
        })),
    )
        .into_response()
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod tests;
