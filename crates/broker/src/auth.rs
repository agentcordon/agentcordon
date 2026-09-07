//! Ed25519 request signature verification for CLI-to-broker authentication,
//! nonce replay refusal, and the optional shared secret for non-loopback
//! deployments.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;

use agentcordon_identity::{canonicalise_path_and_query, VerifyError, MAX_CLOCK_SKEW_SECS};

use crate::state::SharedState;

/// Header carrying the shared secret when the broker is started with
/// `--shared-secret`.
pub const SHARED_SECRET_HEADER: &str = "X-AgentCordon-Broker-Secret";

/// Error type for authentication failures.
///
/// Coarser than [`VerifyError`]: the middleware answers every failure with
/// the same 401, and callers only distinguish "bad key", "bad signature",
/// and "bad clock".
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("timestamp out of range")]
    TimestampOutOfRange,
    #[error("nonce missing, malformed, or already used")]
    InvalidNonce,
}

impl From<VerifyError> for AuthError {
    fn from(e: VerifyError) -> Self {
        match e {
            VerifyError::InvalidPublicKey => AuthError::InvalidPublicKey,
            VerifyError::InvalidSignature | VerifyError::SignatureMismatch => {
                AuthError::InvalidSignature
            }
            VerifyError::TimestampOutOfRange => AuthError::TimestampOutOfRange,
            VerifyError::InvalidNonce => AuthError::InvalidNonce,
        }
    }
}

/// Verify an Ed25519 signature over the request payload against the
/// broker's clock. The payload, canonical path, and skew window are the
/// identity crate's; `path` must already be canonical. Replay of the nonce
/// is checked separately by [`NonceCache`].
pub fn verify_workspace_signature(
    public_key_hex: &str,
    timestamp_str: &str,
    nonce: &str,
    signature_hex: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<(), AuthError> {
    agentcordon_identity::verify_request(
        public_key_hex,
        timestamp_str,
        nonce,
        signature_hex,
        method,
        path,
        body,
        chrono::Utc::now().timestamp(),
    )
    .map_err(AuthError::from)
}

/// Compute SHA-256 hex hash of a public key hex string (hashes the raw bytes).
pub fn pk_hash(public_key_hex: &str) -> Result<String, AuthError> {
    agentcordon_identity::pk_hash_from_hex(public_key_hex).map_err(AuthError::from)
}

// ---------------------------------------------------------------------------
// Nonce seen-set
// ---------------------------------------------------------------------------

/// How long an accepted `(key, nonce)` pair is remembered. A signed
/// timestamp is accepted for `MAX_CLOCK_SKEW_SECS` either side of the
/// broker's clock, so a nonce first seen at `t` can only be re-presented
/// with a still-valid signature until `t + 2 * MAX_CLOCK_SKEW_SECS`.
pub const NONCE_TTL_SECS: i64 = MAX_CLOCK_SKEW_SECS * 2;

/// Upper bound on remembered nonces. At the TTL this is over a thousand
/// requests per second sustained; beyond it the oldest entries are
/// evicted, which shrinks the replay window rather than refusing service.
pub const NONCE_CAPACITY: usize = 100_000;

/// Bounded set of `(pk_hash, nonce)` pairs accepted within the skew window.
///
/// One instance per broker, on [`crate::state::BrokerState`]. Entries
/// expire after [`NONCE_TTL_SECS`]; when the set reaches its capacity the
/// oldest entry is evicted first. The clock is a parameter so the window
/// is testable.
pub struct NonceCache {
    capacity: usize,
    inner: Mutex<NonceInner>,
}

#[derive(Default)]
struct NonceInner {
    /// `(pk_hash, nonce)` -> expiry, Unix seconds.
    seen: HashMap<(String, String), i64>,
    /// Insertion order; the TTL is constant, so the front is the oldest
    /// and the earliest to expire.
    order: VecDeque<(String, String)>,
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::with_capacity(NONCE_CAPACITY)
    }
}

impl NonceCache {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            inner: Mutex::new(NonceInner::default()),
        }
    }

    /// Record `(pk_hash, nonce)` as seen at `now` (Unix seconds).
    ///
    /// Returns `true` when the pair was not already present within its
    /// TTL — the request is fresh — and `false` for a replay. Expired
    /// entries are dropped on the way in.
    pub fn check_and_insert(&self, pk_hash: &str, nonce: &str, now: i64) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        while let Some(front) = inner.order.front() {
            let expired = inner.seen.get(front).is_none_or(|expiry| *expiry <= now);
            if !expired {
                break;
            }
            let key = inner.order.pop_front().expect("front exists");
            inner.seen.remove(&key);
        }

        let key = (pk_hash.to_string(), nonce.to_string());
        if inner.seen.contains_key(&key) {
            return false;
        }

        while inner.seen.len() >= self.capacity {
            match inner.order.pop_front() {
                Some(oldest) => {
                    inner.seen.remove(&oldest);
                }
                None => break,
            }
        }

        inner.seen.insert(key.clone(), now + NONCE_TTL_SECS);
        inner.order.push_back(key);
        true
    }

    /// Number of remembered pairs (for tests).
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .seen
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

/// Axum middleware that verifies Ed25519 signatures on incoming requests.
///
/// Extracts `X-AC-PublicKey`, `X-AC-Timestamp`, `X-AC-Nonce`,
/// `X-AC-Signature`, verifies the signature, checks that the workspace is
/// registered, and refuses a nonce this key has already used within the
/// window. On success, injects the `pk_hash` into request extensions.
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
    let nonce = match headers.get("X-AC-Nonce").and_then(|v| v.to_str().ok()) {
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
        &nonce,
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

    // Replay check last, so only a verified, registered key consumes an
    // entry in the seen-set.
    if !state
        .nonces
        .check_and_insert(&hash, &nonce, chrono::Utc::now().timestamp())
    {
        return auth_error_response();
    }

    // Rebuild request with buffered body and inject pk_hash
    let mut request = Request::from_parts(parts, axum::body::Body::from(body_bytes));
    request
        .extensions_mut()
        .insert(AuthenticatedWorkspace { pk_hash: hash });

    next.run(request).await
}

/// Axum middleware that requires [`SHARED_SECRET_HEADER`] to equal the
/// configured `--shared-secret`. A no-op when no secret is configured.
/// Runs before signature verification on signed routes and on
/// `/register`; `/health` is exempt so discovery still works.
pub async fn shared_secret_middleware(
    State(state): State<SharedState>,
    request: Request,
    next: Next,
) -> Response {
    if let Some(expected) = state.config.shared_secret.as_deref() {
        let presented = request
            .headers()
            .get(SHARED_SECRET_HEADER)
            .map(|v| v.as_bytes())
            .unwrap_or_default();
        if !shared_secret_matches(expected.as_bytes(), presented) {
            return shared_secret_response();
        }
    }
    next.run(request).await
}

/// Constant-time comparison of the presented secret with the expected one.
pub fn shared_secret_matches(expected: &[u8], presented: &[u8]) -> bool {
    expected.len() == presented.len() && bool::from(expected.ct_eq(presented))
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

fn shared_secret_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({
            "error": {
                "code": "unauthorized",
                "message": format!(
                    "Broker shared secret missing or incorrect. Set AGTCRDN_BROKER_SHARED_SECRET \
                     to the value the broker was started with (sent as {SHARED_SECRET_HEADER})"
                )
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
                "message": "Workspace not registered with this broker. Run: agentcordon register --server-url <server_url>"
            }
        })),
    )
        .into_response()
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod tests;
