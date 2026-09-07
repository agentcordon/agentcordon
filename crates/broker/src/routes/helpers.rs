//! Shared helpers for broker route handlers.

use std::future::Future;

use axum::http::StatusCode;

use crate::server_client::ServerClientError;
use crate::state::SharedState;
use crate::token_refresh;

/// Standard JSON error response used across all route handlers.
pub fn error_response(
    status: StatusCode,
    code: &str,
    message: &str,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        status,
        axum::Json(serde_json::json!({
            "error": { "code": code, "message": message }
        })),
    )
}

/// Standard JSON success response.
pub fn ok_response(data: serde_json::Value) -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({ "data": data })),
    )
}

/// Error codes on a server 403 that the broker relays verbatim instead of
/// summarising as a policy denial. Each names a cause the caller can act on
/// and that has nothing to do with Cedar.
const RELAYED_403_CODES: &[&str] = &["url_pattern_denied"];

/// The server's own error envelope, when a 403 body carries one of the codes
/// in [`RELAYED_403_CODES`]. `None` for every other 403, which stays
/// summarised.
fn passthrough_403(body: &str) -> Option<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(body).ok()?;
    let code = parsed.get("error")?.get("code")?.as_str()?;
    RELAYED_403_CODES
        .contains(&code)
        .then_some(())
        .map(|()| parsed)
}

/// Execute a server request with automatic 401 retry via token refresh.
///
/// 1. Gets the current access token for the workspace.
/// 2. Calls `make_request` with the token.
/// 3. On 401 (not "workspace not found"), refreshes the token and retries once.
/// 4. Returns the successful response or the final error.
pub async fn with_token_refresh<F, Fut, T>(
    state: &SharedState,
    pk_hash: &str,
    make_request: F,
) -> Result<T, (StatusCode, axum::Json<serde_json::Value>)>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<T, ServerClientError>>,
{
    let access_token = get_access_token(state, pk_hash).await.ok_or_else(|| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "reregistration_required",
            "Workspace tokens expired and could not be refreshed. Run: agentcordon register --force --server-url <server_url>",
        )
    })?;

    match make_request(access_token).await {
        Ok(result) => Ok(result),
        Err(ServerClientError::ServerError {
            status: 401,
            ref body,
        }) if body.contains("workspace not found") => {
            tracing::warn!("server reports workspace not found — workspace may have been deleted");
            Err(error_response(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Workspace not found on server (workspace may have been deleted). \
                 Try: agentcordon register --force",
            ))
        }
        Err(ServerClientError::ServerError { status: 401, .. }) => {
            // Attempt reactive refresh and retry
            if token_refresh::try_reactive_refresh(state, pk_hash).await {
                if let Some(new_token) = get_access_token(state, pk_hash).await {
                    return make_request(new_token).await.map_err(|e| {
                        tracing::error!(error = %e, "request failed after token refresh");
                        error_response(
                            StatusCode::BAD_GATEWAY,
                            "bad_gateway",
                            "Server request failed after token refresh",
                        )
                    });
                }
            }
            Err(error_response(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Token expired and refresh failed",
            ))
        }
        Err(ServerClientError::ServerError {
            status: 403,
            ref body,
        }) => {
            // A 403 is summarised rather than relayed, so a Cedar denial does
            // not leak policy detail to an agent. One kind of 403 is not a
            // policy decision at all — the credential's own
            // `allowed_url_pattern` — and reporting that as "access denied by
            // server policy" sends the reader to the wrong screen entirely.
            // That one code, and its message, come through as the server
            // wrote them.
            if let Some(envelope) = passthrough_403(body) {
                return Err((StatusCode::FORBIDDEN, axum::Json(envelope)));
            }
            Err(error_response(
                StatusCode::FORBIDDEN,
                "forbidden",
                "Access denied by server policy",
            ))
        }
        Err(ServerClientError::ServerError { status, body }) => {
            tracing::warn!(status = status, "server request failed");
            // Propagate the server's error envelope verbatim when present so the
            // CLI can render the actual `error.message` and any `candidates` array
            // (e.g., 300 Multiple Choices for ambiguous credential names) instead
            // of a generic "Server request failed" message.
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) {
                if parsed.get("error").is_some() {
                    let mapped = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
                    return Err((mapped, axum::Json(parsed)));
                }
            }
            let snippet: String = body.chars().take(200).collect();
            Err(error_response(
                StatusCode::BAD_GATEWAY,
                "bad_gateway",
                &format!("Server request failed ({}): {}", status, snippet),
            ))
        }
        Err(e) => {
            tracing::error!(error = %e, "server request failed");
            Err(error_response(
                StatusCode::BAD_GATEWAY,
                "bad_gateway",
                "Server request failed",
            ))
        }
    }
}

/// Get a workspace's current access token.
pub async fn get_access_token(state: &SharedState, pk_hash: &str) -> Option<String> {
    let workspaces = state.workspaces.read().await;
    workspaces.get(pk_hash).map(|ws| ws.access_token.clone())
}
