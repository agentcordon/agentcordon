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

/// Check that the workspace identified by `pk_hash` has the required OAuth scope.
///
/// `action` describes the operation being attempted (e.g., "proxy", "credentials.list")
/// and is included in denial logs for audit/debugging context.
///
/// Returns `Ok(())` if the scope is present, or a 403 error response if missing.
pub async fn require_scope(
    state: &SharedState,
    pk_hash: &str,
    required_scope: &str,
    action: &str,
) -> Result<(), (StatusCode, axum::Json<serde_json::Value>)> {
    let workspaces = state.workspaces.read().await;
    match workspaces.get(pk_hash) {
        Some(ws) => {
            // Empty scopes = unrestricted (workspace registered without explicit scope limits)
            if ws.scopes.is_empty() || ws.scopes.iter().any(|s| s == required_scope) {
                Ok(())
            } else {
                tracing::warn!(
                    action = %action,
                    workspace_name = %ws.workspace_name,
                    client_id = %ws.client_id,
                    pk_hash = %pk_hash,
                    required_scope = %required_scope,
                    granted_scopes = ?ws.scopes,
                    token_status = ?ws.token_status,
                    "scope check denied: workspace missing required scope"
                );
                Err(error_response(
                    StatusCode::FORBIDDEN,
                    "forbidden",
                    &format!("Workspace does not have required scope: {}", required_scope),
                ))
            }
        }
        None => {
            tracing::warn!(
                action = %action,
                pk_hash = %pk_hash,
                required_scope = %required_scope,
                "scope check denied: workspace not registered"
            );
            Err(error_response(
                StatusCode::UNAUTHORIZED,
                "reregistration_required",
                "Workspace tokens expired and could not be refreshed. Run: agentcordon setup <server_url>",
            ))
        }
    }
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
            "Workspace tokens expired and could not be refreshed. Run: agentcordon setup <server_url>",
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
        Err(ServerClientError::ServerError { status: 403, .. }) => Err(error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Access denied by server policy",
        )),
        Err(ServerClientError::ServerError { status: 404, .. }) => Err(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Resource not found",
        )),
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
