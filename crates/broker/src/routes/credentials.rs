use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::auth::AuthenticatedWorkspace;
use crate::server_client::ServerClient;
use crate::state::SharedState;
use crate::token_refresh;

pub async fn get_credentials(
    State(state): State<SharedState>,
    request: axum::extract::Request,
) -> impl IntoResponse {
    let auth = request
        .extensions()
        .get::<AuthenticatedWorkspace>()
        .cloned()
        .unwrap();

    let access_token = {
        let workspaces = state.workspaces.read().await;
        match workspaces.get(&auth.pk_hash) {
            Some(ws) => ws.access_token.clone(),
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    axum::Json(serde_json::json!({
                        "error": { "code": "unauthorized", "message": "Workspace not registered" }
                    })),
                );
            }
        }
    };

    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());

    match server_client.list_credentials(&access_token).await {
        Ok(creds) => (
            StatusCode::OK,
            axum::Json(serde_json::json!({ "data": creds })),
        ),
        Err(crate::server_client::ServerClientError::ServerError {
            status: 401,
            ref body,
        }) if body.contains("workspace not found") => {
            tracing::warn!("server reports workspace not found — workspace may have been deleted");
            (
                StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({
                    "error": {
                        "code": "unauthorized",
                        "message": "Workspace not found on server (workspace may have been deleted). Try: agentcordon register --force"
                    }
                })),
            )
        }
        Err(crate::server_client::ServerClientError::ServerError { status: 401, .. }) => {
            // Try reactive refresh
            if token_refresh::try_reactive_refresh(&state, &auth.pk_hash).await {
                let access_token = {
                    let workspaces = state.workspaces.read().await;
                    workspaces
                        .get(&auth.pk_hash)
                        .map(|ws| ws.access_token.clone())
                };
                if let Some(token) = access_token {
                    match server_client.list_credentials(&token).await {
                        Ok(creds) => {
                            return (
                                StatusCode::OK,
                                axum::Json(serde_json::json!({ "data": creds })),
                            );
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "credential list retry failed");
                            return (
                                StatusCode::BAD_GATEWAY,
                                axum::Json(serde_json::json!({
                                    "error": { "code": "bad_gateway", "message": server_error_message(&e) }
                                })),
                            );
                        }
                    }
                }
            }
            (
                StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({
                    "error": { "code": "unauthorized", "message": "Token expired and refresh failed" }
                })),
            )
        }
        Err(e) => {
            tracing::error!(error = %e, "credential list failed");
            (
                StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({
                    "error": { "code": "bad_gateway", "message": server_error_message(&e) }
                })),
            )
        }
    }
}

/// Extract a user-facing message from a server client error, preserving
/// server-side context when available instead of returning a generic string.
fn server_error_message(e: &crate::server_client::ServerClientError) -> String {
    match e {
        crate::server_client::ServerClientError::ServerError { status, body } => {
            // Try to extract the nested error message from the JSON body
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body) {
                if let Some(msg) = parsed
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                {
                    return format!("Server returned {status}: {msg}");
                }
            }
            format!("Server returned {status}: {body}")
        }
        other => format!("Server request failed: {other}"),
    }
}
