use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::auth::AuthenticatedWorkspace;
use crate::server_client::ServerClient;
use crate::state::SharedState;

use super::helpers::{error_response, require_scope, with_token_refresh};

pub async fn get_credentials(
    State(state): State<SharedState>,
    request: axum::extract::Request,
) -> impl IntoResponse {
    let auth = request
        .extensions()
        .get::<AuthenticatedWorkspace>()
        .cloned()
        .unwrap();

    // Scope pre-check: workspace must have credentials:discover
    if let Err(e) = require_scope(
        &state,
        &auth.pk_hash,
        "credentials:discover",
        "credentials.list",
    )
    .await
    {
        return e;
    }

    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());

    match with_token_refresh(&state, &auth.pk_hash, |token| {
        let sc = server_client.clone();
        async move { sc.list_credentials(&token).await }
    })
    .await
    {
        Ok(creds) => (
            StatusCode::OK,
            axum::Json(serde_json::json!({ "data": creds })),
        ),
        Err(e) => e,
    }
}

/// POST /credentials/create — workspace-initiated credential creation passthrough.
///
/// Forwards the JSON body to the server's `POST /api/v1/credentials/agent-store`
/// endpoint using the workspace's access token.
pub async fn post_create_credential(
    State(state): State<SharedState>,
    request: axum::extract::Request,
) -> impl IntoResponse {
    let auth = request
        .extensions()
        .get::<AuthenticatedWorkspace>()
        .cloned()
        .unwrap();

    // Scope pre-check: workspace must have credentials:vend (the same scope
    // the server's agent-store route requires).
    if let Err(e) = require_scope(
        &state,
        &auth.pk_hash,
        "credentials:vend",
        "credentials.create",
    )
    .await
    {
        return e;
    }

    // Read body (cap at 1 MiB — credentials are small).
    let body_bytes = match axum::body::to_bytes(request.into_body(), 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "Failed to read request body",
            );
        }
    };

    let body_json: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "bad_request",
                &format!("Invalid JSON body: {e}"),
            );
        }
    };

    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());

    match with_token_refresh(&state, &auth.pk_hash, |token| {
        let sc = server_client.clone();
        let body = body_json.clone();
        async move { sc.agent_store_credential(&token, &body).await }
    })
    .await
    {
        Ok(summary) => (
            StatusCode::OK,
            axum::Json(serde_json::json!({ "data": summary })),
        ),
        Err(e) => e,
    }
}
