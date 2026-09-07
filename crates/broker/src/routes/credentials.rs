use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::{DateTime, Utc};
use serde::Serialize;

use agent_cordon_core::domain::credential::{CredentialId, CredentialSummary};

use crate::auth::AuthenticatedWorkspace;
use crate::server_client::ServerClient;
use crate::state::SharedState;

use super::helpers::{error_response, with_token_refresh};

/// What an agent is told about a credential.
///
/// The server's [`CredentialSummary`] carries more than an agent has any
/// business seeing (transform scripts, metadata, ownership, tags), so this
/// is a deliberate projection of it rather than a passthrough. Because it
/// is built field-by-field from the server's type, a rename there is a
/// compile error here instead of a silently empty column.
#[derive(Serialize)]
struct CredentialListEntry {
    id: CredentialId,
    name: String,
    service: String,
    credential_type: String,
    scopes: Vec<String>,
    allowed_url_pattern: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    expired: bool,
    /// The vault's display name. An agent groups by what it can read, not by
    /// the vault's id.
    vault: String,
}

impl From<CredentialSummary> for CredentialListEntry {
    fn from(c: CredentialSummary) -> Self {
        Self {
            id: c.id,
            name: c.name,
            service: c.service,
            credential_type: c.credential_type,
            scopes: c.scopes,
            allowed_url_pattern: c.allowed_url_pattern,
            expires_at: c.expires_at,
            expired: c.expired,
            vault: c.vault_name,
        }
    }
}

pub async fn get_credentials(
    State(state): State<SharedState>,
    request: axum::extract::Request,
) -> impl IntoResponse {
    let auth = request
        .extensions()
        .get::<AuthenticatedWorkspace>()
        .cloned()
        .unwrap();

    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());

    match with_token_refresh(&state, &auth.pk_hash, |token| {
        let sc = server_client.clone();
        async move { sc.list_credentials(&token).await }
    })
    .await
    {
        Ok(creds) => {
            let entries: Vec<CredentialListEntry> =
                creds.into_iter().map(CredentialListEntry::from).collect();
            (
                StatusCode::OK,
                axum::Json(serde_json::json!({ "data": entries })),
            )
        }
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
        Ok(summary) => {
            let entry = CredentialListEntry::from(summary);
            (
                StatusCode::OK,
                axum::Json(serde_json::json!({ "data": entry })),
            )
        }
        Err(e) => e,
    }
}
