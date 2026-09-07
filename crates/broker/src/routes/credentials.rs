use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::{DateTime, Utc};
use serde::Serialize;

use agent_cordon_core::domain::credential::{CredentialId, CredentialSummary};

use crate::auth::AuthenticatedWorkspace;
use crate::server_client::ServerClient;
use crate::state::{CachedCredentialList, SharedState};

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

/// The listing an agent chooses from, cached for
/// [`crate::state::CREDENTIAL_LIST_TTL`].
///
/// `agentcordon proxy --auto` asks for this before every call it makes, so
/// serving it from the server every time would put a second broker→server
/// round trip on the fast path. The **vend** is deliberately not cached:
/// that round trip is what writes the audit row and re-checks the target
/// against the fence (ADR-0007). This is the catalogue, not the secret.
///
/// A failed fetch is not cached, so one bad answer does not stand for the
/// whole TTL.
pub async fn get_credentials(
    State(state): State<SharedState>,
    request: axum::extract::Request,
) -> impl IntoResponse {
    let auth = request
        .extensions()
        .get::<AuthenticatedWorkspace>()
        .cloned()
        .unwrap();

    if let Some(cached) = cached_listing(&state, &auth.pk_hash).await {
        return (StatusCode::OK, axum::Json(listing_body(cached)));
    }

    let server_client = ServerClient::new(state.http_client.clone(), state.server_url.clone());

    match with_token_refresh(&state, &auth.pk_hash, |token| {
        let sc = server_client.clone();
        async move { sc.list_credentials(&token).await }
    })
    .await
    {
        Ok(creds) => {
            state.credential_lists.write().await.insert(
                auth.pk_hash.clone(),
                CachedCredentialList {
                    fetched_at: std::time::Instant::now(),
                    entries: creds.clone(),
                },
            );
            (StatusCode::OK, axum::Json(listing_body(creds)))
        }
        Err(e) => e,
    }
}

/// This workspace's listing, if one was fetched inside the TTL.
async fn cached_listing(state: &SharedState, pk_hash: &str) -> Option<Vec<CredentialSummary>> {
    let now = std::time::Instant::now();
    let cache = state.credential_lists.read().await;
    let cached = cache.get(pk_hash)?;
    cached.is_fresh(now).then(|| cached.entries.clone())
}

/// Drop this workspace's cached listing.
///
/// Called wherever the broker learns the server's view of the workspace has
/// moved — a sync, a deregistration — so a stale catalogue never outlives
/// the reason it was fetched.
pub async fn invalidate_listing(state: &SharedState, pk_hash: &str) {
    state.credential_lists.write().await.remove(pk_hash);
}

fn listing_body(creds: Vec<CredentialSummary>) -> serde_json::Value {
    let entries: Vec<CredentialListEntry> =
        creds.into_iter().map(CredentialListEntry::from).collect();
    serde_json::json!({ "data": entries })
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
