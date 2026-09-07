//! OAuth client registration and admin management endpoints.

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::services::oauth::RegisterClient;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// POST /api/v1/oauth/clients — Register client
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct RegisterClientRequest {
    workspace_name: String,
    redirect_uris: Vec<String>,
    scopes: Vec<String>,
    public_key_hash: String,
}

#[derive(Serialize)]
pub(crate) struct RegisterClientResponse {
    client_id: String,
    client_secret: Option<String>,
    workspace_name: String,
    redirect_uris: Vec<String>,
    allowed_scopes: Vec<String>,
    created_at: String,
}

/// POST /api/v1/oauth/clients — Admin-only confidential client registration.
///
/// Creates a confidential OAuth client with a client_secret, intended for
/// CI/CD and server-to-server use cases. Public clients for interactive agents
/// are created automatically via the consent flow in `authorize.rs`.
pub(crate) async fn register_client(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<RegisterClientRequest>,
) -> Result<
    (
        axum::http::StatusCode,
        Json<ApiResponse<RegisterClientResponse>>,
    ),
    ApiError,
> {
    let (client, client_secret) = state
        .services
        .oauth
        .register_client(
            &auth,
            &corr.0,
            RegisterClient {
                workspace_name: req.workspace_name,
                redirect_uris: req.redirect_uris,
                scopes: req.scopes,
                public_key_hash: req.public_key_hash,
            },
        )
        .await?;

    let response = RegisterClientResponse {
        client_id: client.client_id,
        client_secret: Some(client_secret),
        workspace_name: client.workspace_name,
        redirect_uris: client.redirect_uris,
        allowed_scopes: client
            .allowed_scopes
            .iter()
            .map(|s| s.to_string())
            .collect(),
        created_at: client.created_at.to_rfc3339(),
    };

    Ok((
        axum::http::StatusCode::CREATED,
        Json(ApiResponse::ok(response)),
    ))
}

// ---------------------------------------------------------------------------
// GET /api/v1/oauth/clients — Admin: list clients
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub(crate) struct ClientListItem {
    id: String,
    client_id: String,
    workspace_name: String,
    allowed_scopes: Vec<String>,
    redirect_uris: Vec<String>,
    created_by_user: String,
    created_at: String,
    revoked_at: Option<String>,
}

/// GET /api/v1/oauth/clients
pub(crate) async fn list_clients(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<ApiResponse<Vec<ClientListItem>>>, ApiError> {
    if !auth.is_root {
        return Err(ApiError::Forbidden("admin access required".into()));
    }

    let clients = state.store.list_oauth_clients().await?;
    let items: Vec<ClientListItem> = clients
        .into_iter()
        .map(|c| ClientListItem {
            id: c.id.to_string(),
            client_id: c.client_id,
            workspace_name: c.workspace_name,
            allowed_scopes: c.allowed_scopes.iter().map(|s| s.to_string()).collect(),
            redirect_uris: c.redirect_uris,
            created_by_user: c.created_by_user.0.to_string(),
            created_at: c.created_at.to_rfc3339(),
            revoked_at: c.revoked_at.map(|d| d.to_rfc3339()),
        })
        .collect();

    Ok(Json(ApiResponse::ok(items)))
}

// ---------------------------------------------------------------------------
// DELETE /api/v1/oauth/clients/{id} — Admin: revoke client
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub(crate) struct RevokeResponse {
    revoked: bool,
}

/// DELETE /api/v1/oauth/clients/{id}
pub(crate) async fn revoke_client(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<RevokeResponse>>, ApiError> {
    let revoked = state
        .services
        .oauth
        .revoke_client(&auth, &corr.0, &id)
        .await?;

    Ok(Json(ApiResponse::ok(RevokeResponse { revoked })))
}
