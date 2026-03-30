//! OAuth client registration and admin management endpoints.

use axum::{
    extract::{Path, State},
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::oauth2::types::OAuthClient;
use agent_cordon_core::oauth2::types::OAuthScope;

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

use super::{generate_client_secret, is_localhost_uri};

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

/// POST /api/v1/oauth/clients
pub(crate) async fn register_client(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<RegisterClientRequest>,
) -> Result<(axum::http::StatusCode, Json<ApiResponse<RegisterClientResponse>>), ApiError> {
    // Validate workspace_name
    if req.workspace_name.is_empty() || req.workspace_name.len() > 255 {
        return Err(ApiError::BadRequest(
            "workspace_name must be 1-255 characters".into(),
        ));
    }

    // Validate public_key_hash format (64 hex chars = SHA-256)
    if req.public_key_hash.len() != 64
        || !req.public_key_hash.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(ApiError::BadRequest(
            "public_key_hash must be a 64-char hex string".into(),
        ));
    }

    // Validate redirect URIs are localhost-only
    if req.redirect_uris.is_empty() {
        return Err(ApiError::BadRequest(
            "at least one redirect_uri is required".into(),
        ));
    }
    for uri in &req.redirect_uris {
        if !is_localhost_uri(uri) {
            return Err(ApiError::BadRequest(format!(
                "redirect_uri must be localhost: {uri}"
            )));
        }
    }

    // Parse and validate scopes
    let scopes: Vec<OAuthScope> = req
        .scopes
        .iter()
        .map(|s| s.parse::<OAuthScope>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::BadRequest)?;

    // Check for existing client with this public_key_hash
    if let Some(existing) = state
        .store
        .get_oauth_client_by_public_key_hash(&req.public_key_hash)
        .await?
    {
        if existing.revoked_at.is_none() {
            return Err(ApiError::Conflict(
                "client already registered for this public_key_hash".into(),
            ));
        }
    }

    // Generate client_id and client_secret
    let client_id = format!("ac_cli_{}", &Uuid::new_v4().simple().to_string()[..12]);
    let (client_secret, client_secret_hash) = generate_client_secret();

    let now = Utc::now();
    let client = OAuthClient {
        id: Uuid::new_v4(),
        client_id: client_id.clone(),
        client_secret_hash: Some(client_secret_hash),
        workspace_name: req.workspace_name.clone(),
        public_key_hash: req.public_key_hash.clone(),
        redirect_uris: req.redirect_uris.clone(),
        allowed_scopes: scopes.clone(),
        created_by_user: auth.user.id.clone(),
        created_at: now,
        revoked_at: None,
    };

    state.store.create_oauth_client(&client).await?;

    // Audit event
    let event = AuditEvent::builder(AuditEventType::Oauth2TokenAcquired)
        .action("oauth_client_registered")
        .user_actor(&auth.user)
        .resource("oauth_client", &client.id.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("client registered"))
        .details(serde_json::json!({
            "client_id": client_id,
            "workspace_name": req.workspace_name,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "failed to write audit event");
    }

    tracing::info!(
        client_id = %client_id,
        workspace_name = %req.workspace_name,
        "OAuth client registered"
    );

    let response = RegisterClientResponse {
        client_id,
        client_secret: Some(client_secret),
        workspace_name: req.workspace_name,
        redirect_uris: req.redirect_uris,
        allowed_scopes: scopes.iter().map(|s| s.to_string()).collect(),
        created_at: now.to_rfc3339(),
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
    if !auth.is_root {
        return Err(ApiError::Forbidden("admin access required".into()));
    }

    // Look up client by UUID id to find client_id
    let clients = state.store.list_oauth_clients().await?;
    let client = clients
        .iter()
        .find(|c| c.id.to_string() == id)
        .ok_or_else(|| ApiError::NotFound("OAuth client not found".into()))?;

    let client_id = client.client_id.clone();

    // Revoke client and all its tokens
    let revoked = state.store.revoke_oauth_client(&client_id).await?;
    state.store.revoke_access_tokens_for_client(&client_id).await?;
    state.store.revoke_refresh_tokens_for_client(&client_id).await?;

    // Audit event
    let event = AuditEvent::builder(AuditEventType::Oauth2TokenFailed)
        .action("oauth_client_revoked")
        .user_actor(&auth.user)
        .resource("oauth_client", &id)
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("client revoked by admin"))
        .details(serde_json::json!({
            "client_id": client_id,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "failed to write audit event");
    }

    Ok(Json(ApiResponse::ok(RevokeResponse { revoked })))
}
