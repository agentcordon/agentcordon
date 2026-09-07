//! OAuth Provider Client CRUD endpoints.
//!
//! Server-wide admin configuration for OAuth client registrations
//! (client_id/client_secret) keyed by upstream authorization server URL.

use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agent_cordon_core::domain::oauth_provider_client::{
    OAuthProviderClient, OAuthProviderClientId, OAuthProviderClientSummary, RegistrationSource,
};

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::services::identity_providers::{NewOAuthProviderClient, OAuthProviderClientChanges};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/oauth-provider-clients",
            post(create_client).get(list_clients),
        )
        .route(
            "/oauth-provider-clients/{id}",
            get(get_client).put(update_client).delete(delete_client),
        )
        .route(
            "/oauth-provider-clients/{id}/reregister",
            post(reregister_client),
        )
}

// --- Request/Response Types ---

#[derive(Deserialize)]
struct CreateClientRequest {
    label: String,
    authorization_server_url: String,
    authorize_endpoint: String,
    token_endpoint: String,
    client_id: String,
    client_secret: Option<String>,
    requested_scopes: Option<String>,
    enabled: Option<bool>,
}

#[derive(Deserialize)]
struct UpdateClientRequest {
    label: Option<String>,
    client_id: Option<String>,
    /// If provided, re-encrypts the client secret.
    client_secret: Option<String>,
    authorize_endpoint: Option<String>,
    token_endpoint: Option<String>,
    requested_scopes: Option<String>,
    enabled: Option<bool>,
}

#[derive(Serialize)]
struct ClientResponse {
    id: String,
    authorization_server_url: String,
    issuer: Option<String>,
    authorize_endpoint: String,
    token_endpoint: String,
    registration_endpoint: Option<String>,
    client_id: String,
    requested_scopes: String,
    registration_source: RegistrationSource,
    label: String,
    enabled: bool,
    created_at: String,
    updated_at: String,
}

impl From<&OAuthProviderClientSummary> for ClientResponse {
    fn from(c: &OAuthProviderClientSummary) -> Self {
        Self {
            id: c.id.0.to_string(),
            authorization_server_url: c.authorization_server_url.clone(),
            issuer: c.issuer.clone(),
            authorize_endpoint: c.authorize_endpoint.clone(),
            token_endpoint: c.token_endpoint.clone(),
            registration_endpoint: c.registration_endpoint.clone(),
            client_id: c.client_id.clone(),
            requested_scopes: c.requested_scopes.clone(),
            registration_source: c.registration_source,
            label: c.label.clone(),
            enabled: c.enabled,
            created_at: c.created_at.to_rfc3339(),
            updated_at: c.updated_at.to_rfc3339(),
        }
    }
}

impl From<&OAuthProviderClient> for ClientResponse {
    fn from(c: &OAuthProviderClient) -> Self {
        Self {
            id: c.id.0.to_string(),
            authorization_server_url: c.authorization_server_url.clone(),
            issuer: c.issuer.clone(),
            authorize_endpoint: c.authorize_endpoint.clone(),
            token_endpoint: c.token_endpoint.clone(),
            registration_endpoint: c.registration_endpoint.clone(),
            client_id: c.client_id.clone(),
            requested_scopes: c.requested_scopes.clone(),
            registration_source: c.registration_source,
            label: c.label.clone(),
            enabled: c.enabled,
            created_at: c.created_at.to_rfc3339(),
            updated_at: c.updated_at.to_rfc3339(),
        }
    }
}

// --- Handlers ---

async fn create_client(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<CreateClientRequest>,
) -> Result<Json<ApiResponse<ClientResponse>>, ApiError> {
    let client = state
        .services
        .identity_providers
        .create_oauth_client(
            &auth,
            &corr.0,
            NewOAuthProviderClient {
                label: req.label,
                authorization_server_url: req.authorization_server_url,
                authorize_endpoint: req.authorize_endpoint,
                token_endpoint: req.token_endpoint,
                client_id: req.client_id,
                client_secret: req.client_secret,
                requested_scopes: req.requested_scopes,
                enabled: req.enabled,
            },
        )
        .await?;

    let summary = OAuthProviderClientSummary::from(&client);
    Ok(Json(ApiResponse::ok(ClientResponse::from(&summary))))
}

async fn list_clients(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<ApiResponse<Vec<ClientResponse>>>, ApiError> {
    state
        .services
        .identity_providers
        .check_read_oauth_clients(&auth)
        .await?;

    let clients = state.store.list_oauth_provider_clients().await?;
    let response: Vec<ClientResponse> = clients.iter().map(ClientResponse::from).collect();
    Ok(Json(ApiResponse::ok(response)))
}

async fn get_client(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<ClientResponse>>, ApiError> {
    state
        .services
        .identity_providers
        .check_read_oauth_clients(&auth)
        .await?;

    let client: OAuthProviderClient = state
        .services
        .identity_providers
        .load_oauth_client(&OAuthProviderClientId(id))
        .await?;

    let summary = OAuthProviderClientSummary::from(&client);
    Ok(Json(ApiResponse::ok(ClientResponse::from(&summary))))
}

async fn update_client(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateClientRequest>,
) -> Result<Json<ApiResponse<ClientResponse>>, ApiError> {
    let client = state
        .services
        .identity_providers
        .update_oauth_client(
            &auth,
            &corr.0,
            &OAuthProviderClientId(id),
            OAuthProviderClientChanges {
                label: req.label,
                client_id: req.client_id,
                client_secret: req.client_secret,
                authorize_endpoint: req.authorize_endpoint,
                token_endpoint: req.token_endpoint,
                requested_scopes: req.requested_scopes,
                enabled: req.enabled,
            },
        )
        .await?;

    let summary = OAuthProviderClientSummary::from(&client);
    Ok(Json(ApiResponse::ok(ClientResponse::from(&summary))))
}

async fn delete_client(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    state
        .services
        .identity_providers
        .delete_oauth_client(&auth, &corr.0, &OAuthProviderClientId(id))
        .await?;

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "deleted": true }),
    )))
}

/// `POST /api/v1/oauth-provider-clients/{id}/reregister`
///
/// Re-register the OAuth client at the authorization server. Re-runs discovery
/// and DCR POST against the same `authorization_server_url`, then updates the
/// existing row in place (stable `id`). Manual rows are rejected — admins should
/// edit those directly.
async fn reregister_client(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<ClientResponse>>, ApiError> {
    let updated = state
        .services
        .identity_providers
        .reregister_oauth_client(&auth, &corr.0, &OAuthProviderClientId(id))
        .await?;

    Ok(Json(ApiResponse::ok(ClientResponse::from(&updated))))
}
