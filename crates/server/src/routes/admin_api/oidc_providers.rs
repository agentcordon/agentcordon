use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agent_cordon_core::domain::oidc::{OidcProvider, OidcProviderId, OidcProviderSummary};

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::services::identity_providers::{NewOidcProvider, OidcProviderChanges};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/oidc-providers", post(create_provider).get(list_providers))
        .route(
            "/oidc-providers/{id}",
            get(get_provider)
                .put(update_provider)
                .delete(delete_provider),
        )
}

// --- Request/Response Types ---

#[derive(Deserialize)]
struct CreateProviderRequest {
    name: String,
    issuer_url: String,
    client_id: String,
    client_secret: String,
    scopes: Option<Vec<String>>,
    role_mapping: Option<serde_json::Value>,
    auto_provision: Option<bool>,
    enabled: Option<bool>,
    /// Which ID token claim to use as the username. Defaults to "preferred_username".
    username_claim: Option<String>,
}

#[derive(Deserialize)]
struct UpdateProviderRequest {
    name: Option<String>,
    issuer_url: Option<String>,
    client_id: Option<String>,
    /// If provided, re-encrypts the client secret.
    client_secret: Option<String>,
    scopes: Option<Vec<String>>,
    role_mapping: Option<serde_json::Value>,
    auto_provision: Option<bool>,
    enabled: Option<bool>,
    /// Which ID token claim to use as the username.
    username_claim: Option<String>,
}

#[derive(Serialize)]
struct ProviderResponse {
    id: String,
    name: String,
    issuer_url: String,
    client_id: String,
    scopes: Vec<String>,
    role_mapping: serde_json::Value,
    auto_provision: bool,
    enabled: bool,
    username_claim: String,
    created_at: String,
    updated_at: String,
}

impl From<&OidcProviderSummary> for ProviderResponse {
    fn from(p: &OidcProviderSummary) -> Self {
        Self {
            id: p.id.0.to_string(),
            name: p.name.clone(),
            issuer_url: p.issuer_url.clone(),
            client_id: p.client_id.clone(),
            scopes: p.scopes.clone(),
            role_mapping: p.role_mapping.clone(),
            auto_provision: p.auto_provision,
            enabled: p.enabled,
            username_claim: p.username_claim.clone(),
            created_at: p.created_at.to_rfc3339(),
            updated_at: p.updated_at.to_rfc3339(),
        }
    }
}

// --- Handlers ---

async fn create_provider(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<CreateProviderRequest>,
) -> Result<Json<ApiResponse<ProviderResponse>>, ApiError> {
    let provider = state
        .services
        .identity_providers
        .create_oidc_provider(
            &auth,
            &corr.0,
            NewOidcProvider {
                name: req.name,
                issuer_url: req.issuer_url,
                client_id: req.client_id,
                client_secret: req.client_secret,
                scopes: req.scopes,
                role_mapping: req.role_mapping,
                auto_provision: req.auto_provision,
                enabled: req.enabled,
                username_claim: req.username_claim,
            },
        )
        .await?;

    let summary = OidcProviderSummary::from(&provider);
    Ok(Json(ApiResponse::ok(ProviderResponse::from(&summary))))
}

async fn list_providers(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<ApiResponse<Vec<ProviderResponse>>>, ApiError> {
    state
        .services
        .identity_providers
        .check_manage_oidc_providers(&auth)
        .await?;

    let providers = state.store.list_oidc_providers().await?;
    let response: Vec<ProviderResponse> = providers.iter().map(ProviderResponse::from).collect();
    Ok(Json(ApiResponse::ok(response)))
}

async fn get_provider(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<ProviderResponse>>, ApiError> {
    state
        .services
        .identity_providers
        .check_manage_oidc_providers(&auth)
        .await?;

    let provider: OidcProvider = state
        .services
        .identity_providers
        .load_oidc_provider(&OidcProviderId(id))
        .await?;

    let summary = OidcProviderSummary::from(&provider);
    Ok(Json(ApiResponse::ok(ProviderResponse::from(&summary))))
}

async fn update_provider(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateProviderRequest>,
) -> Result<Json<ApiResponse<ProviderResponse>>, ApiError> {
    let provider = state
        .services
        .identity_providers
        .update_oidc_provider(
            &auth,
            &corr.0,
            &OidcProviderId(id),
            OidcProviderChanges {
                name: req.name,
                issuer_url: req.issuer_url,
                client_id: req.client_id,
                client_secret: req.client_secret,
                scopes: req.scopes,
                role_mapping: req.role_mapping,
                auto_provision: req.auto_provision,
                enabled: req.enabled,
                username_claim: req.username_claim,
            },
        )
        .await?;

    let summary = OidcProviderSummary::from(&provider);
    Ok(Json(ApiResponse::ok(ProviderResponse::from(&summary))))
}

async fn delete_provider(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    state
        .services
        .identity_providers
        .delete_oidc_provider(&auth, &corr.0, &OidcProviderId(id))
        .await?;

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "deleted": true }),
    )))
}
