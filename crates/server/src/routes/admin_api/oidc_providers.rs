use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::oidc::{OidcProvider, OidcProviderId, OidcProviderSummary};
use agent_cordon_core::policy::actions;

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
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

// --- Helpers ---

/// Check Cedar policy for `manage_oidc_providers` on `System` resource.
fn check_manage_oidc_providers(
    state: &AppState,
    auth: &AuthenticatedUser,
) -> Result<agent_cordon_core::domain::policy::PolicyDecision, ApiError> {
    super::check_cedar_permission(
        state,
        auth,
        actions::MANAGE_OIDC_PROVIDERS,
        agent_cordon_core::policy::PolicyResource::System,
    )
}

/// Validate an issuer URL: must be HTTPS except for localhost (dev).
fn validate_issuer_url(url: &str) -> Result<(), ApiError> {
    let parsed = reqwest::Url::parse(url.trim())
        .map_err(|_| ApiError::BadRequest("issuer_url is not a valid URL".to_string()))?;

    let scheme = parsed.scheme();
    let host = parsed.host_str().unwrap_or("");

    if scheme != "https" && host != "localhost" && host != "127.0.0.1" {
        return Err(ApiError::BadRequest(
            "issuer_url must use HTTPS (except localhost for development)".to_string(),
        ));
    }

    Ok(())
}

// --- Handlers ---

async fn create_provider(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<CreateProviderRequest>,
) -> Result<Json<ApiResponse<ProviderResponse>>, ApiError> {
    let policy_decision = check_manage_oidc_providers(&state, &auth)?;

    // Validate input
    if req.name.trim().is_empty() {
        return Err(ApiError::BadRequest("name is required".to_string()));
    }
    if req.client_id.trim().is_empty() {
        return Err(ApiError::BadRequest("client_id is required".to_string()));
    }
    if req.client_secret.is_empty() {
        return Err(ApiError::BadRequest(
            "client_secret is required".to_string(),
        ));
    }
    validate_issuer_url(&req.issuer_url)?;

    // Generate provider ID early so we can use it as AAD
    let provider_id = OidcProviderId(Uuid::new_v4());

    // Encrypt the client secret with provider ID as AAD
    let (encrypted_secret, nonce) = state.encryptor.encrypt(
        req.client_secret.as_bytes(),
        provider_id.0.to_string().as_bytes(),
    )?;

    let now = chrono::Utc::now();
    let provider = OidcProvider {
        id: provider_id,
        name: req.name.trim().to_string(),
        issuer_url: req.issuer_url.trim().trim_end_matches('/').to_string(),
        client_id: req.client_id.trim().to_string(),
        encrypted_client_secret: encrypted_secret,
        nonce,
        scopes: req.scopes.unwrap_or_else(|| {
            vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ]
        }),
        role_mapping: req.role_mapping.unwrap_or(serde_json::json!({})),
        auto_provision: req.auto_provision.unwrap_or(true),
        enabled: req.enabled.unwrap_or(true),
        username_claim: req
            .username_claim
            .unwrap_or_else(|| "preferred_username".to_string()),
        created_at: now,
        updated_at: now,
    };

    state.store.create_oidc_provider(&provider).await?;

    // Audit
    let event = AuditEvent::builder(AuditEventType::OidcProviderCreated)
        .action("create")
        .user_actor(&auth.user)
        .resource("oidc_provider", &provider.id.0.to_string())
        .correlation_id(&corr.0)
        .decision(
            AuditDecision::Permit,
            Some(&policy_decision.reasons.join(", ")),
        )
        .details(serde_json::json!({
            "provider_name": provider.name,
            "issuer_url": provider.issuer_url,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    let summary = OidcProviderSummary::from(&provider);
    Ok(Json(ApiResponse::ok(ProviderResponse::from(&summary))))
}

async fn list_providers(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<ApiResponse<Vec<ProviderResponse>>>, ApiError> {
    // OIDC management is admin-only. Non-admin users get an empty list
    // instead of a 403 so the settings page renders without error.
    if check_manage_oidc_providers(&state, &auth).is_err() {
        return Ok(Json(ApiResponse::ok(vec![])));
    }

    let providers = state.store.list_oidc_providers().await?;
    let response: Vec<ProviderResponse> = providers.iter().map(ProviderResponse::from).collect();
    Ok(Json(ApiResponse::ok(response)))
}

async fn get_provider(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<ProviderResponse>>, ApiError> {
    check_manage_oidc_providers(&state, &auth)?;

    let provider_id = OidcProviderId(id);
    let provider = state
        .store
        .get_oidc_provider(&provider_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("OIDC provider not found".to_string()))?;

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
    let policy_decision = check_manage_oidc_providers(&state, &auth)?;

    let provider_id = OidcProviderId(id);
    let mut provider = state
        .store
        .get_oidc_provider(&provider_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("OIDC provider not found".to_string()))?;

    if let Some(name) = req.name {
        let trimmed = name.trim().to_string();
        if trimmed.is_empty() {
            return Err(ApiError::BadRequest("name cannot be empty".to_string()));
        }
        provider.name = trimmed;
    }
    if let Some(issuer_url) = req.issuer_url {
        validate_issuer_url(&issuer_url)?;
        provider.issuer_url = issuer_url.trim().trim_end_matches('/').to_string();
    }
    if let Some(client_id) = req.client_id {
        let trimmed = client_id.trim().to_string();
        if trimmed.is_empty() {
            return Err(ApiError::BadRequest(
                "client_id cannot be empty".to_string(),
            ));
        }
        provider.client_id = trimmed;
    }
    if let Some(client_secret) = req.client_secret {
        if client_secret.is_empty() {
            return Err(ApiError::BadRequest(
                "client_secret cannot be empty".to_string(),
            ));
        }
        // Re-encrypt the new client secret with provider ID as AAD
        let (encrypted, nonce) = state.encryptor.encrypt(
            client_secret.as_bytes(),
            provider_id.0.to_string().as_bytes(),
        )?;
        provider.encrypted_client_secret = encrypted;
        provider.nonce = nonce;
    }
    if let Some(scopes) = req.scopes {
        provider.scopes = scopes;
    }
    if let Some(role_mapping) = req.role_mapping {
        provider.role_mapping = role_mapping;
    }
    if let Some(auto_provision) = req.auto_provision {
        provider.auto_provision = auto_provision;
    }
    if let Some(enabled) = req.enabled {
        provider.enabled = enabled;
    }
    if let Some(username_claim) = req.username_claim {
        provider.username_claim = username_claim;
    }
    provider.updated_at = chrono::Utc::now();

    state.store.update_oidc_provider(&provider).await?;

    // Audit
    let event = AuditEvent::builder(AuditEventType::OidcProviderUpdated)
        .action("update")
        .user_actor(&auth.user)
        .resource("oidc_provider", &provider.id.0.to_string())
        .correlation_id(&corr.0)
        .decision(
            AuditDecision::Permit,
            Some(&policy_decision.reasons.join(", ")),
        )
        .details(serde_json::json!({
            "provider_name": provider.name,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    let summary = OidcProviderSummary::from(&provider);
    Ok(Json(ApiResponse::ok(ProviderResponse::from(&summary))))
}

async fn delete_provider(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let policy_decision = check_manage_oidc_providers(&state, &auth)?;

    let provider_id = OidcProviderId(id);

    let provider = state
        .store
        .get_oidc_provider(&provider_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("OIDC provider not found".to_string()))?;

    state.store.delete_oidc_provider(&provider_id).await?;

    // Audit
    let event = AuditEvent::builder(AuditEventType::OidcProviderDeleted)
        .action("delete")
        .user_actor(&auth.user)
        .resource("oidc_provider", &provider.id.0.to_string())
        .correlation_id(&corr.0)
        .decision(
            AuditDecision::Permit,
            Some(&policy_decision.reasons.join(", ")),
        )
        .details(serde_json::json!({
            "provider_name": provider.name,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "deleted": true }),
    )))
}
