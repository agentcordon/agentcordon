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

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::oauth_provider_client::{
    OAuthProviderClient, OAuthProviderClientId, OAuthProviderClientSummary, RegistrationSource,
};
use agent_cordon_core::policy::actions;

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
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

// --- Helpers ---

fn check_manage(
    state: &AppState,
    auth: &AuthenticatedUser,
) -> Result<agent_cordon_core::domain::policy::PolicyDecision, ApiError> {
    super::check_cedar_permission(
        state,
        auth,
        actions::MANAGE_MCP_SERVERS,
        agent_cordon_core::policy::PolicyResource::System,
    )
}

fn validate_url(url: &str, field_name: &str) -> Result<(), ApiError> {
    let parsed = reqwest::Url::parse(url.trim())
        .map_err(|_| ApiError::BadRequest(format!("{field_name} is not a valid URL")))?;

    let scheme = parsed.scheme();
    let host = parsed.host_str().unwrap_or("");

    if scheme != "https" && host != "localhost" && host != "127.0.0.1" {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must use HTTPS (except localhost for development)"
        )));
    }

    Ok(())
}

// --- Handlers ---

async fn create_client(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<CreateClientRequest>,
) -> Result<Json<ApiResponse<ClientResponse>>, ApiError> {
    let policy_decision = check_manage(&state, &auth)?;

    if req.label.trim().is_empty() {
        return Err(ApiError::BadRequest("label is required".to_string()));
    }
    if req.client_id.trim().is_empty() {
        return Err(ApiError::BadRequest("client_id is required".to_string()));
    }
    validate_url(&req.authorization_server_url, "authorization_server_url")?;
    validate_url(&req.authorize_endpoint, "authorize_endpoint")?;
    validate_url(&req.token_endpoint, "token_endpoint")?;

    let as_url = req.authorization_server_url.trim().to_string();

    if state
        .store
        .get_oauth_provider_client_by_authorization_server_url(&as_url)
        .await?
        .is_some()
    {
        return Err(ApiError::Conflict(format!(
            "An OAuth provider client for '{as_url}' already exists"
        )));
    }

    let client_id_val = OAuthProviderClientId(Uuid::new_v4());

    let (encrypted_secret, nonce) = if let Some(secret) = req.client_secret.as_ref() {
        if secret.is_empty() {
            (None, None)
        } else {
            let (enc, n) = state
                .encryptor
                .encrypt(secret.as_bytes(), client_id_val.0.to_string().as_bytes())?;
            (Some(enc), Some(n))
        }
    } else {
        (None, None)
    };

    let now = chrono::Utc::now();
    let client = OAuthProviderClient {
        id: client_id_val,
        authorization_server_url: as_url,
        issuer: None,
        authorize_endpoint: req.authorize_endpoint.trim().to_string(),
        token_endpoint: req.token_endpoint.trim().to_string(),
        registration_endpoint: None,
        code_challenge_methods_supported: vec![],
        token_endpoint_auth_methods_supported: vec![],
        scopes_supported: vec![],
        client_id: req.client_id.trim().to_string(),
        encrypted_client_secret: encrypted_secret,
        nonce,
        requested_scopes: req.requested_scopes.unwrap_or_default(),
        registration_source: RegistrationSource::Manual,
        client_id_issued_at: None,
        client_secret_expires_at: None,
        registration_access_token_encrypted: None,
        registration_access_token_nonce: None,
        registration_client_uri: None,
        label: req.label.trim().to_string(),
        enabled: req.enabled.unwrap_or(true),
        created_at: now,
        updated_at: now,
    };

    state.store.create_oauth_provider_client(&client).await?;

    let event = AuditEvent::builder(AuditEventType::OAuthProviderClientCreated)
        .action("create")
        .user_actor(&auth.user)
        .resource("oauth_provider_client", &client.id.0.to_string())
        .correlation_id(&corr.0)
        .decision(
            AuditDecision::Permit,
            Some(&policy_decision.reasons.join(", ")),
        )
        .details(serde_json::json!({
            "authorization_server_url": client.authorization_server_url,
            "label": client.label,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    let summary = OAuthProviderClientSummary::from(&client);
    Ok(Json(ApiResponse::ok(ClientResponse::from(&summary))))
}

async fn list_clients(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<ApiResponse<Vec<ClientResponse>>>, ApiError> {
    if check_manage(&state, &auth).is_err() {
        return Ok(Json(ApiResponse::ok(vec![])));
    }

    let clients = state.store.list_oauth_provider_clients().await?;
    let response: Vec<ClientResponse> = clients.iter().map(ClientResponse::from).collect();
    Ok(Json(ApiResponse::ok(response)))
}

async fn get_client(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<ClientResponse>>, ApiError> {
    check_manage(&state, &auth)?;

    let client_id = OAuthProviderClientId(id);
    let client = state
        .store
        .get_oauth_provider_client(&client_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("OAuth provider client not found".to_string()))?;

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
    let policy_decision = check_manage(&state, &auth)?;

    let client_id = OAuthProviderClientId(id);
    let mut client = state
        .store
        .get_oauth_provider_client(&client_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("OAuth provider client not found".to_string()))?;

    // Reject edits on DCR-sourced rows.
    if client.registration_source == RegistrationSource::Dcr {
        return Err(ApiError::Conflict(
            "cannot edit DCR-registered clients — delete and re-register instead".to_string(),
        ));
    }

    if let Some(label) = req.label {
        let trimmed = label.trim().to_string();
        if trimmed.is_empty() {
            return Err(ApiError::BadRequest("label cannot be empty".to_string()));
        }
        client.label = trimmed;
    }
    if let Some(cid) = req.client_id {
        let trimmed = cid.trim().to_string();
        if trimmed.is_empty() {
            return Err(ApiError::BadRequest(
                "client_id cannot be empty".to_string(),
            ));
        }
        client.client_id = trimmed;
    }
    if let Some(secret) = req.client_secret {
        if secret.is_empty() {
            return Err(ApiError::BadRequest(
                "client_secret cannot be empty".to_string(),
            ));
        }
        let (enc, n) = state
            .encryptor
            .encrypt(secret.as_bytes(), client_id.0.to_string().as_bytes())?;
        client.encrypted_client_secret = Some(enc);
        client.nonce = Some(n);
    }
    if let Some(authorize_endpoint) = req.authorize_endpoint {
        validate_url(&authorize_endpoint, "authorize_endpoint")?;
        client.authorize_endpoint = authorize_endpoint.trim().to_string();
    }
    if let Some(token_endpoint) = req.token_endpoint {
        validate_url(&token_endpoint, "token_endpoint")?;
        client.token_endpoint = token_endpoint.trim().to_string();
    }
    if let Some(scopes) = req.requested_scopes {
        client.requested_scopes = scopes;
    }
    if let Some(enabled) = req.enabled {
        client.enabled = enabled;
    }
    client.updated_at = chrono::Utc::now();

    state.store.update_oauth_provider_client(&client).await?;

    let event = AuditEvent::builder(AuditEventType::OAuthProviderClientUpdated)
        .action("update")
        .user_actor(&auth.user)
        .resource("oauth_provider_client", &client.id.0.to_string())
        .correlation_id(&corr.0)
        .decision(
            AuditDecision::Permit,
            Some(&policy_decision.reasons.join(", ")),
        )
        .details(serde_json::json!({
            "authorization_server_url": client.authorization_server_url,
            "label": client.label,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    let summary = OAuthProviderClientSummary::from(&client);
    Ok(Json(ApiResponse::ok(ClientResponse::from(&summary))))
}

async fn delete_client(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let policy_decision = check_manage(&state, &auth)?;

    let client_id = OAuthProviderClientId(id);

    let client = state
        .store
        .get_oauth_provider_client(&client_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("OAuth provider client not found".to_string()))?;

    state.store.delete_oauth_provider_client(&client_id).await?;

    let event = AuditEvent::builder(AuditEventType::OAuthProviderClientDeleted)
        .action("delete")
        .user_actor(&auth.user)
        .resource("oauth_provider_client", &client.id.0.to_string())
        .correlation_id(&corr.0)
        .decision(
            AuditDecision::Permit,
            Some(&policy_decision.reasons.join(", ")),
        )
        .details(serde_json::json!({
            "authorization_server_url": client.authorization_server_url,
            "label": client.label,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

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
    use agent_cordon_core::crypto::SecretEncryptor;

    let policy_decision = check_manage(&state, &auth)?;

    let client_id = OAuthProviderClientId(id);
    let existing = state
        .store
        .get_oauth_provider_client(&client_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("OAuth provider client not found".to_string()))?;

    if existing.registration_source != RegistrationSource::Dcr {
        return Err(ApiError::BadRequest(
            "only DCR-registered clients can be re-registered; edit manual clients directly"
                .to_string(),
        ));
    }

    // Re-fetch AS metadata to pick up any endpoint changes.
    let as_meta = crate::oauth_discovery::fetch_authorization_server_metadata(
        &existing.authorization_server_url,
    )
    .await
    .map_err(|e| ApiError::BadRequest(format!("failed to re-fetch AS metadata: {e}")))?;

    // Build redirect URI from configured base_url.
    let base_url = state.config.base_url.as_deref().ok_or_else(|| {
        ApiError::BadRequest("AGTCRDN_BASE_URL must be configured for DCR".to_string())
    })?;
    let redirect_uri = format!(
        "{}/api/v1/mcp-servers/oauth/callback",
        base_url.trim_end_matches('/')
    );

    let client_name = state
        .config
        .instance_label
        .clone()
        .unwrap_or_else(|| "AgentCordon".to_string());

    let scopes = if existing.requested_scopes.is_empty() {
        None
    } else {
        Some(existing.requested_scopes.as_str())
    };

    let dcr_resp =
        crate::oauth_discovery::register_client(&as_meta, &redirect_uri, &client_name, scopes)
            .await
            .map_err(|e| ApiError::BadRequest(format!("DCR re-registration failed: {e}")))?;

    // Build the updated row, keeping the same id.
    let id_bytes = existing.id.0.to_string();
    let (encrypted_client_secret, secret_nonce) =
        if let Some(secret) = dcr_resp.client_secret.as_deref() {
            let (enc, nonce) = state
                .encryptor
                .encrypt(secret.as_bytes(), id_bytes.as_bytes())
                .map_err(|e| ApiError::Internal(format!("encryption: {e}")))?;
            (Some(enc), Some(nonce))
        } else {
            (None, None)
        };
    let (rat_enc, rat_nonce) = if let Some(rat) = dcr_resp.registration_access_token.as_deref() {
        let (enc, nonce) = state
            .encryptor
            .encrypt(rat.as_bytes(), id_bytes.as_bytes())
            .map_err(|e| ApiError::Internal(format!("encryption: {e}")))?;
        (Some(enc), Some(nonce))
    } else {
        (None, None)
    };

    let updated = OAuthProviderClient {
        id: existing.id.clone(),
        authorization_server_url: existing.authorization_server_url.clone(),
        issuer: Some(as_meta.issuer.clone()),
        authorize_endpoint: as_meta.authorization_endpoint.clone(),
        token_endpoint: as_meta.token_endpoint.clone(),
        registration_endpoint: as_meta.registration_endpoint.clone(),
        code_challenge_methods_supported: as_meta.code_challenge_methods_supported.clone(),
        token_endpoint_auth_methods_supported: as_meta
            .token_endpoint_auth_methods_supported
            .clone(),
        scopes_supported: as_meta.scopes_supported.clone(),
        client_id: dcr_resp.client_id.clone(),
        encrypted_client_secret,
        nonce: secret_nonce,
        requested_scopes: existing.requested_scopes.clone(),
        registration_source: RegistrationSource::Dcr,
        client_id_issued_at: dcr_resp
            .client_id_issued_at
            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0)),
        client_secret_expires_at: dcr_resp
            .client_secret_expires_at
            .filter(|ts| *ts != 0)
            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0)),
        registration_access_token_encrypted: rat_enc,
        registration_access_token_nonce: rat_nonce,
        registration_client_uri: dcr_resp.registration_client_uri.clone(),
        label: existing.label.clone(),
        enabled: existing.enabled,
        created_at: existing.created_at,
        updated_at: chrono::Utc::now(),
    };

    state.store.update_oauth_provider_client(&updated).await?;

    let event = AuditEvent::builder(AuditEventType::OAuthProviderClientUpdated)
        .action("reregister")
        .user_actor(&auth.user)
        .resource("oauth_provider_client", &updated.id.0.to_string())
        .correlation_id(&corr.0)
        .decision(
            AuditDecision::Permit,
            Some(&policy_decision.reasons.join(", ")),
        )
        .details(serde_json::json!({
            "authorization_server_url": updated.authorization_server_url,
            "source": "dcr",
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    Ok(Json(ApiResponse::ok(ClientResponse::from(&updated))))
}
