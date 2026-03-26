use axum::{
    extract::State,
    http::{header, HeaderMap},
    Json,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agent_cordon_core::auth::jwt::AUDIENCE_WORKSPACE_IDENTITY;
use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::workspace::{
    generate_provisioning_token, hash_provisioning_token, ProvisioningToken, Workspace,
    WorkspaceId, WorkspaceIdentityClaims, WorkspaceStatus,
};

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

use super::IDENTITY_JWT_TTL_SECONDS;

/// Provisioning token TTL in seconds (1 hour).
const PROVISION_TOKEN_TTL_SECONDS: i64 = 3600;

// ============================================================================
// POST /api/v1/workspaces/provision — Create provisioning token (admin)
// ============================================================================

#[derive(Deserialize)]
pub(super) struct ProvisionRequest {
    name: String,
}

#[derive(Serialize)]
pub(super) struct ProvisionResponse {
    token: String,
    server_url: String,
    env_snippet: String,
    expires_in: i64,
}

pub(super) async fn create_provisioning_token(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<ProvisionRequest>,
) -> Result<(HeaderMap, Json<ApiResponse<ProvisionResponse>>), ApiError> {
    // Validate name
    if req.name.is_empty() || req.name.len() > 128 {
        return Err(ApiError::BadRequest(
            "name must be 1-128 characters".to_string(),
        ));
    }

    let raw_token = generate_provisioning_token();
    let token_hash = hash_provisioning_token(&raw_token);
    let now = Utc::now();
    let expires_at = now + Duration::seconds(PROVISION_TOKEN_TTL_SECONDS);

    let token = ProvisioningToken {
        token_hash,
        name: req.name.clone(),
        expires_at,
        used: false,
        created_at: now,
    };

    state.store.create_provisioning_token(&token).await?;

    // Determine server URL from config
    let server_url = state
        .config
        .base_url
        .clone()
        .unwrap_or_else(|| format!("http://{}", state.config.listen_addr));

    let env_snippet = format!(
        "AGENTCORDON_PROVISION_TOKEN={}\nAGENTCORDON_SERVER_URL={}",
        raw_token, server_url
    );

    // Audit
    let event = AuditEvent::builder(AuditEventType::WorkspaceRegistered)
        .action("create_provisioning_token")
        .user_actor(&auth.user)
        .resource_type("provisioning_token")
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("bypass:admin"))
        .details(serde_json::json!({ "name": req.name }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    // Cache-Control: no-store — token must not be cached
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert(header::PRAGMA, "no-cache".parse().unwrap());

    Ok((
        headers,
        Json(ApiResponse::ok(ProvisionResponse {
            token: raw_token,
            server_url,
            env_snippet,
            expires_in: PROVISION_TOKEN_TTL_SECONDS,
        })),
    ))
}

// ============================================================================
// POST /api/v1/workspaces/provision/complete — Complete provisioning (no auth)
// ============================================================================

#[derive(Deserialize)]
pub(super) struct CompleteProvisionRequest {
    token: String,
    public_key: String,
    #[serde(default)]
    encryption_key: Option<serde_json::Value>,
    name: String,
}

#[derive(Serialize)]
pub(super) struct CompleteProvisionResponse {
    workspace_id: String,
    identity_jwt: String,
}

pub(super) async fn complete_provisioning(
    State(state): State<AppState>,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<CompleteProvisionRequest>,
) -> Result<(HeaderMap, Json<ApiResponse<CompleteProvisionResponse>>), ApiError> {
    // Validate inputs
    if req.token.is_empty() {
        return Err(ApiError::BadRequest("token is required".to_string()));
    }
    if req.name.is_empty() || req.name.len() > 128 {
        return Err(ApiError::BadRequest(
            "name must be 1-128 characters".to_string(),
        ));
    }

    let pubkey_bytes = hex::decode(&req.public_key)
        .map_err(|_| ApiError::BadRequest("invalid hex in public_key".to_string()))?;
    if pubkey_bytes.len() != 32 {
        return Err(ApiError::BadRequest(
            "public key must be 32 bytes".to_string(),
        ));
    }

    // Hash token and look up
    let token_hash = hash_provisioning_token(&req.token);
    let stored = state
        .store
        .get_provisioning_token(&token_hash)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("invalid provisioning token".to_string()))?;

    // Check not expired
    if stored.expires_at < Utc::now() {
        return Err(ApiError::Gone("provisioning token expired".to_string()));
    }

    // Check not already used
    if stored.used {
        return Err(ApiError::Conflict(
            "provisioning token already used".to_string(),
        ));
    }

    // Atomically mark token as used
    let marked = state
        .store
        .mark_provisioning_token_used(&token_hash)
        .await?;
    if !marked {
        return Err(ApiError::Conflict(
            "provisioning token already used".to_string(),
        ));
    }

    // Validate encryption key if provided
    super::validate_encryption_key(req.encryption_key.as_ref()).map_err(ApiError::BadRequest)?;

    // Create workspace (same pattern as code_exchange)
    let pk_hash = agent_cordon_core::crypto::ed25519::compute_pk_hash(&pubkey_bytes);
    let workspace_id = WorkspaceId(Uuid::new_v4());
    let now = Utc::now();
    let assigned_name = if req.name.is_empty() {
        format!("workspace:{}", &pk_hash[..8])
    } else {
        req.name.clone()
    };

    let encryption_public_key = req.encryption_key.as_ref().map(|jwk| jwk.to_string());

    let ws = Workspace {
        id: workspace_id.clone(),
        name: assigned_name.clone(),
        enabled: true,
        status: WorkspaceStatus::Active,
        pk_hash: Some(pk_hash.clone()),
        encryption_public_key,
        tags: vec![],
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };

    if let Err(e) = state.store.create_workspace(&ws).await {
        let err_msg = e.to_string();
        if err_msg.contains("UNIQUE")
            || err_msg.contains("unique")
            || err_msg.contains("constraint")
        {
            return Err(ApiError::Conflict(format!(
                "workspace name '{}' is already in use; please choose a different name",
                assigned_name
            )));
        }
        return Err(ApiError::Internal(format!(
            "failed to create workspace: {}",
            e
        )));
    }

    // Issue identity JWT
    let claims = WorkspaceIdentityClaims {
        sub: workspace_id.0.to_string(),
        wkt: pk_hash.clone(),
        ekt: None,
        exp: (now + Duration::seconds(IDENTITY_JWT_TTL_SECONDS)).timestamp(),
        iss: agent_cordon_core::auth::jwt::ISSUER.to_string(),
        aud: AUDIENCE_WORKSPACE_IDENTITY.to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        jti: Uuid::new_v4().to_string(),
    };
    let jwt = state
        .jwt_issuer
        .sign_custom_claims(&claims)
        .map_err(|e| ApiError::Internal(format!("failed to sign identity JWT: {}", e)))?;

    // Audit
    let event = AuditEvent::builder(AuditEventType::WorkspaceRegistered)
        .action("complete_provisioning")
        .workspace_actor(&workspace_id, &assigned_name)
        .resource("workspace", &workspace_id.0.to_string())
        .correlation_id(&corr.0)
        .decision(
            AuditDecision::Permit,
            Some("bypass:provisioning_token_redeemed"),
        )
        .details(serde_json::json!({ "pk_hash": pk_hash }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    // Cache-Control: no-store
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());

    Ok((
        headers,
        Json(ApiResponse::ok(CompleteProvisionResponse {
            workspace_id: workspace_id.0.to_string(),
            identity_jwt: jwt,
        })),
    ))
}
