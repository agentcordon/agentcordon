use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use base64::engine::general_purpose::{STANDARD as B64_STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;

use agent_cordon_core::crypto::ecies::{build_aad, CredentialEnvelopeEncryptor, EciesEncryptor};
use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::domain::workspace::Workspace;
use agent_cordon_core::policy::{
    actions, PolicyContext, PolicyEngine, PolicyPrincipal, PolicyResource,
};

use crate::extractors::authenticated_workspace;
use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

#[derive(Serialize)]
pub(crate) struct VendResponse {
    credential_type: String,
    transform_name: Option<String>,
    encrypted_envelope: VendEnvelopeResponse,
    vend_id: String,
}

#[derive(Serialize)]
struct VendEnvelopeResponse {
    version: u8,
    ephemeral_public_key: String,
    ciphertext: String,
    nonce: String,
    aad: String,
}

/// Optional request body for vend endpoints. The broker may provide its own
/// ECIES public key so the server encrypts the credential to the broker
/// rather than to the workspace's stored key.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct VendRequest {
    /// Base64url-encoded uncompressed P-256 public key (65 bytes decoded).
    /// When present, the server encrypts the credential envelope to this key
    /// instead of the workspace's `encryption_public_key`.
    #[serde(default)]
    broker_public_key: Option<String>,
}

/// Decode a base64url-encoded uncompressed P-256 point and validate its length.
fn parse_broker_public_key(encoded: &str) -> Result<Vec<u8>, ApiError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ApiError::BadRequest("invalid base64url in broker_public_key".to_string()))?;
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(ApiError::BadRequest(
            "broker_public_key must be a 65-byte uncompressed P-256 point (0x04 || x || y)"
                .to_string(),
        ));
    }
    Ok(bytes)
}

/// Extract the encryption JWK from a workspace's `encryption_public_key` value (JWK JSON string).
fn parse_encryption_jwk(encryption_public_key: &str) -> Result<serde_json::Value, ApiError> {
    let jwk: serde_json::Value = serde_json::from_str(encryption_public_key)
        .map_err(|_| ApiError::Internal("invalid encryption public key JWK".to_string()))?;
    Ok(jwk)
}

/// Convert a P-256 JWK to uncompressed SEC1 bytes (65 bytes: 0x04 || x || y).
fn jwk_to_uncompressed_point(jwk: &serde_json::Value) -> Result<Vec<u8>, ApiError> {
    let x = jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::Internal("encryption key missing 'x' coordinate".to_string()))?;
    let y = jwk
        .get("y")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::Internal("encryption key missing 'y' coordinate".to_string()))?;

    let x_bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| ApiError::Internal("invalid x coordinate encoding".to_string()))?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(y)
        .map_err(|_| ApiError::Internal("invalid y coordinate encoding".to_string()))?;

    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&x_bytes);
    point.extend_from_slice(&y_bytes);

    Ok(point)
}

/// Shared vend logic: policy check → decrypt → ECIES encrypt → audit → response.
///
/// Both `vend_credential` (by ID) and `vend_credential_to_device` (by name)
/// delegate here after their unique credential lookup.
///
/// `broker_pub_bytes`: If `Some`, use this P-256 public key for ECIES encryption
/// (provided by the broker in the request body). Otherwise fall back to
/// `workspace.encryption_public_key`.
async fn vend_inner(
    state: &AppState,
    workspace: &Workspace,
    cred: &StoredCredential,
    corr_id: String,
    broker_pub_bytes: Option<Vec<u8>>,
    oauth_claims: Option<serde_json::Value>,
) -> Result<VendResponse, ApiError> {
    if cred.is_expired() {
        return Err(ApiError::Forbidden("credential has expired".to_string()));
    }

    // Cedar policy evaluation with workspace principal
    let decision = state.policy_engine.evaluate(
        &PolicyPrincipal::Workspace(workspace),
        actions::VEND_CREDENTIAL,
        &PolicyResource::Credential {
            credential: cred.clone(),
        },
        &PolicyContext {
            correlation_id: Some(corr_id.clone()),
            oauth_claims,
            ..Default::default()
        },
    )?;

    let now = chrono::Utc::now();

    if decision.decision == PolicyDecisionResult::Forbid {
        // Audit event emitted automatically by AuditingPolicyEngine.
        return Err(ApiError::Forbidden("access denied by policy".to_string()));
    }

    // Generate vend_id
    let vend_id = format!("vnd_{}", Uuid::new_v4());

    // Decrypt credential material (AES-GCM with credential ID as AAD)
    let plaintext = state.encryptor.decrypt(
        &cred.encrypted_value,
        &cred.nonce,
        cred.id.0.to_string().as_bytes(),
    )?;

    // Resolve encryption public key: prefer broker-provided key, fall back to workspace key
    let ws_pub_bytes = if let Some(broker_bytes) = broker_pub_bytes {
        broker_bytes
    } else {
        let encryption_key_str = workspace
            .encryption_public_key
            .as_ref()
            .ok_or_else(|| ApiError::UnprocessableEntity(
                "workspace encryption key not configured \u{2014} provide broker_public_key in the request body or register with an encryption key".to_string(),
            ))?;
        let encryption_jwk = parse_encryption_jwk(encryption_key_str)?;
        jwk_to_uncompressed_point(&encryption_jwk)?
    };

    // Build AAD: workspace_id||credential_id||vend_id||timestamp
    let timestamp = now.timestamp().to_string();
    let aad = build_aad(
        &workspace.id.0.to_string(),
        &cred.id.0.to_string(),
        &vend_id,
        &timestamp,
    );

    // Wrap the raw secret in a JSON envelope matching the device's CredentialMaterial format.
    let plaintext_str = String::from_utf8(plaintext)
        .map_err(|_| ApiError::Internal("credential secret is not valid UTF-8".to_string()))?;
    let credential_material = serde_json::json!({
        "value": plaintext_str,
    });
    let material_bytes = serde_json::to_vec(&credential_material).map_err(|e| {
        ApiError::Internal(format!("failed to serialize credential material: {}", e))
    })?;

    // ECIES encrypt
    let ecies = EciesEncryptor::new();
    let envelope = ecies
        .encrypt_for_device(&ws_pub_bytes, &material_bytes, &aad)
        .await
        .map_err(|e| ApiError::Internal(format!("ECIES encryption failed: {}", e)))?;

    // Domain audit: credential was vended — NEVER include credential secret values.
    // Policy decision audit is handled by AuditingPolicyEngine.
    let event = AuditEvent::builder(AuditEventType::CredentialVended)
        .action("vend_credential")
        .workspace_actor(&workspace.id, &workspace.name)
        .resource("credential", &cred.id.0.to_string())
        .correlation_id(&corr_id)
        .decision(AuditDecision::Permit, None)
        .details(serde_json::json!({
            "workspace_id": workspace.id.0.to_string(),
            "credential_name": cred.name,
            "vend_id": vend_id,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    // Build response — credential material is ONLY in the ECIES envelope
    Ok(VendResponse {
        credential_type: cred.credential_type.clone(),
        transform_name: cred.transform_name.clone(),
        encrypted_envelope: VendEnvelopeResponse {
            version: envelope.version,
            ephemeral_public_key: B64_STANDARD.encode(&envelope.ephemeral_public_key),
            ciphertext: B64_STANDARD.encode(&envelope.ciphertext),
            nonce: B64_STANDARD.encode(&envelope.nonce),
            aad: B64_STANDARD.encode(&envelope.aad),
        },
        vend_id,
    })
}

/// POST /credentials/{id}/reveal
///
/// Vault-style secret reveal: decrypts and returns the credential's raw secret
/// value. Only human users (session cookie auth) are allowed. Cedar policy
/// with action `"unprotect"` is evaluated BEFORE decryption. Agents are
/// forbidden from using this endpoint via both extractor and Cedar forbid rule.
pub(crate) async fn reveal_credential(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let cred_id = CredentialId(id);

    // Load the credential — return 404 for both "not found" and later "not authorized"
    // to avoid leaking credential existence.
    let cred = state
        .store
        .get_credential(&cred_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("credential not found".to_string()))?;

    // Cedar policy check BEFORE decryption (deny-first).
    // Root users bypass Cedar entirely (handled in evaluate).
    let principal = PolicyPrincipal::User(&auth_user.user);
    let decision = state.policy_engine.evaluate(
        &principal,
        actions::UNPROTECT,
        &PolicyResource::Credential {
            credential: cred.clone(),
        },
        &PolicyContext {
            target_url: None,
            requested_scopes: vec![],
            correlation_id: Some(corr.0.clone()),
            ..Default::default()
        },
    )?;

    if decision.decision == PolicyDecisionResult::Forbid {
        // Policy deny audit is emitted by AuditingPolicyEngine.
        // Return 404 to avoid leaking credential existence to unauthorized users.
        return Err(ApiError::NotFound("credential not found".to_string()));
    }

    // Decrypt the credential secret value with credential ID as AAD
    let plaintext = state.encryptor.decrypt(
        &cred.encrypted_value,
        &cred.nonce,
        cred_id.0.to_string().as_bytes(),
    )?;
    let secret_value = String::from_utf8(plaintext)
        .map_err(|_| ApiError::Internal("credential value is not valid UTF-8".to_string()))?;

    // Domain audit: secret was revealed — NEVER log the secret itself.
    // Policy decision audit is handled by AuditingPolicyEngine.
    let event = AuditEvent::builder(AuditEventType::CredentialSecretViewed)
        .action("unprotect")
        .user_actor(&auth_user.user)
        .resource("credential", &id.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, None)
        .details(serde_json::json!({
            "credential_name": cred.name,
            "service": cred.service,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    Ok(Json(ApiResponse::ok(serde_json::json!({
        "secret_value": secret_value,
    }))))
}

/// POST /credentials/{id}/vend
///
/// Vend a credential to a workspace by credential ID.
/// Auth: workspace JWT (Authorization: Bearer).
pub(crate) async fn vend_credential(
    State(state): State<AppState>,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
    headers: axum::http::HeaderMap,
    body: Option<Json<VendRequest>>,
) -> Result<Json<ApiResponse<VendResponse>>, ApiError> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::Unauthorized("missing Authorization header".to_string()))?;
    let auth = authenticated_workspace::authenticate_workspace(&state, auth_header).await?;
    auth.require_scope(agent_cordon_core::oauth2::types::OAuthScope::CredentialsVend)?;

    let broker_pub = match &body {
        Some(Json(req)) => req
            .broker_public_key
            .as_deref()
            .map(parse_broker_public_key)
            .transpose()?,
        None => None,
    };

    let cred_id = CredentialId(id);
    let cred = state
        .store
        .get_credential(&cred_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("credential not found".to_string()))?;

    let response =
        vend_inner(&state, &auth.workspace, &cred, corr.0, broker_pub, auth.oauth_claims).await?;
    Ok(Json(ApiResponse::ok(response)))
}

/// POST /api/v1/credentials/vend-device/{name}
///
/// Vend a credential to a workspace by credential name.
/// Auth: workspace JWT (Authorization: Bearer).
pub(crate) async fn vend_credential_to_device(
    State(state): State<AppState>,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    headers: axum::http::HeaderMap,
    Path(name): Path<String>,
    body: Option<Json<VendRequest>>,
) -> Result<Json<ApiResponse<VendResponse>>, ApiError> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::Unauthorized("workspace authentication required".to_string()))?;
    let auth = authenticated_workspace::authenticate_workspace(&state, auth_header).await?;
    auth.require_scope(agent_cordon_core::oauth2::types::OAuthScope::CredentialsVend)?;

    let broker_pub = match &body {
        Some(Json(req)) => req
            .broker_public_key
            .as_deref()
            .map(parse_broker_public_key)
            .transpose()?,
        None => None,
    };

    // Look up credential scoped to workspace first, fall back to global
    let cred = match state
        .store
        .get_credential_by_workspace_and_name(&auth.workspace.id, &name)
        .await?
    {
        Some(c) => c,
        None => state
            .store
            .get_credential_by_name(&name)
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("credential '{}' not found", name)))?,
    };

    let response =
        vend_inner(&state, &auth.workspace, &cred, corr.0, broker_pub, auth.oauth_claims).await?;
    Ok(Json(ApiResponse::ok(response)))
}
