use axum::{extract::State, Json};
use chrono::{Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agent_cordon_core::auth::jwt::AUDIENCE_WORKSPACE_IDENTITY;
use agent_cordon_core::crypto::ed25519;
use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::workspace::{
    IdentityChallenge, WorkspaceIdentityClaims, WorkspaceStatus,
};

use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

use super::{
    audit_workspace_auth_failed, CHALLENGE_TTL_SECONDS, IDENTITY_JWT_TTL_SECONDS,
    MAX_CHALLENGES_PER_MINUTE,
};

#[derive(Deserialize)]
pub(super) struct IdentifyRequest {
    public_key_hash: String,
}

#[derive(Serialize)]
pub(super) struct IdentifyResponse {
    challenge: String,
    issued_at: String,
    expires_at: String,
    audience: String,
}

/// POST /api/v1/agents/identify — request a challenge for workspace identity authentication.
pub(super) async fn request_challenge(
    State(state): State<AppState>,
    Json(req): Json<IdentifyRequest>,
) -> Result<Json<ApiResponse<IdentifyResponse>>, ApiError> {
    let pk_hash = req.public_key_hash.trim().to_string();

    // Validate pk_hash format (should be 64 hex chars = SHA-256)
    if pk_hash.len() != 64 || !pk_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest(
            "invalid public_key_hash format".to_string(),
        ));
    }

    // Verify the workspace exists and is active
    let workspace = state.store.get_workspace_by_pk_hash(&pk_hash).await?;
    match &workspace {
        Some(w) if w.status != WorkspaceStatus::Active => {
            return Err(ApiError::Forbidden("workspace is not active".to_string()));
        }
        None => {
            return Err(ApiError::NotFound("workspace not found".to_string()));
        }
        _ => {}
    }

    // Rate limiting: count challenges for this pk_hash in the store
    {
        let store = state.workspace_challenges.read().await;
        let count = store
            .values()
            .filter(|c| c.pk_hash == pk_hash && c.issued_at > Utc::now() - Duration::seconds(60))
            .count();
        if count >= MAX_CHALLENGES_PER_MINUTE as usize {
            return Err(ApiError::TooManyRequests(
                "rate limit exceeded: max 10 challenges per minute".to_string(),
            ));
        }
    }

    // Generate challenge
    let mut challenge_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut challenge_bytes);
    let now = Utc::now();
    let expires_at = now + Duration::seconds(CHALLENGE_TTL_SECONDS);

    let challenge = IdentityChallenge {
        pk_hash: pk_hash.clone(),
        challenge: challenge_bytes.to_vec(),
        issued_at: now,
        expires_at,
    };

    // Store challenge (replace any existing for this pk_hash)
    {
        let mut store = state.workspace_challenges.write().await;
        // Cleanup expired entries opportunistically
        store.retain(|_, c| c.expires_at > Utc::now());
        store.insert(pk_hash, challenge);
    }

    use base64::Engine;
    let challenge_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);

    Ok(Json(ApiResponse::ok(IdentifyResponse {
        challenge: challenge_b64,
        issued_at: now.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
        audience: ed25519::CHALLENGE_AUDIENCE.to_string(),
    })))
}

#[derive(Deserialize)]
pub(super) struct VerifyRequest {
    public_key: String,
    signature: String,
    signed_payload: String,
}

#[derive(Serialize)]
pub(super) struct VerifyResponse {
    identity_jwt: String,
    expires_in: i64,
}

/// POST /api/v1/agents/identify/verify — verify Ed25519 signature, issue identity JWT.
pub(super) async fn verify_challenge(
    State(state): State<AppState>,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<ApiResponse<VerifyResponse>>, ApiError> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let pubkey_bytes = b64
        .decode(&req.public_key)
        .map_err(|_| ApiError::BadRequest("invalid base64url in public_key".to_string()))?;
    let signature_bytes = b64
        .decode(&req.signature)
        .map_err(|_| ApiError::BadRequest("invalid base64url in signature".to_string()))?;
    let payload_bytes = b64
        .decode(&req.signed_payload)
        .map_err(|_| ApiError::BadRequest("invalid base64url in signed_payload".to_string()))?;

    if pubkey_bytes.len() != 32 {
        return Err(ApiError::BadRequest(
            "public key must be 32 bytes".to_string(),
        ));
    }
    if signature_bytes.len() != 64 {
        return Err(ApiError::BadRequest(
            "signature must be 64 bytes".to_string(),
        ));
    }

    let pk_hash = ed25519::compute_pk_hash(&pubkey_bytes);

    // Consume challenge (single-use)
    let challenge = {
        let mut store = state.workspace_challenges.write().await;
        store.remove(&pk_hash)
    };

    let challenge = match challenge {
        Some(c) if c.expires_at > Utc::now() => c,
        Some(_) => {
            audit_workspace_auth_failed(&state, &corr.0, &pk_hash, "challenge expired").await;
            return Err(ApiError::Unauthorized("challenge expired".to_string()));
        }
        None => {
            audit_workspace_auth_failed(&state, &corr.0, &pk_hash, "no pending challenge").await;
            return Err(ApiError::Unauthorized(
                "no pending challenge for this public key".to_string(),
            ));
        }
    };

    // Rebuild expected payload and compare
    let expected_payload = ed25519::build_challenge_payload(
        &challenge.challenge,
        challenge.issued_at.timestamp(),
        ed25519::CHALLENGE_AUDIENCE,
        &pubkey_bytes,
    );

    if payload_bytes != expected_payload {
        audit_workspace_auth_failed(&state, &corr.0, &pk_hash, "payload mismatch").await;
        return Err(ApiError::Unauthorized(
            "signed payload does not match expected challenge".to_string(),
        ));
    }

    // Verify Ed25519 signature
    if ed25519::verify_challenge_signature(&pubkey_bytes, &signature_bytes, &payload_bytes).is_err()
    {
        audit_workspace_auth_failed(&state, &corr.0, &pk_hash, "invalid signature").await;
        return Err(ApiError::Unauthorized(
            "signature verification failed".to_string(),
        ));
    }

    // Look up workspace by pk_hash
    let workspace = state
        .store
        .get_workspace_by_pk_hash(&pk_hash)
        .await?
        .ok_or_else(|| ApiError::NotFound("workspace not found".to_string()))?;

    if workspace.status != WorkspaceStatus::Active {
        audit_workspace_auth_failed(&state, &corr.0, &pk_hash, "workspace not active").await;
        return Err(ApiError::Forbidden("workspace is not active".to_string()));
    }

    // Compute encryption key thumbprint (ekt) if workspace has an encryption key
    let ekt = workspace
        .encryption_public_key
        .as_ref()
        .and_then(|epk_str| {
            let epk: serde_json::Value = serde_json::from_str(epk_str).ok()?;
            let x = epk.get("x")?.as_str()?;
            let y = epk.get("y")?.as_str()?;
            Some(agent_cordon_core::auth::jwt::compute_p256_thumbprint(x, y))
        });

    // Issue identity JWT
    let now = Utc::now();
    let claims = WorkspaceIdentityClaims {
        sub: workspace.id.0.to_string(),
        wkt: pk_hash.clone(),
        ekt,
        exp: (now + Duration::seconds(IDENTITY_JWT_TTL_SECONDS)).timestamp(),
        iss: agent_cordon_core::auth::jwt::ISSUER.to_string(),
        aud: AUDIENCE_WORKSPACE_IDENTITY.to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        jti: Uuid::new_v4().to_string(),
    };

    let token = state
        .jwt_issuer
        .sign_custom_claims(&claims)
        .map_err(|e| ApiError::Internal(format!("failed to sign identity JWT: {}", e)))?;

    // Audit: success
    let event = AuditEvent::builder(AuditEventType::WorkspaceAuthenticated)
        .action("workspace_authenticate")
        .resource("workspace", &workspace.id.0.to_string())
        .correlation_id(&corr.0)
        .decision(
            AuditDecision::Permit,
            Some("bypass:ed25519_challenge_verified"),
        )
        .details(serde_json::json!({ "pk_hash": pk_hash }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    Ok(Json(ApiResponse::ok(VerifyResponse {
        identity_jwt: token,
        expires_in: IDENTITY_JWT_TTL_SECONDS,
    })))
}
