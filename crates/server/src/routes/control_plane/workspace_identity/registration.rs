use axum::{
    extract::{Query, State},
    http::{header, HeaderMap},
    Json,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use agent_cordon_core::auth::jwt::AUDIENCE_WORKSPACE_IDENTITY;
use agent_cordon_core::crypto::ed25519;
use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::user::UserId;
use agent_cordon_core::domain::workspace::{
    self, Workspace, WorkspaceId, WorkspaceIdentityClaims, WorkspaceRegistration, WorkspaceStatus,
};

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

use super::{IDENTITY_JWT_TTL_SECONDS, REGISTRATION_TTL_SECONDS};

#[derive(Deserialize)]
pub(super) struct RegisterQuery {
    pk_hash: Option<String>,
    cc: Option<String>,
}

/// GET /register — render registration page (NO server state created on GET).
pub(super) async fn render_register_page(
    Query(query): Query<RegisterQuery>,
) -> axum::response::Html<String> {
    // Validate inputs are hex to prevent XSS — reject anything that isn't a 64-char hex string
    let pk_hash = query.pk_hash.unwrap_or_default();
    let pk_hash = pk_hash
        .strip_prefix("sha256:")
        .unwrap_or(&pk_hash)
        .to_string();
    let pk_hash = if pk_hash.len() == 64 && pk_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        pk_hash
    } else {
        String::new()
    };
    let code_challenge = query.cc.unwrap_or_default();
    let code_challenge =
        if code_challenge.len() == 64 && code_challenge.chars().all(|c| c.is_ascii_hexdigit()) {
            code_challenge
        } else {
            String::new()
        };
    let fingerprint = if pk_hash.len() >= 16 {
        &pk_hash[..16]
    } else {
        &pk_hash
    };

    axum::response::Html(format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Workspace Registration</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; background: #f6f5f3; color: #1a1a1a; }}
  code {{ background: #e8e6e1; padding: 2px 6px; border-radius: 3px; font-size: 1.1em; }}
  button {{ background: #d4551a; color: white; border: none; padding: 10px 24px; border-radius: 6px; font-size: 1em; cursor: pointer; }}
  button:hover {{ background: #b8460f; }}
  pre {{ font-size: 2em; padding: 1em; background: #e8e6e1; border-radius: 6px; }}
  h1 {{ color: #1a1a1a; }}

  details {{ margin-bottom: 16px; }}
  summary {{ cursor: pointer; color: #666; }}
  .cli-instructions {{ padding: 12px; background: #e8e6e1; border-radius: 6px; margin-top: 8px; }}

  @media (prefers-color-scheme: dark) {{
    body {{ background: #1a1a1a; color: #e8e6e1; }}
    code {{ background: #333333; color: #e8e6e1; }}
    pre {{ background: #333333; color: #e8e6e1; }}
    h1 {{ color: #e8e6e1; }}
    p {{ color: #cccccc; }}
    strong {{ color: #e8e6e1; }}
    summary {{ color: #999; }}
    .cli-instructions {{ background: #333333; }}
    div[style*="background: #e8e6e1"] {{ background: #2a2a2a !important; }}
  }}
</style>
</head>
<body>
<h1>Workspace Registration</h1>
<details>
  <summary>CLI quick-start instructions</summary>
  <div class="cli-instructions">
    <p>To register a workspace:</p>
    <code style="display: block; margin: 8px 0;">agentcordon init --server &lt;this-server-url&gt;</code>
    <p style="font-size: 0.9em; color: #666;">The CLI will poll automatically &mdash; just click Approve below.</p>
  </div>
</details>
<p>A workspace is requesting registration.</p>
<p><strong>Fingerprint:</strong> <code>{fingerprint}</code></p>
<p>Verify this fingerprint matches what the CLI displayed, then click Approve.</p>
<form method="POST" action="/register">
  <input type="hidden" name="pk_hash" value="{pk_hash}" />
  <input type="hidden" name="code_challenge" value="{code_challenge}" />
  <button type="submit">Approve</button>
</form>
</body>
</html>"#
    ))
}

#[derive(Deserialize)]
pub(super) struct ApproveRegistrationForm {
    pk_hash: String,
    code_challenge: String,
}

/// POST /register — Admin approves registration, creates approval code.
pub(super) async fn approve_registration(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    axum::Form(form): axum::Form<ApproveRegistrationForm>,
) -> Result<axum::response::Html<String>, ApiError> {
    let pk_hash = form.pk_hash.trim().to_string();
    let pk_hash = pk_hash
        .strip_prefix("sha256:")
        .unwrap_or(&pk_hash)
        .to_string();
    let code_challenge = form.code_challenge.trim().to_string();

    if pk_hash.len() != 64 || !pk_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest("invalid pk_hash".to_string()));
    }
    if code_challenge.len() != 64 || !code_challenge.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest("invalid code_challenge".to_string()));
    }

    // Workspace owner is always the user who approves the registration.
    let owner_id = auth.user.id.0.to_string();

    // Generate approval code
    let approval_code = workspace::generate_approval_code();
    let code_hash = workspace::hash_approval_code(&approval_code);
    let now = Utc::now();

    let registration = WorkspaceRegistration {
        pk_hash: pk_hash.clone(),
        code_challenge,
        code_hash,
        approval_code: Some(approval_code.clone()),
        expires_at: now + Duration::seconds(REGISTRATION_TTL_SECONDS),
        attempts: 0,
        max_attempts: 5,
        approved_by: Some(owner_id),
        created_at: now,
    };

    state
        .store
        .create_workspace_registration(&registration)
        .await?;

    // Audit
    let event = AuditEvent::builder(AuditEventType::WorkspaceRegistered)
        .action("approve_workspace_registration")
        .user_actor(&auth.user)
        .resource("workspace_registration", &pk_hash)
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("bypass:admin"))
        .details(serde_json::json!({ "pk_hash_fingerprint": &pk_hash[..16] }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    Ok(axum::response::Html(format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Registration Approved</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; background: #f6f5f3; color: #1a1a1a; }}
  code {{ background: #e8e6e1; padding: 2px 6px; border-radius: 3px; font-size: 1.1em; }}
  button {{ background: #d4551a; color: white; border: none; padding: 10px 24px; border-radius: 6px; font-size: 1em; cursor: pointer; }}
  button:hover {{ background: #b8460f; }}
  pre {{ font-size: 2em; padding: 1em; background: #e8e6e1; border-radius: 6px; }}
  h1 {{ color: #1a1a1a; }}

  @media (prefers-color-scheme: dark) {{
    body {{ background: #1a1a1a; color: #e8e6e1; }}
    code {{ background: #333333; color: #e8e6e1; }}
    pre {{ background: #333333; color: #e8e6e1; }}
    h1 {{ color: #e8e6e1; }}
    p {{ color: #cccccc; }}
  }}
</style>
</head>
<body>
<h1>Registration Approved</h1>
<p>Paste this approval code into the CLI:</p>
<pre>{approval_code}</pre>
<p style="color: #666; font-size: 0.9em;">If the CLI is polling, it will pick up the approval automatically. Otherwise, paste the code above into the CLI.</p>
<p>This code expires in 5 minutes.</p>
</body>
</html>"#
    )))
}

// ============================================================================
// Code Exchange
// ============================================================================

#[derive(Deserialize)]
pub(super) struct CodeExchangeRequest {
    approval_code: String,
    public_key: String,
    nonce: String,
    timestamp: i64,
    signature: String,
    #[serde(default)]
    name: Option<String>,
    /// Optional P-256 encryption public key (JWK format) for ECIES credential vending.
    #[serde(default)]
    encryption_key: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub(super) struct CodeExchangeResponse {
    workspace_id: String,
    identity_jwt: String,
    name: String,
}

/// POST /api/v1/agents/register — exchange approval code + PKCE + signature for identity.
pub(super) async fn code_exchange(
    State(state): State<AppState>,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<CodeExchangeRequest>,
) -> Result<Json<ApiResponse<CodeExchangeResponse>>, ApiError> {
    // Decode hex inputs
    let pubkey_bytes = hex::decode(&req.public_key)
        .map_err(|_| ApiError::BadRequest("invalid hex in public_key".to_string()))?;
    let nonce_bytes = hex::decode(&req.nonce)
        .map_err(|_| ApiError::BadRequest("invalid hex in nonce".to_string()))?;
    let sig_bytes = hex::decode(&req.signature)
        .map_err(|_| ApiError::BadRequest("invalid hex in signature".to_string()))?;

    if pubkey_bytes.len() != 32 {
        return Err(ApiError::BadRequest(
            "public key must be 32 bytes".to_string(),
        ));
    }
    if nonce_bytes.len() != 32 {
        return Err(ApiError::BadRequest("nonce must be 32 bytes".to_string()));
    }

    let pk_hash = ed25519::compute_pk_hash(&pubkey_bytes);

    // 1. Look up registration
    let registration = state
        .store
        .get_workspace_registration(&pk_hash)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound("no pending registration for this public key".to_string())
        })?;

    // 2. Check expiry
    if registration.expires_at < Utc::now() {
        state
            .store
            .delete_workspace_registration(&pk_hash)
            .await
            .ok();
        return Err(ApiError::Gone("registration expired".to_string()));
    }

    // 3. Check attempts
    if registration.attempts >= registration.max_attempts {
        state
            .store
            .delete_workspace_registration(&pk_hash)
            .await
            .ok();
        return Err(ApiError::TooManyRequests(
            "max verification attempts exceeded".to_string(),
        ));
    }

    // Increment attempts
    state
        .store
        .increment_registration_attempts(&pk_hash)
        .await?;

    // 4. Verify PKCE: SHA-256(nonce) must match stored code_challenge
    let nonce_hash = hex::encode(Sha256::digest(&nonce_bytes));
    if nonce_hash != registration.code_challenge {
        return Err(ApiError::Unauthorized(
            "PKCE verification failed".to_string(),
        ));
    }

    // 5. Verify approval code hash
    let code_hash = workspace::hash_approval_code(&req.approval_code);
    if code_hash != registration.code_hash {
        return Err(ApiError::Unauthorized("invalid approval code".to_string()));
    }

    // 6. Verify Ed25519 signature over (domain_separator || approval_code || pk_hash || nonce || timestamp)
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(b"agentcordon:registration-v1");
    signed_data.extend_from_slice(req.approval_code.as_bytes());
    signed_data.extend_from_slice(&hex::decode(&pk_hash).unwrap_or_default());
    signed_data.extend_from_slice(&nonce_bytes);
    signed_data.extend_from_slice(&req.timestamp.to_be_bytes());

    ed25519::verify_challenge_signature(&pubkey_bytes, &sig_bytes, &signed_data)
        .map_err(|_| ApiError::Unauthorized("signature verification failed".to_string()))?;

    // 7. Verify timestamp skew
    let now = Utc::now().timestamp();
    if (req.timestamp - now).abs() > 30 {
        return Err(ApiError::Unauthorized(
            "timestamp skew too large".to_string(),
        ));
    }

    // 7b. Validate name if provided
    if let Some(ref name) = req.name {
        if name.len() > 128 {
            return Err(ApiError::BadRequest(
                "name must be 128 characters or fewer".to_string(),
            ));
        }
        if name.contains('<')
            || name.contains('>')
            || name.contains('&')
            || name.contains('"')
            || name.contains('\'')
        {
            return Err(ApiError::BadRequest(
                "workspace name contains invalid characters".to_string(),
            ));
        }
    }

    // 7c. Validate encryption key if provided
    super::validate_encryption_key(req.encryption_key.as_ref()).map_err(ApiError::BadRequest)?;

    // 8. Create workspace
    let workspace_id = WorkspaceId(Uuid::new_v4());
    let now_dt = Utc::now();
    let assigned_name = req
        .name
        .clone()
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| format!("workspace:{}", &pk_hash[..8]));

    // Store the P-256 encryption public key (JWK JSON) if provided.
    let encryption_public_key = req.encryption_key.as_ref().map(|jwk| jwk.to_string());

    // Set workspace owner to the user who approved the registration.
    // NOTE: This means the owner is whoever clicks "Approve" in the web UI,
    // which is typically the admin — not the CLI user who ran `agentcordon init`.
    // The CLI enrollment flow uses workspace keys (Ed25519), not web UI user
    // accounts, so there's no web UI user identity to associate with the
    // enrolling CLI user. To transfer ownership, use the workspace update API.
    let owner_id = registration
        .approved_by
        .as_ref()
        .and_then(|id_str| Uuid::parse_str(id_str).ok())
        .map(UserId);

    let ws = Workspace {
        id: workspace_id.clone(),
        name: assigned_name.clone(),
        enabled: true,
        status: WorkspaceStatus::Active,
        pk_hash: Some(pk_hash.clone()),
        encryption_public_key,
        tags: vec![],
        owner_id,
        parent_id: None,
        tool_name: None,
        created_at: now_dt,
        updated_at: now_dt,
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

    // 9. Delete registration (single-use)
    state
        .store
        .delete_workspace_registration(&pk_hash)
        .await
        .ok();

    // 10. Issue identity JWT (ekt is None at registration — set during enrollment)
    let claims = WorkspaceIdentityClaims {
        sub: workspace_id.0.to_string(),
        wkt: pk_hash.clone(),
        ekt: None,
        exp: (now_dt + Duration::seconds(IDENTITY_JWT_TTL_SECONDS)).timestamp(),
        iss: agent_cordon_core::auth::jwt::ISSUER.to_string(),
        aud: AUDIENCE_WORKSPACE_IDENTITY.to_string(),
        iat: now_dt.timestamp(),
        nbf: now_dt.timestamp(),
        jti: Uuid::new_v4().to_string(),
    };
    let token = state
        .jwt_issuer
        .sign_custom_claims(&claims)
        .map_err(|e| ApiError::Internal(format!("failed to sign identity JWT: {}", e)))?;

    // Audit
    let event = AuditEvent::builder(AuditEventType::WorkspaceRegistered)
        .action("workspace_register")
        .resource("workspace", &workspace_id.0.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("bypass:code_exchange_verified"))
        .details(serde_json::json!({ "pk_hash": pk_hash }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    Ok(Json(ApiResponse::ok(CodeExchangeResponse {
        workspace_id: workspace_id.0.to_string(),
        identity_jwt: token,
        name: assigned_name,
    })))
}

// ============================================================================
// Registration Polling
// ============================================================================

#[derive(Deserialize)]
pub(super) struct PollRegistrationQuery {
    pk_hash: String,
    cc: String,
}

#[derive(Serialize)]
pub(super) struct PollRegistrationResponse {
    status: String,
    approval_code: String,
}

/// GET /api/v1/workspaces/registration-status — CLI polls for approval.
pub(super) async fn poll_registration_status(
    State(state): State<AppState>,
    Query(query): Query<PollRegistrationQuery>,
) -> Result<(HeaderMap, Json<ApiResponse<PollRegistrationResponse>>), ApiError> {
    // Validate inputs — return 404 for all invalid cases to prevent enumeration
    let pk_hash = query.pk_hash.trim().to_string();
    let pk_hash = pk_hash
        .strip_prefix("sha256:")
        .unwrap_or(&pk_hash)
        .to_string();
    if pk_hash.len() != 64 || !pk_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::NotFound("not found".to_string()));
    }
    let cc = query.cc.trim().to_string();
    if cc.len() != 64 || !cc.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::NotFound("not found".to_string()));
    }

    // Look up registration
    let registration = state
        .store
        .get_workspace_registration(&pk_hash)
        .await?
        .ok_or_else(|| ApiError::NotFound("not found".to_string()))?;

    // Check expiry
    if registration.expires_at < chrono::Utc::now() {
        return Err(ApiError::NotFound("not found".to_string()));
    }

    // Check code_challenge matches
    if registration.code_challenge != cc {
        return Err(ApiError::NotFound("not found".to_string()));
    }

    // Check if approval_code is present (None means not yet approved)
    let approval_code = registration
        .approval_code
        .ok_or_else(|| ApiError::NotFound("not found".to_string()))?;

    // Null the approval_code after first read (single-read security)
    state
        .store
        .null_registration_approval_code(&pk_hash)
        .await
        .ok();

    // Return with Cache-Control: no-store to prevent caching of sensitive data
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());

    Ok((
        headers,
        Json(ApiResponse::ok(PollRegistrationResponse {
            status: "approved".to_string(),
            approval_code,
        })),
    ))
}
