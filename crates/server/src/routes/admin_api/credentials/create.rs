use axum::{extract::State, Json};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::credential::CredentialSummary;
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::policy::actions;
use agent_cordon_core::policy::{PolicyEngine, PolicyResource};
use agent_cordon_core::transform::MAX_TRANSFORM_SCRIPT_SIZE;

use crate::credential_service::{self, NewCredentialParams};
use crate::extractors::AuthenticatedActor;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

use super::enrich_owner_usernames;

#[derive(Deserialize)]
pub(crate) struct StoreCredentialRequest {
    pub name: String,
    pub service: String,
    /// The raw secret value. Required for "generic" type. For "aws" type, can be
    /// provided as JSON or omitted in favor of structured aws_* fields.
    pub secret_value: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub metadata: Option<serde_json::Value>,
    pub allowed_url_pattern: Option<String>,
    /// Optional expiry date in ISO 8601 format. `null` or absent means never expires.
    pub expires_at: Option<DateTime<Utc>>,
    /// Optional Rhai script for transforming the decrypted secret before proxy injection.
    pub transform_script: Option<String>,
    /// Optional named built-in transform (e.g., "identity", "basic-auth", "bearer", "aws-sigv4").
    pub transform_name: Option<String>,
    /// Optional vault grouping. Defaults to "default" if not provided.
    pub vault: Option<String>,
    /// Credential type: "generic" (default), "aws".
    pub credential_type: Option<String>,
    /// Optional AWS Access Key ID. Used when credential_type is "aws" instead of raw JSON.
    pub aws_access_key_id: Option<String>,
    /// Optional AWS Secret Access Key. Used when credential_type is "aws" instead of raw JSON.
    pub aws_secret_access_key: Option<String>,
    /// Optional AWS region (e.g., "us-east-1"). Used when credential_type is "aws".
    pub aws_region: Option<String>,
    /// Optional AWS service name (e.g., "s3", "execute-api"). Used when credential_type is "aws".
    pub aws_service: Option<String>,
    /// Optional tags for categorization and policy matching.
    pub tags: Option<Vec<String>>,
    /// Optional free-form description to help agents select the right credential.
    pub description: Option<String>,
    /// Optional target identity identifier (e.g., AWS role ARN, email, UUID).
    pub target_identity: Option<String>,
    /// OAuth2 client ID. Required when credential_type is "oauth2_client_credentials".
    pub oauth2_client_id: Option<String>,
    /// OAuth2 token endpoint URL. Required when credential_type is "oauth2_client_credentials".
    pub oauth2_token_endpoint: Option<String>,
    /// OAuth2 scopes (space-delimited). Optional for "oauth2_client_credentials" type.
    pub oauth2_scopes: Option<String>,
    /// Agent ID to associate credential with (for user-created credentials).
    /// Parsed from JSON but currently unused in the handler (permissions are
    /// managed separately). Kept for API compatibility.
    #[allow(dead_code)]
    pub agent_id: Option<String>,
}

pub(crate) async fn store_credential(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<StoreCredentialRequest>,
) -> Result<Json<ApiResponse<CredentialSummary>>, ApiError> {
    // Policy check: can this actor create credentials?
    let decision = state.policy_engine.evaluate(
        &actor.policy_principal(),
        actions::CREATE,
        &PolicyResource::System,
        &actor.policy_context(Some(corr.0.clone())),
    )?;

    if decision.decision == PolicyDecisionResult::Forbid {
        return Err(ApiError::Forbidden("access denied by policy".to_string()));
    }

    // Validate transform_script size
    if let Some(ref script) = req.transform_script {
        if script.len() > MAX_TRANSFORM_SCRIPT_SIZE {
            return Err(ApiError::BadRequest(format!(
                "transform_script exceeds maximum size of {} bytes ({} bytes provided)",
                MAX_TRANSFORM_SCRIPT_SIZE,
                script.len()
            )));
        }
    }

    // Resolve credential type (default: "generic")
    let credential_type = req
        .credential_type
        .clone()
        .unwrap_or_else(|| "generic".to_string());

    // Validate credential_type against known types
    credential_service::validate_credential_type(&credential_type)?;

    // Resolve the secret_value and validate credential_type-specific constraints
    let mut transform_name = req.transform_name.clone();
    let mut allowed_url_pattern = req.allowed_url_pattern.clone();
    let resolved_secret = if credential_type == "aws" {
        // Determine secret_value: structured fields take precedence, then raw JSON
        let secret_value = if req.aws_access_key_id.is_some() || req.aws_secret_access_key.is_some()
        {
            // Structured AWS fields provided — assemble JSON
            let access_key = req.aws_access_key_id.as_deref().unwrap_or("");
            let secret_key = req.aws_secret_access_key.as_deref().unwrap_or("");
            if access_key.is_empty() {
                return Err(ApiError::BadRequest(
                    "credential_type 'aws' requires non-empty aws_access_key_id".to_string(),
                ));
            }
            if secret_key.is_empty() {
                // SECURITY: do not mention the field value in the error
                return Err(ApiError::BadRequest(
                    "credential_type 'aws' requires non-empty aws_secret_access_key".to_string(),
                ));
            }
            {
                let mut aws_json = serde_json::json!({
                    "access_key_id": access_key,
                    "secret_access_key": secret_key
                });
                if let Some(ref region) = req.aws_region {
                    if !region.is_empty() {
                        aws_json["region"] = serde_json::Value::String(region.clone());
                    }
                }
                if let Some(ref service) = req.aws_service {
                    if !service.is_empty() {
                        aws_json["service"] = serde_json::Value::String(service.clone());
                    }
                }
                aws_json.to_string()
            }
        } else if let Some(ref sv) = req.secret_value {
            // Raw JSON secret_value — validate it
            let aws_json: serde_json::Value = serde_json::from_str(sv)
                .map_err(|_| ApiError::BadRequest(
                    "credential_type 'aws' requires secret_value to be valid JSON with fields: access_key_id, secret_access_key".to_string()
                ))?;
            for field in &["access_key_id", "secret_access_key"] {
                match aws_json.get(field) {
                    Some(v) if v.is_string() && !v.as_str().unwrap_or("").is_empty() => {}
                    _ => {
                        return Err(ApiError::BadRequest(format!(
                            "credential_type 'aws' requires non-empty string field: {}",
                            field
                        )));
                    }
                }
            }
            sv.clone()
        } else {
            return Err(ApiError::BadRequest(
                "credential_type 'aws' requires either aws_access_key_id + aws_secret_access_key fields, or a valid JSON secret_value".to_string()
            ));
        };

        // Auto-default transform_name to "aws-sigv4" if not specified
        if transform_name.is_none() {
            transform_name = Some("aws-sigv4".to_string());
        }

        // Pre-default allowed_url_pattern for AWS credentials
        if allowed_url_pattern.is_none() {
            allowed_url_pattern = Some("https://*.amazonaws.com/*".to_string());
        }

        secret_value
    } else if credential_type == "oauth2_client_credentials" {
        // OAuth2 Client Credentials: validate required fields
        let client_id = req.oauth2_client_id.as_deref().unwrap_or("");
        if client_id.is_empty() {
            return Err(ApiError::BadRequest(
                "credential_type 'oauth2_client_credentials' requires oauth2_client_id".to_string(),
            ));
        }

        let token_endpoint = req.oauth2_token_endpoint.as_deref().unwrap_or("");
        if token_endpoint.is_empty() {
            return Err(ApiError::BadRequest(
                "credential_type 'oauth2_client_credentials' requires oauth2_token_endpoint"
                    .to_string(),
            ));
        }

        // Validate token_endpoint is a valid URL and uses HTTPS
        let parsed_endpoint = url::Url::parse(token_endpoint).map_err(|_| {
            ApiError::BadRequest("oauth2_token_endpoint must be a valid URL".to_string())
        })?;
        // Enforce HTTPS to prevent client secrets from being sent in plaintext.
        // Allow http:// only for localhost/127.0.0.1 (dev convenience).
        if parsed_endpoint.scheme() != "https" {
            let host = parsed_endpoint.host_str().unwrap_or("");
            let is_loopback = host == "localhost" || host == "127.0.0.1" || host == "::1";
            if !is_loopback {
                return Err(ApiError::BadRequest(
                    "oauth2_token_endpoint must use HTTPS".to_string(),
                ));
            }
        }

        // secret_value is required (the client_secret)
        match req.secret_value {
            Some(ref sv) if !sv.is_empty() => sv.clone(),
            _ => {
                return Err(ApiError::BadRequest(
                    "credential_type 'oauth2_client_credentials' requires secret_value (client secret)".to_string()
                ));
            }
        }
    } else {
        // Generic type: secret_value is required
        match req.secret_value {
            Some(ref sv) => {
                // Detect AWS Access Key IDs pasted into generic credential fields
                if looks_like_aws_key(sv) {
                    return Err(ApiError::BadRequest(
                        "Detected AWS Access Key ID pattern (AKIA...) in secret value. \
                         Use credential_type 'aws' with separate aws_access_key_id and \
                         aws_secret_access_key fields for proper SigV4 signing support."
                            .to_string(),
                    ));
                }
                // Auth prefix stripping is now handled by build_credential()
                // in credential_service.rs — no need to strip here.
                sv.clone()
            }
            None => {
                return Err(ApiError::BadRequest("secret_value is required".to_string()));
            }
        }
    };

    // Determine creator identity: user or workspace
    let (created_by, created_by_user) = match &actor {
        AuthenticatedActor::User(user) => (None, Some(user.id.clone())),
        AuthenticatedActor::Workspace { workspace, .. } => {
            (Some(workspace.id.clone()), workspace.owner_id.clone())
        }
    };

    // Enrich metadata with OAuth2 fields when applicable
    let metadata = {
        let mut meta = req
            .metadata
            .unwrap_or(serde_json::Value::Object(Default::default()));
        if credential_type == "oauth2_client_credentials" {
            if let serde_json::Value::Object(ref mut map) = meta {
                if let Some(ref cid) = req.oauth2_client_id {
                    map.insert("oauth2_client_id".to_string(), serde_json::json!(cid));
                }
                if let Some(ref ep) = req.oauth2_token_endpoint {
                    map.insert("oauth2_token_endpoint".to_string(), serde_json::json!(ep));
                }
                if let Some(ref sc) = req.oauth2_scopes {
                    map.insert("oauth2_scopes".to_string(), serde_json::json!(sc));
                }
            }
        }
        meta
    };

    // Build credential via shared service (generates ID, encrypts secret)
    let cred = credential_service::build_credential(
        state.encryptor.as_ref(),
        NewCredentialParams {
            name: req.name.clone(),
            service: req.service.clone(),
            secret_value: resolved_secret,
            credential_type,
            scopes: req.scopes.unwrap_or_default(),
            metadata,
            tags: req.tags.clone().unwrap_or_default(),
            vault: req.vault.clone().unwrap_or_else(|| "default".to_string()),
            created_by: created_by.clone(),
            created_by_user: created_by_user.clone(),
            allowed_url_pattern: allowed_url_pattern.clone(),
            expires_at: req.expires_at,
            transform_script: req.transform_script.clone(),
            transform_name,
            description: req.description.clone(),
            target_identity: req.target_identity.clone(),
        },
    )?;
    state.store.store_credential(&cred).await?;

    // Audit log
    let (ws_id, ws_name, u_id, u_name) = actor.audit_actor_fields();
    let event = AuditEvent::builder(AuditEventType::CredentialCreated)
        .action("create")
        .actor_fields(ws_id, ws_name, u_id, u_name)
        .resource("credential", &cred.id.0.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some(&decision.reasons.join(", ")))
        .details(serde_json::json!({
            "credential_name": req.name,
            "service": req.service,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    // Emit UI event for browser auto-refresh
    credential_service::emit_credential_created(&state, cred.id.0, cred.name.clone());

    let mut summary: CredentialSummary = cred.into();
    enrich_owner_usernames(state.store.as_ref(), std::slice::from_mut(&mut summary)).await;

    Ok(Json(ApiResponse::ok(summary)))
}

/// Returns true if the value contains an AWS Access Key ID pattern (AKIA + 16 alphanumeric).
fn looks_like_aws_key(value: &str) -> bool {
    // AWS Access Key IDs are exactly "AKIA" followed by 16 uppercase alphanumeric characters.
    // We scan for this pattern anywhere in the string to catch both bare keys and
    // pasted multi-line key+secret combos.
    let bytes = value.as_bytes();
    let prefix = b"AKIA";
    for i in 0..bytes.len().saturating_sub(19) {
        if &bytes[i..i + 4] == prefix {
            let candidate = &bytes[i + 4..i + 20];
            if candidate
                .iter()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            {
                return true;
            }
        }
    }
    false
}
