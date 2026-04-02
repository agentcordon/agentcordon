//! OAuth 2.0 consent processing — POST /api/v1/oauth/authorize.
//!
//! Handles the user's approve/deny decision, creates OAuth clients and
//! workspace records for new registrations, and issues authorization codes.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use chrono::{Duration, Utc};
use serde::Deserialize;
use uuid::Uuid;

use subtle::ConstantTimeEq;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::user::UserId;
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
use agent_cordon_core::oauth2::types::{OAuthAuthCode, OAuthClient, OAuthConsent, OAuthScope};

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::ApiError;
use crate::state::AppState;

use super::authorize::{compute_csrf_token, extract_session_token, validate_new_workspace_params};
use super::{generate_auth_code, is_localhost_uri};
use agent_cordon_core::oauth2::tokens::generate_client_id;

// ---------------------------------------------------------------------------
// POST /api/v1/oauth/authorize — Process consent decision
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct AuthorizeForm {
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
    decision: String,
    csrf_token: String,
    #[serde(default)]
    public_key_hash: String,
    #[serde(default)]
    workspace_name: String,
    #[serde(default)]
    is_new_workspace: bool,
}

/// POST /api/v1/oauth/authorize
pub(crate) async fn authorize_post(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    headers: axum::http::HeaderMap,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    axum::Form(form): axum::Form<AuthorizeForm>,
) -> Result<Response, ApiError> {
    // Validate CSRF token: recompute from session and compare
    let session_token = extract_session_token(&headers)
        .ok_or_else(|| ApiError::Unauthorized("session required".into()))?;
    let expected_csrf = compute_csrf_token(&session_token, &state.session_hash_key);
    if !bool::from(form.csrf_token.as_bytes().ct_eq(expected_csrf.as_bytes())) {
        return Err(ApiError::Forbidden("invalid csrf_token".into()));
    }

    let scopes =
        OAuthScope::parse_scope_string(&form.scope).map_err(ApiError::BadRequest)?;

    // Handle deny before client creation
    if form.decision == "deny" {
        return handle_deny(&state, &auth, &corr, &form).await;
    }

    if form.decision != "approve" {
        return Err(ApiError::BadRequest(
            "decision must be 'approve' or 'deny'".into(),
        ));
    }

    // PKCE validation
    if form.code_challenge.is_empty() {
        return Err(ApiError::BadRequest("code_challenge is required".into()));
    }
    if form.code_challenge_method != "S256" {
        return Err(ApiError::BadRequest(
            "code_challenge_method must be S256".into(),
        ));
    }

    // Determine client_id: create new client if new workspace, or validate existing
    let (client_id, client_uuid, is_new) = if form.is_new_workspace {
        let new_client =
            create_client_on_consent(&state, &auth, &corr, &form).await?;
        let cid = new_client.client_id.clone();
        let uuid = new_client.id;
        (cid, uuid, true)
    } else {
        let client = state
            .store
            .get_oauth_client_by_client_id(&form.client_id)
            .await?
            .ok_or_else(|| ApiError::BadRequest("unknown client_id".into()))?;

        if client.revoked_at.is_some() {
            return Err(ApiError::BadRequest("client has been revoked".into()));
        }

        if !client.redirect_uris.contains(&form.redirect_uri) {
            return Err(ApiError::BadRequest(
                "redirect_uri does not match".into(),
            ));
        }

        (client.client_id, client.id, false)
    };

    // Generate auth code
    let (code, code_hash) = generate_auth_code();
    let now = Utc::now();

    let auth_code = OAuthAuthCode {
        code_hash,
        client_id: client_id.clone(),
        user_id: auth.user.id.clone(),
        redirect_uri: form.redirect_uri.clone(),
        scopes: scopes.clone(),
        code_challenge: Some(form.code_challenge),
        created_at: now,
        expires_at: now + Duration::seconds(300),
        consumed_at: None,
    };
    state.store.create_oauth_auth_code(&auth_code).await?;

    // Upsert consent record
    let consent = OAuthConsent {
        client_id: client_id.clone(),
        user_id: auth.user.id.clone(),
        scopes: scopes.clone(),
        granted_at: now,
    };
    state.store.upsert_oauth_consent(&consent).await?;

    // Audit: consent granted
    let event = AuditEvent::builder(AuditEventType::Oauth2TokenAcquired)
        .action("oauth_consent_granted")
        .user_actor(&auth.user)
        .resource("oauth_client", &client_uuid.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("user approved consent"))
        .details(serde_json::json!({
            "client_id": client_id,
            "scopes": OAuthScope::to_scope_string(&scopes),
            "is_new_workspace": is_new,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "failed to write audit event");
    }

    // For new workspace registrations, include client_id in the callback
    let redirect_url = if is_new {
        format!(
            "{}?code={}&state={}&client_id={}",
            form.redirect_uri,
            urlencoding::encode(&code),
            urlencoding::encode(&form.state),
            urlencoding::encode(&client_id),
        )
    } else {
        format!(
            "{}?code={}&state={}",
            form.redirect_uri,
            urlencoding::encode(&code),
            urlencoding::encode(&form.state)
        )
    };
    Ok(
        (StatusCode::FOUND, [("Location", redirect_url.as_str())])
            .into_response(),
    )
}

/// Handle the "deny" decision — audit + redirect with error.
async fn handle_deny(
    state: &AppState,
    auth: &AuthenticatedUser,
    corr: &CorrelationId,
    form: &AuthorizeForm,
) -> Result<Response, ApiError> {
    if !is_localhost_uri(&form.redirect_uri) {
        return Err(ApiError::BadRequest("invalid redirect_uri".to_string()));
    }

    let resource_id = if form.client_id.is_empty() {
        "new-workspace".to_string()
    } else {
        form.client_id.clone()
    };
    let event = AuditEvent::builder(AuditEventType::Oauth2TokenFailed)
        .action("oauth_consent_denied")
        .user_actor(&auth.user)
        .resource("oauth_client", &resource_id)
        .correlation_id(&corr.0)
        .decision(AuditDecision::Forbid, Some("user denied consent"))
        .details(serde_json::json!({
            "client_id": form.client_id,
            "workspace_name": form.workspace_name,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "failed to write audit event");
    }

    let redirect_url = format!(
        "{}?error=access_denied&error_description={}&state={}",
        form.redirect_uri,
        urlencoding::encode("User denied consent"),
        urlencoding::encode(&form.state)
    );
    Ok(Redirect::to(&redirect_url).into_response())
}

/// Create an OAuth client and workspace record as part of the consent flow.
async fn create_client_on_consent(
    state: &AppState,
    auth: &AuthenticatedUser,
    corr: &CorrelationId,
    form: &AuthorizeForm,
) -> Result<OAuthClient, ApiError> {
    validate_new_workspace_params(&form.public_key_hash, &form.workspace_name)?;

    if !is_localhost_uri(&form.redirect_uri) {
        return Err(ApiError::BadRequest(
            "redirect_uri must be localhost".into(),
        ));
    }

    let scopes =
        OAuthScope::parse_scope_string(&form.scope).map_err(ApiError::BadRequest)?;

    // If an existing client for this public_key_hash exists, revoke it so the
    // new registration succeeds.  This handles `--force` re-registrations where
    // the CLI cleared its local state but the server still has the old client.
    if let Some(existing) = state
        .store
        .get_oauth_client_by_public_key_hash(&form.public_key_hash)
        .await?
    {
        if existing.revoked_at.is_none() {
            state.store.revoke_oauth_client(&existing.client_id).await?;
            tracing::info!(
                client_id = %existing.client_id,
                pk_hash = %form.public_key_hash,
                "revoked existing OAuth client for re-registration"
            );
        }
    }

    let client_id = generate_client_id();
    let now = Utc::now();

    let client = OAuthClient {
        id: Uuid::new_v4(),
        client_id: client_id.clone(),
        client_secret_hash: None,
        workspace_name: form.workspace_name.clone(),
        public_key_hash: form.public_key_hash.clone(),
        redirect_uris: vec![form.redirect_uri.clone()],
        allowed_scopes: scopes,
        created_by_user: UserId(auth.user.id.0),
        created_at: now,
        revoked_at: None,
    };

    state.store.create_oauth_client(&client).await?;

    // Reuse existing workspace if it has the same name AND pk_hash (re-registration),
    // or create a new one. This prevents duplicate workspaces on `agentcordon register`
    // after a client-side state reset.
    create_or_reuse_workspace(state, auth, &form.workspace_name, &form.public_key_hash)
        .await?;

    // Audit: client created via consent
    let event = AuditEvent::builder(AuditEventType::Oauth2TokenAcquired)
        .action("oauth_client_created_via_consent")
        .user_actor(&auth.user)
        .resource("oauth_client", &client.id.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("client created during consent"))
        .details(serde_json::json!({
            "client_id": client_id,
            "workspace_name": form.workspace_name,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "failed to write audit event");
    }

    tracing::info!(
        client_id = %client_id,
        workspace_name = %form.workspace_name,
        "OAuth client created via consent flow"
    );

    Ok(client)
}

/// Reuse an existing workspace on re-registration or create a new one.
///
/// When a workspace with the same name already exists:
/// - Same `pk_hash` -- reuse it (update pk_hash to ensure consistency)
/// - Different `pk_hash` -- reject with a conflict error
/// - No existing workspace -- create a new one
async fn create_or_reuse_workspace(
    state: &AppState,
    auth: &AuthenticatedUser,
    workspace_name: &str,
    pk_hash: &str,
) -> Result<(), ApiError> {
    if let Some(existing) = state.store.get_workspace_by_name(workspace_name).await? {
        let existing_pk = existing.pk_hash.as_deref().unwrap_or("");
        if existing_pk == pk_hash {
            // Same key -- re-registration. Re-enable the workspace if it was disabled.
            let mut updated = existing;
            updated.pk_hash = Some(pk_hash.to_string());
            updated.enabled = true;
            updated.status = WorkspaceStatus::Active;
            updated.updated_at = Utc::now();
            state.store.update_workspace(&updated).await?;
            tracing::info!(
                workspace_id = %updated.id.0,
                workspace_name = %workspace_name,
                "reused existing workspace on re-registration"
            );
            return Ok(());
        }
        // Different key -- this name is taken by another identity
        return Err(ApiError::Conflict(format!(
            "workspace name '{}' is already registered with a different key",
            workspace_name,
        )));
    }

    // No existing workspace -- create a fresh one
    let now = Utc::now();
    let workspace = Workspace {
        id: WorkspaceId(Uuid::new_v4()),
        name: workspace_name.to_string(),
        enabled: true,
        status: WorkspaceStatus::Active,
        pk_hash: Some(pk_hash.to_string()),
        encryption_public_key: None,
        tags: vec![],
        owner_id: Some(UserId(auth.user.id.0)),
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };
    state.store.create_workspace(&workspace).await?;
    Ok(())
}
