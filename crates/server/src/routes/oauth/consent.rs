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

/// Minimal HTML escape for embedding error messages in the fallback error page.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

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
///
/// If the session has expired between viewing the consent page and submitting,
/// redirect back through the authorization flow (which will land on login).
pub(crate) async fn authorize_post(
    State(state): State<AppState>,
    auth: Result<AuthenticatedUser, ApiError>,
    headers: axum::http::HeaderMap,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    axum::Form(form): axum::Form<AuthorizeForm>,
) -> Result<Response, ApiError> {
    // If session expired, redirect back through the authorize flow
    let auth = match auth {
        Ok(a) => a,
        Err(_) => {
            // Reconstruct the authorize URL so the user re-authenticates and sees
            // the consent page again.
            let mut qs = format!(
                "response_type=code&redirect_uri={}&scope={}&state={}",
                urlencoding::encode(&form.redirect_uri),
                urlencoding::encode(&form.scope),
                urlencoding::encode(&form.state),
            );
            if !form.client_id.is_empty() {
                qs.push_str(&format!(
                    "&client_id={}",
                    urlencoding::encode(&form.client_id)
                ));
            }
            if !form.public_key_hash.is_empty() {
                qs.push_str(&format!(
                    "&public_key_hash={}",
                    urlencoding::encode(&form.public_key_hash)
                ));
            }
            if !form.workspace_name.is_empty() {
                qs.push_str(&format!(
                    "&workspace_name={}",
                    urlencoding::encode(&form.workspace_name)
                ));
            }
            if !form.code_challenge.is_empty() {
                qs.push_str(&format!(
                    "&code_challenge={}",
                    urlencoding::encode(&form.code_challenge)
                ));
            }
            if !form.code_challenge_method.is_empty() {
                qs.push_str(&format!(
                    "&code_challenge_method={}",
                    urlencoding::encode(&form.code_challenge_method)
                ));
            }
            let next = format!("/api/v1/oauth/authorize?{qs}");
            let login_url = format!("/login?next={}", urlencoding::encode(&next));
            return Ok(Redirect::to(&login_url).into_response());
        }
    };
    // Validate CSRF token: recompute from session and compare
    let session_token = extract_session_token(&headers)
        .ok_or_else(|| ApiError::Unauthorized("session required".into()))?;
    let expected_csrf = compute_csrf_token(&session_token, &state.session_hash_key);
    if !bool::from(form.csrf_token.as_bytes().ct_eq(expected_csrf.as_bytes())) {
        return Err(ApiError::Forbidden("invalid csrf_token".into()));
    }

    let scopes = OAuthScope::parse_scope_string(&form.scope).map_err(ApiError::BadRequest)?;

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
        let new_client = match create_client_on_consent(&state, &auth, &corr, &form).await {
            Ok(c) => c,
            Err(e) => {
                // Browser-friendly: redirect back to the broker callback with
                // an OAuth error so the CLI sees a real failure (not a hang)
                // and the user sees the redirect_uri's error page (not raw JSON).
                let err_code = match &e {
                    ApiError::Conflict(_) => "access_denied",
                    _ => "server_error",
                };
                let err_desc = format!("{e:?}");
                if is_localhost_uri(&form.redirect_uri) {
                    let redirect = format!(
                        "{}?error={}&error_description={}&state={}",
                        form.redirect_uri,
                        urlencoding::encode(err_code),
                        urlencoding::encode(&err_desc),
                        urlencoding::encode(&form.state),
                    );
                    return Ok(
                        (StatusCode::FOUND, [("Location", redirect.as_str())]).into_response()
                    );
                }
                // Fallback: render an HTML error page so the browser doesn't show raw JSON.
                let html = format!(
                    "<!DOCTYPE html><html><head><title>Authorization Failed</title>\
                    <style>body{{font-family:system-ui;max-width:600px;margin:60px auto;padding:20px;color:#1a1a1a}}\
                    h1{{color:#c00}}code{{background:#f4f4f4;padding:2px 6px;border-radius:3px}}</style></head>\
                    <body><h1>Authorization Failed</h1>\
                    <p>{}</p>\
                    <p><a href=\"/dashboard\">Return to dashboard</a></p></body></html>",
                    html_escape(&err_desc),
                );
                return Ok((
                    StatusCode::CONFLICT,
                    [("Content-Type", "text/html; charset=utf-8")],
                    html,
                )
                    .into_response());
            }
        };
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
            return Err(ApiError::BadRequest("redirect_uri does not match".into()));
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

    // Audit: consent granted (issue #28). Resource shape matches
    // ConsentRevoked's so admins can correlate grant/revoke pairs by
    // (resource_type, resource_id).
    let event = AuditEvent::builder(AuditEventType::ConsentGranted)
        .action("grant")
        .user_actor(&auth.user)
        .resource("oauth_consent", &auth.user.id.0.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("user approved consent"))
        .details(serde_json::json!({
            "client_id": client_id,
            "client_uuid": client_uuid.to_string(),
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
    Ok((StatusCode::FOUND, [("Location", redirect_url.as_str())]).into_response())
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

    let scopes = OAuthScope::parse_scope_string(&form.scope).map_err(ApiError::BadRequest)?;

    // If an existing client for this public_key_hash exists, delete it so the
    // new registration can succeed. The schema enforces UNIQUE on public_key_hash,
    // so a soft-revoke leaves the row in place and blocks the INSERT. This handles
    // re-registrations where the CLI cleared its local state but the server still
    // has the old client.
    if let Some(existing) = state
        .store
        .get_oauth_client_by_public_key_hash(&form.public_key_hash)
        .await?
    {
        // Revoke first to cascade-revoke any active tokens, then delete the row.
        if existing.revoked_at.is_none() {
            let _ = state.store.revoke_oauth_client(&existing.client_id).await;
        }
        state.store.delete_oauth_client(&existing.client_id).await?;
        tracing::info!(
            client_id = %existing.client_id,
            pk_hash = %form.public_key_hash,
            "deleted existing OAuth client for re-registration"
        );
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
    create_or_reuse_workspace(state, auth, &form.workspace_name, &form.public_key_hash).await?;

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
/// Identity is the `pk_hash`, not the display name (#39):
/// - Same `pk_hash` (regardless of name match) -- reuse the existing row
/// - No matching `pk_hash` -- create a new workspace, even if another
///   identity already owns a workspace with the same name
pub(super) async fn create_or_reuse_workspace(
    state: &AppState,
    auth: &AuthenticatedUser,
    workspace_name: &str,
    pk_hash: &str,
) -> Result<(), ApiError> {
    // #39: identity is the `pk_hash` (DB-unique), not the display name.
    // Same-key re-registration reuses the existing row and accepts a
    // possibly-different display name as a rename. Names are free to
    // collide across identities; the lookup by pk_hash is what
    // disambiguates.
    if let Some(existing) = state.store.get_workspace_by_pk_hash(pk_hash).await? {
        let mut updated = existing;
        updated.name = workspace_name.to_string();
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

    // No workspace yet for this identity — create a fresh one. The name may
    // collide with another tenant's workspace; that's allowed.
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

#[cfg(test)]
mod tests {
    use super::*;
    use agent_cordon_core::crypto::password::hash_password;
    use agent_cordon_core::domain::user::{User, UserId, UserRole};
    use agent_cordon_core::storage::Store;

    use crate::test_helpers::TestAppBuilder;

    async fn make_admin_auth(store: &dyn Store, username: &str) -> AuthenticatedUser {
        let password_hash = hash_password("test-pass-123!").expect("hash");
        let now = chrono::Utc::now();
        let user = User {
            id: UserId(Uuid::new_v4()),
            username: username.to_string(),
            display_name: Some(username.to_string()),
            password_hash,
            role: UserRole::Admin,
            is_root: false,
            enabled: true,
            created_at: now,
            updated_at: now,
        };
        store.create_user(&user).await.expect("create user");
        AuthenticatedUser {
            user,
            is_root: false,
        }
    }

    /// Issue #39: two distinct identities registering a workspace with the
    /// same name should both succeed — workspace names are not unique.
    #[tokio::test]
    async fn create_or_reuse_workspace_allows_duplicate_names_under_different_keys() {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let auth_a = make_admin_auth(&*ctx.store, "alice").await;
        let auth_b = make_admin_auth(&*ctx.store, "bob").await;

        create_or_reuse_workspace(&ctx.state, &auth_a, "dev", "pk_hash_alice")
            .await
            .expect("first registration succeeds");

        create_or_reuse_workspace(&ctx.state, &auth_b, "dev", "pk_hash_bob")
            .await
            .expect("second registration with same name but different key must also succeed");

        let workspaces = ctx.store.list_workspaces().await.expect("list");
        let named_dev: Vec<_> = workspaces.iter().filter(|w| w.name == "dev").collect();
        assert_eq!(
            named_dev.len(),
            2,
            "two distinct workspaces named 'dev' should coexist; got {}",
            named_dev.len()
        );
    }

    /// Idempotent re-registration must survive even when *another tenant*
    /// is squatting on the same display name. Reproduces the bug where the
    /// implementation looked up by name (not by pk_hash), so Alice's second
    /// `register --name dev` after Bob also registered `dev` ended up
    /// creating a duplicate Alice row.
    #[tokio::test]
    async fn create_or_reuse_workspace_is_idempotent_even_when_name_collides_with_other_tenant() {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let auth_alice = make_admin_auth(&*ctx.store, "alice").await;
        let auth_bob = make_admin_auth(&*ctx.store, "bob").await;

        create_or_reuse_workspace(&ctx.state, &auth_alice, "dev", "pk_hash_alice")
            .await
            .expect("alice initial register");
        create_or_reuse_workspace(&ctx.state, &auth_bob, "dev", "pk_hash_bob")
            .await
            .expect("bob register with same name, different key");

        // Alice re-registers. Identity is the key, not the name.
        create_or_reuse_workspace(&ctx.state, &auth_alice, "dev", "pk_hash_alice")
            .await
            .expect("alice re-register should reuse her existing workspace");

        let workspaces = ctx.store.list_workspaces().await.expect("list");
        let alice_dev: Vec<_> = workspaces
            .iter()
            .filter(|w| w.name == "dev" && w.pk_hash.as_deref() == Some("pk_hash_alice"))
            .collect();
        assert_eq!(
            alice_dev.len(),
            1,
            "alice must end up with exactly one 'dev' workspace; got {}",
            alice_dev.len()
        );
        let total_dev = workspaces.iter().filter(|w| w.name == "dev").count();
        assert_eq!(total_dev, 2, "alice's + bob's = 2 'dev' workspaces total");
    }

    /// Re-registration with a different name should rename the workspace —
    /// otherwise `register --name new-label` is a no-op after the first run.
    #[tokio::test]
    async fn create_or_reuse_workspace_renames_on_same_key_with_different_name() {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let auth = make_admin_auth(&*ctx.store, "alice").await;

        create_or_reuse_workspace(&ctx.state, &auth, "old-name", "pk_hash_alice")
            .await
            .expect("first register");
        create_or_reuse_workspace(&ctx.state, &auth, "new-name", "pk_hash_alice")
            .await
            .expect("rename via re-register");

        let workspaces = ctx.store.list_workspaces().await.expect("list");
        let alice_owned: Vec<_> = workspaces
            .iter()
            .filter(|w| w.pk_hash.as_deref() == Some("pk_hash_alice"))
            .collect();
        assert_eq!(alice_owned.len(), 1, "still one workspace for alice");
        assert_eq!(
            alice_owned[0].name, "new-name",
            "renamed to the value supplied at re-registration"
        );
    }

    /// Same-key re-registration must stay idempotent: a single row, possibly
    /// re-enabled, with the same identity.
    #[tokio::test]
    async fn create_or_reuse_workspace_is_idempotent_for_same_key() {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let auth = make_admin_auth(&*ctx.store, "alice").await;

        create_or_reuse_workspace(&ctx.state, &auth, "dev", "pk_hash_alice")
            .await
            .expect("first registration");
        create_or_reuse_workspace(&ctx.state, &auth, "dev", "pk_hash_alice")
            .await
            .expect("second registration with same key reuses the existing workspace");

        let workspaces = ctx.store.list_workspaces().await.expect("list");
        let named_dev: Vec<_> = workspaces.iter().filter(|w| w.name == "dev").collect();
        assert_eq!(
            named_dev.len(),
            1,
            "same-key re-registration must not create a duplicate row"
        );
    }
}
