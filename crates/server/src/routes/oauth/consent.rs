//! OAuth 2.0 consent processing — POST /api/v1/oauth/authorize.
//!
//! Handles the user's approve/deny decision, creates OAuth clients and
//! workspace records for new registrations, and issues authorization codes.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use subtle::ConstantTimeEq;

use agent_cordon_core::oauth2::types::OAuthScope;

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::ApiError;
use crate::services::oauth::{ConsentGrant, ConsentRegistration};
use crate::services::workspaces::refuse_reregistration_unless_allowed;
use crate::state::AppState;

use super::authorize::{compute_csrf_token, extract_session_token};
use super::is_localhost_uri;

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
    let expected_csrf = compute_csrf_token(&session_token, &state.crypto.session_hash_key);
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

    // Registering a workspace through the consent form creates a workspace
    // and an OAuth client for a caller-supplied key hash. That is the same
    // privilege the device-flow approve route gates on; without the gate any
    // signed-in user could bind, or take over, any workspace.
    if form.is_new_workspace {
        state
            .authz
            .authorize(
                &auth,
                agent_cordon_core::policy::actions::MANAGE_WORKSPACES,
                &agent_cordon_core::policy::PolicyResource::System,
            )
            .await?;
        // Decide before touching any row: creating the client deletes the
        // key hash's previous client, which must not happen for a workspace
        // that is staying revoked.
        if let Some(existing) = state
            .store
            .get_workspace_by_pk_hash(&form.public_key_hash)
            .await?
        {
            refuse_reregistration_unless_allowed(&existing, &auth)?;
        }
    }

    // Determine client_id: create new client if new workspace, or validate existing
    let (client_id, client_uuid, is_new) = if form.is_new_workspace {
        let registration = state
            .services
            .oauth
            .register_workspace_on_consent(
                &auth,
                &corr.0,
                ConsentRegistration {
                    public_key_hash: &form.public_key_hash,
                    workspace_name: &form.workspace_name,
                    redirect_uri: &form.redirect_uri,
                    scope: &form.scope,
                },
            )
            .await;
        let new_client = match registration {
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
                return Ok(ApiError::Conflict(err_desc).into_html_response());
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

    let code = state
        .services
        .oauth
        .grant_consent(
            &auth,
            &corr.0,
            ConsentGrant {
                client_id: &client_id,
                client_uuid,
                redirect_uri: &form.redirect_uri,
                scopes,
                code_challenge: &form.code_challenge,
                is_new_workspace: is_new,
            },
        )
        .await?;

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

    state
        .services
        .oauth
        .deny_consent(auth, &corr.0, &form.client_id, &form.workspace_name)
        .await;

    let redirect_url = format!(
        "{}?error=access_denied&error_description={}&state={}",
        form.redirect_uri,
        urlencoding::encode("User denied consent"),
        urlencoding::encode(&form.state)
    );
    Ok(Redirect::to(&redirect_url).into_response())
}
