//! OAuth 2.0 Authorization endpoint — consent page rendering (GET).

use askama::Template;
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect, Response},
};
use chrono::{Duration, Utc};
use serde::Deserialize;

use agent_cordon_core::crypto::session::hash_session_token_hmac;
use agent_cordon_core::oauth2::types::{OAuthAuthCode, OAuthScope};

use crate::extractors::AuthenticatedUser;
use crate::response::ApiError;
use crate::state::AppState;
use crate::utils::cookies::parse_cookie;

use super::{generate_auth_code, is_localhost_uri, scope_descriptions, ScopeDisplay};

/// Compute a deterministic CSRF token from the session cookie using HMAC.
///
/// Uses HMAC-SHA256(session_hash_key, raw_session_token || "csrf-oauth-consent")
/// so no server-side CSRF state is needed -- the token can be recomputed on POST.
pub(crate) fn compute_csrf_token(session_token: &str, session_hash_key: &[u8; 32]) -> String {
    let csrf_input = format!("{session_token}\0csrf-oauth-consent");
    hash_session_token_hmac(&csrf_input, session_hash_key)
}

/// Extract the raw session token from the Cookie header.
pub(crate) fn extract_session_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let cookie_header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    parse_cookie(cookie_header, "agtcrdn_session").map(|s| s.to_string())
}

/// Validate new workspace registration parameters.
pub(crate) fn validate_new_workspace_params(pk_hash: &str, ws_name: &str) -> Result<(), ApiError> {
    if ws_name.is_empty() || ws_name.len() > 255 {
        return Err(ApiError::BadRequest(
            "workspace_name must be 1-255 characters".into(),
        ));
    }
    if pk_hash.len() != 64 || !pk_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest(
            "public_key_hash must be a 64-char hex string".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// GET /api/v1/oauth/authorize -- Render consent page
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct AuthorizeQuery {
    response_type: String,
    client_id: Option<String>,
    public_key_hash: Option<String>,
    workspace_name: Option<String>,
    redirect_uri: String,
    scope: String,
    state: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

#[derive(Template)]
#[template(path = "consent.html")]
struct ConsentTemplate {
    workspace_name: String,
    scopes: Vec<ScopeDisplay>,
    user_name: String,
    client_id: String,
    redirect_uri: String,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
    csrf_token: String,
    is_new_workspace: bool,
    public_key_hash: String,
}

/// GET /api/v1/oauth/authorize
pub(crate) async fn authorize_get(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    headers: axum::http::HeaderMap,
    Query(params): Query<AuthorizeQuery>,
) -> Result<Response, ApiError> {
    // Validate response_type
    if params.response_type != "code" {
        return Err(ApiError::BadRequest("response_type must be 'code'".into()));
    }

    // PKCE is required
    let code_challenge = params.code_challenge.as_deref().unwrap_or("");
    if code_challenge.is_empty() {
        return Err(ApiError::BadRequest("code_challenge is required".into()));
    }
    let code_challenge_method = params.code_challenge_method.as_deref().unwrap_or("");
    if code_challenge_method != "S256" {
        return Err(ApiError::BadRequest(
            "code_challenge_method must be 'S256'".into(),
        ));
    }

    // Validate redirect_uri is localhost
    if !is_localhost_uri(&params.redirect_uri) {
        return Err(ApiError::BadRequest(
            "redirect_uri must be localhost".into(),
        ));
    }

    // Validate requested scopes
    let requested_scopes =
        OAuthScope::parse_scope_string(&params.scope).map_err(ApiError::BadRequest)?;

    // Determine if this is an existing client or new workspace registration
    let (workspace_name, client_id_str, is_new_workspace, public_key_hash) =
        if let Some(ref client_id) = params.client_id {
            // Existing client path
            let client = state
                .store
                .get_oauth_client_by_client_id(client_id)
                .await?
                .ok_or_else(|| ApiError::BadRequest("unknown client_id".into()))?;

            if client.revoked_at.is_some() {
                return Err(ApiError::BadRequest("client has been revoked".into()));
            }

            if !client.redirect_uris.contains(&params.redirect_uri) {
                return Err(ApiError::BadRequest("redirect_uri does not match".into()));
            }

            for scope in &requested_scopes {
                if !client.allowed_scopes.contains(scope) {
                    return Err(ApiError::BadRequest(format!(
                        "scope not allowed for this client: {scope}"
                    )));
                }
            }

            (
                client.workspace_name,
                client_id.clone(),
                false,
                String::new(),
            )
        } else if let (Some(ref pk_hash), Some(ref ws_name)) =
            (&params.public_key_hash, &params.workspace_name)
        {
            // New workspace registration path
            validate_new_workspace_params(pk_hash, ws_name)?;
            (ws_name.clone(), String::new(), true, pk_hash.clone())
        } else {
            return Err(ApiError::BadRequest(
                "must provide either client_id or (public_key_hash and workspace_name)".into(),
            ));
        };

    // Check for existing consent -- if scopes match, skip consent page (existing client only)
    if !is_new_workspace {
        if let Some(consent) = state
            .store
            .get_oauth_consent(&client_id_str, &auth.user.id)
            .await?
        {
            let consent_covers_all = requested_scopes.iter().all(|s| consent.scopes.contains(s));
            if consent_covers_all {
                let (code, code_hash) = generate_auth_code();
                let now = Utc::now();

                let auth_code = OAuthAuthCode {
                    code_hash,
                    client_id: client_id_str.clone(),
                    user_id: auth.user.id.clone(),
                    redirect_uri: params.redirect_uri.clone(),
                    scopes: requested_scopes,
                    code_challenge: Some(code_challenge.to_string()),
                    created_at: now,
                    expires_at: now + Duration::seconds(300),
                    consumed_at: None,
                };
                state.store.create_oauth_auth_code(&auth_code).await?;

                let redirect_url = format!(
                    "{}?code={}&state={}",
                    params.redirect_uri,
                    urlencoding::encode(&code),
                    urlencoding::encode(&params.state)
                );
                return Ok(Redirect::to(&redirect_url).into_response());
            }
        }
    }

    // Compute CSRF token from session cookie via HMAC (double-submit pattern)
    let session_token = extract_session_token(&headers)
        .ok_or_else(|| ApiError::Unauthorized("session required".into()))?;
    let csrf_token = compute_csrf_token(&session_token, &state.session_hash_key);

    let template = ConsentTemplate {
        workspace_name,
        scopes: scope_descriptions(&requested_scopes),
        user_name: auth.user.username.clone(),
        client_id: client_id_str,
        redirect_uri: params.redirect_uri,
        state: params.state,
        code_challenge: code_challenge.to_string(),
        code_challenge_method: "S256".to_string(),
        csrf_token,
        is_new_workspace,
        public_key_hash,
    };

    match template.render() {
        Ok(html) => Ok(Html(html).into_response()),
        Err(e) => {
            tracing::error!(error = %e, "failed to render consent template");
            Err(ApiError::Internal("template render failed".into()))
        }
    }
}
