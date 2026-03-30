//! OAuth 2.0 Authorization endpoint — consent page rendering and processing.

use askama::Template;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use chrono::{Duration, Utc};
use serde::Deserialize;

use agent_cordon_core::crypto::session::hash_session_token_hmac;
use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::oauth2::types::{OAuthAuthCode, OAuthConsent, OAuthScope};

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::ApiError;
use crate::state::AppState;
use crate::utils::cookies::parse_cookie;

use super::{generate_auth_code, scope_descriptions, ScopeDisplay};

/// Compute a deterministic CSRF token from the session cookie using HMAC.
///
/// Uses HMAC-SHA256(session_hash_key, raw_session_token || "csrf-oauth-consent")
/// so no server-side CSRF state is needed — the token can be recomputed on POST.
fn compute_csrf_token(session_token: &str, session_hash_key: &[u8; 32]) -> String {
    // Domain-separate from session hashing by appending a fixed suffix
    let csrf_input = format!("{session_token}\0csrf-oauth-consent");
    hash_session_token_hmac(&csrf_input, session_hash_key)
}

/// Extract the raw session token from the Cookie header.
fn extract_session_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let cookie_header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    parse_cookie(cookie_header, "agtcrdn_session").map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// GET /api/v1/oauth/authorize — Render consent page
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct AuthorizeQuery {
    response_type: String,
    client_id: String,
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
        return Err(ApiError::BadRequest(
            "response_type must be 'code'".into(),
        ));
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

    // Look up client
    let client = state
        .store
        .get_oauth_client_by_client_id(&params.client_id)
        .await?
        .ok_or_else(|| ApiError::BadRequest("unknown client_id".into()))?;

    if client.revoked_at.is_some() {
        return Err(ApiError::BadRequest("client has been revoked".into()));
    }

    // Validate redirect_uri matches registered URIs
    if !client.redirect_uris.contains(&params.redirect_uri) {
        return Err(ApiError::BadRequest("redirect_uri does not match".into()));
    }

    // Validate requested scopes
    let requested_scopes = OAuthScope::parse_scope_string(&params.scope)
        .map_err(ApiError::BadRequest)?;
    for scope in &requested_scopes {
        if !client.allowed_scopes.contains(scope) {
            return Err(ApiError::BadRequest(format!(
                "scope not allowed for this client: {scope}"
            )));
        }
    }

    // Check for existing consent — if scopes match, skip consent page
    if let Some(consent) = state
        .store
        .get_oauth_consent(&params.client_id, &auth.user.id)
        .await?
    {
        let consent_covers_all = requested_scopes
            .iter()
            .all(|s| consent.scopes.contains(s));
        if consent_covers_all {
            // Silent re-authorization: generate code and redirect immediately
            let (code, code_hash) = generate_auth_code();
            let now = Utc::now();

            let auth_code = OAuthAuthCode {
                code_hash,
                client_id: params.client_id.clone(),
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

    // Compute CSRF token from session cookie via HMAC (double-submit pattern)
    let session_token = extract_session_token(&headers)
        .ok_or_else(|| ApiError::Unauthorized("session required".into()))?;
    let csrf_token = compute_csrf_token(&session_token, &state.session_hash_key);

    let template = ConsentTemplate {
        workspace_name: client.workspace_name,
        scopes: scope_descriptions(&requested_scopes),
        user_name: auth.user.username.clone(),
        client_id: params.client_id,
        redirect_uri: params.redirect_uri,
        state: params.state,
        code_challenge: code_challenge.to_string(),
        code_challenge_method: "S256".to_string(),
        csrf_token,
    };

    match template.render() {
        Ok(html) => Ok(Html(html).into_response()),
        Err(e) => {
            tracing::error!(error = %e, "failed to render consent template");
            Err(ApiError::Internal("template render failed".into()))
        }
    }
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
    if form.csrf_token != expected_csrf {
        return Err(ApiError::Forbidden("invalid csrf_token".into()));
    }

    // Validate client
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

    let scopes = OAuthScope::parse_scope_string(&form.scope)
        .map_err(ApiError::BadRequest)?;

    if form.decision == "deny" {
        // Audit: consent denied
        let event = AuditEvent::builder(AuditEventType::Oauth2TokenFailed)
            .action("oauth_consent_denied")
            .user_actor(&auth.user)
            .resource("oauth_client", &client.id.to_string())
            .correlation_id(&corr.0)
            .decision(AuditDecision::Forbid, Some("user denied consent"))
            .details(serde_json::json!({
                "client_id": form.client_id,
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
        return Ok(Redirect::to(&redirect_url).into_response());
    }

    if form.decision != "approve" {
        return Err(ApiError::BadRequest("decision must be 'approve' or 'deny'".into()));
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

    // Generate auth code
    let (code, code_hash) = generate_auth_code();
    let now = Utc::now();

    let auth_code = OAuthAuthCode {
        code_hash,
        client_id: form.client_id.clone(),
        user_id: auth.user.id.clone(),
        redirect_uri: form.redirect_uri.clone(),
        scopes: scopes.clone(),
        code_challenge: Some(form.code_challenge),
        created_at: now,
        expires_at: now + Duration::seconds(300), // 5 min TTL
        consumed_at: None,
    };
    state.store.create_oauth_auth_code(&auth_code).await?;

    // Upsert consent record
    let consent = OAuthConsent {
        client_id: form.client_id.clone(),
        user_id: auth.user.id.clone(),
        scopes: scopes.clone(),
        granted_at: now,
    };
    state.store.upsert_oauth_consent(&consent).await?;

    // Audit: consent granted
    let event = AuditEvent::builder(AuditEventType::Oauth2TokenAcquired)
        .action("oauth_consent_granted")
        .user_actor(&auth.user)
        .resource("oauth_client", &client.id.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("user approved consent"))
        .details(serde_json::json!({
            "client_id": form.client_id,
            "scopes": OAuthScope::to_scope_string(&scopes),
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "failed to write audit event");
    }

    let redirect_url = format!(
        "{}?code={}&state={}",
        form.redirect_uri,
        urlencoding::encode(&code),
        urlencoding::encode(&form.state)
    );
    Ok((StatusCode::FOUND, [("Location", redirect_url.as_str())])
        .into_response())
}
