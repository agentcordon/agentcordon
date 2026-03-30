//! Integration tests for v3.0.0: OAuth 2.0 Authorization Server.
//!
//! Tests cover the full OAuth authorization code flow with PKCE:
//! client registration, authorization/consent, token exchange,
//! token refresh with rotation, revocation, and scope enforcement.

use crate::common::*;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::oauth2::types::{OAuthScope, OAuthAccessToken};
use agent_cordon_core::storage::Store;

use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Build test app with enrollment enabled and return (Router, Store, AppState).
async fn setup() -> (
    Router,
    Arc<dyn Store + Send + Sync>,
    agent_cordon_server::state::AppState,
) {
    let ctx = TestAppBuilder::new().with_enrollment().build().await;
    (ctx.app, ctx.store, ctx.state)
}

/// Login and return (combined_cookie, csrf_token).
async fn login(app: &Router, username: &str, password: &str) -> (String, String) {
    let (session, csrf) = login_user(app, username, password).await;
    (combined_cookie(&session, &csrf), csrf)
}

/// Register an OAuth client via the API and return the response JSON.
async fn register_client(
    app: &Router,
    cookie: &str,
    csrf: &str,
    workspace_name: &str,
    pk_hash: &str,
    scopes: &[&str],
    redirect_uris: &[&str],
) -> (StatusCode, Value) {
    send_json(
        app,
        Method::POST,
        "/api/v1/oauth/clients",
        None,
        Some(cookie),
        Some(csrf),
        Some(json!({
            "workspace_name": workspace_name,
            "public_key_hash": pk_hash,
            "scopes": scopes,
            "redirect_uris": redirect_uris,
        })),
    )
    .await
}

/// Helper: send a form-urlencoded POST request (for /oauth/token and /oauth/revoke).
async fn send_form(app: &Router, uri: &str, body: &str) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));
    (status, json)
}

/// Helper: GET /api/v1/oauth/authorize and return (status, body_text, headers).
async fn get_authorize(
    app: &Router,
    cookie: &str,
    query: &str,
) -> (StatusCode, String, Vec<(String, String)>) {
    let uri = format!("/api/v1/oauth/authorize?{}", query);
    let request = Request::builder()
        .method(Method::GET)
        .uri(&uri)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&bytes).to_string();
    (status, text, headers)
}

/// Helper: POST /api/v1/oauth/authorize (consent form submit).
async fn post_consent(
    app: &Router,
    cookie: &str,
    form_body: &str,
) -> (StatusCode, String, Vec<(String, String)>) {
    // Extract CSRF token from cookie for the X-CSRF-Token header
    let csrf = extract_csrf_from_cookie(cookie).unwrap_or_default();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/oauth/authorize")
        .header(header::COOKIE, cookie)
        .header("x-csrf-token", &csrf)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form_body.to_string()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&bytes).to_string();
    (status, text, headers)
}

/// Generate a PKCE code_verifier and code_challenge (S256).
fn generate_pkce() -> (String, String) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"; // test constant
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());
    (verifier.to_string(), challenge)
}

/// A valid test pk_hash (64 hex chars).
const TEST_PK_HASH: &str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
const TEST_REDIRECT_URI: &str = "http://localhost:9876/callback";

/// Full flow helper: register client, authorize, consent, exchange → returns tokens.
async fn full_oauth_flow(
    app: &Router,
    store: &(dyn Store + Send + Sync),
    state: &agent_cordon_server::state::AppState,
    scopes_str: &str,
) -> (String, String, String, String, String) {
    // Create admin user and login
    let _admin = create_test_user(store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(app, "admin", TEST_PASSWORD).await;

    // Register client
    let (status, body) = register_client(
        app,
        &cookie,
        &csrf,
        "test-workspace",
        TEST_PK_HASH,
        &scopes_str.split_whitespace().collect::<Vec<_>>(),
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "register: {}", body);
    let client_id = body["data"]["client_id"].as_str().unwrap().to_string();
    let client_secret = body["data"]["client_secret"].as_str().unwrap().to_string();

    // Generate PKCE
    let (verifier, challenge) = generate_pkce();

    // Compute consent CSRF token from session
    let consent_csrf = compute_consent_csrf(&cookie, &state.session_hash_key);

    // POST consent (approve)
    let form = format!(
        "client_id={}&redirect_uri={}&scope={}&state=test-state&code_challenge={}&code_challenge_method=S256&decision=approve&csrf_token={}",
        urlencoding::encode(&client_id),
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(scopes_str),
        urlencoding::encode(&challenge),
        urlencoding::encode(&consent_csrf),
    );
    let (status, _body, headers) = post_consent(app, &cookie, &form).await;
    assert!(
        status == StatusCode::FOUND || status == StatusCode::SEE_OTHER,
        "consent: status={}, body={}",
        status,
        _body
    );

    // Extract code from Location header
    let location = headers
        .iter()
        .find(|(k, _)| k == "location")
        .map(|(_, v)| v.clone())
        .expect("Location header must be present");
    let code = url::Url::parse(&format!("http://localhost{}", location))
        .or_else(|_| url::Url::parse(&location))
        .expect("parse redirect URL")
        .query_pairs()
        .find(|(k, _)| k == "code")
        .expect("code param must be present")
        .1
        .to_string();

    // Exchange code for tokens
    let form = format!(
        "grant_type=authorization_code&code={}&client_id={}&client_secret={}&redirect_uri={}&code_verifier={}",
        urlencoding::encode(&code),
        urlencoding::encode(&client_id),
        urlencoding::encode(&client_secret),
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&verifier),
    );
    let (status, body) = send_form(app, "/api/v1/oauth/token", &form).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {}", body);

    let access_token = body["access_token"].as_str().unwrap().to_string();
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    (client_id, client_secret, access_token, refresh_token, cookie)
}

// ===========================================================================
// A1. OAuth Client Registration (Happy Path)
// ===========================================================================

#[tokio::test]
async fn test_register_oauth_client_success() {
    let (app, store, _state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "my-workspace",
        TEST_PK_HASH,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "body: {}", body);
    let client_id = body["data"]["client_id"].as_str().unwrap();
    assert!(client_id.starts_with("ac_cli_"), "client_id format: {}", client_id);
    assert_eq!(body["data"]["workspace_name"], "my-workspace");
    assert!(body["data"]["client_secret"].as_str().is_some());
}

#[tokio::test]
async fn test_register_client_with_all_scopes() {
    let (app, store, _state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "all-scopes-ws",
        TEST_PK_HASH,
        &["credentials:discover", "credentials:vend", "mcp:invoke"],
        &[TEST_REDIRECT_URI],
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "body: {}", body);
    let scopes = body["data"]["allowed_scopes"].as_array().unwrap();
    assert_eq!(scopes.len(), 3);
}

#[tokio::test]
async fn test_register_client_minimal_scopes() {
    let (app, store, _state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "minimal-ws",
        TEST_PK_HASH,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "body: {}", body);
    let scopes = body["data"]["allowed_scopes"].as_array().unwrap();
    assert_eq!(scopes.len(), 1);
    assert_eq!(scopes[0], "credentials:discover");
}

// ===========================================================================
// A2. Client Registration (Retry/Idempotency)
// ===========================================================================

#[tokio::test]
async fn test_register_same_workspace_twice_conflict() {
    let (app, store, _state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (status, _body) = register_client(
        &app,
        &cookie,
        &csrf,
        "dup-ws",
        TEST_PK_HASH,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Second registration with same pk_hash → 409 Conflict
    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "dup-ws",
        TEST_PK_HASH,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {}", body);
}

// ===========================================================================
// A3. Client Registration (Error Handling)
// ===========================================================================

#[tokio::test]
async fn test_register_invalid_scopes() {
    let (app, store, _state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "bad-scopes-ws",
        TEST_PK_HASH,
        &["admin:delete_everything"],
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {}", body);
}

#[tokio::test]
async fn test_register_missing_redirect_uri() {
    let (app, store, _state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "no-redirect-ws",
        TEST_PK_HASH,
        &["credentials:discover"],
        &[], // empty redirect_uris
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {}", body);
}

#[tokio::test]
async fn test_register_no_auth() {
    let (app, _store, _state) = setup().await;

    // Client registration is a public endpoint (RFC 7591 Dynamic Client Registration).
    // No authentication required — authorization happens in the consent flow.
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/oauth/clients",
        None,
        None,
        None,
        Some(json!({
            "workspace_name": "unauth-ws",
            "public_key_hash": TEST_PK_HASH,
            "scopes": ["credentials:discover"],
            "redirect_uris": [TEST_REDIRECT_URI],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body: {}", body);
    assert!(body["data"]["client_id"].as_str().is_some());
}

#[tokio::test]
async fn test_register_non_localhost_redirect_uri() {
    let (app, store, _state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "external-redirect",
        TEST_PK_HASH,
        &["credentials:discover"],
        &["https://evil.com/callback"],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {}", body);
}

// ===========================================================================
// A6. Authorization Endpoint (Happy Path)
// ===========================================================================

#[tokio::test]
async fn test_authorize_renders_consent_page() {
    let (app, store, _state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    // Register a client first
    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "consent-ws",
        TEST_PK_HASH,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let client_id = body["data"]["client_id"].as_str().unwrap();

    let (_verifier, challenge) = generate_pkce();

    let query = format!(
        "response_type=code&client_id={}&redirect_uri={}&scope=credentials:discover&state=xyz&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(client_id),
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
    );
    let (status, body, _headers) = get_authorize(&app, &cookie, &query).await;
    assert_eq!(status, StatusCode::OK, "body: {}", body);
    // Consent page should contain the workspace name
    assert!(body.contains("consent-ws"), "consent page should show workspace name: {}", body);
}

// ===========================================================================
// A7. Authorization Endpoint (Error Handling)
// ===========================================================================

#[tokio::test]
async fn test_authorize_invalid_client_id() {
    let (app, store, _state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, _csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (_verifier, challenge) = generate_pkce();
    let query = format!(
        "response_type=code&client_id=nonexistent&redirect_uri={}&scope=credentials:discover&state=xyz&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
    );
    let (status, _body, _headers) = get_authorize(&app, &cookie, &query).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_authorize_missing_code_challenge() {
    let (app, store, _state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "pkce-ws",
        TEST_PK_HASH,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let client_id = body["data"]["client_id"].as_str().unwrap();

    // No code_challenge
    let query = format!(
        "response_type=code&client_id={}&redirect_uri={}&scope=credentials:discover&state=xyz&code_challenge_method=S256",
        urlencoding::encode(client_id),
        urlencoding::encode(TEST_REDIRECT_URI),
    );
    let (status, _body, _headers) = get_authorize(&app, &cookie, &query).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_authorize_unsupported_challenge_method() {
    let (app, store, _state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "plain-pkce-ws",
        TEST_PK_HASH,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let client_id = body["data"]["client_id"].as_str().unwrap();

    // code_challenge_method=plain (only S256 supported)
    let query = format!(
        "response_type=code&client_id={}&redirect_uri={}&scope=credentials:discover&state=xyz&code_challenge=abc&code_challenge_method=plain",
        urlencoding::encode(client_id),
        urlencoding::encode(TEST_REDIRECT_URI),
    );
    let (status, _body, _headers) = get_authorize(&app, &cookie, &query).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_authorize_scope_exceeds_client_registration() {
    let (app, store, _state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    // Register with only credentials:discover
    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "narrow-scope-ws",
        TEST_PK_HASH,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let client_id = body["data"]["client_id"].as_str().unwrap();

    let (_verifier, challenge) = generate_pkce();

    // Request credentials:vend which exceeds registration
    let query = format!(
        "response_type=code&client_id={}&redirect_uri={}&scope=credentials:vend&state=xyz&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(client_id),
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
    );
    let (status, _body, _headers) = get_authorize(&app, &cookie, &query).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_authorize_invalid_redirect_uri() {
    let (app, store, _state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "redirect-ws",
        TEST_PK_HASH,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let client_id = body["data"]["client_id"].as_str().unwrap();

    let (_verifier, challenge) = generate_pkce();

    // Use a different redirect_uri than registered
    let query = format!(
        "response_type=code&client_id={}&redirect_uri={}&scope=credentials:discover&state=xyz&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(client_id),
        urlencoding::encode("http://localhost:9999/other-callback"),
        urlencoding::encode(&challenge),
    );
    let (status, _body, _headers) = get_authorize(&app, &cookie, &query).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_authorize_missing_response_type() {
    let (app, store, _state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "no-rt-ws",
        TEST_PK_HASH,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let client_id = body["data"]["client_id"].as_str().unwrap();

    let (_verifier, challenge) = generate_pkce();

    // response_type=token (wrong)
    let query = format!(
        "response_type=token&client_id={}&redirect_uri={}&scope=credentials:discover&state=xyz&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(client_id),
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
    );
    let (status, _body, _headers) = get_authorize(&app, &cookie, &query).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ===========================================================================
// A9. Auth Code Issuance — Consent Approve/Deny
// ===========================================================================

#[tokio::test]
async fn test_consent_approve_issues_code() {
    let (app, store, state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "approve-ws",
        TEST_PK_HASH,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let client_id = body["data"]["client_id"].as_str().unwrap();

    let (_verifier, challenge) = generate_pkce();
    let consent_csrf = compute_consent_csrf(&cookie, &state.session_hash_key);

    let form = format!(
        "client_id={}&redirect_uri={}&scope=credentials:discover&state=test-state-123&code_challenge={}&code_challenge_method=S256&decision=approve&csrf_token={}",
        urlencoding::encode(client_id),
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
        urlencoding::encode(&consent_csrf),
    );
    let (status, _body, headers) = post_consent(&app, &cookie, &form).await;
    assert!(
        status == StatusCode::FOUND || status == StatusCode::SEE_OTHER,
        "expected redirect, got: {} {}",
        status,
        _body
    );

    let location = headers
        .iter()
        .find(|(k, _)| k == "location")
        .expect("Location header")
        .1
        .clone();

    // Parse the redirect URL for code and state
    let parsed = url::Url::parse(&format!("http://localhost{}", location))
        .or_else(|_| url::Url::parse(&location))
        .expect("parse redirect");
    let params: std::collections::HashMap<_, _> = parsed.query_pairs().collect();
    assert!(params.contains_key("code"), "code param missing: {}", location);
    assert_eq!(params.get("state").map(|s| s.as_ref()), Some("test-state-123"));
}

#[tokio::test]
async fn test_consent_deny_returns_error() {
    let (app, store, state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "deny-ws",
        TEST_PK_HASH,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let client_id = body["data"]["client_id"].as_str().unwrap();

    let (_verifier, challenge) = generate_pkce();
    let consent_csrf = compute_consent_csrf(&cookie, &state.session_hash_key);

    let form = format!(
        "client_id={}&redirect_uri={}&scope=credentials:discover&state=deny-state&code_challenge={}&code_challenge_method=S256&decision=deny&csrf_token={}",
        urlencoding::encode(client_id),
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
        urlencoding::encode(&consent_csrf),
    );
    let (status, _body, headers) = post_consent(&app, &cookie, &form).await;
    assert!(
        status == StatusCode::FOUND || status == StatusCode::SEE_OTHER,
        "expected redirect, got: {}",
        status
    );

    let location = headers
        .iter()
        .find(|(k, _)| k == "location")
        .expect("Location header")
        .1
        .clone();

    let parsed = url::Url::parse(&format!("http://localhost{}", location))
        .or_else(|_| url::Url::parse(&location))
        .expect("parse redirect");
    let params: std::collections::HashMap<_, _> = parsed.query_pairs().collect();
    assert_eq!(params.get("error").map(|s| s.as_ref()), Some("access_denied"));
    assert_eq!(params.get("state").map(|s| s.as_ref()), Some("deny-state"));
}

// ===========================================================================
// A12. Auth Code Issuance (Security)
// ===========================================================================

#[tokio::test]
async fn test_auth_code_single_use() {
    let (app, store, state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "single-use-ws",
        TEST_PK_HASH,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let client_id = body["data"]["client_id"].as_str().unwrap().to_string();
    let client_secret = body["data"]["client_secret"].as_str().unwrap().to_string();

    let (verifier, challenge) = generate_pkce();
    let consent_csrf = compute_consent_csrf(&cookie, &state.session_hash_key);

    // Get code via consent
    let form = format!(
        "client_id={}&redirect_uri={}&scope=credentials:discover&state=s&code_challenge={}&code_challenge_method=S256&decision=approve&csrf_token={}",
        urlencoding::encode(&client_id),
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
        urlencoding::encode(&consent_csrf),
    );
    let (status, _body, headers) = post_consent(&app, &cookie, &form).await;
    assert!(status == StatusCode::FOUND || status == StatusCode::SEE_OTHER);

    let location = headers.iter().find(|(k, _)| k == "location").unwrap().1.clone();
    let parsed = url::Url::parse(&format!("http://localhost{}", location))
        .or_else(|_| url::Url::parse(&location))
        .expect("parse");
    let code = parsed.query_pairs().find(|(k, _)| k == "code").unwrap().1.to_string();

    // First exchange → success
    let form1 = format!(
        "grant_type=authorization_code&code={}&client_id={}&client_secret={}&redirect_uri={}&code_verifier={}",
        urlencoding::encode(&code),
        urlencoding::encode(&client_id),
        urlencoding::encode(&client_secret),
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&verifier),
    );
    let (status, body) = send_form(&app, "/api/v1/oauth/token", &form1).await;
    assert_eq!(status, StatusCode::OK, "first exchange: {}", body);

    // Second exchange with same code → 400
    let (status, body) = send_form(&app, "/api/v1/oauth/token", &form1).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "second exchange should fail: {}", body);
    assert!(
        body["error"].as_str().unwrap_or("").contains("invalid_grant"),
        "error should be invalid_grant: {}",
        body
    );
}

// ===========================================================================
// A13. Token Endpoint — Auth Code Exchange (Happy Path)
// ===========================================================================

#[tokio::test]
async fn test_token_exchange_success() {
    let (app, store, state) = setup().await;
    let (client_id, _client_secret, access_token, refresh_token, _cookie) =
        full_oauth_flow(&app, &*store, &state, "credentials:discover").await;

    assert!(!access_token.is_empty(), "access_token must be non-empty");
    assert!(!refresh_token.is_empty(), "refresh_token must be non-empty");
    assert!(!client_id.is_empty());
}

#[tokio::test]
async fn test_refresh_token_is_opaque() {
    let (app, store, state) = setup().await;
    let (_client_id, _client_secret, _access_token, refresh_token, _cookie) =
        full_oauth_flow(&app, &*store, &state, "credentials:discover").await;

    // Refresh token should NOT be a JWT (no 3-part dot-separated structure that decodes)
    use base64::Engine;
    let parts: Vec<&str> = refresh_token.split('.').collect();
    // Opaque tokens may contain dots in base64url, but shouldn't decode as JWT header.claims.sig
    if parts.len() == 3 {
        // Try to decode the first part as base64 JSON — if it has "alg", it's a JWT
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .unwrap_or_default();
        let parsed: Result<Value, _> = serde_json::from_slice(&decoded);
        if let Ok(val) = parsed {
            assert!(
                val.get("alg").is_none(),
                "refresh token looks like a JWT (has 'alg' header)"
            );
        }
    }
    // If it doesn't have 3 dot-separated parts, it's definitely opaque — pass
}

#[tokio::test]
async fn test_token_exchange_content_type() {
    let (app, store, _state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;

    // Send JSON body to /oauth/token instead of form-urlencoded → should fail
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/oauth/token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"grant_type": "authorization_code"})).unwrap(),
        ))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    // Should be 400 or 415 (unsupported media type) or 422
    assert!(
        status == StatusCode::BAD_REQUEST
            || status == StatusCode::UNSUPPORTED_MEDIA_TYPE
            || status == StatusCode::UNPROCESSABLE_ENTITY,
        "JSON body on token endpoint should be rejected: got {}",
        status
    );
}

// ===========================================================================
// A14/A15. Token Exchange Error Handling
// ===========================================================================

#[tokio::test]
async fn test_token_exchange_wrong_pkce_verifier() {
    let (app, store, state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "wrong-pkce-ws",
        TEST_PK_HASH,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let client_id = body["data"]["client_id"].as_str().unwrap().to_string();
    let client_secret = body["data"]["client_secret"].as_str().unwrap().to_string();

    let (_verifier, challenge) = generate_pkce();
    let consent_csrf = compute_consent_csrf(&cookie, &state.session_hash_key);

    // Consent
    let form = format!(
        "client_id={}&redirect_uri={}&scope=credentials:discover&state=s&code_challenge={}&code_challenge_method=S256&decision=approve&csrf_token={}",
        urlencoding::encode(&client_id),
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
        urlencoding::encode(&consent_csrf),
    );
    let (_status, _body, headers) = post_consent(&app, &cookie, &form).await;
    let location = headers.iter().find(|(k, _)| k == "location").unwrap().1.clone();
    let parsed = url::Url::parse(&format!("http://localhost{}", location))
        .or_else(|_| url::Url::parse(&location))
        .expect("parse");
    let code = parsed.query_pairs().find(|(k, _)| k == "code").unwrap().1.to_string();

    // Exchange with wrong verifier
    let form = format!(
        "grant_type=authorization_code&code={}&client_id={}&client_secret={}&redirect_uri={}&code_verifier=wrong-verifier-value",
        urlencoding::encode(&code),
        urlencoding::encode(&client_id),
        urlencoding::encode(&client_secret),
        urlencoding::encode(TEST_REDIRECT_URI),
    );
    let (status, body) = send_form(&app, "/api/v1/oauth/token", &form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {}", body);
}

#[tokio::test]
async fn test_token_exchange_missing_pkce_verifier() {
    let (app, store, state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "no-pkce-ws",
        TEST_PK_HASH,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let client_id = body["data"]["client_id"].as_str().unwrap().to_string();
    let client_secret = body["data"]["client_secret"].as_str().unwrap().to_string();

    let (_verifier, challenge) = generate_pkce();
    let consent_csrf = compute_consent_csrf(&cookie, &state.session_hash_key);

    let form = format!(
        "client_id={}&redirect_uri={}&scope=credentials:discover&state=s&code_challenge={}&code_challenge_method=S256&decision=approve&csrf_token={}",
        urlencoding::encode(&client_id),
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
        urlencoding::encode(&consent_csrf),
    );
    let (_status, _body, headers) = post_consent(&app, &cookie, &form).await;
    let location = headers.iter().find(|(k, _)| k == "location").unwrap().1.clone();
    let parsed = url::Url::parse(&format!("http://localhost{}", location))
        .or_else(|_| url::Url::parse(&location))
        .expect("parse");
    let code = parsed.query_pairs().find(|(k, _)| k == "code").unwrap().1.to_string();

    // Exchange without code_verifier
    let form = format!(
        "grant_type=authorization_code&code={}&client_id={}&client_secret={}&redirect_uri={}",
        urlencoding::encode(&code),
        urlencoding::encode(&client_id),
        urlencoding::encode(&client_secret),
        urlencoding::encode(TEST_REDIRECT_URI),
    );
    let (status, body) = send_form(&app, "/api/v1/oauth/token", &form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {}", body);
}

#[tokio::test]
async fn test_token_exchange_invalid_grant_type() {
    let (app, _store, _state) = setup().await;

    let form = "grant_type=password&username=admin&password=test";
    let (status, body) = send_form(&app, "/api/v1/oauth/token", form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {}", body);
    assert_eq!(body["error"], "unsupported_grant_type");
}

// ===========================================================================
// A16. Token Endpoint Security
// ===========================================================================

#[tokio::test]
async fn test_token_no_secrets_in_error_response() {
    let (app, _store, _state) = setup().await;

    // Send a bad request — error response should only have "error" and "error_description"
    let form = "grant_type=authorization_code&code=invalid&client_id=nonexistent";
    let (status, body) = send_form(&app, "/api/v1/oauth/token", form).await;
    assert!(status.is_client_error() || status.is_server_error());

    // Verify only RFC 6749 error fields are present (no stack traces, no internal IDs)
    if let Some(obj) = body.as_object() {
        for key in obj.keys() {
            assert!(
                key == "error" || key == "error_description" || key == "status" || key == "message",
                "unexpected field in error response: {}",
                key
            );
        }
    }
}

// ===========================================================================
// A17. Token Endpoint — Refresh (Happy Path)
// ===========================================================================

#[tokio::test]
async fn test_refresh_token_success() {
    let (app, store, state) = setup().await;
    let (client_id, client_secret, _access_token, refresh_token, _cookie) =
        full_oauth_flow(&app, &*store, &state, "credentials:discover").await;

    let form = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret={}",
        urlencoding::encode(&refresh_token),
        urlencoding::encode(&client_id),
        urlencoding::encode(&client_secret),
    );
    let (status, body) = send_form(&app, "/api/v1/oauth/token", &form).await;
    assert_eq!(status, StatusCode::OK, "refresh: {}", body);
    assert!(body["access_token"].as_str().is_some());
    assert!(body["refresh_token"].as_str().is_some());
    assert_eq!(body["token_type"], "Bearer");
}

#[tokio::test]
async fn test_refresh_preserves_scopes() {
    let (app, store, state) = setup().await;
    let (client_id, client_secret, _access_token, refresh_token, _cookie) =
        full_oauth_flow(&app, &*store, &state, "credentials:discover credentials:vend").await;

    let form = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret={}",
        urlencoding::encode(&refresh_token),
        urlencoding::encode(&client_id),
        urlencoding::encode(&client_secret),
    );
    let (status, body) = send_form(&app, "/api/v1/oauth/token", &form).await;
    assert_eq!(status, StatusCode::OK, "refresh: {}", body);

    let scope = body["scope"].as_str().unwrap();
    assert!(scope.contains("credentials:discover"), "scope: {}", scope);
    assert!(scope.contains("credentials:vend"), "scope: {}", scope);
}

#[tokio::test]
async fn test_refresh_new_access_token_different() {
    let (app, store, state) = setup().await;
    let (client_id, client_secret, old_access_token, refresh_token, _cookie) =
        full_oauth_flow(&app, &*store, &state, "credentials:discover").await;

    let form = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret={}",
        urlencoding::encode(&refresh_token),
        urlencoding::encode(&client_id),
        urlencoding::encode(&client_secret),
    );
    let (status, body) = send_form(&app, "/api/v1/oauth/token", &form).await;
    assert_eq!(status, StatusCode::OK);

    let new_access_token = body["access_token"].as_str().unwrap();
    assert_ne!(new_access_token, old_access_token, "new access token must differ");
}

// ===========================================================================
// A18. Token Refresh — Rotation
// ===========================================================================

#[tokio::test]
async fn test_refresh_token_rotation() {
    let (app, store, state) = setup().await;
    let (client_id, client_secret, _access_token, refresh_token, _cookie) =
        full_oauth_flow(&app, &*store, &state, "credentials:discover").await;

    // First refresh → success, get new refresh token
    let form = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret={}",
        urlencoding::encode(&refresh_token),
        urlencoding::encode(&client_id),
        urlencoding::encode(&client_secret),
    );
    let (status, body) = send_form(&app, "/api/v1/oauth/token", &form).await;
    assert_eq!(status, StatusCode::OK, "first refresh: {}", body);
    let new_refresh_token = body["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(new_refresh_token, refresh_token, "new refresh token should differ");

    // Try using old refresh token → should fail (revoked after rotation)
    let form_old = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret={}",
        urlencoding::encode(&refresh_token),
        urlencoding::encode(&client_id),
        urlencoding::encode(&client_secret),
    );
    let (status, body) = send_form(&app, "/api/v1/oauth/token", &form_old).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "old refresh token replay: {}", body);
}

// ===========================================================================
// A19. Token Refresh (Error Handling)
// ===========================================================================

#[tokio::test]
async fn test_refresh_invalid_token() {
    let (app, store, state) = setup().await;
    let (client_id, client_secret, _at, _rt, _cookie) =
        full_oauth_flow(&app, &*store, &state, "credentials:discover").await;

    let form = format!(
        "grant_type=refresh_token&refresh_token=totally-random-garbage&client_id={}&client_secret={}",
        urlencoding::encode(&client_id),
        urlencoding::encode(&client_secret),
    );
    let (status, body) = send_form(&app, "/api/v1/oauth/token", &form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {}", body);
}

#[tokio::test]
async fn test_refresh_wrong_client_id() {
    let (app, store, state) = setup().await;
    let (_client_id, _client_secret, _at, refresh_token, cookie) =
        full_oauth_flow(&app, &*store, &state, "credentials:discover").await;

    // Extract csrf from cookie
    let csrf = extract_csrf_from_cookie(&cookie).unwrap_or_default();

    // Register a second client
    let pk_hash2 = "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3";
    let (status, body2) = register_client(
        &app,
        &cookie,
        &csrf,
        "second-ws",
        pk_hash2,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body: {}", body2);
    let client_id_2 = body2["data"]["client_id"].as_str().unwrap().to_string();
    let client_secret_2 = body2["data"]["client_secret"].as_str().unwrap().to_string();

    // Try refresh with client B's credentials but client A's refresh token
    let form = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret={}",
        urlencoding::encode(&refresh_token),
        urlencoding::encode(&client_id_2),
        urlencoding::encode(&client_secret_2),
    );
    let (status, body) = send_form(&app, "/api/v1/oauth/token", &form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "wrong client: {}", body);
}

// ===========================================================================
// A21/A22. Token Validation on Resource Endpoints
// ===========================================================================

#[tokio::test]
async fn test_access_token_accepted_by_resource_endpoints() {
    let (app, store, state) = setup().await;

    // Create a workspace in the DB that matches the client's pk_hash
    let now = chrono::Utc::now();
    let workspace = agent_cordon_core::domain::workspace::Workspace {
        id: agent_cordon_core::domain::workspace::WorkspaceId(uuid::Uuid::new_v4()),
        name: "token-validation-ws".to_string(),
        enabled: true,
        status: agent_cordon_core::domain::workspace::WorkspaceStatus::Active,
        pk_hash: Some(TEST_PK_HASH.to_string()),
        encryption_public_key: None,
        tags: vec![],
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };
    store.create_workspace(&workspace).await.expect("create workspace");

    let (_client_id, _client_secret, access_token, _refresh_token, _cookie) =
        full_oauth_flow(&app, &*store, &state, "credentials:discover").await;

    // Use the access token as Bearer on a resource endpoint
    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/credentials",
        Some(&access_token),
        None,
        None,
        None,
    )
    .await;

    // Should be 200 (or at least not 401 — may be empty list)
    assert_ne!(status, StatusCode::UNAUTHORIZED, "token should be accepted: {} {}", status, body);
}

#[tokio::test]
async fn test_expired_access_token_rejected() {
    let (app, store, _state) = setup().await;
    let admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;

    // Create an OAuth client first (FK constraint)
    let now = chrono::Utc::now();
    let client = agent_cordon_core::oauth2::types::OAuthClient {
        id: uuid::Uuid::new_v4(),
        client_id: "ac_cli_expired".to_string(),
        client_secret_hash: None,
        workspace_name: "expired-ws".to_string(),
        public_key_hash: "e1e2e3e4e5e6e7e8e1e2e3e4e5e6e7e8e1e2e3e4e5e6e7e8e1e2e3e4e5e6e7e8".to_string(),
        redirect_uris: vec![TEST_REDIRECT_URI.to_string()],
        allowed_scopes: vec![OAuthScope::CredentialsDiscover],
        created_by_user: admin.id.clone(),
        created_at: now,
        revoked_at: None,
    };
    store.create_oauth_client(&client).await.expect("create client");

    // Now insert an expired access token
    let token_raw = "expired-test-token-12345678901234567890";
    let token_hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(token_raw.as_bytes()))
    };
    let expired_token = OAuthAccessToken {
        token_hash,
        client_id: "ac_cli_expired".to_string(),
        user_id: admin.id,
        scopes: vec![OAuthScope::CredentialsDiscover],
        created_at: now - chrono::Duration::hours(2),
        expires_at: now - chrono::Duration::hours(1), // expired 1 hour ago
        revoked_at: None,
    };
    store.create_oauth_access_token(&expired_token).await.expect("insert expired token");

    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/credentials",
        Some(token_raw),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "expired token should be rejected");
}

#[tokio::test]
async fn test_revoked_access_token_rejected() {
    let (app, store, _state) = setup().await;
    let admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;

    // Create an OAuth client first (FK constraint)
    let now = chrono::Utc::now();
    let client = agent_cordon_core::oauth2::types::OAuthClient {
        id: uuid::Uuid::new_v4(),
        client_id: "ac_cli_revoked".to_string(),
        client_secret_hash: None,
        workspace_name: "revoked-ws".to_string(),
        public_key_hash: "f1f2f3f4f5f6f7f8f1f2f3f4f5f6f7f8f1f2f3f4f5f6f7f8f1f2f3f4f5f6f7f8".to_string(),
        redirect_uris: vec![TEST_REDIRECT_URI.to_string()],
        allowed_scopes: vec![OAuthScope::CredentialsDiscover],
        created_by_user: admin.id.clone(),
        created_at: now,
        revoked_at: None,
    };
    store.create_oauth_client(&client).await.expect("create client");

    // Insert a revoked access token
    let token_raw = "revoked-test-token-12345678901234567890";
    let token_hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(token_raw.as_bytes()))
    };
    let revoked_token = OAuthAccessToken {
        token_hash,
        client_id: "ac_cli_revoked".to_string(),
        user_id: admin.id,
        scopes: vec![OAuthScope::CredentialsDiscover],
        created_at: now,
        expires_at: now + chrono::Duration::hours(1),
        revoked_at: Some(now), // explicitly revoked
    };
    store.create_oauth_access_token(&revoked_token).await.expect("insert revoked token");

    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/credentials",
        Some(token_raw),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "revoked token should be rejected");
}

// ===========================================================================
// A24. Scope Enforcement
// ===========================================================================

// Note: scope enforcement on resource endpoints depends on how endpoints check
// OAuthScope. We test the token endpoint's scope validation and the
// revocation endpoint here.

#[tokio::test]
async fn test_token_revocation_success() {
    let (app, store, state) = setup().await;
    let (_client_id, _client_secret, access_token, _refresh_token, _cookie) =
        full_oauth_flow(&app, &*store, &state, "credentials:discover").await;

    // Revoke the access token
    let form = format!(
        "token={}&token_type_hint=access_token",
        urlencoding::encode(&access_token),
    );
    let (status, body) = send_form(&app, "/api/v1/oauth/revoke", &form).await;
    assert_eq!(status, StatusCode::OK, "revoke: {}", body);
}

#[tokio::test]
async fn test_revoked_token_rejected_on_next_request() {
    let (app, store, state) = setup().await;

    // Create workspace in DB matching pk_hash
    let now = chrono::Utc::now();
    let workspace = agent_cordon_core::domain::workspace::Workspace {
        id: agent_cordon_core::domain::workspace::WorkspaceId(uuid::Uuid::new_v4()),
        name: "revoke-test-ws".to_string(),
        enabled: true,
        status: agent_cordon_core::domain::workspace::WorkspaceStatus::Active,
        pk_hash: Some(TEST_PK_HASH.to_string()),
        encryption_public_key: None,
        tags: vec![],
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };
    store.create_workspace(&workspace).await.expect("create workspace");

    let (_client_id, _client_secret, access_token, _refresh_token, _cookie) =
        full_oauth_flow(&app, &*store, &state, "credentials:discover").await;

    // Verify token works first
    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/credentials",
        Some(&access_token),
        None,
        None,
        None,
    )
    .await;
    assert_ne!(status, StatusCode::UNAUTHORIZED, "token should work before revocation");

    // Revoke
    let form = format!(
        "token={}&token_type_hint=access_token",
        urlencoding::encode(&access_token),
    );
    let (status, _) = send_form(&app, "/api/v1/oauth/revoke", &form).await;
    assert_eq!(status, StatusCode::OK);

    // Token should now be rejected
    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/credentials",
        Some(&access_token),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "revoked token should be rejected immediately");
}

// ===========================================================================
// Client Credentials Grant
// ===========================================================================

#[tokio::test]
async fn test_client_credentials_grant() {
    let (app, store, _state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "cc-ws",
        TEST_PK_HASH,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let client_id = body["data"]["client_id"].as_str().unwrap().to_string();
    let client_secret = body["data"]["client_secret"].as_str().unwrap().to_string();

    let form = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}&scope=credentials:discover",
        urlencoding::encode(&client_id),
        urlencoding::encode(&client_secret),
    );
    let (status, body) = send_form(&app, "/api/v1/oauth/token", &form).await;
    assert_eq!(status, StatusCode::OK, "client_credentials: {}", body);
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["access_token"].as_str().is_some());
    // client_credentials should not issue refresh token
    assert!(body["refresh_token"].is_null(), "no refresh token for client_credentials");
}

#[tokio::test]
async fn test_client_credentials_wrong_secret() {
    let (app, store, _state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "cc-bad-ws",
        TEST_PK_HASH,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let client_id = body["data"]["client_id"].as_str().unwrap().to_string();

    let form = format!(
        "grant_type=client_credentials&client_id={}&client_secret=wrong-secret",
        urlencoding::encode(&client_id),
    );
    let (status, body) = send_form(&app, "/api/v1/oauth/token", &form).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {}", body);
}

// ===========================================================================
// Client Revocation (Admin)
// ===========================================================================

#[tokio::test]
async fn test_admin_revoke_client() {
    let (app, store, _state) = setup().await;
    // list_clients and revoke_client require is_root
    let _admin = create_user_in_db(&*store, "admin", TEST_PASSWORD, UserRole::Admin, true, true).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "to-revoke-ws",
        TEST_PK_HASH,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let client_id = body["data"]["client_id"].as_str().unwrap().to_string();

    // List clients to get the internal UUID
    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/oauth/clients",
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let clients = body["data"].as_array().unwrap();
    let client = clients
        .iter()
        .find(|c| c["client_id"] == client_id)
        .expect("find registered client");
    let internal_id = client["id"].as_str().unwrap();

    // Delete the client
    let uri = format!("/api/v1/oauth/clients/{}", internal_id);
    let (status, body) = send_json(
        &app,
        Method::DELETE,
        &uri,
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke client: {}", body);
}

// ===========================================================================
// PKCE Validation (D4)
// ===========================================================================

#[tokio::test]
async fn test_pkce_prevents_code_interception() {
    let (app, store, state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "pkce-intercept-ws",
        TEST_PK_HASH,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let client_id = body["data"]["client_id"].as_str().unwrap().to_string();
    let client_secret = body["data"]["client_secret"].as_str().unwrap().to_string();

    let (_verifier, challenge) = generate_pkce();
    let consent_csrf = compute_consent_csrf(&cookie, &state.session_hash_key);

    // Get a code
    let form = format!(
        "client_id={}&redirect_uri={}&scope=credentials:discover&state=s&code_challenge={}&code_challenge_method=S256&decision=approve&csrf_token={}",
        urlencoding::encode(&client_id),
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
        urlencoding::encode(&consent_csrf),
    );
    let (_status, _body, headers) = post_consent(&app, &cookie, &form).await;
    let location = headers.iter().find(|(k, _)| k == "location").unwrap().1.clone();
    let parsed = url::Url::parse(&format!("http://localhost{}", location))
        .or_else(|_| url::Url::parse(&location))
        .expect("parse");
    let code = parsed.query_pairs().find(|(k, _)| k == "code").unwrap().1.to_string();

    // Attacker intercepts code but doesn't have verifier — exchange without it
    let form = format!(
        "grant_type=authorization_code&code={}&client_id={}&client_secret={}&redirect_uri={}",
        urlencoding::encode(&code),
        urlencoding::encode(&client_id),
        urlencoding::encode(&client_secret),
        urlencoding::encode(TEST_REDIRECT_URI),
    );
    let (status, body) = send_form(&app, "/api/v1/oauth/token", &form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "code without verifier: {}", body);
}

// ===========================================================================
// Refresh token revocation cascades
// ===========================================================================

#[tokio::test]
async fn test_refresh_token_revocation_cascades_to_access_token() {
    let (app, store, state) = setup().await;

    // Create workspace matching pk_hash
    let now = chrono::Utc::now();
    let workspace = agent_cordon_core::domain::workspace::Workspace {
        id: agent_cordon_core::domain::workspace::WorkspaceId(uuid::Uuid::new_v4()),
        name: "cascade-ws".to_string(),
        enabled: true,
        status: agent_cordon_core::domain::workspace::WorkspaceStatus::Active,
        pk_hash: Some(TEST_PK_HASH.to_string()),
        encryption_public_key: None,
        tags: vec![],
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };
    store.create_workspace(&workspace).await.expect("create workspace");

    let (_client_id, _client_secret, access_token, refresh_token, _cookie) =
        full_oauth_flow(&app, &*store, &state, "credentials:discover").await;

    // Revoke the refresh token
    let form = format!(
        "token={}&token_type_hint=refresh_token",
        urlencoding::encode(&refresh_token),
    );
    let (status, _) = send_form(&app, "/api/v1/oauth/revoke", &form).await;
    assert_eq!(status, StatusCode::OK);

    // The associated access token should also be revoked
    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/credentials",
        Some(&access_token),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "access token should be revoked when refresh token is revoked"
    );
}

// ===========================================================================
// Consent-Based Workspace Creation (new workspace via consent flow)
// ===========================================================================

const TEST_PK_HASH_2: &str = "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3";

#[tokio::test]
async fn test_consent_new_workspace_renders_consent_page() {
    let (app, store, _state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, _csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (_verifier, challenge) = generate_pkce();

    let query = format!(
        "response_type=code&workspace_name=new-ws&public_key_hash={}&redirect_uri={}&scope=credentials:discover&state=xyz&code_challenge={}&code_challenge_method=S256",
        TEST_PK_HASH_2,
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
    );
    let (status, body, _headers) = get_authorize(&app, &cookie, &query).await;
    assert_eq!(status, StatusCode::OK, "body: {}", body);
    assert!(body.contains("new-ws"), "consent page should show workspace name");
    assert!(body.contains("Create"), "consent page should say Create for new workspace");
    assert!(body.contains(TEST_PK_HASH_2), "consent page should include public_key_hash in hidden field");
}

#[tokio::test]
async fn test_consent_new_workspace_approve_creates_client_and_issues_code() {
    let (app, store, state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, _csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (_verifier, challenge) = generate_pkce();
    let consent_csrf = compute_consent_csrf(&cookie, &state.session_hash_key);

    let form = format!(
        "client_id=&redirect_uri={}&scope=credentials:discover&state=new-ws-state&code_challenge={}&code_challenge_method=S256&decision=approve&csrf_token={}&public_key_hash={}&workspace_name=consent-created-ws&is_new_workspace=true",
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
        urlencoding::encode(&consent_csrf),
        TEST_PK_HASH_2,
    );
    let (status, _body, headers) = post_consent(&app, &cookie, &form).await;
    assert!(
        status == StatusCode::FOUND || status == StatusCode::SEE_OTHER,
        "expected redirect, got: {} {}",
        status,
        _body
    );

    let location = headers
        .iter()
        .find(|(k, _)| k == "location")
        .expect("Location header")
        .1
        .clone();

    let parsed = url::Url::parse(&format!("http://localhost{}", location))
        .or_else(|_| url::Url::parse(&location))
        .expect("parse redirect");
    let params: std::collections::HashMap<_, _> = parsed.query_pairs().collect();
    assert!(params.contains_key("code"), "code param missing: {}", location);
    assert_eq!(params.get("state").map(|s| s.as_ref()), Some("new-ws-state"));
    // New workspace flow includes client_id in callback
    assert!(params.contains_key("client_id"), "client_id param missing in callback: {}", location);
    let client_id = params.get("client_id").unwrap().to_string();
    assert!(client_id.starts_with("ac_cli_"), "client_id should have expected prefix: {}", client_id);
}

#[tokio::test]
async fn test_consent_new_workspace_full_token_exchange() {
    let (app, store, state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, _csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let pk_hash = "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
    let (verifier, challenge) = generate_pkce();
    let consent_csrf = compute_consent_csrf(&cookie, &state.session_hash_key);

    // Approve consent for new workspace
    let form = format!(
        "client_id=&redirect_uri={}&scope=credentials:discover&state=full-flow-state&code_challenge={}&code_challenge_method=S256&decision=approve&csrf_token={}&public_key_hash={}&workspace_name=full-flow-ws&is_new_workspace=true",
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
        urlencoding::encode(&consent_csrf),
        pk_hash,
    );
    let (status, _body, headers) = post_consent(&app, &cookie, &form).await;
    assert!(
        status == StatusCode::FOUND || status == StatusCode::SEE_OTHER,
        "expected redirect, got: {} {}",
        status,
        _body
    );

    let location = headers
        .iter()
        .find(|(k, _)| k == "location")
        .expect("Location header")
        .1
        .clone();

    let parsed = url::Url::parse(&format!("http://localhost{}", location))
        .or_else(|_| url::Url::parse(&location))
        .expect("parse redirect");
    let params: std::collections::HashMap<_, _> = parsed.query_pairs().collect();
    let code = params.get("code").expect("code param missing").to_string();
    let client_id = params.get("client_id").expect("client_id param missing").to_string();

    // Exchange code for tokens
    let token_form = format!(
        "grant_type=authorization_code&code={}&client_id={}&redirect_uri={}&code_verifier={}",
        urlencoding::encode(&code),
        urlencoding::encode(&client_id),
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&verifier),
    );
    let (status, body) = send_form(&app, "/api/v1/oauth/token", &token_form).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {}", body);
    assert!(body["access_token"].is_string(), "should have access_token");
    assert!(body["refresh_token"].is_string(), "should have refresh_token");
}

#[tokio::test]
async fn test_consent_new_workspace_deny() {
    let (app, store, state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, _csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (_verifier, challenge) = generate_pkce();
    let consent_csrf = compute_consent_csrf(&cookie, &state.session_hash_key);
    let pk_hash = "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5";

    let form = format!(
        "client_id=&redirect_uri={}&scope=credentials:discover&state=deny-state&code_challenge={}&code_challenge_method=S256&decision=deny&csrf_token={}&public_key_hash={}&workspace_name=deny-ws&is_new_workspace=true",
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
        urlencoding::encode(&consent_csrf),
        pk_hash,
    );
    let (status, _body, headers) = post_consent(&app, &cookie, &form).await;
    assert!(
        status == StatusCode::FOUND || status == StatusCode::SEE_OTHER,
        "expected redirect, got: {} {}",
        status,
        _body
    );

    let location = headers
        .iter()
        .find(|(k, _)| k == "location")
        .expect("Location header")
        .1
        .clone();
    assert!(location.contains("error=access_denied"), "should contain error: {}", location);
    // No client should have been created
    assert!(!location.contains("client_id="), "no client_id on deny: {}", location);
}

#[tokio::test]
async fn test_consent_missing_both_client_id_and_pk_hash() {
    let (app, store, _state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, _csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (_verifier, challenge) = generate_pkce();

    // No client_id and no public_key_hash
    let query = format!(
        "response_type=code&redirect_uri={}&scope=credentials:discover&state=xyz&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
    );
    let (status, _body, _headers) = get_authorize(&app, &cookie, &query).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_consent_existing_client_still_works() {
    let (app, store, state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let pk_hash = "e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6";

    // Register client normally
    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "existing-client-ws",
        pk_hash,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let client_id = body["data"]["client_id"].as_str().unwrap();
    let client_secret = body["data"]["client_secret"].as_str().unwrap();

    let (verifier, challenge) = generate_pkce();
    let consent_csrf = compute_consent_csrf(&cookie, &state.session_hash_key);

    // Approve with existing client_id (backward compat path)
    let form = format!(
        "client_id={}&redirect_uri={}&scope=credentials:discover&state=compat-state&code_challenge={}&code_challenge_method=S256&decision=approve&csrf_token={}",
        urlencoding::encode(client_id),
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
        urlencoding::encode(&consent_csrf),
    );
    let (status, _body, headers) = post_consent(&app, &cookie, &form).await;
    assert!(
        status == StatusCode::FOUND || status == StatusCode::SEE_OTHER,
        "expected redirect, got: {} {}",
        status,
        _body
    );

    let location = headers
        .iter()
        .find(|(k, _)| k == "location")
        .expect("Location header")
        .1
        .clone();

    let parsed = url::Url::parse(&format!("http://localhost{}", location))
        .or_else(|_| url::Url::parse(&location))
        .expect("parse redirect");
    let params: std::collections::HashMap<_, _> = parsed.query_pairs().collect();
    assert!(params.contains_key("code"), "code param missing");
    // Existing client flow should NOT include client_id in callback
    assert!(!params.contains_key("client_id"), "existing client flow should not include client_id");

    // Exchange code for tokens (existing client requires client_secret)
    let code = params.get("code").unwrap().to_string();
    let token_form = format!(
        "grant_type=authorization_code&code={}&client_id={}&client_secret={}&redirect_uri={}&code_verifier={}",
        urlencoding::encode(&code),
        urlencoding::encode(client_id),
        urlencoding::encode(client_secret),
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&verifier),
    );
    let (status, body) = send_form(&app, "/api/v1/oauth/token", &token_form).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {}", body);
    assert!(body["access_token"].is_string());
}
