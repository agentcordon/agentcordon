//! Cross-cutting security tests for v3.0.0 OAuth architecture.
//!
//! Tests cover:
//! - PKCE security (D4)
//! - Token revocation enforcement (D2)
//! - Privilege escalation prevention (D5)
//! - Token binding (D6)
//! - Old auth token rejection (A23)

use crate::common::*;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::oauth2::types::{OAuthAccessToken, OAuthScope};
use agent_cordon_core::storage::Store;

use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Test helpers (mirrored from v300_oauth_as for self-containment)
// ---------------------------------------------------------------------------

async fn setup() -> (
    Router,
    Arc<dyn Store + Send + Sync>,
    agent_cordon_server::state::AppState,
) {
    let ctx = TestAppBuilder::new().with_enrollment().build().await;
    (ctx.app, ctx.store, ctx.state)
}

async fn login(app: &Router, username: &str, password: &str) -> (String, String) {
    let (session, csrf) = login_user(app, username, password).await;
    (combined_cookie(&session, &csrf), csrf)
}

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

async fn post_consent(
    app: &Router,
    cookie: &str,
    form_body: &str,
) -> (StatusCode, String, Vec<(String, String)>) {
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

fn generate_pkce() -> (String, String) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());
    (verifier.to_string(), challenge)
}

const TEST_PK_HASH: &str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
const TEST_REDIRECT_URI: &str = "http://localhost:9876/callback";

/// Full OAuth flow → returns (client_id, client_secret, access_token, refresh_token, cookie).
async fn full_oauth_flow(
    app: &Router,
    store: &(dyn Store + Send + Sync),
    state: &agent_cordon_server::state::AppState,
    scopes_str: &str,
) -> (String, String, String, String, String) {
    let _admin = create_test_user(store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(app, "admin", TEST_PASSWORD).await;

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

    let (verifier, challenge) = generate_pkce();
    let consent_csrf = compute_consent_csrf(&cookie, &state.session_hash_key);

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
        "consent: {}",
        status
    );

    let location = headers
        .iter()
        .find(|(k, _)| k == "location")
        .unwrap()
        .1
        .clone();
    let code = url::Url::parse(&format!("http://localhost{}", location))
        .or_else(|_| url::Url::parse(&location))
        .expect("parse redirect URL")
        .query_pairs()
        .find(|(k, _)| k == "code")
        .expect("code param")
        .1
        .to_string();

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
// D2. OAuth Token Security — Revoked token denied immediately
// ===========================================================================

#[tokio::test]
async fn test_revoked_oauth_token_denied_immediately() {
    let (app, store, state) = setup().await;

    // Create workspace matching pk_hash so token validation can find it
    let now = chrono::Utc::now();
    let workspace = agent_cordon_core::domain::workspace::Workspace {
        id: agent_cordon_core::domain::workspace::WorkspaceId(uuid::Uuid::new_v4()),
        name: "revoke-immediate-ws".to_string(),
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

    // Verify token works
    let (status, _) = send_json(
        &app,
        Method::GET,
        "/api/v1/credentials",
        Some(&access_token),
        None,
        None,
        None,
    )
    .await;
    assert_ne!(status, StatusCode::UNAUTHORIZED);

    // Revoke via API
    let form = format!(
        "token={}&token_type_hint=access_token",
        urlencoding::encode(&access_token),
    );
    let (status, _) = send_form(&app, "/api/v1/oauth/revoke", &form).await;
    assert_eq!(status, StatusCode::OK);

    // Immediately try again — must be 401
    let (status, _) = send_json(
        &app,
        Method::GET,
        "/api/v1/credentials",
        Some(&access_token),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "revoked token must be rejected immediately");
}

// ===========================================================================
// D4. PKCE Security
// ===========================================================================

#[tokio::test]
async fn test_pkce_wrong_verifier_rejected() {
    let (app, store, state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "pkce-wrong-ws",
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
    let code = url::Url::parse(&format!("http://localhost{}", location))
        .or_else(|_| url::Url::parse(&location))
        .expect("parse")
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .to_string();

    // Exchange with WRONG verifier
    let form = format!(
        "grant_type=authorization_code&code={}&client_id={}&client_secret={}&redirect_uri={}&code_verifier=totally-wrong-verifier-that-wont-match",
        urlencoding::encode(&code),
        urlencoding::encode(&client_id),
        urlencoding::encode(&client_secret),
        urlencoding::encode(TEST_REDIRECT_URI),
    );
    let (status, body) = send_form(&app, "/api/v1/oauth/token", &form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "wrong verifier: {}", body);
    assert!(
        body["error_description"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("pkce")
            || body["error"].as_str().unwrap_or("") == "invalid_grant",
        "error should indicate PKCE failure: {}",
        body
    );
}

// ===========================================================================
// D5. Privilege Escalation Prevention
// ===========================================================================

#[tokio::test]
async fn test_workspace_cannot_escalate_scopes_via_refresh() {
    let (app, store, state) = setup().await;
    let (client_id, client_secret, _at, refresh_token, _cookie) =
        full_oauth_flow(&app, &*store, &state, "credentials:discover").await;

    // Try to refresh with a wider scope
    let form = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret={}&scope=credentials:discover%20credentials:vend",
        urlencoding::encode(&refresh_token),
        urlencoding::encode(&client_id),
        urlencoding::encode(&client_secret),
    );
    let (status, body) = send_form(&app, "/api/v1/oauth/token", &form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "scope escalation: {}", body);
    assert!(
        body["error"].as_str().unwrap_or("") == "invalid_scope",
        "should be invalid_scope: {}",
        body
    );
}

// ===========================================================================
// D6. Token Binding
// ===========================================================================

#[tokio::test]
async fn test_refresh_token_bound_to_client_id() {
    let (app, store, state) = setup().await;
    let (_client_id_a, _secret_a, _at, refresh_token_a, cookie) =
        full_oauth_flow(&app, &*store, &state, "credentials:discover").await;

    let csrf = extract_csrf_from_cookie(&cookie).unwrap_or_default();

    // Register a second client
    let pk_hash_b = "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
    let (status, body) = register_client(
        &app,
        &cookie,
        &csrf,
        "binding-ws-b",
        pk_hash_b,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let client_id_b = body["data"]["client_id"].as_str().unwrap().to_string();
    let client_secret_b = body["data"]["client_secret"].as_str().unwrap().to_string();

    // Try to use client A's refresh token with client B's credentials
    let form = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret={}",
        urlencoding::encode(&refresh_token_a),
        urlencoding::encode(&client_id_b),
        urlencoding::encode(&client_secret_b),
    );
    let (status, body) = send_form(&app, "/api/v1/oauth/token", &form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "cross-client refresh: {}", body);
}

// ===========================================================================
// A23.1 — Old workspace JWT rejected (inverted: must REJECT)
// ===========================================================================

#[tokio::test]
async fn test_old_workspace_jwt_rejected_on_resource_endpoint() {
    let (app, store, state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;

    // Create a workspace
    let (agent, _key) = create_agent_in_db(&*store, "old-jwt-ws", vec!["admin"], true, None).await;

    // Issue a v2-style workspace identity JWT (manually, not via issue_agent_jwt which now creates OAuth tokens)
    let now = chrono::Utc::now();
    let claims = serde_json::json!({
        "sub": agent.id.0.to_string(),
        "aud": "agentcordon:workspace-identity",
        "iss": agent_cordon_core::auth::jwt::ISSUER,
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
        "wkt": "test-workspace-key-thumbprint",
    });
    let old_jwt = state
        .jwt_issuer
        .sign_custom_claims(&claims)
        .expect("issue test JWT");

    // Try using this old JWT as Bearer on the credentials endpoint
    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/credentials",
        Some(&old_jwt),
        None,
        None,
        None,
    )
    .await;
    // The OAuth extractor should reject this because the JWT's hash won't match any
    // stored OAuth access token
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "old workspace JWT should be rejected by OAuth extractor"
    );
}

// ===========================================================================
// A23.4 — Only OAuth access token audience accepted
// ===========================================================================

#[tokio::test]
async fn test_forged_jwt_wrong_audience_rejected() {
    let (app, _store, state) = setup().await;

    // Create a JWT with wrong audience (e.g., "workspace-identity")
    let now = chrono::Utc::now();
    let claims = json!({
        "sub": uuid::Uuid::new_v4().to_string(),
        "aud": "workspace-identity",
        "iss": agent_cordon_core::auth::jwt::ISSUER,
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let jwt = state.jwt_issuer.sign_custom_claims(&claims).expect("sign JWT");

    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/credentials",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "JWT with wrong audience should be rejected"
    );
}

// ===========================================================================
// No bearer token → 401
// ===========================================================================

#[tokio::test]
async fn test_no_bearer_token_rejected() {
    let (app, _store, _state) = setup().await;

    // Request to resource endpoint without any Authorization header
    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/credentials",
        None, // no bearer
        None,
        None,
        None,
    )
    .await;
    // Should be 401 (or possibly require a different auth form — but not 200)
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "no auth should be rejected: {}",
        status
    );
}

// ===========================================================================
// Random string as bearer → 401
// ===========================================================================

#[tokio::test]
async fn test_random_bearer_token_rejected() {
    let (app, _store, _state) = setup().await;

    let (status, _body) = send_json(
        &app,
        Method::GET,
        "/api/v1/credentials",
        Some("this-is-not-a-valid-token-at-all"),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "random token should be rejected");
}

// ===========================================================================
// Disabled workspace → rejected even with valid token
// ===========================================================================

#[tokio::test]
async fn test_token_for_disabled_workspace_rejected() {
    let (app, store, _state) = setup().await;

    // Create and insert a workspace that matches a token, but disabled
    let now = chrono::Utc::now();
    let pk_hash = "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5";
    let workspace = agent_cordon_core::domain::workspace::Workspace {
        id: agent_cordon_core::domain::workspace::WorkspaceId(uuid::Uuid::new_v4()),
        name: "disabled-ws".to_string(),
        enabled: false, // disabled
        status: agent_cordon_core::domain::workspace::WorkspaceStatus::Active,
        pk_hash: Some(pk_hash.to_string()),
        encryption_public_key: None,
        tags: vec![],
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };
    store.create_workspace(&workspace).await.expect("create workspace");

    // Create an OAuth client for this pk_hash
    let admin = create_test_user(&*store, "admin-dis", TEST_PASSWORD, UserRole::Admin).await;
    let client = agent_cordon_core::oauth2::types::OAuthClient {
        id: uuid::Uuid::new_v4(),
        client_id: "ac_cli_disabled123".to_string(),
        client_secret_hash: None,
        workspace_name: "disabled-ws".to_string(),
        public_key_hash: pk_hash.to_string(),
        redirect_uris: vec![TEST_REDIRECT_URI.to_string()],
        allowed_scopes: vec![OAuthScope::CredentialsDiscover],
        created_by_user: admin.id.clone(),
        created_at: now,
        revoked_at: None,
    };
    store.create_oauth_client(&client).await.expect("create client");

    // Create an access token pointing to this client
    let token_raw = "disabled-ws-token-1234567890abcdef";
    let token_hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(token_raw.as_bytes()))
    };
    let access_token = OAuthAccessToken {
        token_hash,
        client_id: "ac_cli_disabled123".to_string(),
        user_id: admin.id,
        scopes: vec![OAuthScope::CredentialsDiscover],
        created_at: now,
        expires_at: now + chrono::Duration::hours(1),
        revoked_at: None,
    };
    store.create_oauth_access_token(&access_token).await.expect("create token");

    // Try using the token
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
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "disabled workspace should be rejected"
    );
}

// ===========================================================================
// Auth code bound to client
// ===========================================================================

#[tokio::test]
async fn test_auth_code_bound_to_client() {
    let (app, store, state) = setup().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&app, "admin", TEST_PASSWORD).await;

    // Register client A
    let (status, body_a) = register_client(
        &app,
        &cookie,
        &csrf,
        "client-a-ws",
        TEST_PK_HASH,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let client_id_a = body_a["data"]["client_id"].as_str().unwrap().to_string();
    let _client_secret_a = body_a["data"]["client_secret"].as_str().unwrap().to_string();

    // Register client B
    let pk_hash_b = "e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6";
    let (status, body_b) = register_client(
        &app,
        &cookie,
        &csrf,
        "client-b-ws",
        pk_hash_b,
        &["credentials:discover"],
        &[TEST_REDIRECT_URI],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let client_id_b = body_b["data"]["client_id"].as_str().unwrap().to_string();
    let client_secret_b = body_b["data"]["client_secret"].as_str().unwrap().to_string();

    // Get a code for client A
    let (verifier, challenge) = generate_pkce();
    let consent_csrf = compute_consent_csrf(&cookie, &state.session_hash_key);
    let form = format!(
        "client_id={}&redirect_uri={}&scope=credentials:discover&state=s&code_challenge={}&code_challenge_method=S256&decision=approve&csrf_token={}",
        urlencoding::encode(&client_id_a),
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
        urlencoding::encode(&consent_csrf),
    );
    let (_status, _body, headers) = post_consent(&app, &cookie, &form).await;
    let location = headers.iter().find(|(k, _)| k == "location").unwrap().1.clone();
    let code = url::Url::parse(&format!("http://localhost{}", location))
        .or_else(|_| url::Url::parse(&location))
        .expect("parse")
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .to_string();

    // Try exchanging client A's code with client B's credentials
    let form = format!(
        "grant_type=authorization_code&code={}&client_id={}&client_secret={}&redirect_uri={}&code_verifier={}",
        urlencoding::encode(&code),
        urlencoding::encode(&client_id_b),
        urlencoding::encode(&client_secret_b),
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&verifier),
    );
    let (status, body) = send_form(&app, "/api/v1/oauth/token", &form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "cross-client code: {}", body);
}
