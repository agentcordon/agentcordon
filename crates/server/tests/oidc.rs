//! Comprehensive integration tests for OIDC (OpenID Connect) functionality.
//!
//! Tests cover:
//! 1. OIDC Provider CRUD (create, list, get, update, delete)
//! 2. Provider admin-only enforcement (non-admin denied)
//! 3. Public providers endpoint (unauthenticated, returns only enabled)
//! 4. Full authorization code flow with mock IdP
//! 5. Callback error handling (IdP error, missing code/state, expired state, replay)
//! 6. User provisioning (auto-create, existing user, disabled user, auto_provision=false)
//! 7. Claim mapping (sub, email, preferred_username)
//! 8. Role mapping (default_role)
//! 9. Session cookie creation on OIDC login
//! 10. Audit events (OidcLoginSuccess, OidcLoginFailed, OidcProviderCreated, etc.)
//! 11. Issuer URL validation
//! 12. Input validation for provider fields

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;
use wiremock::matchers::{method as wm_method, path as wm_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use agent_cordon_core::crypto::aes_gcm::AesGcmEncryptor;
use agent_cordon_core::crypto::password::hash_password;
use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::oidc::{OidcAuthState, OidcProviderId};
use agent_cordon_core::domain::user::{User, UserId, UserRole};
use agent_cordon_core::storage::Store;

use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Test RSA key pair (2048-bit, generated for testing only — NOT a real secret)
// ---------------------------------------------------------------------------

const TEST_RSA_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDNfbw4WKi+Y9cD
LbYmCqHY1dqCld4vKU5NCkG6Ljcd6Y8vc9tLWtjJZ59ov0iylDRWKWXvWAlW/0Jo
6FVBA9xu45UDq+g2lcMz/QRjM+Rkt89e/SEzqPxToP06imklpMbSsBVGNdg37mL0
1XBZ8mVWUcPUyG9fmkmZ1qmxBck3PSHcqRKWVb9ctVKhQxilKftOSoTJNjTaZ6Pa
wQvWSUwyW77f88qmtFsIqaZjZVrRNQYWgqxVxs8KoB7hwQnnd9pVcxZTZ+TAU0g3
P0k5b9tEQqgCuqksKRYPsfJHzX5qV8v5k4BPcCpJ+E7HNK1vN1A11HYV23fn65x1
SD+GELwnAgMBAAECggEACGs3U+Ol/i7e9z1fMg3LdbPFQQZc1PfPQm7CJJuSHIKe
ICaR/HNbYF0DdeooU1CpGEKX74de0pagpOWn4IME+/IM/9qCKAJYvf+Gt32/xLSX
JWAfhRtOQyrcVRKoniczEhyusnKwShJVMYyxDq5UooW1DTms/nC2xTu7NgpzpPSk
Wbg6bn/FLr0fLWJQ/irQzivKOvVeUzUvZNFXh20Vl2ZjRE4/LxdkSHv3hDVx7UBR
iRvB/LArJzNty55+4vwR9hMRDZsewuCHu4R7fdJtOJ8bZZDM3WAbjr3w0VBujQmT
inn0ek8qv47uCRAmLspby8nhKrYpfEXr5hanHPCT6QKBgQD6cg89us/VZRXcjs2N
Lh+tOe1dSaAF6gAJ2UnuJlelZMzRo7irDmoECBVhL4JnJzKVkHXcWHyy9Q7Duiyg
Zo0aIooeJZ/1TQh7h/JdeJYIgJ7gMR8FMHpFV6UJWq5su+zS4gjJqopjMmQOmPg3
O7ihxE1aLyy8oJ0lpuYfOvxRKwKBgQDSDHDRpEykaaA7YxLTyQ4GqvOR1Nzm5id5
BCj+6cJ0Uc2ZjVH1nG4/wAHSM1Fxc9SZYr6e8JgFc87ah8EtAmYhuPY1zXdt+Qhh
tCR+daHBsWXODCF2lRhF0PuxyvbYt0XUMEi9SwWFndrYKRHqJVUOJ8MVviE4td4J
WYigSNIq9QKBgQD0PFdws8YLLVFsjjcW/2wU2vEIkMxl+BWhhS37+ZhvyyWTLD7j
UmNBG0D+Tf616hwCj6bhA8pYG3QSnHT42Amy+wwG6lpcNouXLLTHQtnN4OEPcdf2
j5guF5Ly1GRV1c7WuWgogxACPRomwjcOZkdgOrfUwzy1l0ypc2HoAvYdkQKBgQDR
aFe9mZhTPX7iVgZ6H/Kc0SfdVqMYi5IEwxH/+ZrEjp10HYD9ZYRAiDMIleL3QaxN
czVpjaFxpiAum7MKJV8e9aB4ySvs9p7VkVvku2+VhD9jqZJe/4tgZ1XWzetE6Ypz
XePW3AlYSaTZZjCXB7sBTsDeV1wVhrMjDSD58z+cVQKBgQCQVO3AsqOD243HFmTi
0WMOzcZVi8L9FNC6W6h64dSY/Y7RDrv97+b6Aav/eigfKPQ9mwXZC7GMWp9RQNqU
k/9chFYvvSksmG/ytnSX0vTeMqPD8YgkuOoSULbusYDpISbCKi793fw/5PTel+cH
9pk7jVVzHpnvrFx1vql8vS5KsA==
-----END PRIVATE KEY-----"#;

// RSA modulus (n) in base64url — extracted from the above public key
const TEST_RSA_N: &str = "zX28OFiovmPXAy22Jgqh2NXagpXeLylOTQpBui43HemPL3PbS1rYyWefaL9IspQ0Vill71gJVv9CaOhVQQPcbuOVA6voNpXDM_0EYzPkZLfPXv0hM6j8U6D9OoppJaTG0rAVRjXYN-5i9NVwWfJlVlHD1MhvX5pJmdapsQXJNz0h3KkSllW_XLVSoUMYpSn7TkqEyTY02mej2sEL1klMMlu-3_PKprRbCKmmY2Va0TUGFoKsVcbPCqAe4cEJ53faVXMWU2fkwFNINz9JOW_bREKoArqpLCkWD7HyR81-alfL-ZOAT3AqSfhOxzStbzdQNdR2Fdt35-ucdUg_hhC8Jw";

// RSA exponent (e) in base64url — standard 65537
const TEST_RSA_E: &str = "AQAB";

const TEST_KID: &str = "test-key-1";

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const TEST_PASSWORD: &str = "strong-password-123!";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

async fn setup_test_app() -> (Router, Arc<dyn Store + Send + Sync>, Arc<AesGcmEncryptor>) {
    setup_test_app_with_config(None).await
}

async fn setup_test_app_with_config(
    base_url: Option<String>,
) -> (Router, Arc<dyn Store + Send + Sync>, Arc<AesGcmEncryptor>) {
    let ctx = TestAppBuilder::new()
        .with_config(move |c| {
            c.base_url = base_url;
            c.oidc_state_ttl_seconds = 600;
        })
        .build()
        .await;
    (ctx.app, ctx.store, ctx.encryptor)
}

async fn create_admin_user(store: &(dyn Store + Send + Sync)) -> User {
    create_user_in_db(
        store,
        "admin-user",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await
}

async fn create_viewer_user(store: &(dyn Store + Send + Sync)) -> User {
    create_user_in_db(
        store,
        "viewer-user",
        TEST_PASSWORD,
        UserRole::Viewer,
        false,
        true,
    )
    .await
}

async fn create_user_in_db(
    store: &(dyn Store + Send + Sync),
    username: &str,
    password: &str,
    role: UserRole,
    is_root: bool,
    enabled: bool,
) -> User {
    let password_hash = hash_password(password).expect("hash password");
    let now = chrono::Utc::now();
    let user = User {
        id: UserId(Uuid::new_v4()),
        username: username.to_string(),
        display_name: Some(format!("Test {}", username)),
        password_hash,
        role,
        is_root,
        enabled,
        created_at: now,
        updated_at: now,
    };
    store.create_user(&user).await.expect("create user");
    user
}

/// Login a user and return the combined cookie string (session + CSRF).
async fn login_user(app: &Router, username: &str, password: &str) -> String {
    let (status, _body, headers) = send_request_with_headers(
        app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({ "username": username, "password": password })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "login failed for user '{}'",
        username,
    );

    let mut cookie_parts = Vec::new();
    for (name, value) in &headers {
        if name == "set-cookie" {
            if let Some(nv) = value.split(';').next() {
                cookie_parts.push(nv.trim().to_string());
            }
        }
    }
    assert!(
        cookie_parts
            .iter()
            .any(|c| c.starts_with("agtcrdn_session=")),
        "login must set session cookie"
    );

    cookie_parts.join("; ")
}

fn extract_csrf_from_cookie(cookie: &str) -> Option<String> {
    for pair in cookie.split(';') {
        let pair = pair.trim();
        if let Some(val) = pair.strip_prefix("agtcrdn_csrf=") {
            return Some(val.to_string());
        }
    }
    None
}

/// Send a request and return (status, body_json, headers).
async fn send_request_with_headers(
    app: &Router,
    method: Method,
    uri: &str,
    bearer: Option<&str>,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value, Vec<(String, String)>) {
    let mut builder = Request::builder().method(method.clone()).uri(uri);

    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {}", token));
    }

    if let Some(cookie_val) = cookie {
        builder = builder.header(header::COOKIE, cookie_val);

        let is_state_changing = method == Method::POST
            || method == Method::PUT
            || method == Method::DELETE
            || method == Method::PATCH;
        if is_state_changing {
            if let Some(csrf) = extract_csrf_from_cookie(cookie_val) {
                builder = builder.header("x-csrf-token", csrf);
            }
        }
    }

    let body = match body {
        Some(v) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&v).unwrap())
        }
        None => Body::empty(),
    };

    let request = builder.body(body).unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();

    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));
    (status, json, headers)
}

/// Convenience: send a JSON request without headers.
async fn send_json(
    app: &Router,
    method: Method,
    uri: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let (status, json, _headers) =
        send_request_with_headers(app, method, uri, None, cookie, body).await;
    (status, json)
}

/// Create an OIDC provider via the API.
async fn create_provider_via_api(
    app: &Router,
    cookie: &str,
    name: &str,
    issuer_url: &str,
    client_id: &str,
    client_secret: &str,
) -> (StatusCode, Value) {
    send_json(
        app,
        Method::POST,
        "/api/v1/oidc-providers",
        Some(cookie),
        Some(json!({
            "name": name,
            "issuer_url": issuer_url,
            "client_id": client_id,
            "client_secret": client_secret,
        })),
    )
    .await
}

/// Build a JWKS JSON response for the mock IdP.
fn build_jwks_response() -> Value {
    json!({
        "keys": [{
            "kty": "RSA",
            "kid": TEST_KID,
            "use": "sig",
            "alg": "RS256",
            "n": TEST_RSA_N,
            "e": TEST_RSA_E,
        }]
    })
}

/// Build a signed ID token JWT for the mock IdP.
#[allow(clippy::too_many_arguments)]
fn build_id_token(
    issuer: &str,
    client_id: &str,
    nonce: &str,
    sub: &str,
    email: Option<&str>,
    preferred_username: Option<&str>,
    name: Option<&str>,
    exp_offset_secs: i64,
) -> String {
    let now = chrono::Utc::now().timestamp() as u64;
    let exp = if exp_offset_secs >= 0 {
        now + exp_offset_secs as u64
    } else {
        now.saturating_sub((-exp_offset_secs) as u64)
    };

    let mut claims = json!({
        "iss": issuer,
        "sub": sub,
        "aud": client_id,
        "exp": exp,
        "iat": now,
        "nonce": nonce,
    });

    if let Some(e) = email {
        claims["email"] = json!(e);
    }
    if let Some(pu) = preferred_username {
        claims["preferred_username"] = json!(pu);
    }
    if let Some(n) = name {
        claims["name"] = json!(n);
    }

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(TEST_KID.to_string());

    let encoding_key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes())
        .expect("failed to create encoding key from test RSA private key");

    encode(&header, &claims, &encoding_key).expect("failed to encode ID token")
}

/// Build a signed ID token JWT with additional custom claims (e.g. "groups").
#[allow(clippy::too_many_arguments)]
/// Same as `build_id_token` but accepts arbitrary extra claims to include in the token.
fn build_id_token_with_extra(
    issuer: &str,
    client_id: &str,
    nonce: &str,
    sub: &str,
    email: Option<&str>,
    preferred_username: Option<&str>,
    name: Option<&str>,
    exp_offset_secs: i64,
    extra_claims: &serde_json::Value,
) -> String {
    let now = chrono::Utc::now().timestamp() as u64;
    let exp = if exp_offset_secs >= 0 {
        now + exp_offset_secs as u64
    } else {
        now.saturating_sub((-exp_offset_secs) as u64)
    };

    let mut claims = json!({
        "iss": issuer,
        "sub": sub,
        "aud": client_id,
        "exp": exp,
        "iat": now,
        "nonce": nonce,
    });

    if let Some(e) = email {
        claims["email"] = json!(e);
    }
    if let Some(pu) = preferred_username {
        claims["preferred_username"] = json!(pu);
    }
    if let Some(n) = name {
        claims["name"] = json!(n);
    }

    // Merge extra claims into the token
    if let Some(obj) = extra_claims.as_object() {
        for (k, v) in obj {
            claims[k] = v.clone();
        }
    }

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(TEST_KID.to_string());

    let encoding_key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes())
        .expect("failed to create encoding key from test RSA private key");

    encode(&header, &claims, &encoding_key).expect("failed to encode ID token")
}

/// Setup a mock IdP (wiremock server) with discovery, JWKS, and token endpoints.
/// Returns (MockServer, issuer_url).
async fn setup_mock_idp() -> MockServer {
    let mock_server = MockServer::start().await;
    let issuer = mock_server.uri();

    // Mount discovery endpoint
    let discovery_doc = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{}/authorize", issuer),
        "token_endpoint": format!("{}/token", issuer),
        "jwks_uri": format!("{}/jwks", issuer),
        "userinfo_endpoint": format!("{}/userinfo", issuer),
    });

    Mock::given(wm_method("GET"))
        .and(wm_path("/.well-known/openid-configuration"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&discovery_doc)
                .insert_header("content-type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    // Mount JWKS endpoint
    Mock::given(wm_method("GET"))
        .and(wm_path("/jwks"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(build_jwks_response())
                .insert_header("content-type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    mock_server
}

/// Mount a token exchange endpoint on the mock IdP that returns the given id_token.
async fn mount_token_endpoint(mock_server: &MockServer, id_token: &str) {
    let token_response = json!({
        "access_token": "mock-access-token-xyz",
        "token_type": "Bearer",
        "id_token": id_token,
        "expires_in": 3600,
    });

    Mock::given(wm_method("POST"))
        .and(wm_path("/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&token_response)
                .insert_header("content-type", "application/json"),
        )
        .mount(mock_server)
        .await;
}
/// Create an OIDC provider directly in the store (bypasses API).
#[allow(clippy::too_many_arguments)]
async fn create_provider_in_db(
    store: &(dyn Store + Send + Sync),
    encryptor: &AesGcmEncryptor,
    name: &str,
    issuer_url: &str,
    client_id: &str,
    client_secret: &str,
    auto_provision: bool,
    enabled: bool,
    role_mapping: Option<Value>,
) -> OidcProviderId {
    let now = chrono::Utc::now();
    let id = OidcProviderId(Uuid::new_v4());
    let (encrypted, nonce) = encryptor
        .encrypt(client_secret.as_bytes(), id.0.to_string().as_bytes())
        .expect("encrypt client secret");
    let provider = agent_cordon_core::domain::oidc::OidcProvider {
        id: id.clone(),
        name: name.to_string(),
        issuer_url: issuer_url.trim_end_matches('/').to_string(),
        client_id: client_id.to_string(),
        encrypted_client_secret: encrypted,
        nonce,
        scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ],
        role_mapping: role_mapping.unwrap_or(json!({})),
        auto_provision,
        enabled,
        username_claim: "preferred_username".to_string(),
        created_at: now,
        updated_at: now,
    };
    store
        .create_oidc_provider(&provider)
        .await
        .expect("create oidc provider");
    id
}

/// Create an OIDC auth state directly in the store and return (state, nonce).
async fn create_auth_state_in_db(
    store: &(dyn Store + Send + Sync),
    provider_id: &OidcProviderId,
    redirect_uri: &str,
    ttl_seconds: i64,
) -> (String, String) {
    let random_state = Uuid::new_v4().to_string();
    let nonce = Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(ttl_seconds);

    let auth_state = OidcAuthState {
        state: random_state.clone(),
        nonce: nonce.clone(),
        provider_id: provider_id.clone(),
        redirect_uri: redirect_uri.to_string(),
        created_at: now,
        expires_at,
    };
    store
        .create_oidc_auth_state(&auth_state)
        .await
        .expect("create auth state");
    (random_state, nonce)
}

/// Send a GET request for the callback and return (status, headers, location).
async fn send_callback(app: &Router, query: &str) -> (StatusCode, Vec<(String, String)>) {
    let uri = format!("/api/v1/auth/oidc/callback?{}", query);
    let request = Request::builder()
        .method(Method::GET)
        .uri(&uri)
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    (status, headers)
}

/// Extract the Location header from a redirect response.
fn get_location(headers: &[(String, String)]) -> String {
    headers
        .iter()
        .find(|(k, _)| k == "location")
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

/// Extract Set-Cookie header values from response headers.
fn get_set_cookies(headers: &[(String, String)]) -> Vec<String> {
    headers
        .iter()
        .filter(|(k, _)| k == "set-cookie")
        .map(|(_, v)| v.clone())
        .collect()
}

// ===========================================================================
// OIDC Provider CRUD Tests
// ===========================================================================

#[tokio::test]
async fn oidc_provider_create_succeeds_for_admin() {
    let (app, store, _enc) = setup_test_app().await;
    create_admin_user(&*store).await;
    let cookie = login_user(&app, "admin-user", TEST_PASSWORD).await;

    let (status, body) = create_provider_via_api(
        &app,
        &cookie,
        "Test IdP",
        "https://idp.example.com",
        "my-client-id",
        "my-client-secret",
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    let data = &body["data"];
    assert_eq!(data["name"], "Test IdP");
    assert_eq!(data["issuer_url"], "https://idp.example.com");
    assert_eq!(data["client_id"], "my-client-id");
    assert_eq!(data["auto_provision"], true);
    assert_eq!(data["enabled"], true);
    // Default scopes
    let scopes = data["scopes"]
        .as_array()
        .expect("scopes should be an array");
    assert_eq!(scopes.len(), 3);
    // Must NOT contain client_secret in response
    assert!(data.get("client_secret").is_none() || data["client_secret"].is_null());
    assert!(data.get("encrypted_client_secret").is_none());
}

#[tokio::test]
async fn oidc_provider_create_denied_for_viewer() {
    let (app, store, _enc) = setup_test_app().await;
    create_viewer_user(&*store).await;
    let cookie = login_user(&app, "viewer-user", TEST_PASSWORD).await;

    let (status, body) = create_provider_via_api(
        &app,
        &cookie,
        "Test IdP",
        "https://idp.example.com",
        "my-client-id",
        "my-client-secret",
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "response: {}", body);
}

#[tokio::test]
async fn oidc_provider_create_denied_unauthenticated() {
    let (app, _store, _enc) = setup_test_app().await;

    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/oidc-providers",
        None,
        Some(json!({
            "name": "Test IdP",
            "issuer_url": "https://idp.example.com",
            "client_id": "cid",
            "client_secret": "csec",
        })),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn oidc_provider_create_validates_empty_name() {
    let (app, store, _enc) = setup_test_app().await;
    create_admin_user(&*store).await;
    let cookie = login_user(&app, "admin-user", TEST_PASSWORD).await;

    let (status, body) = create_provider_via_api(
        &app,
        &cookie,
        "  ",
        "https://idp.example.com",
        "my-client-id",
        "my-client-secret",
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "response: {}", body);
    assert!(body["error"]["message"].as_str().unwrap().contains("name"));
}

#[tokio::test]
async fn oidc_provider_create_validates_empty_client_id() {
    let (app, store, _enc) = setup_test_app().await;
    create_admin_user(&*store).await;
    let cookie = login_user(&app, "admin-user", TEST_PASSWORD).await;

    let (status, body) = create_provider_via_api(
        &app,
        &cookie,
        "Test IdP",
        "https://idp.example.com",
        "  ",
        "my-client-secret",
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "response: {}", body);
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("client_id"));
}

#[tokio::test]
async fn oidc_provider_create_validates_empty_client_secret() {
    let (app, store, _enc) = setup_test_app().await;
    create_admin_user(&*store).await;
    let cookie = login_user(&app, "admin-user", TEST_PASSWORD).await;

    let (status, body) = create_provider_via_api(
        &app,
        &cookie,
        "Test IdP",
        "https://idp.example.com",
        "my-client-id",
        "",
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "response: {}", body);
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("client_secret"));
}

#[tokio::test]
async fn oidc_provider_create_validates_issuer_url_http_rejected() {
    let (app, store, _enc) = setup_test_app().await;
    create_admin_user(&*store).await;
    let cookie = login_user(&app, "admin-user", TEST_PASSWORD).await;

    let (status, body) = create_provider_via_api(
        &app,
        &cookie,
        "Test IdP",
        "http://insecure.example.com",
        "my-client-id",
        "my-client-secret",
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "response: {}", body);
    let msg = body["error"]["message"].as_str().unwrap();
    assert!(msg.contains("HTTPS"), "error should mention HTTPS: {}", msg);
}

#[tokio::test]
async fn oidc_provider_create_allows_localhost_http() {
    let (app, store, _enc) = setup_test_app().await;
    create_admin_user(&*store).await;
    let cookie = login_user(&app, "admin-user", TEST_PASSWORD).await;

    let (status, body) = create_provider_via_api(
        &app,
        &cookie,
        "Local IdP",
        "http://localhost:8080",
        "my-client-id",
        "my-client-secret",
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
}

#[tokio::test]
async fn oidc_provider_create_allows_127001_http() {
    let (app, store, _enc) = setup_test_app().await;
    create_admin_user(&*store).await;
    let cookie = login_user(&app, "admin-user", TEST_PASSWORD).await;

    let (status, body) = create_provider_via_api(
        &app,
        &cookie,
        "Loopback IdP",
        "http://127.0.0.1:8080",
        "my-client-id",
        "my-client-secret",
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
}

#[tokio::test]
async fn oidc_provider_create_strips_trailing_slash_from_issuer() {
    let (app, store, _enc) = setup_test_app().await;
    create_admin_user(&*store).await;
    let cookie = login_user(&app, "admin-user", TEST_PASSWORD).await;

    let (status, body) = create_provider_via_api(
        &app,
        &cookie,
        "Trailing Slash IdP",
        "https://idp.example.com/",
        "my-client-id",
        "my-client-secret",
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(body["data"]["issuer_url"], "https://idp.example.com");
}

#[tokio::test]
async fn oidc_provider_create_with_custom_scopes_and_role_mapping() {
    let (app, store, _enc) = setup_test_app().await;
    create_admin_user(&*store).await;
    let cookie = login_user(&app, "admin-user", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/oidc-providers",
        Some(&cookie),
        Some(json!({
            "name": "Custom IdP",
            "issuer_url": "https://custom.example.com",
            "client_id": "custom-client",
            "client_secret": "custom-secret",
            "scopes": ["openid", "email"],
            "role_mapping": {"default_role": "operator"},
            "auto_provision": false,
            "enabled": false,
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    let data = &body["data"];
    assert_eq!(data["scopes"], json!(["openid", "email"]));
    assert_eq!(data["role_mapping"], json!({"default_role": "operator"}));
    assert_eq!(data["auto_provision"], false);
    assert_eq!(data["enabled"], false);
}

#[tokio::test]
async fn oidc_provider_list() {
    let (app, store, _enc) = setup_test_app().await;
    create_admin_user(&*store).await;
    let cookie = login_user(&app, "admin-user", TEST_PASSWORD).await;

    // Create two providers
    let (s1, _) = create_provider_via_api(
        &app,
        &cookie,
        "IdP One",
        "https://one.example.com",
        "cid1",
        "csec1",
    )
    .await;
    assert_eq!(s1, StatusCode::OK);

    let (s2, _) = create_provider_via_api(
        &app,
        &cookie,
        "IdP Two",
        "https://two.example.com",
        "cid2",
        "csec2",
    )
    .await;
    assert_eq!(s2, StatusCode::OK);

    // List
    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/oidc-providers",
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    let providers = body["data"].as_array().expect("data should be array");
    assert_eq!(providers.len(), 2);
    // No client_secret leaked
    for p in providers {
        assert!(p.get("client_secret").is_none() || p["client_secret"].is_null());
    }
}

#[tokio::test]
async fn oidc_provider_get_by_id() {
    let (app, store, _enc) = setup_test_app().await;
    create_admin_user(&*store).await;
    let cookie = login_user(&app, "admin-user", TEST_PASSWORD).await;

    let (status, create_body) = create_provider_via_api(
        &app,
        &cookie,
        "Get Test IdP",
        "https://get.example.com",
        "cid",
        "csec",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let provider_id = create_body["data"]["id"].as_str().unwrap();

    let (status, body) = send_json(
        &app,
        Method::GET,
        &format!("/api/v1/oidc-providers/{}", provider_id),
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(body["data"]["name"], "Get Test IdP");
    assert_eq!(body["data"]["client_id"], "cid");
}

#[tokio::test]
async fn oidc_provider_get_not_found() {
    let (app, store, _enc) = setup_test_app().await;
    create_admin_user(&*store).await;
    let cookie = login_user(&app, "admin-user", TEST_PASSWORD).await;

    let fake_id = Uuid::new_v4();
    let (status, _body) = send_json(
        &app,
        Method::GET,
        &format!("/api/v1/oidc-providers/{}", fake_id),
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn oidc_provider_update() {
    let (app, store, _enc) = setup_test_app().await;
    create_admin_user(&*store).await;
    let cookie = login_user(&app, "admin-user", TEST_PASSWORD).await;

    let (_, create_body) = create_provider_via_api(
        &app,
        &cookie,
        "Update Me",
        "https://update.example.com",
        "cid",
        "csec",
    )
    .await;
    let provider_id = create_body["data"]["id"].as_str().unwrap();

    let (status, body) = send_json(
        &app,
        Method::PUT,
        &format!("/api/v1/oidc-providers/{}", provider_id),
        Some(&cookie),
        Some(json!({
            "name": "Updated IdP",
            "enabled": false,
            "auto_provision": false,
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(body["data"]["name"], "Updated IdP");
    assert_eq!(body["data"]["enabled"], false);
    assert_eq!(body["data"]["auto_provision"], false);
    // issuer_url should be unchanged
    assert_eq!(body["data"]["issuer_url"], "https://update.example.com");
}

#[tokio::test]
async fn oidc_provider_update_validates_empty_name() {
    let (app, store, _enc) = setup_test_app().await;
    create_admin_user(&*store).await;
    let cookie = login_user(&app, "admin-user", TEST_PASSWORD).await;

    let (_, create_body) = create_provider_via_api(
        &app,
        &cookie,
        "Validate Name",
        "https://val.example.com",
        "cid",
        "csec",
    )
    .await;
    let provider_id = create_body["data"]["id"].as_str().unwrap();

    let (status, body) = send_json(
        &app,
        Method::PUT,
        &format!("/api/v1/oidc-providers/{}", provider_id),
        Some(&cookie),
        Some(json!({ "name": "  " })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "response: {}", body);
}

#[tokio::test]
async fn oidc_provider_update_reencrypts_client_secret() {
    let (app, store, enc) = setup_test_app().await;
    create_admin_user(&*store).await;
    let cookie = login_user(&app, "admin-user", TEST_PASSWORD).await;

    let (_, create_body) = create_provider_via_api(
        &app,
        &cookie,
        "ReEncrypt",
        "https://reencrypt.example.com",
        "cid",
        "csec-old",
    )
    .await;
    let provider_id = create_body["data"]["id"].as_str().unwrap();

    // Update with new client secret
    let (status, _) = send_json(
        &app,
        Method::PUT,
        &format!("/api/v1/oidc-providers/{}", provider_id),
        Some(&cookie),
        Some(json!({ "client_secret": "new-secret-value" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Verify by reading from store and decrypting
    let provider = store
        .get_oidc_provider(&OidcProviderId(provider_id.parse().unwrap()))
        .await
        .unwrap()
        .unwrap();
    let decrypted = enc
        .decrypt(
            &provider.encrypted_client_secret,
            &provider.nonce,
            provider.id.0.to_string().as_bytes(),
        )
        .unwrap();
    assert_eq!(String::from_utf8(decrypted).unwrap(), "new-secret-value");
}

#[tokio::test]
async fn oidc_provider_delete() {
    let (app, store, _enc) = setup_test_app().await;
    create_admin_user(&*store).await;
    let cookie = login_user(&app, "admin-user", TEST_PASSWORD).await;

    let (_, create_body) = create_provider_via_api(
        &app,
        &cookie,
        "Delete Me",
        "https://delete.example.com",
        "cid",
        "csec",
    )
    .await;
    let provider_id = create_body["data"]["id"].as_str().unwrap();

    let (status, body) = send_json(
        &app,
        Method::DELETE,
        &format!("/api/v1/oidc-providers/{}", provider_id),
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    assert_eq!(body["data"]["deleted"], true);

    // Verify it's gone
    let (status, _) = send_json(
        &app,
        Method::GET,
        &format!("/api/v1/oidc-providers/{}", provider_id),
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn oidc_provider_delete_not_found() {
    let (app, store, _enc) = setup_test_app().await;
    create_admin_user(&*store).await;
    let cookie = login_user(&app, "admin-user", TEST_PASSWORD).await;

    let fake_id = Uuid::new_v4();
    let (status, _) = send_json(
        &app,
        Method::DELETE,
        &format!("/api/v1/oidc-providers/{}", fake_id),
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ===========================================================================
// Public Providers Endpoint Tests
// ===========================================================================

#[tokio::test]
async fn oidc_public_providers_returns_only_enabled() {
    let (app, store, enc) = setup_test_app().await;

    // Create one enabled, one disabled provider
    create_provider_in_db(
        &*store,
        &enc,
        "Enabled IdP",
        "https://enabled.example.com",
        "cid1",
        "csec1",
        true,
        true,
        None,
    )
    .await;
    create_provider_in_db(
        &*store,
        &enc,
        "Disabled IdP",
        "https://disabled.example.com",
        "cid2",
        "csec2",
        true,
        false,
        None,
    )
    .await;

    // Public endpoint — no auth required
    let (status, body) =
        send_json(&app, Method::GET, "/api/v1/auth/oidc/providers", None, None).await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    let providers = body["data"].as_array().expect("data should be array");
    assert_eq!(providers.len(), 1, "only enabled providers");
    assert_eq!(providers[0]["name"], "Enabled IdP");
    // Must only return id and name — no secrets, no config
    assert!(providers[0].get("client_id").is_none());
    assert!(providers[0].get("issuer_url").is_none());
    assert!(providers[0].get("client_secret").is_none());
}

#[tokio::test]
async fn oidc_public_providers_empty_when_none_enabled() {
    let (app, _store, _enc) = setup_test_app().await;

    let (status, body) =
        send_json(&app, Method::GET, "/api/v1/auth/oidc/providers", None, None).await;

    assert_eq!(status, StatusCode::OK, "response: {}", body);
    let providers = body["data"].as_array().expect("data should be array");
    assert_eq!(providers.len(), 0);
}

// ===========================================================================
// OIDC Authorize Endpoint Tests
// ===========================================================================

#[tokio::test]
async fn oidc_authorize_redirects_to_idp() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) =
        setup_test_app_with_config(Some("http://localhost:3140".to_string())).await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "Mock IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        true,
        None,
    )
    .await;

    // Hit the authorize endpoint
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/auth/oidc/authorize?provider={}",
            provider_id.0
        ))
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();

    // Should redirect (307 Temporary Redirect)
    assert!(
        status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER,
        "should redirect to IdP, got {}",
        status
    );

    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();

    // The redirect URL should contain IdP authorize endpoint
    assert!(
        location.contains("/authorize"),
        "should redirect to IdP authorize endpoint: {}",
        location
    );
    assert!(
        location.contains("response_type=code"),
        "should include response_type=code: {}",
        location
    );
    assert!(
        location.contains("client_id=test-client"),
        "should include client_id: {}",
        location
    );
    assert!(
        location.contains("redirect_uri="),
        "should include redirect_uri: {}",
        location
    );
    assert!(
        location.contains("state="),
        "should include state parameter: {}",
        location
    );
    assert!(
        location.contains("nonce="),
        "should include nonce parameter: {}",
        location
    );
}

#[tokio::test]
async fn oidc_authorize_disabled_provider_rejected() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) = setup_test_app().await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "Disabled IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        false,
        None,
    )
    .await;

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/auth/oidc/authorize?provider={}",
            provider_id.0
        ))
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn oidc_authorize_nonexistent_provider_returns_404() {
    let (app, _store, _enc) = setup_test_app().await;

    let fake_id = Uuid::new_v4();
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/v1/auth/oidc/authorize?provider={}", fake_id))
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ===========================================================================
// OIDC Callback Tests — Full Flow
// ===========================================================================

#[tokio::test]
async fn oidc_callback_full_flow_new_user() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) =
        setup_test_app_with_config(Some("http://localhost:3140".to_string())).await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "Flow IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        true,
        None,
    )
    .await;

    // Create auth state manually (simulating the authorize step)
    let redirect_uri = "http://localhost:3140/api/v1/auth/oidc/callback";
    let (state_param, nonce) =
        create_auth_state_in_db(&*store, &provider_id, redirect_uri, 600).await;

    // Build a valid ID token
    let id_token = build_id_token(
        &issuer,
        "test-client",
        &nonce,
        "user-sub-123",
        Some("oidcuser@example.com"),
        Some("oidcuser"),
        Some("OIDC User"),
        3600,
    );

    // Mount the token exchange endpoint
    mount_token_endpoint(&mock_idp, &id_token).await;

    // Hit the callback
    let (status, headers) =
        send_callback(&app, &format!("code=authcode123&state={}", state_param)).await;

    // Should redirect to / with session cookies
    assert!(
        status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER,
        "should redirect after successful OIDC login, got {}",
        status
    );
    let location = get_location(&headers);
    assert_eq!(location, "/", "should redirect to UI root");

    // Should set session and CSRF cookies
    let cookies = get_set_cookies(&headers);
    assert!(
        cookies.iter().any(|c| c.contains("agtcrdn_session=")),
        "should set session cookie, got: {:?}",
        cookies
    );
    assert!(
        cookies.iter().any(|c| c.contains("agtcrdn_csrf=")),
        "should set CSRF cookie, got: {:?}",
        cookies
    );

    // Verify user was auto-provisioned
    let user = store
        .get_user_by_username("oidcuser")
        .await
        .unwrap()
        .expect("user should be auto-created");
    assert_eq!(user.username, "oidcuser");
    assert_eq!(user.display_name, Some("OIDC User".to_string()));
    assert!(user.enabled);
    // Default role is viewer when no role_mapping specified
    assert_eq!(user.role, UserRole::Viewer);
}

#[tokio::test]
async fn oidc_callback_existing_user_login() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) =
        setup_test_app_with_config(Some("http://localhost:3140".to_string())).await;

    // Pre-create the user
    create_user_in_db(
        &*store,
        "existing-oidc-user",
        "dummy-pass",
        UserRole::Admin,
        false,
        true,
    )
    .await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "Existing User IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        true,
        None,
    )
    .await;

    let redirect_uri = "http://localhost:3140/api/v1/auth/oidc/callback";
    let (state_param, nonce) =
        create_auth_state_in_db(&*store, &provider_id, redirect_uri, 600).await;

    let id_token = build_id_token(
        &issuer,
        "test-client",
        &nonce,
        "existing-sub",
        None,
        Some("existing-oidc-user"),
        None,
        3600,
    );
    mount_token_endpoint(&mock_idp, &id_token).await;

    let (status, headers) =
        send_callback(&app, &format!("code=authcode456&state={}", state_param)).await;

    assert!(
        status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER,
        "should redirect after login, got {}",
        status
    );
    let location = get_location(&headers);
    assert_eq!(location, "/");

    // Verify session cookies are set
    let cookies = get_set_cookies(&headers);
    assert!(cookies.iter().any(|c| c.contains("agtcrdn_session=")));
}

#[tokio::test]
async fn oidc_callback_disabled_user_rejected() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) =
        setup_test_app_with_config(Some("http://localhost:3140".to_string())).await;

    // Pre-create a disabled user
    create_user_in_db(
        &*store,
        "disabled-oidc-user",
        "dummy-pass",
        UserRole::Viewer,
        false,
        false,
    )
    .await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "Disabled User IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        true,
        None,
    )
    .await;

    let redirect_uri = "http://localhost:3140/api/v1/auth/oidc/callback";
    let (state_param, nonce) =
        create_auth_state_in_db(&*store, &provider_id, redirect_uri, 600).await;

    let id_token = build_id_token(
        &issuer,
        "test-client",
        &nonce,
        "disabled-sub",
        None,
        Some("disabled-oidc-user"),
        None,
        3600,
    );
    mount_token_endpoint(&mock_idp, &id_token).await;

    let (status, headers) =
        send_callback(&app, &format!("code=authcode789&state={}", state_param)).await;

    // Should redirect to login page with error
    assert!(
        status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER,
        "got {}",
        status
    );
    let location = get_location(&headers);
    assert!(
        location.contains("oidc_error="),
        "should include oidc_error in redirect: {}",
        location
    );
    assert!(
        location.contains("disabled"),
        "error should mention disabled: {}",
        location
    );

    // No session cookie should be set
    let cookies = get_set_cookies(&headers);
    assert!(
        !cookies.iter().any(|c| c.contains("agtcrdn_session=")),
        "should NOT set session cookie for disabled user"
    );
}

#[tokio::test]
async fn oidc_callback_auto_provision_false_rejects_unknown_user() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) =
        setup_test_app_with_config(Some("http://localhost:3140".to_string())).await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "NoProvision IdP",
        &issuer,
        "test-client",
        "test-secret",
        false, // auto_provision = false
        true,
        None,
    )
    .await;

    let redirect_uri = "http://localhost:3140/api/v1/auth/oidc/callback";
    let (state_param, nonce) =
        create_auth_state_in_db(&*store, &provider_id, redirect_uri, 600).await;

    let id_token = build_id_token(
        &issuer,
        "test-client",
        &nonce,
        "unknown-user-sub",
        None,
        Some("unknown-oidc-user"),
        None,
        3600,
    );
    mount_token_endpoint(&mock_idp, &id_token).await;

    let (status, headers) =
        send_callback(&app, &format!("code=authcode&state={}", state_param)).await;

    assert!(
        status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER,
        "got {}",
        status
    );
    let location = get_location(&headers);
    assert!(
        location.contains("oidc_error="),
        "should include error in redirect: {}",
        location
    );
    assert!(
        location.contains("not+provisioned") || location.contains("not%20provisioned"),
        "error should mention not provisioned: {}",
        location
    );

    // Verify user was NOT created
    let user = store
        .get_user_by_username("unknown-oidc-user")
        .await
        .unwrap();
    assert!(user.is_none(), "user should not have been created");
}

// ===========================================================================
// Claim Mapping Tests
// ===========================================================================

#[tokio::test]
async fn oidc_callback_username_from_preferred_username() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) =
        setup_test_app_with_config(Some("http://localhost:3140".to_string())).await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "PrefUsername IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        true,
        None,
    )
    .await;

    let redirect_uri = "http://localhost:3140/api/v1/auth/oidc/callback";
    let (state_param, nonce) =
        create_auth_state_in_db(&*store, &provider_id, redirect_uri, 600).await;

    // ID token with preferred_username, email, and sub — preferred_username should win
    let id_token = build_id_token(
        &issuer,
        "test-client",
        &nonce,
        "sub-value",
        Some("email@example.com"),
        Some("preferred-user"),
        None,
        3600,
    );
    mount_token_endpoint(&mock_idp, &id_token).await;

    let (status, _headers) =
        send_callback(&app, &format!("code=authcode&state={}", state_param)).await;

    assert!(status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER);

    let user = store
        .get_user_by_username("preferred-user")
        .await
        .unwrap()
        .expect("user should be created with preferred_username");
    assert_eq!(user.username, "preferred-user");
}

#[tokio::test]
async fn oidc_callback_username_from_email_fallback() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) =
        setup_test_app_with_config(Some("http://localhost:3140".to_string())).await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "EmailFallback IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        true,
        None,
    )
    .await;

    let redirect_uri = "http://localhost:3140/api/v1/auth/oidc/callback";
    let (state_param, nonce) =
        create_auth_state_in_db(&*store, &provider_id, redirect_uri, 600).await;

    // No preferred_username — should fall back to email
    let id_token = build_id_token(
        &issuer,
        "test-client",
        &nonce,
        "sub-value",
        Some("fallback@example.com"),
        None,
        None,
        3600,
    );
    mount_token_endpoint(&mock_idp, &id_token).await;

    let (status, _headers) =
        send_callback(&app, &format!("code=authcode&state={}", state_param)).await;

    assert!(status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER);

    let user = store
        .get_user_by_username("fallback@example.com")
        .await
        .unwrap()
        .expect("user should be created with email as username");
    assert_eq!(user.username, "fallback@example.com");
}

#[tokio::test]
async fn oidc_callback_username_from_sub_final_fallback() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) =
        setup_test_app_with_config(Some("http://localhost:3140".to_string())).await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "SubFallback IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        true,
        None,
    )
    .await;

    let redirect_uri = "http://localhost:3140/api/v1/auth/oidc/callback";
    let (state_param, nonce) =
        create_auth_state_in_db(&*store, &provider_id, redirect_uri, 600).await;

    // No preferred_username, no email — should fall back to sub
    let id_token = build_id_token(
        &issuer,
        "test-client",
        &nonce,
        "sub-only-user-id",
        None,
        None,
        None,
        3600,
    );
    mount_token_endpoint(&mock_idp, &id_token).await;

    let (status, _headers) =
        send_callback(&app, &format!("code=authcode&state={}", state_param)).await;

    assert!(status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER);

    let user = store
        .get_user_by_username("sub-only-user-id")
        .await
        .unwrap()
        .expect("user should be created with sub as username");
    assert_eq!(user.username, "sub-only-user-id");
}

// ===========================================================================
// Role Mapping Tests
// ===========================================================================

#[tokio::test]
async fn oidc_callback_role_mapping_default_role_admin() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) =
        setup_test_app_with_config(Some("http://localhost:3140".to_string())).await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "Admin Role IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        true,
        Some(json!({"default_role": "admin"})),
    )
    .await;

    let redirect_uri = "http://localhost:3140/api/v1/auth/oidc/callback";
    let (state_param, nonce) =
        create_auth_state_in_db(&*store, &provider_id, redirect_uri, 600).await;

    let id_token = build_id_token(
        &issuer,
        "test-client",
        &nonce,
        "admin-role-sub",
        None,
        Some("admin-role-user"),
        None,
        3600,
    );
    mount_token_endpoint(&mock_idp, &id_token).await;

    let (status, _) = send_callback(&app, &format!("code=authcode&state={}", state_param)).await;

    assert!(status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER);

    let user = store
        .get_user_by_username("admin-role-user")
        .await
        .unwrap()
        .expect("user should be created");
    assert_eq!(user.role, UserRole::Admin);
}

#[tokio::test]
async fn oidc_callback_role_mapping_default_role_operator() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) =
        setup_test_app_with_config(Some("http://localhost:3140".to_string())).await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "Operator Role IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        true,
        Some(json!({"default_role": "operator"})),
    )
    .await;

    let redirect_uri = "http://localhost:3140/api/v1/auth/oidc/callback";
    let (state_param, nonce) =
        create_auth_state_in_db(&*store, &provider_id, redirect_uri, 600).await;

    let id_token = build_id_token(
        &issuer,
        "test-client",
        &nonce,
        "operator-role-sub",
        None,
        Some("operator-role-user"),
        None,
        3600,
    );
    mount_token_endpoint(&mock_idp, &id_token).await;

    let (status, _) = send_callback(&app, &format!("code=authcode&state={}", state_param)).await;

    assert!(status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER);

    let user = store
        .get_user_by_username("operator-role-user")
        .await
        .unwrap()
        .expect("user should be created");
    assert_eq!(user.role, UserRole::Operator);
}

#[tokio::test]
async fn oidc_callback_role_mapping_no_mapping_defaults_to_viewer() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) =
        setup_test_app_with_config(Some("http://localhost:3140".to_string())).await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "NoRole IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        true,
        None, // No role_mapping
    )
    .await;

    let redirect_uri = "http://localhost:3140/api/v1/auth/oidc/callback";
    let (state_param, nonce) =
        create_auth_state_in_db(&*store, &provider_id, redirect_uri, 600).await;

    let id_token = build_id_token(
        &issuer,
        "test-client",
        &nonce,
        "viewer-role-sub",
        None,
        Some("viewer-role-user"),
        None,
        3600,
    );
    mount_token_endpoint(&mock_idp, &id_token).await;

    let (status, _) = send_callback(&app, &format!("code=authcode&state={}", state_param)).await;

    assert!(status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER);

    let user = store
        .get_user_by_username("viewer-role-user")
        .await
        .unwrap()
        .expect("user should be created");
    assert_eq!(user.role, UserRole::Viewer);
}

#[tokio::test]
async fn oidc_callback_role_mapping_groups_claim_match() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) =
        setup_test_app_with_config(Some("http://localhost:3140".to_string())).await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "Groups IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        true,
        Some(json!({
            "claim": "groups",
            "mappings": {
                "AgentCordon-Admins": "admin",
                "AgentCordon-Ops": "operator"
            },
            "default_role": "viewer"
        })),
    )
    .await;

    let redirect_uri = "http://localhost:3140/api/v1/auth/oidc/callback";
    let (state_param, nonce) =
        create_auth_state_in_db(&*store, &provider_id, redirect_uri, 600).await;

    let id_token = build_id_token_with_extra(
        &issuer,
        "test-client",
        &nonce,
        "groups-match-sub",
        None,
        Some("groups-match-user"),
        None,
        3600,
        &json!({"groups": "AgentCordon-Admins"}),
    );
    mount_token_endpoint(&mock_idp, &id_token).await;

    let (status, _) = send_callback(&app, &format!("code=authcode&state={}", state_param)).await;

    assert!(status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER);

    let user = store
        .get_user_by_username("groups-match-user")
        .await
        .unwrap()
        .expect("user should be created");
    assert_eq!(user.role, UserRole::Admin);
}

#[tokio::test]
async fn oidc_callback_role_mapping_groups_no_match_uses_default() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) =
        setup_test_app_with_config(Some("http://localhost:3140".to_string())).await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "NoMatch IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        true,
        Some(json!({
            "claim": "groups",
            "mappings": {
                "AgentCordon-Admins": "admin"
            },
            "default_role": "operator"
        })),
    )
    .await;

    let redirect_uri = "http://localhost:3140/api/v1/auth/oidc/callback";
    let (state_param, nonce) =
        create_auth_state_in_db(&*store, &provider_id, redirect_uri, 600).await;

    let id_token = build_id_token_with_extra(
        &issuer,
        "test-client",
        &nonce,
        "nomatch-sub",
        None,
        Some("nomatch-user"),
        None,
        3600,
        &json!({"groups": "SomeOtherGroup"}),
    );
    mount_token_endpoint(&mock_idp, &id_token).await;

    let (status, _) = send_callback(&app, &format!("code=authcode&state={}", state_param)).await;

    assert!(status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER);

    let user = store
        .get_user_by_username("nomatch-user")
        .await
        .unwrap()
        .expect("user should be created");
    assert_eq!(user.role, UserRole::Operator);
}

#[tokio::test]
async fn oidc_callback_role_mapping_array_claim() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) =
        setup_test_app_with_config(Some("http://localhost:3140".to_string())).await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "Array Groups IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        true,
        Some(json!({
            "claim": "groups",
            "mappings": {
                "AgentCordon-Admins": "admin",
                "AgentCordon-Ops": "operator"
            },
            "default_role": "viewer"
        })),
    )
    .await;

    let redirect_uri = "http://localhost:3140/api/v1/auth/oidc/callback";
    let (state_param, nonce) =
        create_auth_state_in_db(&*store, &provider_id, redirect_uri, 600).await;

    // groups claim is an array; one value matches "AgentCordon-Ops"
    let id_token = build_id_token_with_extra(
        &issuer,
        "test-client",
        &nonce,
        "array-groups-sub",
        None,
        Some("array-groups-user"),
        None,
        3600,
        &json!({"groups": ["Users", "AgentCordon-Ops", "Developers"]}),
    );
    mount_token_endpoint(&mock_idp, &id_token).await;

    let (status, _) = send_callback(&app, &format!("code=authcode&state={}", state_param)).await;

    assert!(status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER);

    let user = store
        .get_user_by_username("array-groups-user")
        .await
        .unwrap()
        .expect("user should be created");
    assert_eq!(user.role, UserRole::Operator);
}

#[tokio::test]
async fn oidc_callback_role_mapping_string_claim() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) =
        setup_test_app_with_config(Some("http://localhost:3140".to_string())).await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "String Claim IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        true,
        Some(json!({
            "claim": "department",
            "mappings": {
                "engineering": "operator",
                "security": "admin"
            },
            "default_role": "viewer"
        })),
    )
    .await;

    let redirect_uri = "http://localhost:3140/api/v1/auth/oidc/callback";
    let (state_param, nonce) =
        create_auth_state_in_db(&*store, &provider_id, redirect_uri, 600).await;

    // Single string claim
    let id_token = build_id_token_with_extra(
        &issuer,
        "test-client",
        &nonce,
        "string-claim-sub",
        None,
        Some("string-claim-user"),
        None,
        3600,
        &json!({"department": "security"}),
    );
    mount_token_endpoint(&mock_idp, &id_token).await;

    let (status, _) = send_callback(&app, &format!("code=authcode&state={}", state_param)).await;

    assert!(status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER);

    let user = store
        .get_user_by_username("string-claim-user")
        .await
        .unwrap()
        .expect("user should be created");
    assert_eq!(user.role, UserRole::Admin);
}

// ===========================================================================
// Callback Error Handling Tests
// ===========================================================================

#[tokio::test]
async fn oidc_callback_idp_returns_error() {
    let (app, _store, _enc) = setup_test_app().await;

    let (status, headers) =
        send_callback(&app, "error=access_denied&error_description=User+cancelled").await;

    assert!(
        status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER,
        "got {}",
        status
    );
    let location = get_location(&headers);
    assert!(
        location.contains("oidc_error="),
        "should redirect with oidc_error: {}",
        location
    );
}

#[tokio::test]
async fn oidc_callback_missing_code() {
    let (app, _store, _enc) = setup_test_app().await;

    let (status, headers) = send_callback(&app, "state=some-state").await;

    assert!(
        status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER,
        "got {}",
        status
    );
    let location = get_location(&headers);
    assert!(location.contains("oidc_error="));
}

#[tokio::test]
async fn oidc_callback_missing_state() {
    let (app, _store, _enc) = setup_test_app().await;

    let (status, headers) = send_callback(&app, "code=authcode123").await;

    assert!(
        status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER,
        "got {}",
        status
    );
    let location = get_location(&headers);
    assert!(location.contains("oidc_error="));
}

#[tokio::test]
async fn oidc_callback_unknown_state() {
    let (app, _store, _enc) = setup_test_app().await;

    let (status, headers) =
        send_callback(&app, "code=authcode&state=nonexistent-state-value").await;

    assert!(
        status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER,
        "got {}",
        status
    );
    let location = get_location(&headers);
    assert!(
        location.contains("oidc_error="),
        "should redirect with error for unknown state: {}",
        location
    );
    assert!(
        location.contains("expired"),
        "error should mention expired/invalid session: {}",
        location
    );
}

#[tokio::test]
async fn oidc_callback_expired_state() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) = setup_test_app().await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "Expired State IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        true,
        None,
    )
    .await;

    // Create auth state that's already expired (negative TTL)
    let redirect_uri = "http://localhost:3140/api/v1/auth/oidc/callback";
    let (state_param, _nonce) =
        create_auth_state_in_db(&*store, &provider_id, redirect_uri, -60).await;

    let (status, headers) =
        send_callback(&app, &format!("code=authcode&state={}", state_param)).await;

    assert!(
        status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER,
        "got {}",
        status
    );
    let location = get_location(&headers);
    assert!(
        location.contains("oidc_error="),
        "should redirect with error for expired state: {}",
        location
    );
}

#[tokio::test]
async fn oidc_callback_state_replay_attack_prevented() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) =
        setup_test_app_with_config(Some("http://localhost:3140".to_string())).await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "Replay IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        true,
        None,
    )
    .await;

    let redirect_uri = "http://localhost:3140/api/v1/auth/oidc/callback";
    let (state_param, nonce) =
        create_auth_state_in_db(&*store, &provider_id, redirect_uri, 600).await;

    let id_token = build_id_token(
        &issuer,
        "test-client",
        &nonce,
        "replay-sub",
        None,
        Some("replay-user"),
        None,
        3600,
    );
    mount_token_endpoint(&mock_idp, &id_token).await;

    // First use — should succeed
    let (status, _) = send_callback(&app, &format!("code=authcode-1&state={}", state_param)).await;
    assert!(
        status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER,
        "first use should succeed, got {}",
        status
    );

    // Second use — state is consumed, should fail
    let (status, headers) =
        send_callback(&app, &format!("code=authcode-2&state={}", state_param)).await;
    assert!(
        status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER,
        "got {}",
        status
    );
    let location = get_location(&headers);
    assert!(
        location.contains("oidc_error="),
        "replayed state should fail: {}",
        location
    );
}

// ===========================================================================
// ID Token Validation Edge Cases
// ===========================================================================

#[tokio::test]
async fn oidc_callback_expired_id_token_rejected() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) =
        setup_test_app_with_config(Some("http://localhost:3140".to_string())).await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "ExpiredToken IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        true,
        None,
    )
    .await;

    let redirect_uri = "http://localhost:3140/api/v1/auth/oidc/callback";
    let (state_param, nonce) =
        create_auth_state_in_db(&*store, &provider_id, redirect_uri, 600).await;

    // Build an expired ID token (exp in the past, beyond clock skew tolerance)
    let id_token = build_id_token(
        &issuer,
        "test-client",
        &nonce,
        "expired-sub",
        None,
        Some("expired-user"),
        None,
        -120, // 120 seconds in the past (beyond 60s clock skew tolerance)
    );
    mount_token_endpoint(&mock_idp, &id_token).await;

    let (status, headers) =
        send_callback(&app, &format!("code=authcode&state={}", state_param)).await;

    assert!(
        status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER,
        "got {}",
        status
    );
    let location = get_location(&headers);
    assert!(
        location.contains("oidc_error="),
        "expired token should fail: {}",
        location
    );

    // User should not have been created
    let user = store.get_user_by_username("expired-user").await.unwrap();
    assert!(
        user.is_none(),
        "user should not be created from expired token"
    );
}

#[tokio::test]
async fn oidc_callback_wrong_audience_rejected() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) =
        setup_test_app_with_config(Some("http://localhost:3140".to_string())).await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "WrongAud IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        true,
        None,
    )
    .await;

    let redirect_uri = "http://localhost:3140/api/v1/auth/oidc/callback";
    let (state_param, nonce) =
        create_auth_state_in_db(&*store, &provider_id, redirect_uri, 600).await;

    // Build ID token with wrong audience
    let id_token = build_id_token(
        &issuer,
        "WRONG-CLIENT-ID", // audience mismatch
        &nonce,
        "wrong-aud-sub",
        None,
        Some("wrong-aud-user"),
        None,
        3600,
    );
    mount_token_endpoint(&mock_idp, &id_token).await;

    let (status, headers) =
        send_callback(&app, &format!("code=authcode&state={}", state_param)).await;

    assert!(
        status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER,
        "got {}",
        status
    );
    let location = get_location(&headers);
    assert!(
        location.contains("oidc_error="),
        "wrong audience should fail: {}",
        location
    );
}

#[tokio::test]
async fn oidc_callback_wrong_nonce_rejected() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) =
        setup_test_app_with_config(Some("http://localhost:3140".to_string())).await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "WrongNonce IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        true,
        None,
    )
    .await;

    let redirect_uri = "http://localhost:3140/api/v1/auth/oidc/callback";
    let (state_param, _nonce) =
        create_auth_state_in_db(&*store, &provider_id, redirect_uri, 600).await;

    // Build ID token with wrong nonce
    let id_token = build_id_token(
        &issuer,
        "test-client",
        "WRONG-NONCE-VALUE",
        "wrong-nonce-sub",
        None,
        Some("wrong-nonce-user"),
        None,
        3600,
    );
    mount_token_endpoint(&mock_idp, &id_token).await;

    let (status, headers) =
        send_callback(&app, &format!("code=authcode&state={}", state_param)).await;

    assert!(
        status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER,
        "got {}",
        status
    );
    let location = get_location(&headers);
    assert!(
        location.contains("oidc_error="),
        "wrong nonce should fail: {}",
        location
    );
}

#[tokio::test]
async fn oidc_callback_token_exchange_failure() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) =
        setup_test_app_with_config(Some("http://localhost:3140".to_string())).await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "TokenFail IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        true,
        None,
    )
    .await;

    let redirect_uri = "http://localhost:3140/api/v1/auth/oidc/callback";
    let (state_param, _nonce) =
        create_auth_state_in_db(&*store, &provider_id, redirect_uri, 600).await;

    // Mount a token endpoint that returns an error
    Mock::given(wm_method("POST"))
        .and(wm_path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "authorization code expired"
        })))
        .mount(&mock_idp)
        .await;

    let (status, headers) =
        send_callback(&app, &format!("code=authcode&state={}", state_param)).await;

    assert!(
        status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER,
        "got {}",
        status
    );
    let location = get_location(&headers);
    assert!(
        location.contains("oidc_error="),
        "token exchange failure should redirect with error: {}",
        location
    );
}

#[tokio::test]
async fn oidc_callback_missing_id_token_in_response() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) =
        setup_test_app_with_config(Some("http://localhost:3140".to_string())).await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "NoIdToken IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        true,
        None,
    )
    .await;

    let redirect_uri = "http://localhost:3140/api/v1/auth/oidc/callback";
    let (state_param, _nonce) =
        create_auth_state_in_db(&*store, &provider_id, redirect_uri, 600).await;

    // Mount a token endpoint that returns access_token but no id_token
    Mock::given(wm_method("POST"))
        .and(wm_path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "some-access-token",
            "token_type": "Bearer",
        })))
        .mount(&mock_idp)
        .await;

    let (status, headers) =
        send_callback(&app, &format!("code=authcode&state={}", state_param)).await;

    assert!(
        status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER,
        "got {}",
        status
    );
    let location = get_location(&headers);
    assert!(
        location.contains("oidc_error="),
        "missing id_token should fail: {}",
        location
    );
}

// ===========================================================================
// Audit Event Tests
// ===========================================================================

#[tokio::test]
async fn oidc_audit_successful_login() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) =
        setup_test_app_with_config(Some("http://localhost:3140".to_string())).await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "Audit IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        true,
        None,
    )
    .await;

    let redirect_uri = "http://localhost:3140/api/v1/auth/oidc/callback";
    let (state_param, nonce) =
        create_auth_state_in_db(&*store, &provider_id, redirect_uri, 600).await;

    let id_token = build_id_token(
        &issuer,
        "test-client",
        &nonce,
        "audit-sub",
        None,
        Some("audit-user"),
        None,
        3600,
    );
    mount_token_endpoint(&mock_idp, &id_token).await;

    let (status, _) = send_callback(&app, &format!("code=authcode&state={}", state_param)).await;
    assert!(status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER);

    // Yield to let any pending async tasks complete
    tokio::task::yield_now().await;

    // Check audit events
    let events = store.list_audit_events(50, 0).await.unwrap();
    let oidc_success = events.iter().find(|e| e.action == "oidc_login_success");
    assert!(
        oidc_success.is_some(),
        "should have OidcLoginSuccess audit event. Events: {:?}",
        events.iter().map(|e| &e.action).collect::<Vec<_>>()
    );
    let event = oidc_success.unwrap();
    assert_eq!(event.user_name, Some("audit-user".to_string()));
    assert!(event.metadata["provider_name"]
        .as_str()
        .unwrap()
        .contains("Audit IdP"));
    assert!(event.metadata["oidc_subject"]
        .as_str()
        .unwrap()
        .contains("audit-sub"));
}

#[tokio::test]
async fn oidc_audit_failed_login_idp_error() {
    let (app, store, _enc) = setup_test_app().await;

    let (_status, _headers) =
        send_callback(&app, "error=access_denied&error_description=User+cancelled").await;

    // Yield to let any pending async tasks complete
    tokio::task::yield_now().await;

    let events = store.list_audit_events(50, 0).await.unwrap();
    let oidc_failed = events.iter().find(|e| e.action == "oidc_login_failed");
    assert!(
        oidc_failed.is_some(),
        "should have OidcLoginFailed audit event for IdP error. Events: {:?}",
        events.iter().map(|e| &e.action).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn oidc_audit_provider_crud() {
    let (app, store, _enc) = setup_test_app().await;
    create_admin_user(&*store).await;
    let cookie = login_user(&app, "admin-user", TEST_PASSWORD).await;

    // Create
    let (status, create_body) = create_provider_via_api(
        &app,
        &cookie,
        "Audit CRUD IdP",
        "https://audit-crud.example.com",
        "cid",
        "csec",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let provider_id = create_body["data"]["id"].as_str().unwrap();

    // Update
    let (status, _) = send_json(
        &app,
        Method::PUT,
        &format!("/api/v1/oidc-providers/{}", provider_id),
        Some(&cookie),
        Some(json!({ "name": "Renamed" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Delete
    let (status, _) = send_json(
        &app,
        Method::DELETE,
        &format!("/api/v1/oidc-providers/{}", provider_id),
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Check audit trail
    let events = store.list_audit_events(50, 0).await.unwrap();
    let actions: Vec<&str> = events.iter().map(|e| e.action.as_str()).collect();

    assert!(
        actions.contains(&"create"),
        "should have create event: {:?}",
        actions
    );
    assert!(
        actions.contains(&"update"),
        "should have update event: {:?}",
        actions
    );
    assert!(
        actions.contains(&"delete"),
        "should have delete event: {:?}",
        actions
    );
}

// ===========================================================================
// OIDC Auth State Cleanup Tests
// ===========================================================================

#[tokio::test]
async fn oidc_expired_state_cleanup() {
    let (_app, store, enc) = setup_test_app().await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "Cleanup IdP",
        "https://cleanup.example.com",
        "cid",
        "csec",
        true,
        true,
        None,
    )
    .await;

    // Create an expired state
    create_auth_state_in_db(&*store, &provider_id, "http://localhost/cb", -120).await;
    // Create a valid state
    let (valid_state, _) =
        create_auth_state_in_db(&*store, &provider_id, "http://localhost/cb", 600).await;

    // Run cleanup
    let cleaned = store.cleanup_expired_oidc_states().await.unwrap();
    assert!(
        cleaned >= 1,
        "should have cleaned up at least 1 expired state"
    );

    // Valid state should still exist
    let remaining = store.get_oidc_auth_state(&valid_state).await.unwrap();
    assert!(remaining.is_some(), "valid state should not be cleaned up");
}

// ===========================================================================
// Session Cookie Security Tests
// ===========================================================================

#[tokio::test]
async fn oidc_session_cookie_has_security_flags() {
    let mock_idp = setup_mock_idp().await;
    let issuer = mock_idp.uri();

    let (app, store, enc) =
        setup_test_app_with_config(Some("http://localhost:3140".to_string())).await;

    let provider_id = create_provider_in_db(
        &*store,
        &enc,
        "Cookie IdP",
        &issuer,
        "test-client",
        "test-secret",
        true,
        true,
        None,
    )
    .await;

    let redirect_uri = "http://localhost:3140/api/v1/auth/oidc/callback";
    let (state_param, nonce) =
        create_auth_state_in_db(&*store, &provider_id, redirect_uri, 600).await;

    let id_token = build_id_token(
        &issuer,
        "test-client",
        &nonce,
        "cookie-sub",
        None,
        Some("cookie-user"),
        None,
        3600,
    );
    mount_token_endpoint(&mock_idp, &id_token).await;

    let (status, headers) =
        send_callback(&app, &format!("code=authcode&state={}", state_param)).await;

    assert!(status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER);

    let cookies = get_set_cookies(&headers);

    // Session cookie must have HttpOnly and Secure flags
    let session_cookie = cookies
        .iter()
        .find(|c| c.contains("agtcrdn_session="))
        .unwrap();
    assert!(
        session_cookie.contains("HttpOnly"),
        "session cookie must be HttpOnly: {}",
        session_cookie
    );
    assert!(
        session_cookie.contains("Secure"),
        "session cookie must be Secure: {}",
        session_cookie
    );
    assert!(
        session_cookie.contains("SameSite=Lax"),
        "session cookie must have SameSite=Lax: {}",
        session_cookie
    );

    // CSRF cookie must NOT be HttpOnly (JS needs to read it)
    let csrf_cookie = cookies
        .iter()
        .find(|c| c.contains("agtcrdn_csrf="))
        .unwrap();
    assert!(
        !csrf_cookie.contains("HttpOnly"),
        "CSRF cookie must NOT be HttpOnly: {}",
        csrf_cookie
    );
    assert!(
        csrf_cookie.contains("Secure"),
        "CSRF cookie must be Secure: {}",
        csrf_cookie
    );
}

// ===========================================================================
// Edge Cases
// ===========================================================================

#[tokio::test]
async fn oidc_callback_both_code_and_error_params_error_takes_precedence() {
    let (app, _store, _enc) = setup_test_app().await;

    // Both error and code present — error should take precedence
    let (status, headers) =
        send_callback(&app, "code=authcode&state=some-state&error=server_error").await;

    assert!(
        status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER,
        "got {}",
        status
    );
    let location = get_location(&headers);
    assert!(
        location.contains("oidc_error="),
        "error should take precedence: {}",
        location
    );
}

#[tokio::test]
async fn oidc_callback_empty_params() {
    let (app, _store, _enc) = setup_test_app().await;

    // No params at all
    let (status, headers) = send_callback(&app, "").await;

    assert!(
        status == StatusCode::TEMPORARY_REDIRECT || status == StatusCode::SEE_OTHER,
        "got {}",
        status
    );
    let location = get_location(&headers);
    assert!(
        location.contains("oidc_error="),
        "empty params should fail: {}",
        location
    );
}
