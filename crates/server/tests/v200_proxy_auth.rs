//! v2.0 — Proxy authentication tests (SECURITY CRITICAL).
//!
//! Validates that the credential proxy endpoint requires workspace JWT auth
//! and rejects cookie auth, missing auth, wrong audience, and disabled workspaces.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::workspace::Workspace;

use crate::common::*;
use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn store_test_cred(
    state: &agent_cordon_server::state::AppState,
    owner: &Workspace,
) -> CredentialId {
    let now = chrono::Utc::now();
    let cred_id = CredentialId(Uuid::new_v4());
    let (encrypted, nonce) = state
        .encryptor
        .encrypt(b"test-secret-value", cred_id.0.to_string().as_bytes())
        .expect("encrypt");
    let cred = StoredCredential {
        id: cred_id.clone(),
        name: "auth-test-cred".to_string(),
        service: "test".to_string(),
        encrypted_value: encrypted,
        nonce,
        scopes: vec!["read".to_string()],
        metadata: json!({}),
        created_by: Some(owner.id.clone()),
        created_by_user: None,
        created_at: now,
        updated_at: now,
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: None,
        transform_name: None,
        vault: "default".to_string(),
        credential_type: "generic".to_string(),
        tags: vec![],
        key_version: 1,
    };
    state
        .store
        .store_credential(&cred)
        .await
        .expect("store credential");

    for perm in &["read", "write", "delete", "delegated_use"] {
        grant_cedar_permission(state, &cred_id, &owner.id, perm).await;
    }

    cred_id
}

/// Send a raw request with custom auth setup.
async fn send_proxy_raw(
    app: &axum::Router,
    auth_header: Option<&str>,
    cookie_header: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/proxy/execute")
        .header(header::CONTENT_TYPE, "application/json");

    if let Some(auth) = auth_header {
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    if let Some(cookie) = cookie_header {
        builder = builder.header(header::COOKIE, cookie);
    }

    let body_json = json!({
        "method": "GET",
        "url": "https://example.com/api?token={{auth-test-cred}}"
    });

    let request = builder
        .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));
    (status, json)
}

// ===========================================================================
// 1. No auth / cookie auth -> 401. Only workspace JWT works.
// ===========================================================================

#[tokio::test]
async fn test_proxy_workspace_jwt_auth_required() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let admin = ctx.admin_agent.as_ref().unwrap();
    let _cred_id = store_test_cred(&ctx.state, admin).await;

    // No auth at all -> 401
    let (status, _body) = send_proxy_raw(&ctx.app, None, None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "no auth header should be rejected"
    );

    // Cookie auth only -> rejected (proxy requires Bearer JWT, not cookies)
    let _user = create_user_in_db(
        &*ctx.store,
        "proxy-tester",
        TEST_PASSWORD,
        agent_cordon_core::domain::user::UserRole::Admin,
        false,
        true,
    )
    .await;
    let cookie = login_user_combined(&ctx.app, "proxy-tester", TEST_PASSWORD).await;
    let (status, _body) = send_proxy_raw(&ctx.app, None, Some(&cookie)).await;
    // Cookie auth identifies a User, not a Workspace. The proxy endpoint requires
    // workspace identity. The server returns 401 (no workspace auth) or 403
    // (user auth present but wrong principal type). Both indicate correct rejection.
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "cookie-only auth should be rejected for proxy, got {}",
        status
    );

    // Valid workspace JWT -> not 401
    let jwt = ctx_admin_jwt(&ctx).await;
    let (status, _body) = send_proxy_raw(&ctx.app, Some(&format!("Bearer {}", jwt)), None).await;
    assert_ne!(
        status,
        StatusCode::UNAUTHORIZED,
        "valid workspace JWT should not return 401"
    );
}

// ===========================================================================
// 2. Wrong audience JWT -> 401
// ===========================================================================

#[tokio::test]
async fn test_proxy_workspace_jwt_audience_enforced() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let admin = ctx.admin_agent.as_ref().unwrap();
    let _cred_id = store_test_cred(&ctx.state, admin).await;

    // Issue a JWT with a wrong audience
    let now = chrono::Utc::now();
    let wrong_aud_claims = json!({
        "sub": admin.id.0.to_string(),
        "aud": "wrong-audience",
        "iss": agent_cordon_core::auth::jwt::ISSUER,
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "jti": Uuid::new_v4().to_string(),
        "wkt": "test-workspace-key-thumbprint",
    });
    let wrong_jwt = ctx
        .state
        .jwt_issuer
        .sign_custom_claims(&wrong_aud_claims)
        .expect("sign wrong-aud JWT");

    let (status, _body) =
        send_proxy_raw(&ctx.app, Some(&format!("Bearer {}", wrong_jwt)), None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "wrong audience JWT should be rejected"
    );
}

// ===========================================================================
// 3. Disabled workspace -> rejected
// ===========================================================================

#[tokio::test]
async fn test_proxy_disabled_workspace_rejected() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("will-disable", &[])
        .build()
        .await;

    let ws = ctx.agents.get("will-disable").unwrap();
    let admin = ctx.admin_agent.as_ref().unwrap();

    // Store a credential owned by admin and grant to will-disable
    let cred_id = store_test_cred(&ctx.state, admin).await;
    grant_cedar_permission(&ctx.state, &cred_id, &ws.id, "delegated_use").await;
    grant_cedar_permission(&ctx.state, &cred_id, &ws.id, "read").await;

    // Get JWT while workspace is enabled
    let ws_jwt = ctx_agent_jwt(&ctx, "will-disable").await;

    // Disable the workspace
    let mut disabled_ws = ws.clone();
    disabled_ws.enabled = false;
    disabled_ws.updated_at = chrono::Utc::now();
    ctx.store
        .update_workspace(&disabled_ws)
        .await
        .expect("disable workspace");

    // Try proxy with the JWT from the now-disabled workspace
    let (status, body) = send_proxy_raw(&ctx.app, Some(&format!("Bearer {}", ws_jwt)), None).await;

    // The server should reject requests from disabled workspaces.
    // Acceptable responses: 401 (auth rejected) or 403 (forbidden).
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "disabled workspace should be rejected, got {} body: {}",
        status,
        body
    );
}
