//! `GET /api/v1/oauth/authorize` gates the new-workspace path.
//!
//! Presenting `public_key_hash` + `workspace_name` (and no `client_id`) is a
//! request to create a workspace and an OAuth client for a caller-supplied
//! key hash. It used to be gated only on having a session, so any signed-in
//! user could reach the form for any key hash — and the workspace-identity
//! list handed those hashes out. Both the GET that renders the consent page
//! and the POST that submits it now require the same manage-workspaces
//! permission the device-flow approve route requires.
//!
//! The POST side (re-registration of an existing hash, revoked workspaces,
//! non-owners) is covered in `authorization.rs`. This module covers the GET,
//! and shows the gate is specific to the new-workspace path: consenting to
//! an *existing* client is unchanged.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

use crate::common::{
    create_test_user, create_user_in_db, login_user_combined, send_json_auto_csrf, TEST_PASSWORD,
};

const PK_HASH: &str = "b1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
const REDIRECT_URI: &str = "http://localhost:9876/callback";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// `GET /api/v1/oauth/authorize` with the given query, as `cookie` (or
/// unauthenticated when `cookie` is `None`).
async fn authorize(
    ctx: &TestContext,
    cookie: Option<&str>,
    query: &str,
) -> (StatusCode, Option<String>) {
    let mut req = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/v1/oauth/authorize?{query}"));
    if let Some(c) = cookie {
        req = req.header(header::COOKIE, c);
    }
    let response = ctx
        .app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    (status, location)
}

fn new_workspace_query(name: &str) -> String {
    format!(
        "response_type=code&redirect_uri={}&scope=credentials:discover&state=s\
         &code_challenge={CHALLENGE}&code_challenge_method=S256\
         &public_key_hash={PK_HASH}&workspace_name={name}",
        urlencoding::encode(REDIRECT_URI),
    )
}

/// A viewer has a session but no manage-workspaces. Without the gate they
/// reach the consent form for any key hash they can name.
#[tokio::test]
async fn a_user_without_manage_workspaces_cannot_open_the_new_workspace_consent_page() {
    let ctx = TestAppBuilder::new().build().await;
    create_user_in_db(
        &*ctx.store,
        "gate-viewer",
        TEST_PASSWORD,
        UserRole::Viewer,
        false,
        true,
    )
    .await;
    let viewer = login_user_combined(&ctx.app, "gate-viewer", TEST_PASSWORD).await;

    let (status, _) = authorize(&ctx, Some(&viewer), &new_workspace_query("gate-ws")).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a viewer must not reach the new-workspace consent form"
    );
}

/// The counterpart: an operator holds manage-workspaces, so the page renders.
#[tokio::test]
async fn a_user_with_manage_workspaces_gets_the_new_workspace_consent_page() {
    let ctx = TestAppBuilder::new().build().await;
    create_test_user(&*ctx.store, "gate-op", TEST_PASSWORD, UserRole::Operator).await;
    let operator = login_user_combined(&ctx.app, "gate-op", TEST_PASSWORD).await;

    let (status, _) = authorize(&ctx, Some(&operator), &new_workspace_query("gate-ws")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an operator may register a workspace"
    );
}

/// No session at all is a browser visitor, not an attacker: send them to
/// log in and bring them back, rather than answering a JSON 401.
#[tokio::test]
async fn an_unauthenticated_visitor_is_sent_to_the_login_page() {
    let ctx = TestAppBuilder::new().build().await;

    let (status, location) = authorize(&ctx, None, &new_workspace_query("gate-ws")).await;
    assert!(
        status.is_redirection(),
        "expected a redirect to login, got {status}"
    );
    let location = location.expect("Location header");
    assert!(
        location.starts_with("/login?next="),
        "the visitor comes back to the authorize URL: {location}"
    );
    assert!(
        location.contains("oauth%2Fauthorize"),
        "the `next` param names the authorize route: {location}"
    );
}

/// The gate belongs to the new-workspace path only. Consenting to a client
/// that already exists is a user deciding about their own account, and a
/// viewer may still do it — so a blanket permission check on the whole
/// route would be wrong.
#[tokio::test]
async fn consenting_to_an_existing_client_needs_no_workspace_permission() {
    let ctx = TestAppBuilder::new().build().await;
    create_user_in_db(
        &*ctx.store,
        "gate-admin",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;
    create_user_in_db(
        &*ctx.store,
        "gate-viewer",
        TEST_PASSWORD,
        UserRole::Viewer,
        false,
        true,
    )
    .await;
    let admin = login_user_combined(&ctx.app, "gate-admin", TEST_PASSWORD).await;
    let viewer = login_user_combined(&ctx.app, "gate-viewer", TEST_PASSWORD).await;

    // Root registers the client; the viewer only consents to it.
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/oauth/clients",
        None,
        Some(&admin),
        Some(json!({
            "workspace_name": "gate-existing",
            "public_key_hash": PK_HASH,
            "scopes": ["credentials:discover"],
            "redirect_uris": [REDIRECT_URI],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "register client: {body}");
    let client_id = body["data"]["client_id"].as_str().unwrap().to_string();

    let query = format!(
        "response_type=code&redirect_uri={}&scope=credentials:discover&state=s\
         &code_challenge={CHALLENGE}&code_challenge_method=S256&client_id={}",
        urlencoding::encode(REDIRECT_URI),
        urlencoding::encode(&client_id),
    );
    let (status, _) = authorize(&ctx, Some(&viewer), &query).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a viewer may consent to an existing client"
    );
}
