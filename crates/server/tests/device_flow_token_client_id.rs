//! P0 regression: device_code grant must return the per-workspace `client_id`
//! in its TokenResponse, not just access/refresh tokens.
//!
//! Background. The broker authenticates the device-code request with the
//! well-known bootstrap `agentcordon-broker` client_id. On approval, the
//! server mints a fresh per-workspace OAuth client (see
//! `routes/oauth/consent.rs::generate_client_id`) and stamps the issued
//! refresh token's `client_id` to that per-workspace value. If the broker
//! does not learn this per-workspace client_id, every subsequent
//! `grant_type=refresh_token` call sends `client_id=agentcordon-broker`
//! and the server rejects it with `invalid_grant: client_id mismatch` —
//! the user is forced to re-register every ~2h when the access token expires.
//!
//! This test pins the protocol contract: the device_code TokenResponse
//! includes the per-workspace `client_id` so the broker can persist and
//! echo it on refresh.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::{compute_consent_csrf, create_user_in_db, login_user, TEST_PASSWORD};

const BOOTSTRAP_CLIENT_ID: &str = "agentcordon-broker";
const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
const TEST_PK_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";

async fn post_form_with_cookie(
    app: &Router,
    uri: &str,
    body: &str,
    cookie: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(c) = cookie {
        builder = builder.header(header::COOKIE, c);
    }
    let req = builder.body(Body::from(body.to_string())).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

#[tokio::test]
async fn device_code_grant_returns_per_workspace_client_id() {
    let ctx = TestAppBuilder::new().build().await;

    create_user_in_db(
        &*ctx.store,
        "approver",
        TEST_PASSWORD,
        UserRole::Operator,
        false,
        true,
    )
    .await;
    let (session_cookie, _csrf) = login_user(&ctx.app, "approver", TEST_PASSWORD).await;

    // 1. Issue a device_code with workspace_name + pk_hash prefill — the same
    //    shape the broker sends on `agentcordon register`.
    let workspace_name = "client-id-roundtrip-ws";
    let issue_body = format!(
        "client_id={BOOTSTRAP_CLIENT_ID}&scope=credentials:discover&\
         workspace_name={workspace_name}&public_key_hash={TEST_PK_HASH}"
    );
    let (s, body) =
        post_form_with_cookie(&ctx.app, "/api/v1/oauth/device/code", &issue_body, None).await;
    assert_eq!(s, StatusCode::OK, "device_code issue: {body}");
    let device_code = body["device_code"].as_str().unwrap().to_string();
    let user_code = body["user_code"].as_str().unwrap().to_string();

    // 2. Approve via UI (mints the per-workspace OAuth client).
    let csrf = compute_consent_csrf(&session_cookie, &ctx.state.crypto.session_hash_key);
    let activate_body = format!(
        "csrf_token={}&user_code={}&decision=approve",
        urlencoding::encode(&csrf),
        urlencoding::encode(&user_code),
    );
    let (s, _) =
        post_form_with_cookie(&ctx.app, "/activate", &activate_body, Some(&session_cookie)).await;
    assert_eq!(s, StatusCode::SEE_OTHER, "approve");

    // 3. Look up the per-workspace OAuth client the server minted at consent.
    //    This is the value the refresh token's `client_id` is stamped with.
    let client = ctx
        .store
        .get_oauth_client_by_public_key_hash(TEST_PK_HASH)
        .await
        .expect("client lookup")
        .expect("workspace OAuth client must exist after approve");
    let workspace_client_id = client.client_id.clone();
    assert_ne!(
        workspace_client_id, BOOTSTRAP_CLIENT_ID,
        "sanity: the workspace client_id must NOT equal the bootstrap"
    );

    // 4. Exchange the device_code and assert the response surfaces the
    //    per-workspace client_id (NOT the bootstrap client_id the broker
    //    used to authenticate the device-code request).
    let token_body = format!(
        "grant_type={DEVICE_GRANT_TYPE}&client_id={BOOTSTRAP_CLIENT_ID}&device_code={device_code}"
    );
    let (s, body) = post_form_with_cookie(&ctx.app, "/api/v1/oauth/token", &token_body, None).await;
    assert_eq!(s, StatusCode::OK, "token exchange: {body}");

    let returned_client_id = body
        .get("client_id")
        .and_then(Value::as_str)
        .expect("token response must include client_id");
    assert_eq!(
        returned_client_id, workspace_client_id,
        "token response client_id must match the per-workspace OAuth client (so the \
         broker persists the right value and refresh_token grant survives)"
    );
    assert_ne!(
        returned_client_id, BOOTSTRAP_CLIENT_ID,
        "token response must NOT echo the bootstrap client_id used to authenticate the \
         device-code request — that is the bug we are fixing"
    );
}
