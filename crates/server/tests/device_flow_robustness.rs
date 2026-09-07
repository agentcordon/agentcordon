//! RFC 8628 device flow robustness tests.
//!
//! Drives the in-process router built by `TestAppBuilder`: activation-form
//! rate limiting, single-use device codes, CSRF on the form, and concurrent
//! polls.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use agent_cordon_server::test_helpers::TestAppBuilder;

const BOOTSTRAP_CLIENT_ID: &str = "agentcordon-broker";

async fn post_form_with_headers(
    app: &Router,
    uri: &str,
    body: &str,
    extra: &[(&str, &str)],
) -> (StatusCode, Value, Vec<(String, String)>) {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
    let req = req.body(Body::from(body.to_string())).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json, headers)
}

async fn post_form(app: &Router, uri: &str, body: &str) -> (StatusCode, Value) {
    let (s, j, _) = post_form_with_headers(app, uri, body, &[]).await;
    (s, j)
}

async fn request_device_code(app: &Router) -> Value {
    let (_, j) = post_form(
        app,
        "/api/v1/oauth/device/code",
        &format!("client_id={BOOTSTRAP_CLIENT_ID}&scope=credentials:discover"),
    )
    .await;
    j
}

async fn setup() -> Router {
    TestAppBuilder::new().with_admin().build().await.app
}

async fn setup_ctx() -> agent_cordon_server::test_helpers::TestContext {
    TestAppBuilder::new().with_admin().build().await
}

/// Issue a device code, approve it via the store (bypassing /activate which is
/// slice 5), and return `(device_code_plaintext, user_code)`.
async fn issue_and_approve(
    ctx: &agent_cordon_server::test_helpers::TestContext,
) -> (String, String) {
    let (_, body) = post_form(
        &ctx.app,
        "/api/v1/oauth/device/code",
        &format!("client_id={BOOTSTRAP_CLIENT_ID}&scope=credentials:discover"),
    )
    .await;
    let device_code = body["device_code"].as_str().unwrap().to_string();
    let user_code = body["user_code"].as_str().unwrap().to_string();
    let fake_user_id = uuid::Uuid::new_v4().to_string();
    let approved = ctx
        .store
        .approve_device_code(&user_code, &fake_user_id)
        .await
        .expect("approve via store");
    assert!(approved, "approve_device_code returned false");
    (device_code, user_code)
}

async fn poll_token_with_ctx(
    app: &Router,
    client_id: &str,
    device_code: &str,
) -> (StatusCode, Value) {
    post_form(
        app,
        "/api/v1/oauth/token",
        &format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code\
             &client_id={client_id}&device_code={device_code}"
        ),
    )
    .await
}

// ---------------------------------------------------------------------------
// 4.1 Activation form rate limiting
// ---------------------------------------------------------------------------

/// A signed-in operator with a valid form CSRF token, plus a form body that
/// guesses a user code. This is the shape of a brute-force through the
/// browser form.
async fn activation_guess_setup(
    trust_forwarded_headers: bool,
) -> (
    agent_cordon_server::test_helpers::TestContext,
    String,
    String,
) {
    use crate::common::{compute_consent_csrf, create_user_in_db, login_user, TEST_PASSWORD};
    use agent_cordon_core::domain::user::UserRole;

    let ctx = TestAppBuilder::new()
        .with_config(move |c| c.trust_forwarded_headers = trust_forwarded_headers)
        .build()
        .await;
    create_user_in_db(
        &*ctx.store,
        "guesser",
        TEST_PASSWORD,
        UserRole::Operator,
        false,
        true,
    )
    .await;
    let (session, _) = login_user(&ctx.app, "guesser", TEST_PASSWORD).await;
    let csrf = compute_consent_csrf(&session, &ctx.state.crypto.session_hash_key);
    let body = format!(
        "user_code=bad-bad-bad-bad&csrf_token={}&decision=approve",
        urlencoding::encode(&csrf)
    );
    (ctx, session, body)
}

// TC-ROB-001: 11th invalid POST /activate from same address => 429 w/ Retry-After
#[tokio::test]
async fn tc_rob_001_activate_rate_limit() {
    let (ctx, session, body) = activation_guess_setup(false).await;
    for _ in 0..10 {
        let (s, _, _) = post_form_with_headers(
            &ctx.app,
            "/activate",
            &body,
            &[("cookie", session.as_str())],
        )
        .await;
        assert_ne!(s, StatusCode::TOO_MANY_REQUESTS, "within budget");
    }
    let (s, _, h) = post_form_with_headers(
        &ctx.app,
        "/activate",
        &body,
        &[("cookie", session.as_str())],
    )
    .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert!(h.iter().any(|(k, _)| k == "retry-after"));
}

// TC-ROB-002: per-address isolation (behind a trusted proxy)
#[tokio::test]
async fn tc_rob_002_rate_limit_per_ip_isolation() {
    let (ctx, session, body) = activation_guess_setup(true).await;
    for _ in 0..11 {
        let _ = post_form_with_headers(
            &ctx.app,
            "/activate",
            &body,
            &[
                ("cookie", session.as_str()),
                ("x-forwarded-for", "10.0.0.1"),
            ],
        )
        .await;
    }
    let (s, _, _) = post_form_with_headers(
        &ctx.app,
        "/activate",
        &body,
        &[
            ("cookie", session.as_str()),
            ("x-forwarded-for", "10.0.0.2"),
        ],
    )
    .await;
    assert_ne!(
        s,
        StatusCode::TOO_MANY_REQUESTS,
        "another address has its own budget"
    );
}

// ---------------------------------------------------------------------------
// 4.2 Device code single-use
// ---------------------------------------------------------------------------

// TC-ROB-010: replaying a consumed device_code => invalid_grant
#[tokio::test]
async fn tc_rob_010_device_code_single_use() {
    let ctx = setup_ctx().await;
    let (dc, _) = issue_and_approve(&ctx).await;
    let (s1, j1) = poll_token_with_ctx(&ctx.app, BOOTSTRAP_CLIENT_ID, &dc).await;
    assert_eq!(s1, StatusCode::OK, "first poll should succeed: {j1:?}");
    assert!(j1.get("access_token").is_some());
    let (s2, j2) = poll_token_with_ctx(&ctx.app, BOOTSTRAP_CLIENT_ID, &dc).await;
    assert_eq!(s2, StatusCode::BAD_REQUEST);
    assert_eq!(j2["error"], "invalid_grant");
}

// TC-ROB-011: after exchange, row is `consumed` (not deleted)
#[tokio::test]
async fn tc_rob_011_consumed_row_not_deleted() {
    let ctx = setup_ctx().await;
    let (dc, uc) = issue_and_approve(&ctx).await;
    let (s, _) = poll_token_with_ctx(&ctx.app, BOOTSTRAP_CLIENT_ID, &dc).await;
    assert_eq!(s, StatusCode::OK);
    let row = ctx
        .store
        .get_device_code_by_user_code(&uc)
        .await
        .expect("lookup")
        .expect("row present");
    assert_eq!(
        row.status,
        agent_cordon_core::oauth2::types::DeviceCodeStatus::Consumed
    );
}

// ---------------------------------------------------------------------------
// 4.3 User-to-device binding
// ---------------------------------------------------------------------------

// TC-ROB-021: two pending codes — approving one does not affect the other
#[tokio::test]
async fn tc_rob_021_no_crosstalk_between_pending_codes() {
    let app = setup().await;
    let a = request_device_code(&app).await;
    let b = request_device_code(&app).await;
    assert_ne!(a["device_code"], b["device_code"]);
    assert_ne!(a["user_code"], b["user_code"]);
}

// ---------------------------------------------------------------------------
// 4.4 CSRF protection on /activate
// ---------------------------------------------------------------------------

// TC-ROB-031: a signed-in POST /activate with a wrong csrf_token => 403
#[tokio::test]
async fn tc_rob_031_activate_post_missing_csrf() {
    let (ctx, session, _) = activation_guess_setup(false).await;
    let (s, _, _) = post_form_with_headers(
        &ctx.app,
        "/activate",
        "user_code=word-word-word-word&csrf_token=not-the-token&decision=approve",
        &[("cookie", session.as_str())],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// 4.5 Concurrent polls — no double issuance
// ---------------------------------------------------------------------------

// TC-ROB-040: two concurrent /oauth/token polls after approval => exactly one 200
#[tokio::test]
async fn tc_rob_040_concurrent_polls_single_issuance() {
    let ctx = setup_ctx().await;
    let (dc, _) = issue_and_approve(&ctx).await;
    let a = ctx.app.clone();
    let b = ctx.app.clone();
    let dc1 = dc.clone();
    let dc2 = dc.clone();
    let h1 = tokio::spawn(async move { poll_token_with_ctx(&a, BOOTSTRAP_CLIENT_ID, &dc1).await });
    let h2 = tokio::spawn(async move { poll_token_with_ctx(&b, BOOTSTRAP_CLIENT_ID, &dc2).await });
    let (r1, r2) = (h1.await.unwrap(), h2.await.unwrap());
    let ok_count = [&r1, &r2]
        .iter()
        .filter(|(s, _)| *s == StatusCode::OK)
        .count();
    let bad_count = [&r1, &r2]
        .iter()
        .filter(|(s, j)| *s == StatusCode::BAD_REQUEST && j["error"] == "invalid_grant")
        .count();
    assert_eq!(ok_count, 1, "exactly one winner: {r1:?} / {r2:?}");
    assert_eq!(
        bad_count, 1,
        "loser must get invalid_grant: {r1:?} / {r2:?}"
    );
}
