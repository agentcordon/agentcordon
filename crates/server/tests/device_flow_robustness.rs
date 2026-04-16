//! RFC 8628 device flow robustness tests — v0.3.0.
//!
//! Source: `docs/internal/plan/test-designs-v0.3.0.md` §4.
//! One `#[tokio::test]` per TC-ROB-* case. Written speculatively against
//! the documented API shape; `#[ignore]` until BE-1 lands the endpoints.

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

// TC-ROB-001: 11th invalid POST /activate from same IP => 429 w/ Retry-After
#[tokio::test]
#[ignore = "pending BE-1 /activate endpoint + rate limiter"]
async fn tc_rob_001_activate_rate_limit() {
    let app = setup().await;
    for _ in 0..10 {
        let (_, _, _) = post_form_with_headers(
            &app,
            "/activate",
            "user_code=bad-bad-bad-bad&csrf_token=x&decision=approve",
            &[("x-forwarded-for", "10.0.0.1")],
        )
        .await;
    }
    let (s, _, h) = post_form_with_headers(
        &app,
        "/activate",
        "user_code=bad-bad-bad-bad&csrf_token=x&decision=approve",
        &[("x-forwarded-for", "10.0.0.1")],
    )
    .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert!(h.iter().any(|(k, _)| k == "retry-after"));
}

// TC-ROB-002: per-IP rate limit isolation
#[tokio::test]
#[ignore = "pending BE-1 /activate endpoint + rate limiter"]
async fn tc_rob_002_rate_limit_per_ip_isolation() {
    let app = setup().await;
    for _ in 0..11 {
        let _ = post_form_with_headers(
            &app,
            "/activate",
            "user_code=bad-bad-bad-bad&csrf_token=x&decision=approve",
            &[("x-forwarded-for", "10.0.0.1")],
        )
        .await;
    }
    let (s, _, _) = post_form_with_headers(
        &app,
        "/activate",
        "user_code=bad-bad-bad-bad&csrf_token=x&decision=approve",
        &[("x-forwarded-for", "10.0.0.2")],
    )
    .await;
    assert_ne!(s, StatusCode::TOO_MANY_REQUESTS);
}

// TC-ROB-003: valid code during lockout still fails
#[tokio::test]
#[ignore = "pending BE-1 /activate endpoint + rate limiter"]
async fn tc_rob_003_valid_code_during_lockout_fails() {}

// TC-ROB-004: 429 emits an audit event
#[tokio::test]
#[ignore = "pending BE-1 /activate endpoint + rate limiter + audit hook"]
async fn tc_rob_004_rate_limit_audit_event() {}

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

// TC-ROB-020: approving user becomes workspace owner
#[tokio::test]
#[ignore = "pending BE-1 /activate + multi-user session helper"]
async fn tc_rob_020_approving_user_owns_workspace() {}

// TC-ROB-021: two pending codes — approving one does not affect the other
#[tokio::test]
#[ignore = "pending BE-1 /activate endpoint"]
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

// TC-ROB-030: GET /activate renders csrf_token hidden field
#[tokio::test]
#[ignore = "pending BE-1 /activate GET template"]
async fn tc_rob_030_activate_get_has_csrf_field() {}

// TC-ROB-031: POST /activate without csrf_token => 403
#[tokio::test]
#[ignore = "pending BE-1 /activate endpoint"]
async fn tc_rob_031_activate_post_missing_csrf() {
    let app = setup().await;
    let (s, _) = post_form(
        &app,
        "/activate",
        "user_code=word-word-word-word&decision=approve",
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

// TC-ROB-032: csrf_token from different session => 403
#[tokio::test]
#[ignore = "pending BE-1 /activate + session helper"]
async fn tc_rob_032_activate_post_cross_session_csrf() {}

// TC-ROB-033: cross-origin w/ no matching session cookie => 403
#[tokio::test]
#[ignore = "pending BE-1 /activate endpoint"]
async fn tc_rob_033_activate_cross_origin_no_session() {}

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

// TC-ROB-041: single DeviceCodeApproved-consumed + single Oauth2TokenAcquired
#[tokio::test]
#[ignore = "pending BE-1 /activate + audit hook"]
async fn tc_rob_041_concurrent_polls_audit_dedup() {}

// ---------------------------------------------------------------------------
// 4.6 User-code entropy / guessability
// ---------------------------------------------------------------------------

// TC-ROB-050: user_code namespace >= 2^42 (4 words, >=1296 per word)
#[tokio::test]
#[ignore = "pending BE-1 device flow + wordlist module"]
async fn tc_rob_050_user_code_entropy() {}

// TC-ROB-051: GET /activate?user_code=<guess> reveals nothing about validity
#[tokio::test]
#[ignore = "pending BE-1 /activate GET endpoint"]
async fn tc_rob_051_get_activate_does_not_leak_validity() {}
