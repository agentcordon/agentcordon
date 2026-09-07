//! Login lockout: failed attempts are counted per client address and
//! username, so one attacker cannot lock a user out for everyone.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

use crate::common::*;
use agent_cordon_server::test_helpers::TestAppBuilder;

async fn login_from(app: &axum::Router, addr: &str, username: &str, password: &str) -> StatusCode {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-forwarded-for", addr)
        .body(Body::from(
            serde_json::to_vec(&json!({ "username": username, "password": password })).unwrap(),
        ))
        .unwrap();
    app.clone().oneshot(req).await.unwrap().status()
}

/// Behind a trusted proxy, a burst of bad passwords from one address locks
/// that address out of the account, and nobody else.
#[tokio::test]
async fn lockout_from_one_address_does_not_lock_out_another() {
    let ctx = TestAppBuilder::new()
        .with_config(|c| {
            c.login_max_attempts = 3;
            c.trust_forwarded_headers = true;
        })
        .build()
        .await;
    create_root_user(&*ctx.store, "the-root", TEST_PASSWORD).await;

    for _ in 0..3 {
        assert_eq!(
            login_from(&ctx.app, "10.0.0.1", "the-root", "wrong-password").await,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        login_from(&ctx.app, "10.0.0.1", "the-root", TEST_PASSWORD).await,
        StatusCode::TOO_MANY_REQUESTS,
        "the attacking address is locked out even with the right password"
    );
    assert_eq!(
        login_from(&ctx.app, "10.0.0.2", "the-root", TEST_PASSWORD).await,
        StatusCode::OK,
        "root logs in from elsewhere"
    );
}

async fn approve_from(
    app: &axum::Router,
    addr: &str,
    cookie: &str,
    csrf: &str,
    user_code: &str,
) -> (StatusCode, Vec<(String, String)>) {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/oauth/device/approve")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, cookie)
        .header("x-csrf-token", csrf)
        .header("x-forwarded-for", addr)
        .body(Body::from(
            serde_json::to_vec(&json!({ "user_code": user_code, "public_key_hash": "" })).unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let headers = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    (resp.status(), headers)
}

/// Guessing user codes through the approve API is limited per address and
/// session. Without a trusted proxy, the forwarded header is ignored, so
/// rotating it does not reset the budget.
#[tokio::test]
async fn device_approve_limit_ignores_forwarded_header_unless_trusted() {
    let ctx = TestAppBuilder::new()
        .with_config(|c| c.trust_forwarded_headers = false)
        .build()
        .await;
    create_root_user(&*ctx.store, "approver", TEST_PASSWORD).await;
    let (cookie, csrf) = login_user(&ctx.app, "approver", TEST_PASSWORD).await;
    let cookie = combined_cookie(&cookie, &csrf);

    for i in 0..10 {
        let (status, _) = approve_from(
            &ctx.app,
            &format!("10.0.0.{i}"),
            &cookie,
            &csrf,
            "nope-nope-nope-nope",
        )
        .await;
        assert!(
            status.is_client_error(),
            "bad code is a client error: {status}"
        );
    }
    let (status, headers) = approve_from(
        &ctx.app,
        "10.0.0.250",
        &cookie,
        &csrf,
        "nope-nope-nope-nope",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "11th guess is limited"
    );
    assert!(
        headers.iter().any(|(k, _)| k == "retry-after"),
        "limited response carries Retry-After"
    );
}

/// Without a trusted proxy the forwarded header is attacker-controlled and
/// is ignored: every caller shares one address bucket, so the header cannot
/// be rotated to escape the limit.
#[tokio::test]
async fn forwarded_header_is_ignored_unless_trusted() {
    let ctx = TestAppBuilder::new()
        .with_config(|c| {
            c.login_max_attempts = 3;
            c.trust_forwarded_headers = false;
        })
        .build()
        .await;
    create_root_user(&*ctx.store, "the-root", TEST_PASSWORD).await;

    for i in 0..3 {
        login_from(
            &ctx.app,
            &format!("10.0.0.{i}"),
            "the-root",
            "wrong-password",
        )
        .await;
    }
    assert_eq!(
        login_from(&ctx.app, "10.0.0.99", "the-root", TEST_PASSWORD).await,
        StatusCode::TOO_MANY_REQUESTS,
        "rotating the header does not escape the lockout"
    );
}
