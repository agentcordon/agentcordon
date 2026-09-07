//! RFC 8628 device flow lifecycle tests.
//!
//! Drives the in-process router built by `TestAppBuilder`. Cases that need
//! a clock override, a restart helper, or RNG injection (sweeper timing,
//! TTL boundaries, user-code collision retry) have no harness support yet
//! and are not stubbed here; add them when the seam exists.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use agent_cordon_server::test_helpers::TestAppBuilder;

const BOOTSTRAP_CLIENT_ID: &str = "agentcordon-broker";

async fn post_form(app: &Router, uri: &str, body: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

async fn setup() -> Router {
    TestAppBuilder::new().with_admin().build().await.app
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

/// Two concurrent device flows get distinct device and user codes.
#[tokio::test]
async fn two_concurrent_device_flows_are_independent() {
    let app = setup().await;
    let a = request_device_code(&app).await;
    let b = request_device_code(&app).await;
    assert_ne!(a["device_code"], b["device_code"]);
    assert_ne!(a["user_code"], b["user_code"]);
}
