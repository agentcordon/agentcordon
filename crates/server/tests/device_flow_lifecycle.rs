//! RFC 8628 device flow lifecycle/resource tests — v0.3.0.
//!
//! Source: `docs/internal/plan/test-designs-v0.3.0.md` §5.
//! One `#[tokio::test]` per TC-LIFE-* case. Written speculatively against
//! the documented API shape; `#[ignore]` until BE-1 lands the endpoints
//! and the `AGTCRDN_DEVICE_CODE_TTL_SECS` override.

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

// TC-LIFE-001: sweeper removes rows where expires_at < now - 1h
#[tokio::test]
#[ignore = "pending BE-1 sweeper + clock override"]
async fn tc_life_001_sweeper_removes_expired_rows() {}

// TC-LIFE-002: sweeper emits DeviceCodeExpired once per row
#[tokio::test]
#[ignore = "pending BE-1 sweeper + audit dedup"]
async fn tc_life_002_sweeper_emits_expired_audit_once() {}

// TC-LIFE-003: two concurrent device flows succeed independently
#[tokio::test]
// un-ignored: slice 3 device_code endpoint live
async fn tc_life_003_two_concurrent_device_flows_independent() {
    let app = setup().await;
    let a = request_device_code(&app).await;
    let b = request_device_code(&app).await;
    assert_ne!(a["device_code"], b["device_code"]);
    assert_ne!(a["user_code"], b["user_code"]);
}

// TC-LIFE-004: server restart mid-flow — state persists to DB
#[tokio::test]
#[ignore = "pending BE-1 persistence + restart helper"]
async fn tc_life_004_restart_mid_flow_preserves_state() {}

// TC-LIFE-005: last_polled_at persisted across restart
#[tokio::test]
#[ignore = "pending BE-1 persistence + restart helper"]
async fn tc_life_005_last_polled_at_persists() {}

// TC-LIFE-006: clock skew (backward jump) tolerated — no permanent slow_down
#[tokio::test]
#[ignore = "pending BE-1 device flow endpoints + clock injection"]
async fn tc_life_006_clock_skew_tolerated() {}

// TC-LIFE-007: duplicate user_code on insert retries with a fresh code
#[tokio::test]
#[ignore = "pending BE-1 device flow endpoints + RNG injection"]
async fn tc_life_007_user_code_collision_retry() {}

// TC-LIFE-008: TTL boundary precision (accepted @ +599s, rejected @ +601s)
#[tokio::test]
#[ignore = "pending AGTCRDN_DEVICE_CODE_TTL_SECS override from BE-1"]
async fn tc_life_008_ttl_boundary_precision() {}
