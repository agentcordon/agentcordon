//! RFC 8628 Device Authorization Grant conformance tests — v0.3.0.
//!
//! Source: `docs/internal/plan/test-designs-v0.3.0.md` §3.
//! One `#[tokio::test]` per TC-CONF-* case. Tests drive the in-process
//! router built by `TestAppBuilder` — no external HTTP, no real clocks.
//!
//! Tests are `#[ignore]` until BE-1 (task #3) lands the device flow
//! endpoints; they are written speculatively against the API shape
//! documented in the test designs doc.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Local helpers (scoped to this file only — do not edit test_helpers.rs)
// ---------------------------------------------------------------------------

const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
const BOOTSTRAP_CLIENT_ID: &str = "agentcordon-broker";

async fn post_form(
    app: &Router,
    uri: &str,
    body: &str,
) -> (StatusCode, Value, Vec<(String, String)>) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap();
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

async fn request_device_code(app: &Router, client_id: &str, scope: &str) -> (StatusCode, Value) {
    let body = format!("client_id={client_id}&scope={scope}");
    let (s, j, _) = post_form(app, "/api/v1/oauth/device/code", &body).await;
    (s, j)
}

async fn poll_token(app: &Router, client_id: &str, device_code: &str) -> (StatusCode, Value) {
    let body =
        format!("grant_type={DEVICE_GRANT_TYPE}&client_id={client_id}&device_code={device_code}");
    let (s, j, _) = post_form(app, "/api/v1/oauth/token", &body).await;
    (s, j)
}

async fn setup() -> Router {
    TestAppBuilder::new().with_admin().build().await.app
}

// ---------------------------------------------------------------------------
// 3.1 POST /oauth/device/code response shape
// ---------------------------------------------------------------------------

// TC-CONF-001: response shape has all RFC 8628 §3.2 fields
#[tokio::test]
// un-ignored: device_code endpoint live (slice 3)
async fn tc_conf_001_device_code_response_shape() {
    let app = setup().await;
    let (status, body) = request_device_code(
        &app,
        BOOTSTRAP_CLIENT_ID,
        "credentials:discover+credentials:vend",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.get("device_code").and_then(Value::as_str).is_some());
    assert!(body.get("user_code").and_then(Value::as_str).is_some());
    assert!(body
        .get("verification_uri")
        .and_then(Value::as_str)
        .is_some_and(|u| u.ends_with("/activate")));
    assert!(body
        .get("verification_uri_complete")
        .and_then(Value::as_str)
        .is_some_and(|u| u.contains("/activate?user_code=")));
    assert_eq!(body.get("expires_in").and_then(Value::as_i64), Some(600));
    assert_eq!(body.get("interval").and_then(Value::as_i64), Some(5));
}

// TC-CONF-002: user_code is 4 lowercase EFF-short words separated by '-'
#[tokio::test]
// un-ignored: device_code endpoint live (slice 3)
async fn tc_conf_002_user_code_shape() {
    let app = setup().await;
    let (_, body) = request_device_code(&app, BOOTSTRAP_CLIENT_ID, "credentials:discover").await;
    let uc = body["user_code"].as_str().unwrap();
    let words: Vec<&str> = uc.split('-').collect();
    assert_eq!(words.len(), 4, "user_code {uc} must be 4 words");
    for w in &words {
        assert!(!w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase()));
    }
}

// TC-CONF-003: device_code has >=128 bits of entropy; two sequential calls differ
#[tokio::test]
// un-ignored: device_code endpoint live (slice 3)
async fn tc_conf_003_device_code_entropy_and_uniqueness() {
    let app = setup().await;
    let (_, a) = request_device_code(&app, BOOTSTRAP_CLIENT_ID, "credentials:discover").await;
    let (_, b) = request_device_code(&app, BOOTSTRAP_CLIENT_ID, "credentials:discover").await;
    let a_dc = a["device_code"].as_str().unwrap();
    let b_dc = b["device_code"].as_str().unwrap();
    assert_ne!(a_dc, b_dc);
    assert!(
        a_dc.len() >= 22,
        "device_code {a_dc} shorter than 128 bits base64url"
    );
}

// TC-CONF-004: missing client_id => 400 invalid_request
#[tokio::test]
async fn tc_conf_004_missing_client_id() {
    let app = setup().await;
    let (s, j, _) = post_form(
        &app,
        "/api/v1/oauth/device/code",
        "scope=credentials:discover",
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(j["error"], "invalid_request");
}

// TC-CONF-005: unknown client_id => 401 invalid_client
#[tokio::test]
async fn tc_conf_005_unknown_client_id() {
    let app = setup().await;
    let (s, j) = request_device_code(&app, "not-a-real-client", "credentials:discover").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(j["error"], "invalid_client");
}

// TC-CONF-006: disallowed scope => 400 invalid_scope
#[tokio::test]
// un-ignored: device_code endpoint live (slice 3)
async fn tc_conf_006_invalid_scope() {
    let app = setup().await;
    let (s, j) = request_device_code(&app, BOOTSTRAP_CLIENT_ID, "root:everything").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(j["error"], "invalid_scope");
}

// TC-CONF-007: Content-Type JSON + Cache-Control: no-store
#[tokio::test]
async fn tc_conf_007_response_headers() {
    let app = setup().await;
    let (_, _, headers) = post_form(
        &app,
        "/api/v1/oauth/device/code",
        &format!("client_id={BOOTSTRAP_CLIENT_ID}&scope=credentials:discover"),
    )
    .await;
    let ct = headers
        .iter()
        .find(|(k, _)| k == "content-type")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert!(ct.starts_with("application/json"));
    let cc = headers
        .iter()
        .find(|(k, _)| k == "cache-control")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert!(cc.contains("no-store"));
}

// ---------------------------------------------------------------------------
// 3.2 POST /oauth/token device_code grant
// ---------------------------------------------------------------------------

// TC-CONF-010: pending => 400 authorization_pending
#[tokio::test]
// un-ignored: slice 4 token endpoint live
async fn tc_conf_010_authorization_pending() {
    let app = setup().await;
    let (_, body) = request_device_code(&app, BOOTSTRAP_CLIENT_ID, "credentials:discover").await;
    let dc = body["device_code"].as_str().unwrap();
    let (s, j) = poll_token(&app, BOOTSTRAP_CLIENT_ID, dc).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(j["error"], "authorization_pending");
}

// TC-CONF-011: after approval => 200 with token response
#[tokio::test]
#[ignore = "pending BE-1 device flow endpoints + approval helper"]
async fn tc_conf_011_token_issued_after_approval() {
    // Scenario needs: issue device code, approve via /activate, then poll.
    // Approval requires admin session — pending helper wiring.
}

// TC-CONF-012: after denial => 400 access_denied
#[tokio::test]
#[ignore = "pending BE-1 device flow endpoints + approval helper"]
async fn tc_conf_012_access_denied_after_deny() {}

// TC-CONF-013: after TTL => 400 expired_token, row marked expired
#[tokio::test]
#[ignore = "pending BE-1 device flow endpoints + AGTCRDN_DEVICE_CODE_TTL_SECS override"]
async fn tc_conf_013_expired_token() {}

// TC-CONF-014: unknown device_code => 400 invalid_grant
#[tokio::test]
// un-ignored: slice 4 token endpoint live
async fn tc_conf_014_unknown_device_code() {
    let app = setup().await;
    let (s, j) = poll_token(&app, BOOTSTRAP_CLIENT_ID, "not-a-real-device-code").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(j["error"], "invalid_grant");
}

// TC-CONF-015: missing/wrong grant_type => 400 unsupported_grant_type
#[tokio::test]
#[ignore = "BUG: BE-1 token.rs still has 422 from Form extractor for unsupported_grant_type — device.rs fix did not propagate"]
async fn tc_conf_015_unsupported_grant_type() {
    let app = setup().await;
    let body = format!("client_id={BOOTSTRAP_CLIENT_ID}&device_code=abc");
    let (s, j, _) = post_form(&app, "/api/v1/oauth/token", &body).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(j["error"], "unsupported_grant_type");
}

// TC-CONF-016: wrong client_id for valid device_code => 400 invalid_grant
#[tokio::test]
// un-ignored: slice 4 token endpoint live
async fn tc_conf_016_client_id_binding() {
    let app = setup().await;
    let (_, body) = request_device_code(&app, BOOTSTRAP_CLIENT_ID, "credentials:discover").await;
    let dc = body["device_code"].as_str().unwrap();
    let (s, j) = poll_token(&app, "different-client", dc).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(j["error"], "invalid_grant");
}

// TC-CONF-017: unknown client_id at token endpoint => 401 invalid_client
#[tokio::test]
#[ignore = "BUG: BE-1 token.rs returns 400 invalid_client; RFC 6749 §5.2 requires 401 — device.rs fix did not propagate"]
async fn tc_conf_017_token_unknown_client_id() {
    let app = setup().await;
    let (s, j) = poll_token(&app, "nobody-knows-me", "abc").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(j["error"], "invalid_client");
}

// ---------------------------------------------------------------------------
// 3.3 slow_down + polling interval
// ---------------------------------------------------------------------------

// TC-CONF-020: poll <5s apart twice => second returns slow_down
#[tokio::test]
// un-ignored: slice 4 token endpoint live
async fn tc_conf_020_slow_down_on_fast_poll() {
    let app = setup().await;
    let (_, body) = request_device_code(&app, BOOTSTRAP_CLIENT_ID, "credentials:discover").await;
    let dc = body["device_code"].as_str().unwrap();
    let _ = poll_token(&app, BOOTSTRAP_CLIENT_ID, dc).await;
    let (s, j) = poll_token(&app, BOOTSTRAP_CLIENT_ID, dc).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(j["error"], "slow_down");
}

// TC-CONF-021: broker that receives slow_down doubles its interval
#[tokio::test]
#[ignore = "verified in BE-2 broker tests, not server-side"]
async fn tc_conf_021_broker_doubles_interval_on_slow_down() {}

// TC-CONF-022: successive slow_down responses double each time
#[tokio::test]
#[ignore = "pending BE-1 device flow endpoints + poll interval override"]
async fn tc_conf_022_slow_down_doubles_each_time() {}

// TC-CONF-023: after slow_down, honoring new interval => no second slow_down
#[tokio::test]
#[ignore = "pending BE-1 device flow endpoints + poll interval override"]
async fn tc_conf_023_slow_down_clears_after_interval_honored() {}

// ---------------------------------------------------------------------------
// 3.4 Expired device code
// ---------------------------------------------------------------------------

// TC-CONF-030: advance clock +601s => expired_token; row marked expired
#[tokio::test]
#[ignore = "pending AGTCRDN_DEVICE_CODE_TTL_SECS override from BE-1"]
async fn tc_conf_030_expired_after_ttl() {}

// TC-CONF-031: expired_token sticks until sweeper, not invalid_grant
#[tokio::test]
#[ignore = "pending AGTCRDN_DEVICE_CODE_TTL_SECS override + sweeper hook"]
async fn tc_conf_031_expired_token_persists_until_sweep() {}
