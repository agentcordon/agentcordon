//! Integration tests for the API documentation endpoints (GET /api/v1/docs
//! and GET /api/v1/docs/quickstart).
//!
//! These endpoints are unauthenticated and return raw JSON (not wrapped in the
//! standard `ApiResponse` envelope). The tests verify HTTP-level behavior:
//! status codes, response structure, headers, and content completeness.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

async fn setup_test_app() -> Router {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    ctx.app
}

/// Send a GET request with no body and no auth, returning status + raw bytes
/// and the full response (for header inspection).
async fn get_raw(app: &Router, uri: &str) -> (StatusCode, Value, axum::http::HeaderMap) {
    let request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json, headers)
}

// ===========================================================================
// 1. GET /api/v1/docs returns 200 with valid JSON (no auth required)
// ===========================================================================

#[tokio::test]
async fn docs_returns_200_without_auth() {
    let app = setup_test_app().await;
    let (status, body, _headers) = get_raw(&app, "/api/v1/docs").await;

    assert_eq!(status, StatusCode::OK, "Expected 200, body: {}", body);
    assert!(body.is_object(), "Response should be a JSON object");
}

// ===========================================================================
// 2. GET /api/v1/docs/quickstart returns 200 with valid JSON (no auth)
// ===========================================================================

#[tokio::test]
async fn quickstart_returns_200_without_auth() {
    let app = setup_test_app().await;
    let (status, body, _headers) = get_raw(&app, "/api/v1/docs/quickstart").await;

    assert_eq!(status, StatusCode::OK, "Expected 200, body: {}", body);
    assert!(body.is_object(), "Response should be a JSON object");
}

// ===========================================================================
// 3. Full docs response contains non-empty endpoints array
// ===========================================================================

#[tokio::test]
async fn docs_contains_non_empty_endpoints() {
    let app = setup_test_app().await;
    let (status, body, _headers) = get_raw(&app, "/api/v1/docs").await;

    assert_eq!(status, StatusCode::OK);
    let endpoints = body
        .get("endpoints")
        .expect("Response should have 'endpoints' key");
    let arr = endpoints
        .as_array()
        .expect("'endpoints' should be an array");
    assert!(!arr.is_empty(), "endpoints array should not be empty");
    // Sanity: should have at least 20 endpoints (we documented ~34)
    assert!(
        arr.len() >= 20,
        "Expected at least 20 endpoints, got {}",
        arr.len()
    );
}

// ===========================================================================
// 4. Quickstart response contains authentication, proxy, and errors keys
// ===========================================================================

#[tokio::test]
async fn quickstart_contains_required_sections() {
    let app = setup_test_app().await;
    let (status, body, _headers) = get_raw(&app, "/api/v1/docs/quickstart").await;

    assert_eq!(status, StatusCode::OK);

    assert!(
        body.get("authentication").is_some(),
        "Quickstart should have 'authentication' key"
    );
    assert!(
        body.get("proxy").is_some(),
        "Quickstart should have 'proxy' key"
    );
    assert!(
        body.get("errors").is_some(),
        "Quickstart should have 'errors' key"
    );

    // Each should be an object, not null
    assert!(
        body["authentication"].is_object(),
        "'authentication' should be an object"
    );
    assert!(body["proxy"].is_object(), "'proxy' should be an object");
    assert!(body["errors"].is_object(), "'errors' should be an object");
}

// ===========================================================================
// 6. Cache-Control header is present on both responses
// ===========================================================================

#[tokio::test]
async fn docs_has_cache_control_header() {
    let app = setup_test_app().await;
    let (_status, _body, headers) = get_raw(&app, "/api/v1/docs").await;

    let cache_control = headers
        .get(header::CACHE_CONTROL)
        .expect("Cache-Control header should be present on /api/v1/docs");
    let value = cache_control
        .to_str()
        .expect("Cache-Control should be valid UTF-8");
    assert!(
        value.contains("max-age="),
        "Cache-Control should contain max-age directive, got: {}",
        value
    );
}

#[tokio::test]
async fn quickstart_has_cache_control_header() {
    let app = setup_test_app().await;
    let (_status, _body, headers) = get_raw(&app, "/api/v1/docs/quickstart").await;

    let cache_control = headers
        .get(header::CACHE_CONTROL)
        .expect("Cache-Control header should be present on /api/v1/docs/quickstart");
    let value = cache_control
        .to_str()
        .expect("Cache-Control should be valid UTF-8");
    assert!(
        value.contains("max-age="),
        "Cache-Control should contain max-age directive, got: {}",
        value
    );
}

// ===========================================================================
// 7. Docs response includes all error codes
// ===========================================================================

#[tokio::test]
async fn docs_includes_all_error_codes() {
    let app = setup_test_app().await;
    let (status, body, _headers) = get_raw(&app, "/api/v1/docs").await;

    assert_eq!(status, StatusCode::OK);

    let codes_arr = body["error_format"]["codes"]
        .as_array()
        .expect("error_format.codes should be an array");

    let codes: Vec<&str> = codes_arr
        .iter()
        .filter_map(|c| c["code"].as_str())
        .collect();

    let expected = [
        "not_found",
        "unauthorized",
        "forbidden",
        "bad_request",
        "conflict",
        "internal_error",
        "bad_gateway",
        "credential_leak_detected",
    ];

    for code in &expected {
        assert!(
            codes.contains(code),
            "Error code '{}' missing from docs error_format.codes. Found: {:?}",
            code,
            codes,
        );
    }

    // Each error code should have a non-empty description and an http_status
    for entry in codes_arr {
        let code = entry["code"].as_str().unwrap_or("<missing>");
        assert!(
            entry["http_status"].is_number(),
            "Error code '{}' should have a numeric http_status",
            code,
        );
        let desc = entry["description"].as_str().unwrap_or("");
        assert!(
            !desc.is_empty(),
            "Error code '{}' should have a non-empty description",
            code,
        );
    }
}
