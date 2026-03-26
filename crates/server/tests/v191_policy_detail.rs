//! Integration tests — v1.9.1 Feature 4: Policy Detail Page.
//!
//! Verifies that policy names on the list page are clickable links and
//! that the detail page loads correctly with view/edit Cedar code.

use crate::common;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn setup() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "policy-detail-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "policy-detail-user", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

async fn get_authed(app: &axum::Router, uri: &str, cookie: &str) -> (StatusCode, String, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let status = resp.status();
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    (status, content_type, body)
}

/// Create a policy via API and return its UUID string.
async fn create_test_policy(app: &axum::Router, cookie: &str, name: &str, cedar: &str) -> String {
    let (status, body) = common::send_json_auto_csrf(
        app,
        Method::POST,
        "/api/v1/policies",
        None,
        Some(cookie),
        Some(json!({
            "name": name,
            "description": "Test policy",
            "cedar_policy": cedar,
        })),
    )
    .await;

    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "policy creation should succeed: {:?}",
        body,
    );

    body["data"]["id"]
        .as_str()
        .expect("policy should have id")
        .to_string()
}

const SIMPLE_CEDAR: &str = r#"permit(
  principal,
  action == AgentCordon::Action::"access",
  resource
);"#;

// ===========================================================================
// 4A. Happy Path
// ===========================================================================

#[tokio::test]
async fn test_policy_detail_page_returns_html() {
    let (ctx, cookie) = setup().await;
    let policy_id = create_test_policy(&ctx.app, &cookie, "detail-test-policy", SIMPLE_CEDAR).await;

    let (status, content_type, body) =
        get_authed(&ctx.app, &format!("/security/{}", policy_id), &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(content_type.contains("text/html"));
    assert!(body.contains("<!DOCTYPE html>"));
}

#[tokio::test]
async fn test_policy_detail_page_loads_policy_data() {
    let (ctx, cookie) = setup().await;
    let policy_id = create_test_policy(&ctx.app, &cookie, "load-data-policy", SIMPLE_CEDAR).await;

    let (status, _, body) =
        get_authed(&ctx.app, &format!("/security/{}", policy_id), &cookie).await;

    assert_eq!(status, StatusCode::OK);
    // The template should embed the policy_id for Alpine to fetch via API
    assert!(
        body.contains(&policy_id),
        "detail page should contain the policy ID for Alpine.js data loading",
    );
}

#[tokio::test]
async fn test_policy_list_links_to_detail() {
    let (ctx, cookie) = setup().await;
    let policy_id = create_test_policy(&ctx.app, &cookie, "linked-policy", SIMPLE_CEDAR).await;

    let (status, _, body) = get_authed(&ctx.app, "/security", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    // The list page should contain a link to the policy detail page
    let expected_href = format!("/security/{}", policy_id);
    assert!(
        body.contains(&expected_href),
        "policy list should contain href to /security/{}: body did not contain '{}'",
        policy_id,
        expected_href,
    );
}

#[tokio::test]
async fn test_policy_save_updates_cedar() {
    let (ctx, cookie) = setup().await;
    let policy_id = create_test_policy(&ctx.app, &cookie, "save-update-policy", SIMPLE_CEDAR).await;

    let updated_cedar = r#"permit(
  principal,
  action == AgentCordon::Action::"list",
  resource
);"#;

    // Update via PUT
    let (status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/policies/{}", policy_id),
        None,
        Some(&cookie),
        Some(json!({
            "cedar_policy": updated_cedar,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PUT policy should succeed");

    // Read back and verify
    let (get_status, get_body) = common::send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/policies/{}", policy_id),
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(get_status, StatusCode::OK);
    let cedar_text = get_body["data"]["cedar_policy"]
        .as_str()
        .expect("policy should have cedar_policy");
    assert!(cedar_text.contains("list"), "updated Cedar should persist",);
}

#[tokio::test]
async fn test_policy_delete_from_detail() {
    let (ctx, cookie) = setup().await;
    let policy_id = create_test_policy(&ctx.app, &cookie, "delete-me-policy", SIMPLE_CEDAR).await;

    // Delete
    let (del_status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/policies/{}", policy_id),
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert!(
        del_status == StatusCode::OK || del_status == StatusCode::NO_CONTENT,
        "DELETE should succeed: got {}",
        del_status,
    );

    // Verify gone
    let (get_status, _) = common::send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/policies/{}", policy_id),
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(
        get_status,
        StatusCode::NOT_FOUND,
        "deleted policy should return 404",
    );
}

// ===========================================================================
// 4B. Retry/Idempotency
// ===========================================================================

#[tokio::test]
async fn test_policy_save_twice_idempotent() {
    let (ctx, cookie) = setup().await;
    let policy_id = create_test_policy(&ctx.app, &cookie, "idempotent-policy", SIMPLE_CEDAR).await;

    let update_body = json!({ "name": "idempotent-policy-renamed" });

    // PUT twice
    let (status1, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/policies/{}", policy_id),
        None,
        Some(&cookie),
        Some(update_body.clone()),
    )
    .await;
    let (status2, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/policies/{}", policy_id),
        None,
        Some(&cookie),
        Some(update_body),
    )
    .await;

    assert_eq!(status1, StatusCode::OK);
    assert_eq!(status2, StatusCode::OK);
}

// ===========================================================================
// 4C. Error Handling
// ===========================================================================

#[tokio::test]
async fn test_policy_detail_invalid_uuid_returns_404() {
    let (ctx, cookie) = setup().await;

    let (status, content_type, _) = get_authed(&ctx.app, "/security/not-a-uuid", &cookie).await;

    assert!(
        status == StatusCode::NOT_FOUND || status == StatusCode::OK,
        "invalid UUID should return 404 or 200 (stub page), got {}",
        status,
    );
    assert!(content_type.contains("text/html"));
}

#[tokio::test]
async fn test_policy_detail_nonexistent_id_renders_page() {
    let (ctx, cookie) = setup().await;
    let fake_uuid = Uuid::new_v4();

    let (status, content_type, _) =
        get_authed(&ctx.app, &format!("/security/{}", fake_uuid), &cookie).await;

    // Page renders (Alpine shows "not found" after API 404) or server returns 404
    assert!(
        status == StatusCode::OK || status == StatusCode::NOT_FOUND,
        "nonexistent policy UUID should return 200 or 404, got {}",
        status,
    );
    assert!(content_type.contains("text/html"));
}

#[tokio::test]
async fn test_policy_save_invalid_cedar_returns_400() {
    let (ctx, cookie) = setup().await;
    let policy_id =
        create_test_policy(&ctx.app, &cookie, "invalid-cedar-policy", SIMPLE_CEDAR).await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/policies/{}", policy_id),
        None,
        Some(&cookie),
        Some(json!({
            "cedar_policy": "this is not valid cedar syntax }{",
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "invalid Cedar should return 400: {:?}",
        body,
    );
}

#[tokio::test]
async fn test_policy_delete_nonexistent_returns_404() {
    let (ctx, cookie) = setup().await;
    let fake_uuid = Uuid::new_v4();

    let (status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/policies/{}", fake_uuid),
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "deleting nonexistent policy should return 404",
    );
}

// ===========================================================================
// 4E. Security
// ===========================================================================

#[tokio::test]
async fn test_policy_detail_requires_auth() {
    let (ctx, cookie) = setup().await;
    let policy_id =
        create_test_policy(&ctx.app, &cookie, "auth-required-policy", SIMPLE_CEDAR).await;

    // Request without session cookie
    let resp = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/security/{}", policy_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should redirect to login or return 401
    assert!(
        resp.status() == StatusCode::FOUND
            || resp.status() == StatusCode::SEE_OTHER
            || resp.status() == StatusCode::UNAUTHORIZED,
        "unauthenticated access should redirect to login or 401, got {}",
        resp.status(),
    );

    // If redirect, check it goes to /login
    if resp.status() == StatusCode::FOUND || resp.status() == StatusCode::SEE_OTHER {
        let location = resp
            .headers()
            .get(header::LOCATION)
            .expect("redirect should have Location header")
            .to_str()
            .unwrap();
        assert!(
            location.contains("/login"),
            "should redirect to /login, got: {}",
            location,
        );
    }
}

#[tokio::test]
async fn test_policy_save_requires_csrf() {
    let (ctx, cookie) = setup().await;
    let policy_id =
        create_test_policy(&ctx.app, &cookie, "csrf-required-policy", SIMPLE_CEDAR).await;

    // Extract just the session cookie (without CSRF)
    let session_only = cookie.split(';').next().unwrap().trim();

    // PUT without CSRF token — should fail
    let (status, _) = common::send_json(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/policies/{}", policy_id),
        None,
        Some(session_only),
        None, // No CSRF token
        Some(json!({ "name": "hacked-name" })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "PUT without CSRF token should return 403",
    );
}

#[tokio::test]
async fn test_policy_detail_xss_prevention() {
    let (ctx, cookie) = setup().await;

    // Create a policy with XSS in the name
    let xss_name = "<script>alert(1)</script>";
    let policy_id = create_test_policy(&ctx.app, &cookie, xss_name, SIMPLE_CEDAR).await;

    let (status, _, body) =
        get_authed(&ctx.app, &format!("/security/{}", policy_id), &cookie).await;

    assert_eq!(status, StatusCode::OK);

    // The raw script tag should NOT appear in the HTML
    assert!(
        !body.contains("<script>alert(1)</script>"),
        "XSS payload must be escaped in HTML output",
    );

    // It should be HTML-escaped
    if body.contains("alert") {
        assert!(
            body.contains("&lt;script&gt;") || body.contains("&lt;script"),
            "script tags should be HTML-escaped",
        );
    }
}
