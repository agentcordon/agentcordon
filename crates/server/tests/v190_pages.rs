//! Integration tests — v1.9.0 Feature 3: Page Migrations.
//!
//! Verifies that every page from the SPA monolith is migrated to its own
//! Askama template and returns correct HTML content.

use crate::common;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

async fn get_raw(app: &axum::Router, uri: &str) -> (StatusCode, String, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
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

/// Create a test context with an admin user logged in.
async fn setup() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "pages-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, "pages-user", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

// ===========================================================================
// 3A. Dashboard
// ===========================================================================

#[tokio::test]
async fn test_dashboard_shows_stats() {
    let (ctx, cookie) = setup().await;

    let (status, _, body) = get_authed(&ctx.app, "/dashboard", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<!DOCTYPE html>"));
    assert!(body.contains("Dashboard"));
}

#[tokio::test]
async fn test_dashboard_stats_api_still_works() {
    let (ctx, cookie) = setup().await;

    let (status, _resp_body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/stats",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "stats API should return 200");
}

// ===========================================================================
// 3B. Credentials Pages
// ===========================================================================

#[tokio::test]
async fn test_credentials_list_page() {
    let (ctx, cookie) = setup().await;

    let (status, content_type, body) = get_authed(&ctx.app, "/credentials", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(content_type.contains("text/html"));
    assert!(body.contains("Credential") || body.contains("credential"));
}

#[tokio::test]
async fn test_credential_detail_page() {
    let (ctx, cookie) = setup().await;

    // Create a credential via API
    let (cred_status, cred_body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "name": "test-cred-detail",
            "service": "test-service",
            "credential_type": "generic",
            "secret_value": "supersecret123"
        })),
    )
    .await;

    assert!(
        cred_status == StatusCode::CREATED || cred_status == StatusCode::OK,
        "credential creation should succeed: {:?}",
        cred_body,
    );

    let cred_id = cred_body["data"]["id"].as_str().unwrap();

    let (status, content_type, body) =
        get_authed(&ctx.app, &format!("/credentials/{}", cred_id), &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(content_type.contains("text/html"));
    assert!(
        !body.contains("supersecret123"),
        "page must not expose secret value"
    );
}

#[tokio::test]
async fn test_credential_new_page() {
    let (ctx, cookie) = setup().await;

    let (status, content_type, body) = get_authed(&ctx.app, "/credentials/new", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(content_type.contains("text/html"));
    assert!(body.contains("<!DOCTYPE html>"));
}

#[tokio::test]
async fn test_credential_detail_nonexistent() {
    let (ctx, cookie) = setup().await;

    let random_uuid = Uuid::new_v4();
    let (status, content_type, _) =
        get_authed(&ctx.app, &format!("/credentials/{}", random_uuid), &cookie).await;

    // Should return 200 with the page (detail page loads data via JS)
    // or 404 if the server validates existence
    assert!(
        status == StatusCode::OK || status == StatusCode::NOT_FOUND,
        "nonexistent credential should return 200 (JS-loaded) or 404, got {}",
        status,
    );
    assert!(content_type.contains("text/html"));
}

// ===========================================================================
// 3C. Agents Pages
// ===========================================================================

#[tokio::test]
async fn test_agents_list_page() {
    let (ctx, cookie) = setup().await;

    let (status, content_type, body) = get_authed(&ctx.app, "/workspaces", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(content_type.contains("text/html"));
    assert!(
        body.contains("Workspace")
            || body.contains("workspace")
            || body.contains("Agent")
            || body.contains("agent")
    );
}

#[tokio::test]
async fn test_agent_detail_page() {
    let (ctx, cookie) = setup().await;

    let (agent, _) =
        common::create_agent_in_db(&*ctx.store, "detail-test-agent", vec!["test"], true, None)
            .await;

    let (status, content_type, _) =
        get_authed(&ctx.app, &format!("/workspaces/{}", agent.id.0), &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(content_type.contains("text/html"));
}

#[tokio::test]
async fn test_agent_detail_nonexistent() {
    let (ctx, cookie) = setup().await;

    // Invalid UUID format — may return 404 (server validates UUID) or 200 (stub page)
    let (status, content_type, _) = get_authed(&ctx.app, "/workspaces/not-a-uuid", &cookie).await;

    // Agent detail validates UUID format and returns 404 for non-UUIDs
    // But if the handler treats it as a valid path param and renders the stub, it returns 200
    assert!(
        status == StatusCode::NOT_FOUND || status == StatusCode::OK,
        "invalid UUID should return 404 or 200 (stub), got {}",
        status,
    );
    assert!(content_type.contains("text/html"));
}

// ===========================================================================
// 3D. Devices Pages
// ===========================================================================

#[tokio::test]
#[ignore = "REMOVED: v2.0 has no /devices page — devices unified into workspaces"]
async fn test_devices_list_page() {
    let (ctx, cookie) = setup().await;

    let (status, content_type, _) = get_authed(&ctx.app, "/devices", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(content_type.contains("text/html"));
}

#[tokio::test]
#[ignore = "REMOVED: v2.0 has no /devices/new page — devices unified into workspaces"]
async fn test_device_new_page() {
    let (ctx, cookie) = setup().await;

    let (status, content_type, _) = get_authed(&ctx.app, "/devices/new", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(content_type.contains("text/html"));
}

// ===========================================================================
// 3E. Policies Pages
// ===========================================================================

#[tokio::test]
async fn test_policies_list_page() {
    let (ctx, cookie) = setup().await;

    let (status, content_type, body) = get_authed(&ctx.app, "/security", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(content_type.contains("text/html"));
    assert!(
        body.contains("Polic")
            || body.contains("polic")
            || body.contains("Secur")
            || body.contains("secur")
    );
}

#[tokio::test]
async fn test_policy_detail_page() {
    let (ctx, cookie) = setup().await;

    let uuid = "00000000-0000-0000-0000-000000000001";
    let (status, content_type, _) =
        get_authed(&ctx.app, &format!("/security/{}", uuid), &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(content_type.contains("text/html"));
}

// ===========================================================================
// 3F. MCP Servers Pages
// ===========================================================================

#[tokio::test]
async fn test_mcp_servers_list_page() {
    let (ctx, cookie) = setup().await;

    let (status, content_type, _) = get_authed(&ctx.app, "/mcp-servers", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(content_type.contains("text/html"));
}

#[tokio::test]
async fn test_mcp_server_new_page() {
    let (ctx, cookie) = setup().await;

    let (status, content_type, _) = get_authed(&ctx.app, "/mcp-servers/new", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(content_type.contains("text/html"));
}

#[tokio::test]
async fn test_mcp_catalog_page() {
    let (ctx, cookie) = setup().await;

    let (status, content_type, _) = get_authed(&ctx.app, "/mcp-servers/catalog", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(content_type.contains("text/html"));
}

// ===========================================================================
// 3G. Audit Log Page
// ===========================================================================

#[tokio::test]
async fn test_audit_log_page() {
    let (ctx, cookie) = setup().await;

    let (status, content_type, body) = get_authed(&ctx.app, "/audit", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(content_type.contains("text/html"));
    assert!(body.contains("Audit") || body.contains("audit"));
}

// ===========================================================================
// 3H. Users Pages
// ===========================================================================

#[tokio::test]
async fn test_users_list_page() {
    let (ctx, cookie) = setup().await;

    let (status, content_type, body) = get_authed(&ctx.app, "/settings/users", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(content_type.contains("text/html"));
    assert!(body.contains("User") || body.contains("user"));
}

#[tokio::test]
async fn test_users_new_page() {
    let (ctx, cookie) = setup().await;

    let (status, content_type, _) = get_authed(&ctx.app, "/settings/users/new", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(content_type.contains("text/html"));
}

// ===========================================================================
// 3I. Settings Page
// ===========================================================================

#[tokio::test]
async fn test_settings_page() {
    let (ctx, cookie) = setup().await;

    let (status, content_type, body) = get_authed(&ctx.app, "/settings", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(content_type.contains("text/html"));
    assert!(body.contains("Setting") || body.contains("setting"));
}

// ===========================================================================
// 3J. Auth Pages (No Session Required)
// ===========================================================================

#[tokio::test]
async fn test_login_page_renders() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (status, content_type, body) = get_raw(&ctx.app, "/login").await;

    assert_eq!(status, StatusCode::OK);
    assert!(content_type.contains("text/html"));
    assert!(body.contains("Sign in") || body.contains("Username") || body.contains("username"));
    assert!(body.contains("Password") || body.contains("password"));
}

#[tokio::test]
async fn test_error_page_404() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (status, content_type, body) = get_raw(&ctx.app, "/nope").await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(content_type.contains("text/html"));
    assert!(body.contains("404") || body.contains("Not Found"));
}

// ===========================================================================
// 3K. Cross-Feature
// ===========================================================================

#[tokio::test]
async fn test_page_then_api_consistency() {
    let (ctx, cookie) = setup().await;

    // Render the page
    let (page_status, _, _) = get_authed(&ctx.app, "/credentials", &cookie).await;
    assert_eq!(page_status, StatusCode::OK);

    // Then hit the API
    let (api_status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(api_status, StatusCode::OK);
}

#[tokio::test]
async fn test_form_submit_creates_entity() {
    let (ctx, cookie) = setup().await;

    // Create credential via API (simulating form submission)
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "name": "form-test-cred",
            "service": "test",
            "credential_type": "generic",
            "secret_value": "secret"
        })),
    )
    .await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "create credential should succeed: {:?}",
        body,
    );

    // Verify the credential page still renders
    let (page_status, _, _) = get_authed(&ctx.app, "/credentials", &cookie).await;
    assert_eq!(page_status, StatusCode::OK);
}
