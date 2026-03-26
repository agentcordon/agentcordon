//! v1.9.4 — Policy Route Tests (Items #1 and #13)
//!
//! Verifies that the "New Policy" button links to `/security/new` (not the
//! old `/security/policies/new` 404), that redirect routes work, and that
//! cancel links point to the correct parent pages.

use crate::common;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn get_html(app: &axum::Router, uri: &str, cookie: &str) -> (StatusCode, String) {
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
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    (status, body)
}

/// GET without auth — returns (status, headers, body).
async fn get_raw(
    app: &axum::Router,
    uri: &str,
    cookie: Option<&str>,
) -> (StatusCode, Vec<(String, String)>, String) {
    let mut builder = Request::builder().method(Method::GET).uri(uri);
    if let Some(c) = cookie {
        builder = builder.header(header::COOKIE, c);
    }
    let resp = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();

    let status = resp.status();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    (status, headers, body)
}

async fn setup() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "policy-route-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "policy-route-user", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

// ===========================================================================
// Item #1: New Policy 404 Route
// ===========================================================================

/// GET /security/new with admin session returns 200 with the new policy form.
#[tokio::test]
async fn test_security_new_returns_200() {
    let (ctx, cookie) = setup().await;

    let (status, body) = get_html(&ctx.app, "/security/new", &cookie).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "GET /security/new should return 200"
    );
    assert!(
        body.contains("<!DOCTYPE html>") || body.contains("<!doctype html>"),
        "response should be HTML"
    );
}

/// GET /security should contain a link to /security/new (not /security/policies/new).
#[tokio::test]
async fn test_security_list_new_button_links_correctly() {
    let (ctx, cookie) = setup().await;

    let (status, body) = get_html(&ctx.app, "/security", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"href="/security/new"#),
        "security list page should contain href=\"/security/new\", not /security/policies/new"
    );
    assert!(
        !body.contains(r#"href="/security/policies/new"#),
        "security list page should NOT contain the old broken href /security/policies/new"
    );
}

/// GET /policies/new should 301-redirect to /security/new.
#[tokio::test]
async fn test_policies_new_redirects_to_security_new() {
    let (ctx, cookie) = setup().await;

    let (status, headers, _body) = get_raw(&ctx.app, "/policies/new", Some(&cookie)).await;
    assert!(
        status == StatusCode::MOVED_PERMANENTLY || status == StatusCode::PERMANENT_REDIRECT,
        "GET /policies/new should return 301, got {}",
        status
    );
    let location = headers
        .iter()
        .find(|(k, _)| k == "location")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert!(
        location.contains("/security/new"),
        "redirect should point to /security/new, got: {}",
        location
    );
}

/// GET /security/policies/new should return 404 (the bug path).
#[tokio::test]
async fn test_security_policies_new_does_not_exist() {
    let (ctx, cookie) = setup().await;

    let (status, _body) = get_html(&ctx.app, "/security/policies/new", &cookie).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "GET /security/policies/new should return 404"
    );
}

/// Full round-trip: GET form → POST policy → policy created.
#[tokio::test]
async fn test_policy_creation_via_security_new() {
    let (ctx, cookie) = setup().await;

    // Step 1: Verify the form is accessible
    let (status, _body) = get_html(&ctx.app, "/security/new", &cookie).await;
    assert_eq!(status, StatusCode::OK, "form page should load");

    // Step 2: Create a policy via API
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "name": "test-policy-roundtrip",
            "description": "Created via security/new roundtrip test",
            "cedar_policy": "permit(principal, action, resource);",
            "enabled": true,
        })),
    )
    .await;
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED,
        "POST /api/v1/policies should succeed: status={}, body={:?}",
        status,
        body
    );
}

// ===========================================================================
// Item #13: Cancel Link in New Policy
// ===========================================================================

/// Cancel link on /security/new should point to /security (not /policies).
#[tokio::test]
async fn test_new_policy_cancel_links_to_security() {
    let (ctx, cookie) = setup().await;

    let (status, body) = get_html(&ctx.app, "/security/new", &cookie).await;
    assert_eq!(status, StatusCode::OK);

    // The cancel link should go to /security, not /policies
    assert!(
        body.contains(r#"href="/security"#),
        "cancel link should point to /security"
    );
    // Make sure it doesn't link to the old /policies path
    // (we check for exact href="/policies" to avoid matching /policies/xxx or /security)
    let has_stale_cancel =
        body.contains(r#"href="/policies""#) || body.contains(r#"href="/policies">"#);
    assert!(
        !has_stale_cancel,
        "cancel link should NOT point to /policies (stale href)"
    );
}

/// All create forms should have cancel links pointing to their parent list page.
#[tokio::test]
async fn test_all_cancel_links_point_to_parent() {
    let (ctx, cookie) = setup().await;

    let form_pages = [
        ("/security/new", "/security"),
        ("/credentials/new", "/credentials"),
        ("/devices/new", "/devices"),
        ("/users/new", "/users"),
        ("/mcp-servers/new", "/mcp-servers"),
    ];

    for (form_path, expected_parent) in &form_pages {
        let (status, body) = get_html(&ctx.app, form_path, &cookie).await;
        if status != StatusCode::OK {
            continue; // Skip forms that don't exist yet
        }

        // Find the Cancel link/button and verify it points to the parent
        let cancel_pos = body.find("Cancel");
        if let Some(pos) = cancel_pos {
            // Look backwards from "Cancel" for the nearest href
            let preceding = &body[pos.saturating_sub(200)..pos];
            if let Some(href_pos) = preceding.rfind("href=\"") {
                let href_start = href_pos + 6;
                let href_end = preceding[href_start..]
                    .find('"')
                    .unwrap_or(preceding.len() - href_start);
                let href = &preceding[href_start..href_start + href_end];
                assert_eq!(
                    href, *expected_parent,
                    "cancel link on {} should point to {}, got {}",
                    form_path, expected_parent, href
                );
            }
        }
    }
}
