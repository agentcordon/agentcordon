//! v1.10.0 — Policy List Improvements Integration Tests (Feature 9).
//!
//! Verifies the policy list page at GET /security renders correctly with
//! expected table structure, policy links, enable/disable actions, and
//! proper HTML elements.

use crate::common;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn setup() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "policy-list-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "policy-list-user", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

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

async fn create_test_policy(
    app: &axum::Router,
    cookie: &str,
    name: &str,
    cedar: &str,
    enabled: bool,
) -> String {
    let (status, body) = common::send_json_auto_csrf(
        app,
        Method::POST,
        "/api/v1/policies",
        None,
        Some(cookie),
        Some(json!({
            "name": name,
            "description": format!("Test policy: {}", name),
            "cedar_policy": cedar,
        })),
    )
    .await;

    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "policy creation should succeed: {:?}",
        body,
    );

    let id = body["data"]["id"]
        .as_str()
        .expect("policy should have id")
        .to_string();

    // If we want it disabled, update it
    if !enabled {
        let (_status, _body) = common::send_json_auto_csrf(
            app,
            Method::PUT,
            &format!("/api/v1/policies/{}", id),
            None,
            Some(cookie),
            Some(json!({
                "enabled": false,
            })),
        )
        .await;
    }

    id
}

const SIMPLE_CEDAR: &str = r#"permit(
  principal,
  action == AgentCordon::Action::"access",
  resource
);"#;

// ===========================================================================
// 9A. Policy List Page Structure
// ===========================================================================

/// GET /security should return 200 with a table or empty state.
#[tokio::test]
async fn test_policy_list_returns_200() {
    let (ctx, cookie) = setup().await;

    let (status, body) = get_html(&ctx.app, "/security", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("<h2>Policies</h2>"),
        "policy list page should have the 'Policies' heading (renamed from \
         'Security Policies' in uat/artifacts/reviews/DESIGN-REVIEW.md §1.1)"
    );
}

/// Policy list should contain a "New Policy" link to /security/new.
#[tokio::test]
async fn test_policy_list_has_new_button() {
    let (ctx, cookie) = setup().await;

    let (status, body) = get_html(&ctx.app, "/security", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"href="/security/new"#),
        "policy list page should have New Policy link to /security/new"
    );
    assert!(
        body.contains("New Policy"),
        "policy list page should have 'New Policy' button text"
    );
}

/// The list page is a shell: its table rows come from `GET /api/v1/policies`
/// (the page never embeds policy data), and each row links to `/security/{id}`.
#[tokio::test]
async fn test_policy_list_shows_policies_in_table() {
    let (ctx, cookie) = setup().await;
    let policy_id = create_test_policy(
        &ctx.app,
        &cookie,
        "list-table-test-policy",
        SIMPLE_CEDAR,
        true,
    )
    .await;

    let (status, body) = get_html(&ctx.app, "/security", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("<table"),
        "policy list page should contain the policies table"
    );
    assert!(
        !body.contains("list-table-test-policy"),
        "policy list page must not embed policy data; it comes from the API"
    );
    assert!(
        body.contains("/api/v1/policies") && body.contains("'/security/' + policy.id"),
        "rows come from the policies API and link to /security/{{id}}"
    );

    let (status, api) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/policies",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let listed = api["data"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["id"] == policy_id.as_str() && p["name"] == "list-table-test-policy");
    assert!(listed, "the policies API lists the policy: {api}");
}

/// The table should have expected column headers.
#[tokio::test]
async fn test_policy_list_table_headers() {
    let (ctx, cookie) = setup().await;
    let _policy_id =
        create_test_policy(&ctx.app, &cookie, "headers-test-policy", SIMPLE_CEDAR, true).await;

    let (status, body) = get_html(&ctx.app, "/security", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Name"), "table should have Name column");
    assert!(
        body.contains(">Description<"),
        "table should have Description column"
    );
    assert!(body.contains("Enabled"), "table should have Enabled column");
}

/// Enabled/disabled status shows as pills bound to the API's `enabled` flag.
#[tokio::test]
async fn test_policy_list_status_pills() {
    let (ctx, cookie) = setup().await;
    let enabled_id =
        create_test_policy(&ctx.app, &cookie, "enabled-pill-test", SIMPLE_CEDAR, true).await;
    let disabled_id =
        create_test_policy(&ctx.app, &cookie, "disabled-pill-test", SIMPLE_CEDAR, false).await;

    let (status, body) = get_html(&ctx.app, "/security", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("policy.enabled ? 'pill-ok' : 'pill-warn'"),
        "the status pill class follows the API's enabled flag"
    );
    assert!(
        body.contains("policy.enabled ? 'Enabled' : 'Disabled'"),
        "the status pill text follows the API's enabled flag"
    );

    let (status, api) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/policies",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let enabled_of = |id: &str| {
        api["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == id)
            .map(|p| p["enabled"].as_bool().unwrap())
    };
    assert_eq!(enabled_of(&enabled_id), Some(true), "{api}");
    assert_eq!(enabled_of(&disabled_id), Some(false), "{api}");
}
