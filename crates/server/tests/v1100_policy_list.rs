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

#[allow(dead_code)]
async fn setup_with_seed() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new()
        .with_config(|c| {
            c.seed_demo = true;
        })
        .build()
        .await;

    agent_cordon_server::seed::seed_demo_data(
        &ctx.store,
        &ctx.encryptor,
        &ctx.state.config,
        &ctx.jwt_issuer,
    )
    .await
    .expect("seed demo data");

    let _user = common::create_test_user(
        &*ctx.store,
        "policy-list-seed-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "policy-list-seed-user", common::TEST_PASSWORD).await;
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
        body.contains("Security Policies"),
        "policy list page should have 'Security Policies' heading"
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

/// With policies created, the list page should show them in a table.
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
        "policy list page should contain a table when policies exist"
    );
    assert!(
        body.contains("list-table-test-policy"),
        "policy list should contain the policy name"
    );
    // Policy name should be a link to the detail page
    let expected_href = format!("/security/{}", policy_id);
    assert!(
        body.contains(&expected_href),
        "policy name should link to /security/{}: body did not contain '{}'",
        policy_id,
        expected_href,
    );
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

/// Enabled/disabled status should show as pills.
#[tokio::test]
async fn test_policy_list_status_pills() {
    let (ctx, cookie) = setup().await;
    let _enabled_id =
        create_test_policy(&ctx.app, &cookie, "enabled-pill-test", SIMPLE_CEDAR, true).await;
    let _disabled_id =
        create_test_policy(&ctx.app, &cookie, "disabled-pill-test", SIMPLE_CEDAR, false).await;

    let (status, body) = get_html(&ctx.app, "/security", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("pill-ok"),
        "enabled policy should have pill-ok class"
    );
    assert!(
        body.contains("pill-warn"),
        "disabled policy should have pill-warn class"
    );
    assert!(body.contains("Enabled"), "should show 'Enabled' text");
    assert!(body.contains("Disabled"), "should show 'Disabled' text");
}
