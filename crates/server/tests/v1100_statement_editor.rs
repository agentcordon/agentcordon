//! v1.10.0 — Statement Editor Integration Tests (Feature 6).
//!
//! Verifies the policy detail page renders the tabbed Cedar view (human-readable
//! Policy tab + raw Cedar tab), the cedar-editor textarea for editing, and
//! the parseReadableStatements JavaScript function.

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
        "stmt-editor-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "stmt-editor-user", common::TEST_PASSWORD).await;
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
            "description": "Test policy for statement editor",
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

// Multi-statement Cedar available for future tests.
#[allow(dead_code)]
const MULTI_STATEMENT_CEDAR: &str = r#"permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"access",
  resource is AgentCordon::Credential
);
forbid(
  principal,
  action == AgentCordon::Action::"delete",
  resource
);"#;

// ===========================================================================
// 6A. Policy detail page contains structured statement elements
// ===========================================================================

/// The policy detail page should contain the cedar-statements container.
#[tokio::test]
async fn test_policy_detail_has_cedar_statements_container() {
    let (ctx, cookie) = setup().await;
    let policy_id =
        create_test_policy(&ctx.app, &cookie, "stmt-container-test", SIMPLE_CEDAR).await;

    let (status, body) = get_html(&ctx.app, &format!("/security/{}", policy_id), &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("cedar-statements"),
        "policy detail page should contain cedar-statements CSS class"
    );
    assert!(
        body.contains("cedar-stmt-card"),
        "policy detail page should contain cedar-stmt-card CSS class"
    );
}

/// The detail page should contain PERMIT/FORBID pill indicators.
#[tokio::test]
async fn test_policy_detail_has_effect_pills() {
    let (ctx, cookie) = setup().await;
    let policy_id = create_test_policy(&ctx.app, &cookie, "effect-pills-test", SIMPLE_CEDAR).await;

    let (status, body) = get_html(&ctx.app, &format!("/security/{}", policy_id), &cookie).await;

    assert_eq!(status, StatusCode::OK);
    // The template uses Alpine x-text for PERMIT/FORBID, but the structural
    // elements and CSS classes should be present in the static HTML.
    assert!(
        body.contains("cedar-stmt-header"),
        "policy detail should have cedar-stmt-header elements"
    );
    assert!(
        body.contains("cedar-raw-block"),
        "policy detail should have cedar-raw-block element for Cedar source display"
    );
}

/// The policy detail page should render the cedar-editor textarea for editing.
#[tokio::test]
async fn test_policy_detail_has_cedar_editor() {
    let (ctx, cookie) = setup().await;
    let policy_id = create_test_policy(&ctx.app, &cookie, "cedar-editor-test", SIMPLE_CEDAR).await;

    let (status, body) = get_html(&ctx.app, &format!("/security/{}", policy_id), &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("cedar-editor"),
        "policy detail should contain a cedar-editor textarea for raw editing"
    );
    assert!(
        body.contains("<textarea"),
        "policy detail should contain a textarea element for Cedar editing"
    );
}

/// The new policy page should also have the cedar-editor textarea.
#[tokio::test]
async fn test_new_policy_has_cedar_editor() {
    let (ctx, cookie) = setup().await;

    let (status, body) = get_html(&ctx.app, "/security/new", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("cedar-editor"),
        "new policy page should contain a cedar-editor textarea"
    );
}

/// The parseCedarStatements JS function should be present on the detail page.
#[tokio::test]
async fn test_policy_detail_has_parse_function() {
    let (ctx, cookie) = setup().await;
    let policy_id = create_test_policy(&ctx.app, &cookie, "parse-fn-test", SIMPLE_CEDAR).await;

    let (status, body) = get_html(&ctx.app, &format!("/security/{}", policy_id), &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("parseReadableStatements"),
        "policy detail page should include the parseReadableStatements JavaScript function"
    );
}
