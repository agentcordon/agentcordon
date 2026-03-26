//! Integration tests — Policy Templates endpoint.

use crate::common;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::http::{Method, StatusCode};

async fn setup() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "policy-tpl-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "policy-tpl-user", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

/// GET /api/v1/policy-templates returns at least 3 templates.
#[tokio::test]
async fn test_policy_templates_endpoint() {
    let (ctx, cookie) = setup().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/policy-templates",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "policy-templates should return 200: {:?}",
        body
    );

    let templates = body["data"].as_array().expect("data should be array");
    assert!(
        templates.len() >= 3,
        "should have at least 3 policy templates, got {}",
        templates.len()
    );
}

/// All policy templates have required fields.
#[tokio::test]
async fn test_policy_templates_have_required_fields() {
    let (ctx, cookie) = setup().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/policy-templates",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let templates = body["data"].as_array().expect("data array");
    for tpl in templates {
        let key = tpl["key"].as_str().expect("template must have key");
        assert!(!key.is_empty(), "key must not be empty");
        assert!(
            tpl["name"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
            "template '{}' must have name",
            key
        );
        assert!(
            tpl["cedar_policy"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            "template '{}' must have cedar_policy",
            key
        );
        assert!(
            tpl["description"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            "template '{}' must have description",
            key
        );
    }
}

/// Policy templates require authentication.
#[tokio::test]
async fn test_policy_templates_require_auth() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/policy-templates",
        None,
        None,
        None,
    )
    .await;

    assert!(
        status == StatusCode::UNAUTHORIZED
            || status == StatusCode::FORBIDDEN
            || status == StatusCode::FOUND,
        "policy-templates without auth should return 401/403/302, got {}",
        status
    );
}
