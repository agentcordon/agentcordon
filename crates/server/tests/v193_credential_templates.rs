//! Integration tests — v1.9.3 Feature 4: Service-Specific Credential Templates.
//!
//! Verifies that GET /api/v1/credential-templates returns pre-built templates
//! for Anthropic, OpenAI, and GitHub, and that templates can be used to create
//! valid credentials.

use crate::common;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::http::{Method, StatusCode};
use serde_json::json;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn setup() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "templates-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "templates-user", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

// ===========================================================================
// 4A. Happy Path
// ===========================================================================

/// GET /api/v1/credential-templates returns at least 3 templates.
#[tokio::test]
async fn test_credential_templates_endpoint() {
    let (ctx, cookie) = setup().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credential-templates",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "credential-templates endpoint should return 200: {:?}",
        body
    );

    let templates = body["data"]
        .as_array()
        .expect("data should be array of templates");
    assert!(
        templates.len() >= 24,
        "should have at least 24 templates (Anthropic, OpenAI, GitHub, AWS + 20 new), got {}",
        templates.len()
    );
}

/// Anthropic template has correct service and URL pattern.
#[tokio::test]
async fn test_anthropic_template() {
    let (ctx, cookie) = setup().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credential-templates",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let templates = body["data"].as_array().expect("data array");
    let anthropic = templates.iter().find(|t| {
        t["name"]
            .as_str()
            .map(|n| n.to_lowercase().contains("anthropic"))
            .unwrap_or(false)
            || t["service"]
                .as_str()
                .map(|s| s.contains("anthropic"))
                .unwrap_or(false)
    });

    assert!(
        anthropic.is_some(),
        "should have an Anthropic template, got: {:?}",
        templates
    );

    let anthropic = anthropic.unwrap();
    let service = anthropic["service"].as_str().unwrap_or("");
    assert!(
        service.contains("anthropic"),
        "Anthropic template service should reference anthropic, got: {}",
        service
    );

    let url_pattern = anthropic["allowed_url_pattern"].as_str().unwrap_or("");
    assert!(
        url_pattern.contains("api.anthropic.com"),
        "Anthropic template URL pattern should match api.anthropic.com, got: {}",
        url_pattern
    );
}

/// OpenAI template has correct service and URL pattern.
#[tokio::test]
async fn test_openai_template() {
    let (ctx, cookie) = setup().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credential-templates",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let templates = body["data"].as_array().expect("data array");
    let openai = templates.iter().find(|t| {
        t["name"]
            .as_str()
            .map(|n| n.to_lowercase().contains("openai"))
            .unwrap_or(false)
            || t["service"]
                .as_str()
                .map(|s| s.contains("openai"))
                .unwrap_or(false)
    });

    assert!(openai.is_some(), "should have an OpenAI template");

    let openai = openai.unwrap();
    let url_pattern = openai["allowed_url_pattern"].as_str().unwrap_or("");
    assert!(
        url_pattern.contains("api.openai.com"),
        "OpenAI template URL pattern should match api.openai.com, got: {}",
        url_pattern
    );
}

/// GitHub template has correct service and URL pattern.
#[tokio::test]
async fn test_github_template() {
    let (ctx, cookie) = setup().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credential-templates",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let templates = body["data"].as_array().expect("data array");
    let github = templates.iter().find(|t| {
        t["name"]
            .as_str()
            .map(|n| n.to_lowercase().contains("github"))
            .unwrap_or(false)
            || t["service"]
                .as_str()
                .map(|s| s.contains("github"))
                .unwrap_or(false)
    });

    assert!(github.is_some(), "should have a GitHub template");

    let github = github.unwrap();
    let url_pattern = github["allowed_url_pattern"].as_str().unwrap_or("");
    assert!(
        url_pattern.contains("api.github.com"),
        "GitHub template URL pattern should match api.github.com, got: {}",
        url_pattern
    );
}

/// Use a template's fields to create a real credential.
#[tokio::test]
async fn test_template_creates_valid_credential() {
    let (ctx, cookie) = setup().await;

    // Get templates
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credential-templates",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let templates = body["data"].as_array().expect("data array");
    assert!(!templates.is_empty(), "need at least one template");

    let template = &templates[0];
    let name = template["name"].as_str().unwrap_or("test-from-template");
    let service = template["service"].as_str().unwrap_or("test-service");
    let url_pattern = template["allowed_url_pattern"]
        .as_str()
        .unwrap_or("https://example.com/*");

    // Create a credential using the template values
    let (create_status, create_body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(json!({
            "name": format!("{}-from-template", name),
            "service": service,
            "credential_type": "generic",
            "secret_value": "template-test-secret",
            "allowed_url_pattern": url_pattern
        })),
    )
    .await;
    assert!(
        create_status == StatusCode::CREATED || create_status == StatusCode::OK,
        "credential creation from template values should succeed: {:?}",
        create_body
    );
}

/// All embedded JSON templates must parse and have required fields.
#[tokio::test]
async fn test_all_templates_have_required_fields() {
    let (ctx, cookie) = setup().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credential-templates",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let templates = body["data"].as_array().expect("data array");
    assert!(
        templates.len() >= 24,
        "should have at least 24 templates, got {}",
        templates.len()
    );

    for tpl in templates {
        let key = tpl["key"].as_str().expect("template must have key");
        assert!(!key.is_empty(), "key must not be empty");
        assert!(
            tpl["name"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
            "template '{}' must have name",
            key
        );
        assert!(
            tpl["service"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            "template '{}' must have service",
            key
        );
        assert!(
            tpl["auth_type"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            "template '{}' must have auth_type",
            key
        );
        assert!(
            tpl["allowed_url_pattern"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            "template '{}' must have allowed_url_pattern",
            key
        );
        assert!(
            tpl["fields"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false),
            "template '{}' must have fields",
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
        assert!(
            tpl["tags"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false),
            "template '{}' must have tags",
            key
        );
        assert!(
            tpl["sort_order"].as_u64().is_some(),
            "template '{}' must have sort_order",
            key
        );
    }
}

// ===========================================================================
// 4C. Error Handling
// ===========================================================================

/// Credential templates endpoint requires authentication.
#[tokio::test]
async fn test_templates_require_auth() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credential-templates",
        None,
        None, // no cookie
        None,
    )
    .await;

    assert!(
        status == StatusCode::UNAUTHORIZED
            || status == StatusCode::FORBIDDEN
            || status == StatusCode::FOUND, // redirect to login
        "credential-templates without auth should return 401/403/302, got {}",
        status
    );
}
