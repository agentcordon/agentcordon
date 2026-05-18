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
        // `_blank_*` templates are internal fallbacks for the "Blank/Custom"
        // path; they intentionally have no service, no tags, and no URL
        // pattern. The frontend uses them as default field-spec sources but
        // hides them from the template picker.
        if key.starts_with('_') {
            continue;
        }
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
// 4B-bis. End-to-end credential creation for common templates.
//
// These tests guard the core use case: a user picks a template, fills the
// fields it declares, clicks Store Credential, and the credential persists.
// The body shape constructed here mirrors what the dynamic-field frontend
// produces in `submitCredential()` — if these break, the Store Credential
// button is broken for that template.
// ===========================================================================

/// Fetch a template by key from the templates endpoint. Panics if absent.
async fn fetch_template(
    ctx: &agent_cordon_server::test_helpers::TestContext,
    cookie: &str,
    key: &str,
) -> serde_json::Value {
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credential-templates",
        None,
        Some(cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list templates failed: {:?}", body);
    let templates = body["data"].as_array().expect("data array");
    templates
        .iter()
        .find(|t| t["key"].as_str() == Some(key))
        .cloned()
        .unwrap_or_else(|| panic!("template '{}' must exist", key))
}

/// Mirror the frontend's `submitCredential` body construction: walk the
/// template's `fields`, copy non-client_only values into the body keyed by
/// field key, then apply `client_substitutions` against the template's URL
/// patterns. Returns the JSON body ready to POST.
fn build_submit_body(
    template: &serde_json::Value,
    name: &str,
    field_values: &[(&str, &str)],
) -> serde_json::Value {
    use serde_json::{json, Map, Value};
    let mut body = json!({
        "name": name,
        "service": template["service"].as_str().unwrap_or(""),
        "credential_type": template["credential_type"].as_str().unwrap_or("generic"),
        "tags": template["tags"].clone(),
        "allowed_url_pattern": template["allowed_url_pattern"].clone(),
        "metadata": {},
    });
    let fv: Map<String, Value> = field_values
        .iter()
        .map(|(k, v)| (k.to_string(), Value::String(v.to_string())))
        .collect();

    if let Some(fields) = template["fields"].as_array() {
        for f in fields {
            let key = match f["key"].as_str() {
                Some(k) => k,
                None => continue,
            };
            if f["client_only"].as_bool().unwrap_or(false) {
                continue;
            }
            if let Some(val) = fv.get(key) {
                body[key] = val.clone();
            }
        }
    }
    if let Some(subs) = template["client_substitutions"].as_array() {
        for sub in subs {
            let target = sub["target"].as_str().unwrap_or("");
            let source = sub["source"].as_str().unwrap_or("");
            if target.is_empty() || source.is_empty() {
                continue;
            }
            let pattern = template[target].as_str().unwrap_or("").to_string();
            let src_val = match fv.get(source).and_then(|v| v.as_str()) {
                Some(v) if !v.is_empty() => v.to_string(),
                _ => continue,
            };
            if pattern.is_empty() {
                continue;
            }
            let placeholder = format!("{{{}}}", source);
            // Frontend uses encodeURIComponent; for these test values
            // (ASCII alnum, hyphens, dots) it's a no-op.
            body[target] = serde_json::Value::String(pattern.replace(&placeholder, &src_val));
        }
    }
    body
}

async fn post_credential(
    ctx: &agent_cordon_server::test_helpers::TestContext,
    cookie: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(cookie),
        Some(body),
    )
    .await
}

#[tokio::test]
async fn test_e2e_create_github_personal_access_token() {
    let (ctx, cookie) = setup().await;
    let tpl = fetch_template(&ctx, &cookie, "github").await;
    let body = build_submit_body(
        &tpl,
        "my-github-pat",
        &[("secret_value", "ghp_dummy0123456789ABCDEFGHIJKLMNOPQRSTUV")],
    );
    let (status, resp) = post_credential(&ctx, &cookie, body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "github PAT create failed: {:?}",
        resp
    );
    assert_eq!(resp["data"]["service"].as_str(), Some("api.github.com"));
    assert_eq!(resp["data"]["credential_type"].as_str(), Some("generic"));
}

#[tokio::test]
async fn test_e2e_create_openai_api_key() {
    let (ctx, cookie) = setup().await;
    let tpl = fetch_template(&ctx, &cookie, "openai").await;
    let body = build_submit_body(
        &tpl,
        "my-openai-key",
        &[("secret_value", "sk-dummy0123456789ABCDEFGHIJKLMNOPQRSTUV")],
    );
    let (status, resp) = post_credential(&ctx, &cookie, body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "openai key create failed: {:?}",
        resp
    );
    assert_eq!(resp["data"]["service"].as_str(), Some("api.openai.com"));
}

#[tokio::test]
async fn test_e2e_create_anthropic_api_key() {
    let (ctx, cookie) = setup().await;
    let tpl = fetch_template(&ctx, &cookie, "anthropic").await;
    let body = build_submit_body(
        &tpl,
        "my-anthropic-key",
        &[("secret_value", "sk-ant-dummy0123456789ABCDEFGHIJK")],
    );
    let (status, resp) = post_credential(&ctx, &cookie, body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "anthropic key create failed: {:?}",
        resp
    );
}

#[tokio::test]
async fn test_e2e_create_aws_credentials() {
    let (ctx, cookie) = setup().await;
    let tpl = fetch_template(&ctx, &cookie, "aws").await;
    let body = build_submit_body(
        &tpl,
        "my-aws-prod",
        &[
            ("aws_access_key_id", "AKIAIOSFODNN7EXAMPLE"),
            (
                "aws_secret_access_key",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            ),
            ("aws_region", "us-east-1"),
            ("aws_service", "s3"),
        ],
    );
    let (status, resp) = post_credential(&ctx, &cookie, body).await;
    assert_eq!(status, StatusCode::OK, "aws create failed: {:?}", resp);
    assert_eq!(resp["data"]["credential_type"].as_str(), Some("aws"));
}

#[tokio::test]
async fn test_e2e_create_entra_id_with_tenant_substitution() {
    let (ctx, cookie) = setup().await;
    let tpl = fetch_template(&ctx, &cookie, "entra-id").await;
    let tenant = "11111111-2222-3333-4444-555555555555";
    let body = build_submit_body(
        &tpl,
        "my-entra-app",
        &[
            ("oauth2_client_id", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            ("tenant_id", tenant),
            ("secret_value", "dummy-client-secret-not-real"),
            ("oauth2_scopes", "https://graph.microsoft.com/.default"),
        ],
    );

    // The frontend must have spliced the tenant_id into the endpoint URL.
    // This guards the client_substitutions wiring.
    let endpoint = body["oauth2_token_endpoint"]
        .as_str()
        .expect("endpoint set");
    assert!(
        endpoint.contains(tenant),
        "tenant_id must be substituted into oauth2_token_endpoint, got: {}",
        endpoint
    );
    assert!(
        !endpoint.contains("{tenant_id}"),
        "placeholder must be replaced, got: {}",
        endpoint
    );
    // tenant_id is client_only; must not reach the backend.
    assert!(
        body.get("tenant_id").is_none(),
        "tenant_id is client_only and must not be in the POST body"
    );

    let (status, resp) = post_credential(&ctx, &cookie, body).await;
    assert_eq!(status, StatusCode::OK, "entra create failed: {:?}", resp);
    assert_eq!(
        resp["data"]["credential_type"].as_str(),
        Some("oauth2_client_credentials")
    );
}

#[tokio::test]
async fn test_e2e_create_blank_generic_uses_fallback_fields() {
    // The Blank/Custom path uses the `_blank_generic` system template's
    // fields when no template is selected. Mirror that here by reading
    // _blank_generic directly and posting a credential without using a
    // user-visible template.
    let (ctx, cookie) = setup().await;
    let fallback = fetch_template(&ctx, &cookie, "_blank_generic").await;
    // The fallback must declare at least secret_value with required:true.
    let fields = fallback["fields"].as_array().expect("fields");
    assert!(
        fields
            .iter()
            .any(|f| f["key"].as_str() == Some("secret_value")
                && f["required"].as_bool().unwrap_or(false)),
        "_blank_generic must declare required secret_value field; got: {:?}",
        fields
    );
    let mut body = build_submit_body(
        &fallback,
        "my-custom-cred",
        &[("secret_value", "some-opaque-token")],
    );
    // For a true blank user, name and service are user-provided.
    body["service"] = serde_json::Value::String("example.internal".to_string());
    body["allowed_url_pattern"] =
        serde_json::Value::String("https://example.internal/*".to_string());

    let (status, resp) = post_credential(&ctx, &cookie, body).await;
    assert_eq!(status, StatusCode::OK, "blank generic failed: {:?}", resp);
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
