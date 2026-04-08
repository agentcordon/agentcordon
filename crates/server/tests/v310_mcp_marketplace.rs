//! v3.1.0 — MCP Marketplace integration tests.
//!
//! Phase 1: McpTransport enum (STDIO removed)
//! Phase 2: MCP template catalog (GET /api/v1/mcp-templates)
//! Phase 3: Provisioning endpoint (POST /api/v1/mcp-servers/provision)

use crate::common;

use agent_cordon_core::domain::mcp::McpTransport;
use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::routes::admin_api::mcp_templates::McpServerTemplate;
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::http::{Method, StatusCode};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a synthetic `mock-mcp` template for provisioning tests.
///
/// The real `mock-mcp.json` template was removed from the production marketplace
/// (we don't ship test fixtures to users). Tests that need it inject this
/// synthetic copy via `TestAppBuilder::with_mcp_template`.
fn mock_mcp_template() -> McpServerTemplate {
    McpServerTemplate {
        key: "mock-mcp".to_string(),
        name: "Mock MCP".to_string(),
        description: "Synthetic MCP template used by integration tests.".to_string(),
        upstream_url: "http://127.0.0.1:1/mock-mcp".to_string(),
        transport: "http".to_string(),
        auth_method: "api_key".to_string(),
        credential_template_key: None,
        category: "testing".to_string(),
        tags: vec!["test".to_string()],
        icon: "beaker".to_string(),
        sort_order: 9999,
        oauth2_authorize_url: None,
        oauth2_token_url: None,
        oauth2_scopes: None,
        oauth2_app_credential_template_key: None,
        oauth2_resource_url: None,
        oauth2_prefer_dcr: None,
    }
}

async fn setup() -> (agent_cordon_server::test_helpers::TestContext, String) {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_mcp_template(mock_mcp_template())
        .build()
        .await;
    let _user = common::create_test_user(
        &*ctx.store,
        "mcp-marketplace-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "mcp-marketplace-user", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

/// Setup returning (ctx, cookie, workspace_id_string) for provisioning tests.
async fn setup_with_workspace() -> (
    agent_cordon_server::test_helpers::TestContext,
    String,
    String,
) {
    let (ctx, cookie) = setup().await;
    let ws_id = ctx
        .admin_agent
        .as_ref()
        .expect("admin workspace must exist")
        .id
        .0
        .to_string();
    (ctx, cookie, ws_id)
}

// ===========================================================================
// Phase 1: McpTransport enum tests
// ===========================================================================

/// Http variant round-trips through serde.
#[tokio::test]
async fn test_mcp_transport_enum_serializes_http() {
    let transport = McpTransport::Http;
    let json = serde_json::to_string(&transport).expect("serialize Http");
    assert_eq!(json, "\"http\"");
    let deserialized: McpTransport = serde_json::from_str(&json).expect("deserialize Http");
    assert_eq!(deserialized, McpTransport::Http);
}

/// Sse variant round-trips through serde.
#[tokio::test]
async fn test_mcp_transport_enum_serializes_sse() {
    let transport = McpTransport::Sse;
    let json = serde_json::to_string(&transport).expect("serialize Sse");
    assert_eq!(json, "\"sse\"");
    let deserialized: McpTransport = serde_json::from_str(&json).expect("deserialize Sse");
    assert_eq!(deserialized, McpTransport::Sse);
}

/// Deserializing "stdio" fails — STDIO has been removed.
#[tokio::test]
async fn test_mcp_transport_enum_rejects_stdio() {
    let result = serde_json::from_str::<McpTransport>("\"stdio\"");
    assert!(result.is_err(), "stdio should be rejected: {:?}", result);
}

/// Deserializing unknown values ("grpc", "") fails.
#[tokio::test]
async fn test_mcp_transport_enum_rejects_unknown() {
    let grpc = serde_json::from_str::<McpTransport>("\"grpc\"");
    assert!(grpc.is_err(), "grpc should be rejected: {:?}", grpc);

    let empty = serde_json::from_str::<McpTransport>("\"\"");
    assert!(
        empty.is_err(),
        "empty string should be rejected: {:?}",
        empty
    );
}

// ===========================================================================
// Phase 2: MCP template catalog tests
// ===========================================================================

/// GET /api/v1/mcp-templates returns 200 with at least 6 templates.
#[tokio::test]
async fn test_mcp_templates_endpoint_returns_list() {
    let (ctx, cookie) = setup().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/mcp-templates",
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "mcp-templates: {:?}", body);
    let templates = body["data"]
        .as_array()
        .expect("data should be array of templates");
    assert!(
        templates.len() >= 6,
        "should have at least 6 templates, got {}",
        templates.len()
    );
}

/// GitHub template has correct key fields.
#[tokio::test]
async fn test_mcp_template_github_has_correct_fields() {
    let (ctx, cookie) = setup().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/mcp-templates",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let templates = body["data"].as_array().expect("data array");
    let github = templates
        .iter()
        .find(|t| t["key"].as_str() == Some("github"))
        .expect("should have a github template");

    assert_eq!(github["name"].as_str().unwrap(), "GitHub");
    assert_eq!(github["transport"].as_str().unwrap(), "sse");
    assert_eq!(github["auth_method"].as_str().unwrap(), "api_key");
    assert_eq!(
        github["credential_template_key"].as_str().unwrap(),
        "github"
    );
    assert_eq!(github["category"].as_str().unwrap(), "developer-tools");
    assert!(
        github["upstream_url"]
            .as_str()
            .unwrap()
            .starts_with("https://"),
        "upstream_url should be an HTTPS URL"
    );
}

/// Templates are sorted by sort_order.
#[tokio::test]
async fn test_mcp_templates_sorted_by_sort_order() {
    let (ctx, cookie) = setup().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/mcp-templates",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let templates = body["data"].as_array().expect("data array");
    assert!(
        templates.len() >= 2,
        "need at least 2 templates for ordering test"
    );

    let sort_orders: Vec<u64> = templates
        .iter()
        .map(|t| t["sort_order"].as_u64().unwrap())
        .collect();

    for window in sort_orders.windows(2) {
        assert!(
            window[0] <= window[1],
            "templates should be sorted by sort_order: {:?}",
            sort_orders
        );
    }
}

/// All templates have required fields (non-empty).
#[tokio::test]
async fn test_mcp_templates_all_have_required_fields() {
    let (ctx, cookie) = setup().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/mcp-templates",
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
            tpl["description"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            "template '{}' must have description",
            key
        );
        assert!(
            tpl["upstream_url"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            "template '{}' must have upstream_url",
            key
        );
        assert!(
            tpl["transport"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            "template '{}' must have transport",
            key
        );
        assert!(
            tpl["auth_method"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            "template '{}' must have auth_method",
            key
        );
        assert!(
            tpl["category"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            "template '{}' must have category",
            key
        );
        assert!(
            tpl["icon"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
            "template '{}' must have icon",
            key
        );
        assert!(
            tpl["sort_order"].as_u64().is_some(),
            "template '{}' must have sort_order",
            key
        );
    }
}

/// All transport values are "http" or "sse".
#[tokio::test]
async fn test_mcp_templates_transport_values_valid() {
    let (ctx, cookie) = setup().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/mcp-templates",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let templates = body["data"].as_array().expect("data array");
    for tpl in templates {
        let key = tpl["key"].as_str().unwrap_or("unknown");
        let transport = tpl["transport"].as_str().unwrap_or("");
        assert!(
            transport == "http" || transport == "sse",
            "template '{}' has invalid transport '{}' — must be 'http' or 'sse'",
            key,
            transport
        );
    }
}

/// All auth_method values are "api_key", "oauth2", or "none".
#[tokio::test]
async fn test_mcp_templates_auth_methods_valid() {
    let (ctx, cookie) = setup().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/mcp-templates",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let templates = body["data"].as_array().expect("data array");
    for tpl in templates {
        let key = tpl["key"].as_str().unwrap_or("unknown");
        let auth_method = tpl["auth_method"].as_str().unwrap_or("");
        assert!(
            auth_method == "api_key" || auth_method == "oauth2" || auth_method == "none",
            "template '{}' has invalid auth_method '{}' — must be 'api_key', 'oauth2', or 'none'",
            key,
            auth_method
        );
    }
}

/// Unauthenticated GET /api/v1/mcp-templates returns 401.
#[tokio::test]
async fn test_mcp_templates_require_auth() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/mcp-templates",
        None,
        None, // no cookie
        None,
    )
    .await;

    assert!(
        status == StatusCode::UNAUTHORIZED
            || status == StatusCode::FORBIDDEN
            || status == StatusCode::FOUND, // redirect to login
        "mcp-templates without auth should return 401/403/302, got {}",
        status
    );
}

/// Every MCP template's credential_template_key (when present) exists in credential templates.
#[tokio::test]
async fn test_mcp_templates_credential_template_keys_exist() {
    let (ctx, cookie) = setup().await;

    // Fetch MCP templates
    let (status, mcp_body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/mcp-templates",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Fetch credential templates
    let (status, cred_body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credential-templates",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let cred_templates = cred_body["data"]
        .as_array()
        .expect("credential templates array");
    let cred_keys: Vec<&str> = cred_templates
        .iter()
        .filter_map(|t| t["key"].as_str())
        .collect();

    let mcp_templates = mcp_body["data"].as_array().expect("mcp templates array");
    for tpl in mcp_templates {
        let key = tpl["key"].as_str().unwrap_or("unknown");
        if let Some(cred_key) = tpl["credential_template_key"].as_str() {
            assert!(
                cred_keys.contains(&cred_key),
                "MCP template '{}' references credential_template_key '{}' which does not exist. Available: {:?}",
                key,
                cred_key,
                cred_keys
            );
        }
    }
}

// ===========================================================================
// Phase 3: Provisioning tests (endpoint not yet implemented)
// ===========================================================================

// Phase 3: Provisioning endpoint is live.

/// Provision with an existing credential creates an MCP server.
#[tokio::test]

async fn test_provision_with_existing_credential() {
    let (ctx, cookie, ws_id) = setup_with_workspace().await;

    // Create a credential first
    let (status, cred_body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "name": "github-pat",
            "service": "github",
            "credential_type": "generic",
            "secret_value": "ghp_test123",
            "allowed_url_pattern": "https://api.github.com/*"
        })),
    )
    .await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "credential creation should succeed: {:?}",
        cred_body
    );
    let credential_id = cred_body["data"]["id"].as_str().expect("credential id");

    // Provision using template + existing credential
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/provision",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "template_key": "mock-mcp",
            "workspace_id": ws_id,
            "credential_id": credential_id
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "provision should succeed: {:?}",
        body
    );

    let data = &body["data"];
    assert!(data["id"].is_string(), "response should have server id");
    assert_eq!(data["name"].as_str(), Some("mock-mcp"));
}

/// Provision with an inline secret creates both credential and MCP server.
#[tokio::test]

async fn test_provision_with_inline_secret() {
    let (ctx, cookie, ws_id) = setup_with_workspace().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/provision",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "template_key": "mock-mcp",
            "workspace_id": ws_id,
            "secret_value": "ghp_inline_test_secret"
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "provision with inline secret should succeed: {:?}",
        body
    );

    let data = &body["data"];
    assert!(data["id"].is_string(), "response should have server id");
}

/// Provisioning does NOT create a per-server Cedar policy — the default policy
/// already permits workspaces to call tools on enabled MCP servers.
#[tokio::test]

async fn test_provision_does_not_create_cedar_policy() {
    let (ctx, cookie, ws_id) = setup_with_workspace().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/provision",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "template_key": "mock-mcp",
            "workspace_id": ws_id,
            "secret_value": "ghp_policy_test"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "provision: {:?}", body);

    // Verify no per-server Cedar policy was created
    let (status, policies_body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/policies",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let policies = policies_body["data"].as_array().expect("policies array");
    let server_id = body["data"]["id"].as_str().unwrap_or("");
    let has_mcp_provision_policy = policies.iter().any(|p| {
        let name = p["name"].as_str().unwrap_or("");
        name.contains("mcp-provision") && name.contains(server_id)
    });
    assert!(
        !has_mcp_provision_policy,
        "should NOT create an auto-grant policy — default policy covers MCP access"
    );
}

/// Provisioning emits an McpServerProvisioned audit event.
#[tokio::test]

async fn test_provision_audit_event() {
    let (ctx, cookie, ws_id) = setup_with_workspace().await;

    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/provision",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "template_key": "mock-mcp",
            "workspace_id": ws_id,
            "secret_value": "ghp_audit_test"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Fetch audit log
    let (status, audit_body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/audit",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let events = audit_body["data"].as_array().expect("audit events array");
    let has_provision_event = events.iter().any(|e| {
        e["event_type"].as_str() == Some("mcp_server_provisioned")
            || e["action"].as_str() == Some("provision")
    });
    assert!(
        has_provision_event,
        "should have an mcp_server_provisioned audit event, got: {:?}",
        events
            .iter()
            .map(|e| e["event_type"].as_str().unwrap_or("?"))
            .collect::<Vec<_>>()
    );
}

/// Provisioning with an invalid template key returns 404.
#[tokio::test]

async fn test_provision_invalid_template_key() {
    let (ctx, cookie, ws_id) = setup_with_workspace().await;

    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/provision",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "template_key": "nonexistent-template",
            "workspace_id": ws_id,
            "secret_value": "some-secret"
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "provisioning with nonexistent template should return 404"
    );
}

/// Provisioning the same template+workspace twice returns 409 Conflict.
#[tokio::test]

async fn test_provision_duplicate_template_workspace() {
    let (ctx, cookie, ws_id) = setup_with_workspace().await;

    // First provision should succeed
    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/provision",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "template_key": "mock-mcp",
            "workspace_id": ws_id,
            "secret_value": "ghp_first"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "first provision should succeed");

    // Second provision of same template should conflict
    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/provision",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "template_key": "mock-mcp",
            "workspace_id": ws_id,
            "secret_value": "ghp_second"
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "duplicate provision should return 409"
    );
}

/// Provisioning without authentication returns 401.
#[tokio::test]

async fn test_provision_requires_auth() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws_id = ctx
        .admin_agent
        .as_ref()
        .expect("admin workspace")
        .id
        .0
        .to_string();

    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/provision",
        None,
        None, // no cookie
        Some(serde_json::json!({
            "template_key": "mock-mcp",
            "workspace_id": ws_id,
            "secret_value": "ghp_unauth"
        })),
    )
    .await;
    assert!(
        status == StatusCode::UNAUTHORIZED
            || status == StatusCode::FORBIDDEN
            || status == StatusCode::FOUND,
        "provision without auth should return 401/403/302, got {}",
        status
    );
}

/// Provision response must not contain the secret value.
#[tokio::test]

async fn test_provision_no_secret_in_response() {
    let (ctx, cookie, ws_id) = setup_with_workspace().await;
    let secret = "ghp_super_secret_value_12345";

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/provision",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "template_key": "mock-mcp",
            "workspace_id": ws_id,
            "secret_value": secret
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let body_str = serde_json::to_string(&body).unwrap();
    assert!(
        !body_str.contains(secret),
        "response must not contain the secret value"
    );
}

/// Audit event for provisioning must not contain the secret value.
#[tokio::test]

async fn test_provision_no_secret_in_audit() {
    let (ctx, cookie, ws_id) = setup_with_workspace().await;
    let secret = "ghp_audit_secret_leak_check_xyz";

    let (status, _body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/provision",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "template_key": "mock-mcp",
            "workspace_id": ws_id,
            "secret_value": secret
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Fetch audit log
    let (status, audit_body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/audit",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let audit_str = serde_json::to_string(&audit_body).unwrap();
    assert!(
        !audit_str.contains(secret),
        "audit events must not contain the secret value"
    );
}
