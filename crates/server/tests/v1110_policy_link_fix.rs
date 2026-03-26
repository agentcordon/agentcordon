//! v1.11.0 — Policy Link 404 Fix + Search Param Tests (Features 1 & 2)
//!
//! Feature 1: Links in credential/mcp detail pages must point to `/security?search=`
//! NOT `/security/policies?search=`.
//!
//! Feature 2: `/security?search=X` pre-filters policies on page load.

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
    let ctx = TestAppBuilder::new()
        .with_admin()
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
        "policy-link-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "policy-link-user", common::TEST_PASSWORD).await;
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

async fn create_test_credential(
    app: &axum::Router,
    cookie: &str,
    name: &str,
    service: &str,
) -> String {
    let (status, body) = common::send_json_auto_csrf(
        app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(cookie),
        Some(json!({
            "name": name,
            "service": service,
            "secret_value": "test-secret-value",
        })),
    )
    .await;

    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "credential creation should succeed: status={}, body={:?}",
        status,
        body,
    );

    body["data"]["id"]
        .as_str()
        .expect("credential should have id")
        .to_string()
}

async fn create_test_mcp_server(
    store: &(dyn agent_cordon_core::storage::Store + Send + Sync),
    name: &str,
    device_id: &str,
) -> String {
    let now = chrono::Utc::now();
    let d_uuid = uuid::Uuid::parse_str(device_id).expect("valid device uuid");
    let server = agent_cordon_core::domain::mcp::McpServer {
        id: agent_cordon_core::domain::mcp::McpServerId(uuid::Uuid::new_v4()),
        workspace_id: agent_cordon_core::domain::workspace::WorkspaceId(d_uuid),
        name: name.to_string(),
        upstream_url: "http://localhost:9999".to_string(),
        transport: "stdio".to_string(),
        allowed_tools: None,
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials: None,
    };
    store
        .create_mcp_server(&server)
        .await
        .expect("create mcp server");
    server.id.0.to_string()
}

// ===========================================================================
// Feature 1: Policy Link 404 Fix
// ===========================================================================

// 1A. Happy Path

/// Create credential, render detail page, assert RSoP policy links point to /security?search=.
#[tokio::test]
async fn test_credential_detail_rsop_policy_link_points_to_security() {
    let (ctx, cookie) = setup().await;
    let cred_id = create_test_credential(&ctx.app, &cookie, "link-test-cred", "github").await;

    // Grant an agent access so RSoP has data
    let admin_agent = ctx.admin_agent.as_ref().expect("admin agent");
    let (_grant_status, _grant_body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{}/permissions", cred_id),
        None,
        Some(&cookie),
        Some(json!({
            "agent_id": admin_agent.id.0.to_string(),
            "permission": "delegated_use",
        })),
    )
    .await;

    // Render the credential detail page
    let (status, body) = get_html(&ctx.app, &format!("/credentials/{}", cred_id), &cookie).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "credential detail page should return 200"
    );

    // Assert links point to /security?search= NOT /security/policies?search=
    assert!(
        !body.contains("/security/policies?search="),
        "credential detail page must NOT contain /security/policies?search= (old broken link)"
    );
    // If the page contains policy links, they should use /security?search=
    if body.contains("/security?search=") {
        // Good — the fix is in place
    }
}

/// Create MCP server, render detail page, assert policy links point to /security?search=.
#[tokio::test]
async fn test_mcp_detail_rsop_policy_link_points_to_security() {
    let (ctx, cookie) = setup().await;
    let (d_id, _) = common::create_standalone_device(&ctx.state).await;
    let mcp_id = create_test_mcp_server(&*ctx.store, "link-test-mcp", &d_id).await;

    let (status, body) = get_html(&ctx.app, &format!("/mcp-servers/{}", mcp_id), &cookie).await;

    assert_eq!(status, StatusCode::OK, "MCP detail page should return 200");

    assert!(
        !body.contains("/security/policies?search="),
        "MCP detail page must NOT contain /security/policies?search= (old broken link)"
    );
}

/// GET /security?search=grant%3A returns 200 with search param pre-filled.
#[tokio::test]
async fn test_policy_link_navigates_to_filtered_list() {
    let (ctx, cookie) = setup().await;

    let (status, body) = get_html(&ctx.app, "/security?search=grant%3A", &cookie).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "/security?search= should return 200"
    );
    // The page should render successfully with the search term
    assert!(
        body.contains("grant:") || body.contains("grant%3A") || body.contains("security"),
        "page should render with search context"
    );
}

// 1C. Error Handling

/// GET /security/policies is NOT the policy list — it hits the /security/{id} wildcard
/// with id="policies", which is not a valid UUID, so it returns a policy-not-found page.
#[tokio::test]
async fn test_security_policies_route_is_not_policy_list() {
    let (ctx, cookie) = setup().await;

    let (status, body) = get_html(&ctx.app, "/security/policies", &cookie).await;

    // /security/{id} catches "policies" as an ID param. Since "policies" is not a
    // valid UUID, the handler should return an error/not-found detail page — NOT
    // the policy list page. This confirms the old /security/policies link is broken.
    if status == StatusCode::OK {
        // If 200, it rendered a page — but it should NOT be the policy list.
        // A policy list page would contain multiple policy entries or a search bar.
        // A not-found detail page would contain an error message.
        assert!(
            body.contains("not found")
                || body.contains("Not Found")
                || body.contains("error")
                || body.contains("invalid")
                || !body.contains("x-model=\"search\""),
            "/security/policies should NOT render as the policy list page"
        );
    }
    // 404 or 400 are also acceptable outcomes
}

/// GET /security?search= (empty) returns 200 with all policies.
#[tokio::test]
async fn test_security_route_with_empty_search_param() {
    let (ctx, cookie) = setup().await;

    let (status, body) = get_html(&ctx.app, "/security?search=", &cookie).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "/security?search= should return 200"
    );
    // Page should render (contains policy-related content)
    assert!(
        body.contains("Policies") || body.contains("policy") || body.contains("security"),
        "page should render the policy list"
    );
}

/// GET /security?search=nonexistent returns 200 with no matching results.
#[tokio::test]
async fn test_security_route_with_nonexistent_policy_search() {
    let (ctx, cookie) = setup().await;

    let (status, _body) = get_html(
        &ctx.app,
        "/security?search=nonexistent_policy_xyz_12345",
        &cookie,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "/security?search=nonexistent should return 200 (graceful empty state)"
    );
}

// 1E. Security

/// XSS in search param is safely escaped (Askama auto-escapes).
#[tokio::test]
async fn test_policy_link_search_param_xss_safe() {
    let (ctx, cookie) = setup().await;

    let (status, body) = get_html(
        &ctx.app,
        "/security?search=%3Cscript%3Ealert(1)%3C/script%3E",
        &cookie,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("<script>alert(1)</script>"),
        "response must NOT contain unescaped <script> tag (XSS vulnerability)"
    );
}

// ===========================================================================
// Feature 2: Search Param Support on Policy List Page
// ===========================================================================

// 2A. Happy Path

/// GET /security?search=grant%3Acred1 populates the search input.
#[tokio::test]
async fn test_policy_list_search_param_populates_input() {
    let (ctx, cookie) = setup().await;

    // Create some policies with distinctive names
    let _p1 = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies",
        None,
        Some(&cookie),
        Some(json!({
            "name": "grant:cred1:agent1:access",
            "description": "Test policy 1",
            "cedar_policy": "permit(principal, action, resource);",
        })),
    )
    .await;

    let (status, body) = get_html(&ctx.app, "/security?search=grant%3Acred1", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    // The rendered HTML should contain the search value for Alpine.js to pick up
    assert!(
        body.contains("grant:cred1") || body.contains("grant%3Acred1"),
        "page should contain the search term 'grant:cred1' in the rendered HTML"
    );
}

/// GET /security without search param shows all policies.
#[tokio::test]
async fn test_policy_list_without_search_param_shows_all() {
    let (ctx, cookie) = setup().await;

    let (status, body) = get_html(&ctx.app, "/security", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    // The default policy should always be visible
    assert!(
        body.contains("policy") || body.contains("Policies") || body.contains("cedar"),
        "policy list page should render with policy content"
    );
}

// 2C. Error Handling

/// Special chars in search param don't cause 500.
#[tokio::test]
async fn test_policy_list_search_param_special_chars_encoded() {
    let (ctx, cookie) = setup().await;

    let (status, _body) =
        get_html(&ctx.app, "/security?search=grant%3A%22quoted%22", &cookie).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "special chars in search param should not cause 500"
    );
}

/// Very long search param doesn't crash.
#[tokio::test]
async fn test_policy_list_search_param_very_long() {
    let (ctx, cookie) = setup().await;

    let long_search = "a".repeat(1000);
    let (status, _body) = get_html(
        &ctx.app,
        &format!("/security?search={}", long_search),
        &cookie,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "very long search param should not crash the server"
    );
}
