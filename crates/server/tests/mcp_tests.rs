//! Integration tests for MCP Identity Gateway.
//!
//! Covers:
//! - WS1: MCP Server Registry CRUD (admin-only user session auth)
//! - WS2: Cedar policy extensions for McpServer entity
//! - WS3: MCP Proxy endpoint (deprecated — 410 Gone)
//! - WS4: MCP Policy Generation

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

use agent_cordon_core::crypto::password::hash_password;
use agent_cordon_core::domain::mcp::{McpAuthMethod, McpServer, McpServerId, McpTransport};
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::domain::user::{User, UserId, UserRole};
use agent_cordon_core::policy::{claim_keys, PolicyPrincipal, PolicyResource};
use agent_cordon_core::storage::Store;

use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TEST_PASSWORD: &str = "strong-test-password-123!";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Create a user directly in the store.
async fn create_user_in_db(
    store: &(dyn Store + Send + Sync),
    username: &str,
    password: &str,
    role: UserRole,
) -> User {
    let password_hash = hash_password(password).expect("hash password");
    let now = chrono::Utc::now();
    let user = User {
        id: UserId(Uuid::new_v4()),
        username: username.to_string(),
        display_name: Some(format!("Test {}", username)),
        password_hash,
        role,
        is_root: false,
        enabled: true,
        created_at: now,
        updated_at: now,
    };
    store.create_user(&user).await.expect("create user");
    user
}

/// Login a user and return (combined_cookie, csrf_token).
async fn login_user(app: &Router, username: &str, password: &str) -> (String, String) {
    let (status, body, headers) = send_json_with_headers(
        app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        None,
        Some(json!({ "username": username, "password": password })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "login failed for user '{}': {:?}",
        username,
        body
    );

    let session_cookie = headers
        .iter()
        .filter(|(name, _)| name == "set-cookie")
        .find(|(_, val)| val.starts_with("agtcrdn_session="))
        .expect("session Set-Cookie header must be present")
        .1
        .clone();
    let session_cookie = session_cookie
        .split(';')
        .next()
        .expect("cookie must have value")
        .trim()
        .to_string();

    let csrf_token = body["data"]["csrf_token"]
        .as_str()
        .expect("login response must include csrf_token")
        .to_string();

    let combined = format!("{}; agtcrdn_csrf={}", session_cookie, csrf_token);
    (combined, csrf_token)
}

/// Extract CSRF token from a combined cookie string.
fn extract_csrf_from_cookie(cookie: &str) -> Option<String> {
    for pair in cookie.split(';') {
        let pair = pair.trim();
        if let Some(val) = pair.strip_prefix("agtcrdn_csrf=") {
            return Some(val.to_string());
        }
    }
    None
}

/// Send a JSON request with optional cookie and bearer, return (status, body, headers).
async fn send_json_with_headers(
    app: &Router,
    method: Method,
    uri: &str,
    bearer: Option<&str>,
    cookie: Option<&str>,
    csrf_token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value, Vec<(String, String)>) {
    let mut builder = Request::builder().method(method.clone()).uri(uri);

    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {}", token));
    }

    if let Some(cookie_val) = cookie {
        builder = builder.header(header::COOKIE, cookie_val);

        let is_state_changing = method == Method::POST
            || method == Method::PUT
            || method == Method::DELETE
            || method == Method::PATCH;
        if is_state_changing {
            if let Some(csrf) = csrf_token {
                builder = builder.header("x-csrf-token", csrf);
            } else if let Some(csrf) = extract_csrf_from_cookie(cookie_val) {
                builder = builder.header("x-csrf-token", csrf);
            }
        }
    } else if let Some(csrf) = csrf_token {
        builder = builder.header("x-csrf-token", csrf);
    }

    let body = match body {
        Some(v) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&v).unwrap())
        }
        None => Body::empty(),
    };

    let request = builder.body(body).unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();

    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));
    (status, json, headers)
}

/// Send a JSON request (no headers returned).
async fn send_json(
    app: &Router,
    method: Method,
    uri: &str,
    bearer: Option<&str>,
    cookie: Option<&str>,
    csrf_token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let (status, json, _headers) =
        send_json_with_headers(app, method, uri, bearer, cookie, csrf_token, body).await;
    (status, json)
}

/// Helper: register an MCP server directly in the store.
async fn register_mcp_server_in_store(
    store: &(dyn Store + Send + Sync),
    name: &str,
    upstream_url: &str,
    enabled: bool,
    allowed_tools: Option<Vec<String>>,
) -> McpServer {
    // Create a test workspace for this MCP server
    let workspace = agent_cordon_core::domain::workspace::Workspace {
        id: agent_cordon_core::domain::workspace::WorkspaceId(Uuid::new_v4()),
        name: format!("test-workspace-{}", name),
        status: agent_cordon_core::domain::workspace::WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        tags: vec![],
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    store
        .create_workspace(&workspace)
        .await
        .expect("create test workspace");
    let now = chrono::Utc::now();
    let server = McpServer {
        id: McpServerId(Uuid::new_v4()),
        workspace_id: Some(workspace.id),
        name: name.to_string(),
        upstream_url: upstream_url.to_string(),
        transport: McpTransport::Http,
        allowed_tools,
        enabled,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials: None,
        auth_method: McpAuthMethod::default(),
        template_key: None,
        discovered_tools: None,
        created_by_user: None,
    };
    store
        .create_mcp_server(&server)
        .await
        .expect("create mcp server");
    server
}

// ===========================================================================
// WS1: MCP Server Registry — CRUD Tests (using store-inserted servers)
// ===========================================================================

// ---------------------------------------------------------------------------
// 4. List MCP servers — returns all servers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mcp_server_list_all() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_user_in_db(&*ctx.store, "mcp-admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, _csrf) = login_user(&ctx.app, "mcp-admin", TEST_PASSWORD).await;

    // Create two servers in the store
    register_mcp_server_in_store(&*ctx.store, "server-a", "http://a:3000", true, None).await;
    register_mcp_server_in_store(&*ctx.store, "server-b", "http://b:3000", true, None).await;

    // List all
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/mcp-servers",
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list failed: {}", body);

    let servers = body["data"].as_array().expect("data should be an array");
    assert!(
        servers.len() >= 2,
        "should have at least 2 servers, got {}",
        servers.len()
    );
    let names: Vec<&str> = servers.iter().filter_map(|s| s["name"].as_str()).collect();
    assert!(names.contains(&"server-a"), "should contain server-a");
    assert!(names.contains(&"server-b"), "should contain server-b");
}

// ---------------------------------------------------------------------------
// 5. Get MCP server by ID — happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mcp_server_get_by_id() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_user_in_db(&*ctx.store, "mcp-admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, _csrf) = login_user(&ctx.app, "mcp-admin", TEST_PASSWORD).await;

    let server = register_mcp_server_in_store(
        &*ctx.store,
        "get-test-server",
        "http://get-test:3000",
        true,
        None,
    )
    .await;

    // Get by ID
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/mcp-servers/{}", server.id.0),
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "get by id failed: {}", body);
    assert_eq!(body["data"]["name"], "get-test-server");
    assert_eq!(body["data"]["id"], server.id.0.to_string());
}

// ---------------------------------------------------------------------------
// 6. Get MCP server — not found returns 404
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mcp_server_get_not_found() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_user_in_db(&*ctx.store, "mcp-admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, _csrf) = login_user(&ctx.app, "mcp-admin", TEST_PASSWORD).await;

    let fake_id = Uuid::new_v4();
    let (status, _body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/mcp-servers/{}", fake_id),
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "should return 404");
}

// ---------------------------------------------------------------------------
// 7. Update MCP server — happy path (name-only)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mcp_server_update_happy_path() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_user_in_db(&*ctx.store, "mcp-admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "mcp-admin", TEST_PASSWORD).await;

    let server =
        register_mcp_server_in_store(&*ctx.store, "update-server", "http://old:3000", true, None)
            .await;

    // Update name
    let (status, body) = send_json(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/mcp-servers/{}", server.id.0),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "updated-server-name"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "update failed: {}", body);
    assert_eq!(body["data"]["name"], "updated-server-name");
}

// ---------------------------------------------------------------------------
// 8. Delete MCP server — happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mcp_server_delete_happy_path() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_user_in_db(&*ctx.store, "mcp-admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "mcp-admin", TEST_PASSWORD).await;

    let server =
        register_mcp_server_in_store(&*ctx.store, "delete-server", "http://del:3000", true, None)
            .await;

    // Delete
    let (status, _body) = send_json(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/mcp-servers/{}", server.id.0),
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "delete should succeed, got {}",
        status
    );

    // Verify it's gone
    let (status, _body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/mcp-servers/{}", server.id.0),
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "deleted server should be gone"
    );
}

// ---------------------------------------------------------------------------
// 9. Delete MCP server — not found returns 404
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mcp_server_delete_not_found() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_user_in_db(&*ctx.store, "mcp-admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "mcp-admin", TEST_PASSWORD).await;

    let fake_id = Uuid::new_v4();
    let (status, _body) = send_json(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/mcp-servers/{}", fake_id),
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "should return 404 for missing server"
    );
}

// ===========================================================================
// WS2: Cedar Policy Tests
// ===========================================================================

// ---------------------------------------------------------------------------
// 23. Cedar schema validates with McpServer entity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_cedar_schema_validates_with_mcp_server() {
    let _ctx = TestAppBuilder::new().build().await;
}

// ---------------------------------------------------------------------------
// 24. MCP tool call policy — admin agent allowed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_cedar_mcp_tool_call_admin_allowed() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let admin = ctx.admin_agent.clone().expect("admin agent");

    let result = ctx
        .state
        .authz
        .request(
            agent_cordon_server::authz::PolicyCaller::Principal {
                principal: PolicyPrincipal::Workspace(&admin),
                oauth_claims: None,
            },
            &uuid::Uuid::new_v4().to_string(),
        )
        .with_claim(
            claim_keys::TOOL_NAME,
            serde_json::json!(Some("create_issue".to_string())),
        )
        .check_with_reasons(
            "mcp_tool_call",
            &PolicyResource::McpServer {
                id: Uuid::new_v4().to_string(),
                name: "test-server".to_string(),
                enabled: true,
                tags: vec![],
                owner: None,
            },
        )
        .await
        .expect("policy evaluation should succeed");

    assert_eq!(
        result.decision,
        PolicyDecisionResult::Permit,
        "admin agent should be allowed to call MCP tools"
    );
}

// ---------------------------------------------------------------------------
// 25. MCP tool call policy — non-admin agent allowed (default policy)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_cedar_mcp_tool_call_non_admin_allowed() {
    use agent_cordon_core::domain::user::UserId;
    let ctx = TestAppBuilder::new()
        .with_agent("viewer-bot", &["viewer"])
        .build()
        .await;
    let mut viewer = ctx.agents.get("viewer-bot").expect("viewer agent").clone();
    let owner_id = UserId(Uuid::new_v4());
    viewer.owner_id = Some(owner_id.clone());

    let result = ctx
        .state
        .authz
        .request(
            agent_cordon_server::authz::PolicyCaller::Principal {
                principal: PolicyPrincipal::Workspace(&viewer),
                oauth_claims: None,
            },
            &uuid::Uuid::new_v4().to_string(),
        )
        .with_claim(
            claim_keys::TOOL_NAME,
            serde_json::json!(Some("create_issue".to_string())),
        )
        .check_with_reasons(
            "mcp_tool_call",
            &PolicyResource::McpServer {
                id: Uuid::new_v4().to_string(),
                name: "test-server".to_string(),
                enabled: true,
                tags: vec![],
                owner: Some(owner_id),
            },
        )
        .await
        .expect("policy evaluation should succeed");

    assert_eq!(
        result.decision,
        PolicyDecisionResult::Permit,
        "non-admin agent should be allowed MCP tool calls on enabled servers"
    );
}

// ---------------------------------------------------------------------------
// 26. MCP list tools policy — enabled agent on enabled server allowed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_cedar_mcp_list_tools_enabled_agent_allowed() {
    use agent_cordon_core::domain::user::UserId;
    let ctx = TestAppBuilder::new()
        .with_agent("enabled-bot", &["worker"])
        .build()
        .await;
    let mut agent = ctx
        .agents
        .get("enabled-bot")
        .expect("enabled agent")
        .clone();
    let owner_id = UserId(Uuid::new_v4());
    agent.owner_id = Some(owner_id.clone());

    let result = ctx
        .state
        .authz
        .request(
            agent_cordon_server::authz::PolicyCaller::Principal {
                principal: PolicyPrincipal::Workspace(&agent),
                oauth_claims: None,
            },
            &uuid::Uuid::new_v4().to_string(),
        )
        .check_with_reasons(
            "mcp_list_tools",
            &PolicyResource::McpServer {
                id: Uuid::new_v4().to_string(),
                name: "test-server".to_string(),
                enabled: true,
                tags: vec![],
                owner: Some(owner_id),
            },
        )
        .await
        .expect("policy evaluation should succeed");

    assert_eq!(
        result.decision,
        PolicyDecisionResult::Permit,
        "enabled agent should be able to list tools on enabled MCP server"
    );
}

// ---------------------------------------------------------------------------
// 33. Update MCP server — empty name in update rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mcp_server_update_empty_name_rejected() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_user_in_db(&*ctx.store, "mcp-admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "mcp-admin", TEST_PASSWORD).await;

    let server = register_mcp_server_in_store(
        &*ctx.store,
        "to-update",
        "http://to-update:3000",
        true,
        None,
    )
    .await;

    let (status, body) = send_json(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/mcp-servers/{}", server.id.0),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({ "name": "  " })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "empty name in update should be rejected: {}",
        body
    );
}

// ---------------------------------------------------------------------------
// 34. Update MCP server — not found returns 404
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mcp_server_update_not_found() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_user_in_db(&*ctx.store, "mcp-admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "mcp-admin", TEST_PASSWORD).await;

    let fake_id = Uuid::new_v4();
    let (status, _body) = send_json(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/mcp-servers/{}", fake_id),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({ "name": "new-name" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "should return 404 for missing server"
    );
}

// ---------------------------------------------------------------------------
// 38. Cedar policy — disabled MCP server forbidden (defense-in-depth)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_cedar_mcp_tool_call_disabled_server_forbidden() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let admin = ctx.admin_agent.clone().expect("admin agent");

    // Even admin agents should be forbidden on disabled servers
    let result = ctx
        .state
        .authz
        .request(
            agent_cordon_server::authz::PolicyCaller::Principal {
                principal: PolicyPrincipal::Workspace(&admin),
                oauth_claims: None,
            },
            &uuid::Uuid::new_v4().to_string(),
        )
        .with_claim(
            claim_keys::TOOL_NAME,
            serde_json::json!(Some("create_issue".to_string())),
        )
        .check_with_reasons(
            "mcp_tool_call",
            &PolicyResource::McpServer {
                id: Uuid::new_v4().to_string(),
                name: "disabled-server".to_string(),
                enabled: false,
                tags: vec![],
                owner: None,
            },
        )
        .await
        .expect("policy evaluation should succeed");

    assert_eq!(
        result.decision,
        PolicyDecisionResult::Forbid,
        "tool calls on disabled MCP servers should be forbidden even for admins"
    );
}

// ---------------------------------------------------------------------------
// 39. Cedar policy — mcp_list_tools on disabled server forbidden
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_cedar_mcp_list_tools_disabled_server_forbidden() {
    let ctx = TestAppBuilder::new()
        .with_agent("enabled-bot", &["worker"])
        .build()
        .await;
    let agent = ctx.agents.get("enabled-bot").expect("enabled agent");

    let result = ctx
        .state
        .authz
        .request(
            agent_cordon_server::authz::PolicyCaller::Principal {
                principal: PolicyPrincipal::Workspace(agent),
                oauth_claims: None,
            },
            &uuid::Uuid::new_v4().to_string(),
        )
        .check_with_reasons(
            "mcp_list_tools",
            &PolicyResource::McpServer {
                id: Uuid::new_v4().to_string(),
                name: "disabled-server".to_string(),
                enabled: false,
                tags: vec![],
                owner: None,
            },
        )
        .await
        .expect("policy evaluation should succeed");

    assert_eq!(
        result.decision,
        PolicyDecisionResult::Forbid,
        "tool listing on disabled MCP servers should be forbidden"
    );
}

// ===========================================================================
// WS4: MCP Policy Generation (generate-policies endpoint still exists)
// ===========================================================================

// ---------------------------------------------------------------------------
// 5. Generate policies — happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_generate_policies_happy_path() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_user_in_db(&*ctx.store, "mcp-admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "mcp-admin", TEST_PASSWORD).await;

    let server = register_mcp_server_in_store(
        &*ctx.store,
        "policy-gen-mcp",
        "http://mcp-test:3000",
        true,
        None,
    )
    .await;

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/mcp-servers/{}/generate-policies", server.id.0),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "tools": ["create_issue", "list_repos"],
            "agent_tags": ["ci"]
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "policy generation should succeed: {}",
        body
    );
    let data = &body["data"];
    let policies = data["policies_created"]
        .as_array()
        .expect("should have policies_created");
    assert_eq!(
        policies.len(),
        2,
        "should create 2 policies (2 tools x 1 tag)"
    );

    // Verify policy names follow the expected pattern
    assert!(policies[0]["name"]
        .as_str()
        .unwrap()
        .contains("create_issue"));
    assert!(policies[0]["name"].as_str().unwrap().contains("ci"));
    assert!(policies[1]["name"].as_str().unwrap().contains("list_repos"));

    // Verify Cedar policy content
    let cedar = policies[0]["cedar_policy"].as_str().unwrap();
    assert!(
        cedar.contains("mcp_tool_call"),
        "should use mcp_tool_call action"
    );
    assert!(cedar.contains("create_issue"), "should reference tool name");
    assert!(cedar.contains("ci"), "should reference agent tag");
    let server_id_str = server.id.0.to_string();
    assert!(cedar.contains(&server_id_str), "should reference server ID");
}

// ---------------------------------------------------------------------------
// 6. Generate policies — multiple tags
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_generate_policies_multiple_tags() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_user_in_db(&*ctx.store, "mcp-admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "mcp-admin", TEST_PASSWORD).await;

    let server = register_mcp_server_in_store(
        &*ctx.store,
        "multi-tag-mcp",
        "http://mcp-test:3000",
        true,
        None,
    )
    .await;

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/mcp-servers/{}/generate-policies", server.id.0),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "tools": ["create_issue"],
            "agent_tags": ["ci", "deploy"]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "should succeed: {}", body);
    let policies = body["data"]["policies_created"].as_array().unwrap();
    assert_eq!(
        policies.len(),
        2,
        "should create 2 policies (1 tool x 2 tags)"
    );
}

// ---------------------------------------------------------------------------
// 7. Generate policies — empty tools rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_generate_policies_empty_tools_rejected() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_user_in_db(&*ctx.store, "mcp-admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "mcp-admin", TEST_PASSWORD).await;

    let server = register_mcp_server_in_store(
        &*ctx.store,
        "empty-tools-mcp",
        "http://mcp-test:3000",
        true,
        None,
    )
    .await;

    let (status, _body) = send_json(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/mcp-servers/{}/generate-policies", server.id.0),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "tools": [],
            "agent_tags": ["ci"]
        })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "empty tools should be rejected"
    );
}

// ---------------------------------------------------------------------------
// 8. Generate policies — non-admin denied
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_generate_policies_non_admin_denied() {
    let ctx = TestAppBuilder::new().build().await;
    let _viewer =
        create_user_in_db(&*ctx.store, "mcp-viewer", TEST_PASSWORD, UserRole::Viewer).await;
    let (cookie, csrf) = login_user(&ctx.app, "mcp-viewer", TEST_PASSWORD).await;

    let server = register_mcp_server_in_store(
        &*ctx.store,
        "denied-policy-mcp",
        "http://mcp-test:3000",
        true,
        None,
    )
    .await;

    let (status, _body) = send_json(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/mcp-servers/{}/generate-policies", server.id.0),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "tools": ["create_issue"],
            "agent_tags": ["ci"]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "non-admin should be denied");
}

// ---------------------------------------------------------------------------
// 9. Generate policies — server not found
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_generate_policies_server_not_found() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_user_in_db(&*ctx.store, "mcp-admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "mcp-admin", TEST_PASSWORD).await;

    let fake_id = Uuid::new_v4();
    let (status, _body) = send_json(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/mcp-servers/{}/generate-policies", fake_id),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "tools": ["create_issue"],
            "agent_tags": ["ci"]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND, "should return 404");
}

// ---------------------------------------------------------------------------
// 7b. Generate policies — an empty body means "every tool, every bound tag"
// ---------------------------------------------------------------------------

/// Create a workspace with `tags`, an MCP server with the given tool lists,
/// and bind the two through the junction. Returns the server.
async fn mcp_bound_to_tagged_workspace(
    store: &(dyn Store + Send + Sync),
    name: &str,
    tags: &[&str],
    allowed_tools: Option<Vec<String>>,
    discovered_tools: Option<Vec<agent_cordon_core::domain::mcp::McpTool>>,
) -> McpServer {
    let now = chrono::Utc::now();
    let workspace = agent_cordon_core::domain::workspace::Workspace {
        id: agent_cordon_core::domain::workspace::WorkspaceId(Uuid::new_v4()),
        name: format!("ws-{}", name),
        status: agent_cordon_core::domain::workspace::WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        tags: tags.iter().map(|t| t.to_string()).collect(),
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };
    store
        .create_workspace(&workspace)
        .await
        .expect("create workspace");

    let server = McpServer {
        id: McpServerId(Uuid::new_v4()),
        workspace_id: None,
        name: name.to_string(),
        upstream_url: "http://mcp-test:3000".to_string(),
        transport: McpTransport::Http,
        allowed_tools,
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials: None,
        auth_method: McpAuthMethod::default(),
        template_key: None,
        discovered_tools,
        created_by_user: None,
    };
    store
        .create_mcp_server(&server)
        .await
        .expect("create mcp server");
    store
        .add_mcp_server_workspace(&server.id, &workspace.id, None)
        .await
        .expect("bind mcp server to workspace");
    server
}

/// An empty body is the "grant what this server has" request: every tool the
/// server currently knows about, to every tag its bound workspaces carry.
#[tokio::test]
async fn test_generate_policies_empty_body_uses_the_servers_own_tools_and_tags() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_user_in_db(&*ctx.store, "mcp-admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "mcp-admin", TEST_PASSWORD).await;

    let server = mcp_bound_to_tagged_workspace(
        &*ctx.store,
        "defaults-mcp",
        &["ci"],
        Some(vec!["create_issue".to_string(), "list_repos".to_string()]),
        None,
    )
    .await;

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/mcp-servers/{}/generate-policies", server.id.0),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({})),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "an empty body is a valid request: {}",
        body
    );
    let policies = body["data"]["policies_created"]
        .as_array()
        .unwrap_or_else(|| panic!("policies_created: {}", body));
    assert_eq!(policies.len(), 2, "2 tools x 1 tag: {}", body);
    let names: Vec<&str> = policies.iter().filter_map(|p| p["name"].as_str()).collect();
    assert!(
        names.iter().any(|n| n.contains("create_issue")),
        "every tool gets a grant: {:?}",
        names
    );
    assert!(
        names.iter().any(|n| n.contains("list_repos")),
        "every tool gets a grant: {:?}",
        names
    );
    for p in policies {
        assert!(
            p["cedar_policy"].as_str().unwrap().contains("\"ci\""),
            "the bound workspace's tag: {}",
            p
        );
    }

    // A POST with no body at all is the same request; the policies already
    // exist, so it is a 200 that creates nothing rather than a 422.
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/mcp-servers/{}/generate-policies", server.id.0),
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a body-less POST: {}", body);
    assert!(
        body["data"]["policies_created"]
            .as_array()
            .unwrap()
            .is_empty(),
        "the same grants already exist: {}",
        body
    );
}

/// A server whose tools are known only from discovery still has tools.
#[tokio::test]
async fn test_generate_policies_falls_back_to_discovered_tools() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_user_in_db(&*ctx.store, "mcp-admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "mcp-admin", TEST_PASSWORD).await;

    let server = mcp_bound_to_tagged_workspace(
        &*ctx.store,
        "discovered-only-mcp",
        &["ci"],
        None,
        Some(vec![agent_cordon_core::domain::mcp::McpTool {
            name: "echo".to_string(),
            description: Some("Echo a message".to_string()),
            input_schema: None,
        }]),
    )
    .await;

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/mcp-servers/{}/generate-policies", server.id.0),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({ "agent_tags": ["ci"] })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{}", body);
    let policies = body["data"]["policies_created"].as_array().unwrap();
    assert_eq!(policies.len(), 1, "one discovered tool: {}", body);
    assert!(policies[0]["name"].as_str().unwrap().contains("echo"));
}

/// Nothing to grant is a 400 that says which half was missing, not an
/// empty 200 that looks like it worked.
#[tokio::test]
async fn test_generate_policies_without_tools_to_default_to_is_rejected() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_user_in_db(&*ctx.store, "mcp-admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "mcp-admin", TEST_PASSWORD).await;

    let server =
        mcp_bound_to_tagged_workspace(&*ctx.store, "toolless-mcp", &["ci"], None, None).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/mcp-servers/{}/generate-policies", server.id.0),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({})),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    let message = body.to_string();
    assert!(
        message.contains("tools"),
        "the error names the missing half: {}",
        message
    );
}

/// Same for the tag half: a server bound only to untagged workspaces has no
/// tags to grant to.
#[tokio::test]
async fn test_generate_policies_without_tags_to_default_to_is_rejected() {
    let ctx = TestAppBuilder::new().build().await;
    let _admin = create_user_in_db(&*ctx.store, "mcp-admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "mcp-admin", TEST_PASSWORD).await;

    let server = mcp_bound_to_tagged_workspace(
        &*ctx.store,
        "untagged-mcp",
        &[],
        Some(vec!["create_issue".to_string()]),
        None,
    )
    .await;

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/mcp-servers/{}/generate-policies", server.id.0),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({})),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{}", body);
    assert!(
        body.to_string().contains("agent_tags"),
        "the error names the missing half: {}",
        body
    );
}
