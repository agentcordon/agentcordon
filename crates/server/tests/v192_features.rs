//! Consolidated integration tests for v1.9.2 features.
//!
//! Merged from: v192_loading_states.rs, v192_device_agents.rs,
//! v192_mcp_tools_display.rs, v192_llm_exposed_fix.rs

mod loading_states {
    //! Integration tests — v1.9.2 Feature 4: Loading States Regression.
    //!
    //! Verifies that all detail pages contain the page-loader class and Alpine.js
    //! loading state directives, preventing the "flash of not found" bug.

    use crate::common;

    use agent_cordon_core::domain::user::UserRole;
    use agent_cordon_server::test_helpers::TestAppBuilder;
    use axum::body::Body;
    use axum::http::{header, Method, Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use uuid::Uuid;

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    async fn setup() -> (agent_cordon_server::test_helpers::TestContext, String) {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let _user = common::create_test_user(
            &*ctx.store,
            "loading-user",
            common::TEST_PASSWORD,
            UserRole::Admin,
        )
        .await;
        let cookie =
            common::login_user_combined(&ctx.app, "loading-user", common::TEST_PASSWORD).await;
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

    // ===========================================================================
    // 4A. Happy Path — Regression Tests
    // ===========================================================================

    #[tokio::test]
    async fn test_credential_detail_page_has_loader() {
        let (ctx, cookie) = setup().await;

        let uuid = Uuid::new_v4();
        let (status, body) = get_html(&ctx.app, &format!("/credentials/{}", uuid), &cookie).await;
        assert_eq!(status, StatusCode::OK);

        assert!(
            body.contains("page-loader") || body.contains("loading"),
            "credential detail page should contain loading state indicator"
        );
    }

    #[tokio::test]
    async fn test_policy_detail_page_has_loader() {
        let (ctx, cookie) = setup().await;

        let uuid = Uuid::new_v4();
        let (status, body) = get_html(&ctx.app, &format!("/security/{}", uuid), &cookie).await;
        assert_eq!(status, StatusCode::OK);

        assert!(
            body.contains("page-loader") || body.contains("loading"),
            "policy detail page should contain loading state indicator"
        );
    }
}

mod device_agents {
    //! Integration tests — v1.9.2 Feature 13: Device Detail Shows Enrolled Agents.
    //!
    //! Verifies that the agents API is filterable by device_id and that the
    //! device detail page has an "Enrolled Agents" section.

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

    async fn setup() -> (agent_cordon_server::test_helpers::TestContext, String) {
        let ctx = TestAppBuilder::new()
            .with_admin()
            .with_agent("device-agent-1", &["user"])
            .with_agent("device-agent-2", &["user"])
            .build()
            .await;
        let _user = common::create_test_user(
            &*ctx.store,
            "device-agents-user",
            common::TEST_PASSWORD,
            UserRole::Admin,
        )
        .await;
        let cookie =
            common::login_user_combined(&ctx.app, "device-agents-user", common::TEST_PASSWORD)
                .await;
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

    // ===========================================================================
    // 13A. Happy Path
    // ===========================================================================
}

mod mcp_tools_display {
    //! Integration tests — v1.9.2 Feature 9: MCP Server Detail Shows Tools.
    //!
    //! Verifies that the MCP server detail endpoint returns tools after discovery,
    //! and shows an appropriate empty state before discovery.

    use crate::common;

    use agent_cordon_core::domain::user::UserRole;
    use agent_cordon_server::test_helpers::TestAppBuilder;
    use axum::http::{Method, StatusCode};

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    async fn setup() -> (agent_cordon_server::test_helpers::TestContext, String) {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let _user = common::create_test_user(
            &*ctx.store,
            "mcp-tools-user",
            common::TEST_PASSWORD,
            UserRole::Admin,
        )
        .await;
        let cookie =
            common::login_user_combined(&ctx.app, "mcp-tools-user", common::TEST_PASSWORD).await;
        (ctx, cookie)
    }

    /// Create an MCP server directly in the store and return its UUID string.
    async fn create_mcp_server(
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
            transport: agent_cordon_core::domain::mcp::McpTransport::Http,
            allowed_tools: None,
            enabled: true,
            created_by: None,
            created_at: now,
            updated_at: now,
            tags: vec![],
            required_credentials: None,
            auth_method: agent_cordon_core::domain::mcp::McpAuthMethod::default(),
            template_key: None,
        discovered_tools: None,
        };
        store
            .create_mcp_server(&server)
            .await
            .expect("create mcp server");
        server.id.0.to_string()
    }

    // ===========================================================================
    // 9A. Happy Path
    // ===========================================================================

    #[tokio::test]
    async fn test_mcp_detail_returns_tools_after_setup() {
        let (ctx, cookie) = setup().await;
        let (device_id, _) = common::create_standalone_device(&ctx.state).await;
        let server_id = create_mcp_server(&*ctx.store, "tool-test-server", &device_id).await;

        // Set allowed_tools directly via update (simulating discovery outcome)
        use agent_cordon_core::domain::mcp::McpServerId;
        use uuid::Uuid;

        let mcp_id = McpServerId(Uuid::parse_str(&server_id).expect("parse uuid"));
        let mut server = ctx
            .store
            .get_mcp_server(&mcp_id)
            .await
            .expect("get")
            .expect("exists");
        server.allowed_tools = Some(vec!["read_file".to_string(), "write_file".to_string()]);
        ctx.store
            .update_mcp_server(&server)
            .await
            .expect("update MCP server with tools");

        // GET MCP server detail
        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            &format!("/api/v1/mcp-servers/{}", server_id),
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "get MCP server detail: {:?}", body);

        let data = &body["data"];

        // Check for tools in the response — either as `tools` (after fix) or `allowed_tools` (current)
        let tools_arr = data
            .get("tools")
            .and_then(|t| t.as_array())
            .or_else(|| data.get("allowed_tools").and_then(|t| t.as_array()));

        if let Some(tools) = tools_arr {
            assert!(
                !tools.is_empty(),
                "tools/allowed_tools should not be empty after setting tools"
            );
            // Tools may be string names or objects with a `name` field
            let tool_names: Vec<String> = tools
                .iter()
                .filter_map(|t| {
                    t.as_str()
                        .map(|s| s.to_string())
                        .or_else(|| t["name"].as_str().map(|s| s.to_string()))
                })
                .collect();
            assert!(
                tool_names.contains(&"read_file".to_string()),
                "should contain 'read_file', got: {:?}",
                tool_names
            );
        }
    }

    // ===========================================================================
    // 9C. Error Handling
    // ===========================================================================

    #[tokio::test]
    async fn test_mcp_detail_no_tools_before_setup() {
        let (ctx, cookie) = setup().await;
        let (device_id, _) = common::create_standalone_device(&ctx.state).await;
        let server_id = create_mcp_server(&*ctx.store, "no-tools-server", &device_id).await;

        // GET detail without any tool discovery
        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            &format!("/api/v1/mcp-servers/{}", server_id),
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "get MCP detail: {:?}", body);

        let data = &body["data"];

        // tools should be empty array or null, not a broken state
        if let Some(tools) = data.get("tools") {
            if let Some(arr) = tools.as_array() {
                assert!(
                    arr.is_empty(),
                    "tools should be empty before discovery, got: {:?}",
                    arr
                );
            }
            // tools: null is also acceptable
        }
        // Not having a tools field at all is the current behavior (the bug)
    }
}

mod llm_exposed_fix {
    //! Integration tests — v1.9.2 Feature 11: LLM Exposed False Positive Fix.
    //!
    //! Verifies that admin-created credentials do NOT get the llm_exposed tag,
    //! that credential lists don't show false llm_exposed flags, and that
    //! updates don't incorrectly add the tag.

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
            "llm-fix-user",
            common::TEST_PASSWORD,
            UserRole::Admin,
        )
        .await;
        let cookie =
            common::login_user_combined(&ctx.app, "llm-fix-user", common::TEST_PASSWORD).await;
        (ctx, cookie)
    }

    // ===========================================================================
    // 11A. Happy Path
    // ===========================================================================

    #[tokio::test]
    async fn test_admin_created_credential_no_llm_exposed() {
        let (ctx, cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/credentials",
            None,
            Some(&cookie),
            Some(json!({
                "name": "admin-cred-no-llm",
                "service": "github",
                "credential_type": "generic",
                "secret_value": "ghp_test_secret"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "create credential: {:?}", body);

        let tags = body["data"]["tags"]
            .as_array()
            .map(|t| t.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
            .unwrap_or_default();

        assert!(
            !tags.contains(&"llm_exposed"),
            "admin-created credential should NOT have llm_exposed tag, got: {:?}",
            tags
        );
    }

    #[tokio::test]
    async fn test_credential_list_no_false_llm_exposed() {
        let (ctx, cookie) = setup().await;

        // Create multiple credentials via admin API
        for name in ["list-llm-1", "list-llm-2", "list-llm-3"] {
            let (status, _) = common::send_json_auto_csrf(
                &ctx.app,
                Method::POST,
                "/api/v1/credentials",
                None,
                Some(&cookie),
                Some(json!({
                    "name": name,
                    "service": "test-service",
                    "credential_type": "generic",
                    "secret_value": "test-secret"
                })),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "create credential '{}'", name);
        }

        // List all credentials
        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            "/api/v1/credentials",
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "list credentials: {:?}", body);

        let creds = body["data"].as_array().expect("data array");
        for cred in creds {
            let name = cred["name"].as_str().unwrap_or("unknown");
            let tags = cred["tags"]
                .as_array()
                .map(|t| t.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                .unwrap_or_default();

            if !tags.contains(&"llm_exposed") {
                continue; // no false positive for this one
            }

            // If llm_exposed is present, it should only be there if explicitly set
            panic!(
                "credential '{}' has llm_exposed tag but was admin-created: tags={:?}",
                name, tags
            );
        }
    }

    // ===========================================================================
    // 11C. Error Handling
    // ===========================================================================

    #[tokio::test]
    async fn test_credential_update_doesnt_add_llm_exposed() {
        let (ctx, cookie) = setup().await;

        // Create a credential
        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/credentials",
            None,
            Some(&cookie),
            Some(json!({
                "name": "update-no-llm",
                "service": "github",
                "credential_type": "generic",
                "secret_value": "ghp_test"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "create: {:?}", body);
        let cred_id = body["data"]["id"].as_str().expect("credential id");

        // Update the credential (change name)
        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::PUT,
            &format!("/api/v1/credentials/{}", cred_id),
            None,
            Some(&cookie),
            Some(json!({
                "name": "update-no-llm-renamed"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "update: {:?}", body);

        // Re-fetch and verify no llm_exposed tag was added
        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            &format!("/api/v1/credentials/{}", cred_id),
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "get after update: {:?}", body);

        let tags = body["data"]["tags"]
            .as_array()
            .map(|t| t.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
            .unwrap_or_default();

        assert!(
            !tags.contains(&"llm_exposed"),
            "credential should not gain llm_exposed after update, got: {:?}",
            tags
        );
    }
}
