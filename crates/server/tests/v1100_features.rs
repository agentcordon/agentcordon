//! Consolidated integration tests for v1.10.0 features.
//!
//! Merged from: v1100_schema_cleanup.rs, v1100_rsop_ui.rs, v1100_validation_errors.rs

mod schema_cleanup {
    //! v1.10.0 — Schema Cleanup Tests (Feature 1 & 10)
    //!
    //! Verifies that:
    //! - `proxy_access` action is no longer referenced in the schema or policies
    //! - `vend_credential` is the canonical action for credential vending
    //! - The Cedar schema endpoint returns valid JSON
    //! - Default policy uses `vend_credential` (not `proxy_access`)
    //! - Policy validation rejects `proxy_access` as an unknown action
    //! - Curated seed policies use `vend_credential`
    //! - Policy test endpoint works with `vend_credential`

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
            "schema-cleanup-user",
            common::TEST_PASSWORD,
            UserRole::Admin,
        )
        .await;
        let cookie =
            common::login_user_combined(&ctx.app, "schema-cleanup-user", common::TEST_PASSWORD)
                .await;
        (ctx, cookie)
    }

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
            "schema-seed-user",
            common::TEST_PASSWORD,
            UserRole::Admin,
        )
        .await;
        let cookie =
            common::login_user_combined(&ctx.app, "schema-seed-user", common::TEST_PASSWORD).await;
        (ctx, cookie)
    }

    // ===========================================================================
    // 1A. Schema endpoint returns valid JSON
    // ===========================================================================

    #[tokio::test]
    async fn test_schema_endpoint_returns_json() {
        let (ctx, cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            "/api/v1/policies/schema",
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "GET /api/v1/policies/schema: {:?}",
            body
        );

        let schema_text = body["data"].as_str().expect("schema should be a string");
        assert!(!schema_text.is_empty(), "schema should not be empty");

        let _: serde_json::Value =
            serde_json::from_str(schema_text).expect("schema should be valid JSON");
    }

    // ===========================================================================
    // 1B. Schema contains vend_credential, not proxy_access
    // ===========================================================================

    #[tokio::test]
    async fn test_schema_contains_vend_credential() {
        let (ctx, cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            "/api/v1/policies/schema",
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let schema_text = body["data"].as_str().expect("schema string");
        assert!(
            schema_text.contains("vend_credential"),
            "schema should contain vend_credential action"
        );
    }

    #[tokio::test]
    async fn test_schema_does_not_contain_proxy_access() {
        let (ctx, cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            "/api/v1/policies/schema",
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let schema_text = body["data"].as_str().expect("schema string");
        assert!(
            !schema_text.contains("proxy_access"),
            "schema should NOT contain deprecated proxy_access action"
        );
    }

    // ===========================================================================
    // 1C. Default policy uses vend_credential
    // ===========================================================================

    #[tokio::test]
    async fn test_default_policy_uses_vend_credential() {
        let (ctx, cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            "/api/v1/policies",
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let policies = body["data"].as_array().expect("data should be array");
        let default_policy = policies
            .iter()
            .find(|p| p["name"].as_str() == Some("default"))
            .expect("default policy should exist");

        let cedar = default_policy["cedar_policy"]
            .as_str()
            .expect("cedar_policy");
        assert!(
            cedar.contains("vend_credential"),
            "default policy should use vend_credential action"
        );
        assert!(
            !cedar.contains("proxy_access"),
            "default policy should NOT contain deprecated proxy_access"
        );
    }

    // ===========================================================================
    // 1D. Policy validation rejects proxy_access as unknown action
    // ===========================================================================

    #[tokio::test]
    async fn test_policy_create_rejects_proxy_access() {
        let (ctx, cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/policies",
            None,
            Some(&cookie),
            Some(serde_json::json!({
                "name": "test-proxy-access-reject",
                "description": "Should fail validation",
                "cedar_policy": r#"permit(
                    principal is AgentCordon::Workspace,
                    action == AgentCordon::Action::"proxy_access",
                    resource is AgentCordon::Credential
                );"#,
            })),
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "creating policy with proxy_access should fail validation: {:?}",
            body
        );
    }

    // ===========================================================================
    // 1E. Policy validation accepts vend_credential
    // ===========================================================================

    #[tokio::test]
    async fn test_policy_create_accepts_vend_credential() {
        let (ctx, cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/policies",
            None,
            Some(&cookie),
            Some(serde_json::json!({
                "name": "test-vend-credential-accept",
                "description": "Should pass validation",
                "cedar_policy": r#"permit(
                    principal is AgentCordon::Workspace,
                    action == AgentCordon::Action::"vend_credential",
                    resource is AgentCordon::Credential
                ) when {
                    principal.tags.contains("test")
                };"#,
            })),
        )
        .await;

        assert!(
            status == StatusCode::OK || status == StatusCode::CREATED,
            "creating policy with vend_credential should succeed: status={}, body={:?}",
            status,
            body
        );
    }

    // ===========================================================================
    // 1F. Curated seed policies use vend_credential, not proxy_access
    // ===========================================================================

    #[tokio::test]
    async fn test_curated_policies_use_vend_credential() {
        let (ctx, cookie) = setup_with_seed().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            "/api/v1/policies",
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let policies = body["data"].as_array().expect("data should be array");

        for policy in policies {
            let cedar = policy["cedar_policy"].as_str().unwrap_or("");
            let name = policy["name"].as_str().unwrap_or("unknown");

            assert!(
                !cedar.contains("proxy_access"),
                "policy '{}' should NOT contain deprecated proxy_access",
                name
            );

            if cedar.contains("vend") {
                assert!(
                    cedar.contains("vend_credential"),
                    "policy '{}' references 'vend' but not 'vend_credential'",
                    name
                );
            }
        }
    }
}

mod rsop_ui {
    //! v1.10.0 — RSoP (Resultant Set of Policy) UI Integration Tests.

    use crate::common;

    use agent_cordon_core::domain::user::UserRole;
    use agent_cordon_server::test_helpers::TestAppBuilder;
    use axum::http::{Method, StatusCode};
    use serde_json::json;

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    async fn setup() -> (agent_cordon_server::test_helpers::TestContext, String) {
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
            "rsop-ui-user",
            common::TEST_PASSWORD,
            UserRole::Admin,
        )
        .await;
        let cookie =
            common::login_user_combined(&ctx.app, "rsop-ui-user", common::TEST_PASSWORD).await;
        (ctx, cookie)
    }

    /// Create a credential via API and return its UUID string.
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

    /// Create an MCP server via API and return its UUID string.
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
            transport: "http".to_string(),
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
    // Feature 4: RSoP UI — Credential
    // ===========================================================================

    #[tokio::test]
    async fn test_rsop_credential_returns_matrix() {
        let (ctx, cookie) = setup().await;
        let cred_id = create_test_credential(&ctx.app, &cookie, "rsop-test-cred", "github").await;
        let cred_uuid: uuid::Uuid = cred_id.parse().expect("valid uuid");

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/policies/rsop",
            None,
            Some(&cookie),
            Some(json!({
                "resource_type": "Credential",
                "resource_id": cred_uuid,
            })),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "RSoP should return 200: {:?}", body);

        let data = &body["data"];
        assert!(
            data["resource"].is_object(),
            "response should have resource metadata"
        );
        assert_eq!(data["resource"]["type"].as_str(), Some("Credential"));
        assert!(
            data["matrix"].is_array(),
            "response should have matrix array"
        );
        assert!(
            data["evaluated_at"].is_string(),
            "response should have evaluated_at timestamp"
        );
        assert!(
            data["conditional_policies"].is_array(),
            "response should have conditional_policies"
        );
    }

    #[tokio::test]
    async fn test_rsop_credential_actions_columns() {
        let (ctx, cookie) = setup().await;
        let cred_id = create_test_credential(&ctx.app, &cookie, "rsop-actions-cred", "slack").await;
        let cred_uuid: uuid::Uuid = cred_id.parse().expect("valid uuid");

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/policies/rsop",
            None,
            Some(&cookie),
            Some(json!({
                "resource_type": "Credential",
                "resource_id": cred_uuid,
            })),
        )
        .await;

        assert_eq!(status, StatusCode::OK);

        let matrix = body["data"]["matrix"].as_array().expect("matrix array");
        if let Some(entry) = matrix.first() {
            let results = entry["results"].as_object().expect("results map");
            let has_access = results.contains_key("access");
            let has_vend = results.contains_key("vend_credential");
            assert!(
                has_access || has_vend,
                "credential RSoP entries should include access or vend_credential actions, got: {:?}",
                results.keys().collect::<Vec<_>>()
            );
        }
    }

    #[tokio::test]
    async fn test_rsop_credential_not_found() {
        let (ctx, cookie) = setup().await;
        let fake_uuid = uuid::Uuid::new_v4();

        let (status, _body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/policies/rsop",
            None,
            Some(&cookie),
            Some(json!({
                "resource_type": "Credential",
                "resource_id": fake_uuid,
            })),
        )
        .await;

        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "RSoP for non-existent credential should return 404"
        );
    }

    // ===========================================================================
    // Feature 5: RSoP UI — MCP Server
    // ===========================================================================

    #[tokio::test]
    async fn test_rsop_mcp_server_returns_matrix() {
        let (ctx, cookie) = setup().await;
        let (device_id, _) = common::create_standalone_device(&ctx.state).await;
        let server_id = create_test_mcp_server(&*ctx.store, "rsop-test-mcp", &device_id).await;
        let server_uuid: uuid::Uuid = server_id.parse().expect("valid uuid");

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/policies/rsop",
            None,
            Some(&cookie),
            Some(json!({
                "resource_type": "McpServer",
                "resource_id": server_uuid,
            })),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "RSoP should return 200: {:?}", body);

        let data = &body["data"];
        assert!(
            data["resource"].is_object(),
            "response should have resource metadata"
        );
        assert_eq!(data["resource"]["type"].as_str(), Some("McpServer"));
        assert!(
            data["matrix"].is_array(),
            "response should have matrix array"
        );
    }

    #[tokio::test]
    async fn test_rsop_invalid_resource_type() {
        let (ctx, cookie) = setup().await;
        let fake_uuid = uuid::Uuid::new_v4();

        let (status, _body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/policies/rsop",
            None,
            Some(&cookie),
            Some(json!({
                "resource_type": "InvalidType",
                "resource_id": fake_uuid,
            })),
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "RSoP with invalid resource_type should return 400"
        );
    }
}

mod validation_errors {
    //! v1.10.0 — Structured Validation Error Tests (Feature 8)

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
            "validation-user",
            common::TEST_PASSWORD,
            UserRole::Admin,
        )
        .await;
        let cookie =
            common::login_user_combined(&ctx.app, "validation-user", common::TEST_PASSWORD).await;
        (ctx, cookie)
    }

    fn assert_structured_error(body: &serde_json::Value, expected_code: &str) {
        let error = &body["error"];
        assert!(
            error.is_object(),
            "response should have 'error' object. Got: {:?}",
            body
        );
        assert!(
            error["code"].is_string(),
            "error should have 'code' field. Got: {:?}",
            error
        );
        assert!(
            error["message"].is_string(),
            "error should have 'message' field. Got: {:?}",
            error
        );
        assert_eq!(
            error["code"].as_str().unwrap_or(""),
            expected_code,
            "error code should be '{}'. Got: {:?}",
            expected_code,
            error
        );
        assert!(
            !error["message"].as_str().unwrap_or("").is_empty(),
            "error message should not be empty"
        );
    }

    // ===========================================================================
    // 8A. Policy creation with invalid Cedar returns structured error
    // ===========================================================================

    #[tokio::test]
    async fn test_policy_syntax_error_structured() {
        let (ctx, cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/policies",
            None,
            Some(&cookie),
            Some(serde_json::json!({
                "name": "bad-syntax",
                "description": "Invalid Cedar syntax",
                "cedar_policy": "permit( this is not valid cedar ;",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {:?}", body);
        assert_structured_error(&body, "VALIDATION_FAILED");
    }

    #[tokio::test]
    async fn test_policy_schema_validation_error_structured() {
        let (ctx, cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/policies",
            None,
            Some(&cookie),
            Some(serde_json::json!({
                "name": "bad-schema",
                "description": "Unknown entity type",
                "cedar_policy": r#"permit(
                    principal is AgentCordon::NonExistentType,
                    action == AgentCordon::Action::"access",
                    resource is AgentCordon::Credential
                );"#,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {:?}", body);
        assert_structured_error(&body, "VALIDATION_FAILED");
    }

    #[tokio::test]
    async fn test_policy_unknown_action_error_structured() {
        let (ctx, cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/policies",
            None,
            Some(&cookie),
            Some(serde_json::json!({
                "name": "unknown-action",
                "description": "Unknown action",
                "cedar_policy": r#"permit(
                    principal is AgentCordon::Workspace,
                    action == AgentCordon::Action::"nonexistent_action",
                    resource is AgentCordon::Credential
                );"#,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {:?}", body);
        assert_structured_error(&body, "VALIDATION_FAILED");
    }

    // ===========================================================================
    // 8B. Not Found errors have structured format
    // ===========================================================================

    #[tokio::test]
    async fn test_not_found_policy_structured() {
        let (ctx, cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            "/api/v1/policies/00000000-0000-0000-0000-000000000000",
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "body: {:?}", body);
        assert_structured_error(&body, "not_found");
    }

    #[tokio::test]
    async fn test_not_found_credential_structured() {
        let (ctx, cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            "/api/v1/credentials/00000000-0000-0000-0000-000000000000",
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "body: {:?}", body);
        assert_structured_error(&body, "not_found");
    }

    #[tokio::test]
    async fn test_not_found_agent_structured() {
        let (ctx, cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            "/api/v1/workspaces/00000000-0000-0000-0000-000000000000",
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "body: {:?}", body);
        assert_structured_error(&body, "not_found");
    }

    // ===========================================================================
    // 8C. Unauthorized errors have structured format
    // ===========================================================================

    #[tokio::test]
    async fn test_unauthorized_no_cookie_structured() {
        let (ctx, _cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            "/api/v1/policies",
            None,
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {:?}", body);
        assert_structured_error(&body, "unauthorized");
    }

    #[tokio::test]
    async fn test_unauthorized_bad_login_structured() {
        let (ctx, _cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/auth/login",
            None,
            None,
            Some(serde_json::json!({
                "username": "nonexistent",
                "password": "wrong"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {:?}", body);
        assert_structured_error(&body, "unauthorized");
    }

    // ===========================================================================
    // 8D. Forbidden errors have structured format
    // ===========================================================================

    #[tokio::test]
    async fn test_forbidden_viewer_manage_policies_structured() {
        let (ctx, _cookie) = setup().await;

        let _viewer = common::create_test_user(
            &*ctx.store,
            "validation-viewer",
            common::TEST_PASSWORD,
            UserRole::Viewer,
        )
        .await;
        let viewer_cookie =
            common::login_user_combined(&ctx.app, "validation-viewer", common::TEST_PASSWORD).await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/policies",
            None,
            Some(&viewer_cookie),
            Some(serde_json::json!({
                "name": "viewer-attempt",
                "cedar_policy": "permit(principal, action, resource);",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "body: {:?}", body);
        assert_structured_error(&body, "forbidden");
    }

    // ===========================================================================
    // 8E. Policy update with invalid Cedar returns structured error
    // ===========================================================================

    #[tokio::test]
    async fn test_policy_update_invalid_cedar_structured() {
        let (ctx, cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            "/api/v1/policies",
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let policies = body["data"].as_array().expect("data");
        let policy = policies.first().expect("at least one policy");
        let policy_id = policy["id"].as_str().expect("policy id");

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::PUT,
            &format!("/api/v1/policies/{}", policy_id),
            None,
            Some(&cookie),
            Some(serde_json::json!({
                "cedar_policy": "invalid cedar syntax <<<",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {:?}", body);
        assert_structured_error(&body, "VALIDATION_FAILED");
    }

    // ===========================================================================
    // 8F. Policy test endpoint missing required fields returns structured error
    // ===========================================================================

    #[tokio::test]
    async fn test_policy_test_missing_principal_structured() {
        let (ctx, cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/policies/test",
            None,
            Some(&cookie),
            Some(serde_json::json!({
                "action": "access",
                "resource": { "type": "Credential" }
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {:?}", body);
        assert_structured_error(&body, "bad_request");
    }

    #[tokio::test]
    async fn test_policy_test_missing_action_structured() {
        let (ctx, cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/policies/test",
            None,
            Some(&cookie),
            Some(serde_json::json!({
                "principal": { "type": "Agent", "id": "test" },
                "resource": { "type": "Credential" }
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {:?}", body);
        assert_structured_error(&body, "bad_request");
    }

    #[tokio::test]
    async fn test_policy_test_missing_resource_structured() {
        let (ctx, cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/policies/test",
            None,
            Some(&cookie),
            Some(serde_json::json!({
                "principal": { "type": "Agent", "id": "test" },
                "action": "access"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {:?}", body);
        assert_structured_error(&body, "bad_request");
    }

    // ===========================================================================
    // 8G. RSoP bad request returns structured error
    // ===========================================================================

    #[tokio::test]
    async fn test_rsop_invalid_type_structured() {
        let (ctx, cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/policies/rsop",
            None,
            Some(&cookie),
            Some(serde_json::json!({
                "resource_type": "InvalidType",
                "resource_id": "00000000-0000-0000-0000-000000000000",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {:?}", body);
        assert_structured_error(&body, "bad_request");
    }

    // ===========================================================================
    // 8H. Delete non-existent resource returns structured error
    // ===========================================================================

    #[tokio::test]
    async fn test_delete_nonexistent_policy_structured() {
        let (ctx, cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::DELETE,
            "/api/v1/policies/00000000-0000-0000-0000-000000000000",
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "body: {:?}", body);
        assert_structured_error(&body, "not_found");
    }

    // ===========================================================================
    // 8I. Error messages don't leak secrets
    // ===========================================================================

    #[tokio::test]
    async fn test_error_messages_dont_leak_internal_details() {
        let (ctx, cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            "/api/v1/credentials/00000000-0000-0000-0000-000000000000",
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let message = body["error"]["message"].as_str().unwrap_or("");
        assert!(
            !message.contains("SELECT"),
            "error message should not contain SQL"
        );
        assert!(
            !message.contains("at src/"),
            "error message should not contain source paths"
        );
        assert!(
            !message.contains("panicked"),
            "error message should not contain panic info"
        );
    }
}
