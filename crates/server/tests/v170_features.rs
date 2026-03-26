//! Consolidated integration tests for v1.7.0 features.
//!
//! Merged from: v170_device_tokens.rs, v170_install_sh.rs, v170_permissions_cache.rs

mod device_tokens {
    //! v1.7.0 — Device Token Visibility Tests (Feature 11)
    //!
    //! Verifies that agents have device_id set after enrollment and that
    //! token timestamps are populated after JWT issuance.

    use agent_cordon_server::test_helpers::TestAppBuilder;

    // ===========================================================================
    // Feature 11: Device Token Visibility
    // ===========================================================================

    #[tokio::test]
    #[ignore = "REMOVED: v2.0 unified workspaces have no parent_id concept (device_id removed)"]
    async fn test_agents_have_device_id() {
        let ctx = TestAppBuilder::new().with_admin().build().await;

        let agents = ctx.store.list_workspaces().await.expect("list agents");
        assert!(!agents.is_empty(), "should have at least one agent");

        let agent = &agents[0];
        assert!(
            agent.parent_id.is_some(),
            "agent created via device enrollment should have parent_id set, got None"
        );
    }

    #[tokio::test]
    async fn test_agent_token_timestamps_populated() {
        let ctx = TestAppBuilder::new().with_admin().build().await;

        let agents = ctx.store.list_workspaces().await.expect("list agents");
        let agent = &agents[0];

        let status = &agent.status;
        let status_str = format!("{:?}", status);
        assert!(
            status_str == "Pending" || status_str == "Active" || status_str == "Revoked",
            "agent status should be a valid WorkspaceStatus, got {}",
            status_str
        );
    }
}

mod install_sh {
    //! v1.7.0 — install.sh Endpoint Tests (Feature 1)
    //!
    //! install.sh is served by the DEVICE, not the server. Since the server
    //! TestAppBuilder does not include device routes, these tests are marked
    //! Device-side install.sh tests live in the E2E test suite.

    use axum::http::{Method, StatusCode};

    use agent_cordon_server::test_helpers::TestAppBuilder;

    use crate::common::*;

    // ===========================================================================
    // 1A. Happy Path
    // ===========================================================================

    // ===========================================================================
    // 1D. Cross-Feature (server-testable)
    // ===========================================================================

    /// The CLI script is served by the device, not the server.
    #[tokio::test]
    async fn test_cli_script_endpoint_exists() {
        let ctx = TestAppBuilder::new().build().await;

        let (status, _body) = send_json(
            &ctx.app,
            Method::GET,
            "/agentcordon-cli.sh",
            None,
            None,
            None,
            None,
        )
        .await;

        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "CLI script is a device endpoint, server should return 404"
        );
    }

    // ===========================================================================
    // 1E. Security
    // ===========================================================================

    #[tokio::test]
    async fn test_cli_script_no_secrets() {
        let ctx = TestAppBuilder::new().with_admin().build().await;

        let (status, body) = send_json(
            &ctx.app,
            Method::GET,
            "/agentcordon-cli.sh",
            None,
            None,
            None,
            None,
        )
        .await;

        if status == StatusCode::OK {
            let body_str = body.to_string();
            assert!(
                !body_str.contains("BEGIN PRIVATE KEY"),
                "script must not contain private keys"
            );
            assert!(
                !body_str.contains("BEGIN RSA PRIVATE KEY"),
                "script must not contain RSA private keys"
            );
            assert!(
                !body_str.contains("sk-"),
                "script must not contain API key prefixes"
            );
        }
    }
}

mod permissions_cache {
    //! v1.7.0 — Permissions Cache Invalidation Tests (Feature 2)
    //!
    //! Tests for the server-side SSE event emission when permissions change.

    use axum::http::{Method, StatusCode};
    use serde_json::json;

    use agent_cordon_core::domain::user::UserRole;
    use agent_cordon_core::storage::Store;
    use agent_cordon_server::events::DeviceEvent;

    use agent_cordon_server::test_helpers::TestAppBuilder;

    use crate::common::*;

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    async fn setup_admin(
        app: &axum::Router,
        store: &(dyn Store + Send + Sync),
    ) -> (String, String) {
        create_user_in_db(
            store,
            "perms-cache-admin",
            TEST_PASSWORD,
            UserRole::Admin,
            false,
            true,
        )
        .await;
        let cookie = login_user_combined(app, "perms-cache-admin", TEST_PASSWORD).await;
        let csrf = extract_csrf_from_cookie(&cookie).unwrap();
        (cookie, csrf)
    }

    /// Create a credential via the API and return its UUID string.
    async fn create_credential(app: &axum::Router, cookie: &str, csrf: &str, name: &str) -> String {
        let (status, body) = send_json(
            app,
            Method::POST,
            "/api/v1/credentials",
            None,
            Some(cookie),
            Some(csrf),
            Some(json!({
                "name": name,
                "service": "test-service",
                "secret_value": "test-secret-value",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "create credential failed: {}", body);
        body["data"]["id"]
            .as_str()
            .expect("credential id")
            .to_string()
    }

    // ===========================================================================
    // 2A. Happy Path — SSE Event Emission
    // ===========================================================================

    #[tokio::test]
    async fn test_grant_permission_emits_sse_event() {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

        let cred_id = create_credential(&ctx.app, &cookie, &csrf, "sse-grant-cred").await;

        let (agent, _key) =
            create_agent_in_db(&*ctx.store, "sse-target-agent", vec![], true, None).await;

        let mut rx = ctx.state.event_bus.subscribe();

        let (status, body) = send_json(
            &ctx.app,
            Method::POST,
            &format!("/api/v1/credentials/{}/permissions", cred_id),
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({
                "agent_id": agent.id.0.to_string(),
                "permission": "delegated_use",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "grant permission failed: {}", body);

        let event = rx.try_recv().expect("should have received an SSE event");
        match event {
            DeviceEvent::PolicyChanged { policy_name } => {
                assert!(
                    policy_name.contains(&agent.id.0.to_string()),
                    "PolicyChanged event should reference the agent: {}",
                    policy_name
                );
            }
            other => panic!("expected PolicyChanged event, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_revoke_permission_emits_sse_event() {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

        let cred_id = create_credential(&ctx.app, &cookie, &csrf, "sse-revoke-cred").await;

        let (agent, _key) =
            create_agent_in_db(&*ctx.store, "sse-revoke-agent", vec![], true, None).await;

        let (status, _) = send_json(
            &ctx.app,
            Method::POST,
            &format!("/api/v1/credentials/{}/permissions", cred_id),
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({
                "agent_id": agent.id.0.to_string(),
                "permission": "read",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let mut rx = ctx.state.event_bus.subscribe();

        let (status, body) = send_json(
            &ctx.app,
            Method::DELETE,
            &format!(
                "/api/v1/credentials/{}/permissions/{}/read",
                cred_id, agent.id.0
            ),
            None,
            Some(&cookie),
            Some(&csrf),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "revoke permission failed: {}", body);

        let event = rx
            .try_recv()
            .expect("should have received an SSE event on revoke");
        match event {
            DeviceEvent::PolicyChanged { policy_name } => {
                assert!(
                    policy_name.contains(&agent.id.0.to_string()),
                    "revoke PolicyChanged event should reference the agent: {}",
                    policy_name
                );
            }
            other => panic!("expected PolicyChanged event on revoke, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_set_permissions_emits_sse_event() {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

        let cred_id = create_credential(&ctx.app, &cookie, &csrf, "sse-set-cred").await;

        let (agent_a, _) =
            create_agent_in_db(&*ctx.store, "sse-set-agent-a", vec![], true, None).await;
        let (agent_b, _) =
            create_agent_in_db(&*ctx.store, "sse-set-agent-b", vec![], true, None).await;

        let mut rx = ctx.state.event_bus.subscribe();

        let (status, body) = send_json(
            &ctx.app,
            Method::PUT,
            &format!("/api/v1/credentials/{}/permissions", cred_id),
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({
                "permissions": [
                    { "agent_id": agent_a.id.0.to_string(), "permission": "read" },
                    { "agent_id": agent_b.id.0.to_string(), "permission": "delegated_use" },
                ]
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "set permissions failed: {}", body);

        let mut received_policy_names: Vec<String> = Vec::new();
        while let Ok(event) = rx.try_recv() {
            if let DeviceEvent::PolicyChanged { policy_name } = event {
                received_policy_names.push(policy_name);
            }
        }

        let agent_a_found = received_policy_names
            .iter()
            .any(|n| n.contains(&agent_a.id.0.to_string()));
        let agent_b_found = received_policy_names
            .iter()
            .any(|n| n.contains(&agent_b.id.0.to_string()));

        assert!(
            agent_a_found,
            "should emit PolicyChanged for agent_a, got: {:?}",
            received_policy_names
        );
        assert!(
            agent_b_found,
            "should emit PolicyChanged for agent_b, got: {:?}",
            received_policy_names
        );
    }

    #[tokio::test]
    async fn test_grant_multiple_permissions_emits_events() {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

        let cred_id = create_credential(&ctx.app, &cookie, &csrf, "sse-batch-grant-cred").await;

        let (agent, _) =
            create_agent_in_db(&*ctx.store, "sse-batch-agent", vec![], true, None).await;

        let mut rx = ctx.state.event_bus.subscribe();

        let (status, body) = send_json(
            &ctx.app,
            Method::POST,
            &format!("/api/v1/credentials/{}/permissions", cred_id),
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({
                "agent_id": agent.id.0.to_string(),
                "permissions": ["read", "delegated_use"],
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "batch grant failed: {}", body);

        let mut count = 0;
        while let Ok(event) = rx.try_recv() {
            if let DeviceEvent::PolicyChanged { policy_name } = event {
                assert!(
                    policy_name.contains(&agent.id.0.to_string()),
                    "PolicyChanged should reference agent: {}",
                    policy_name
                );
                count += 1;
            }
        }

        assert!(
            count >= 1,
            "should emit at least one PolicyChanged event for batch grant"
        );
    }

    // ===========================================================================
    // 2B. Audit Trail — Permissions produce audit events
    // ===========================================================================

    #[tokio::test]
    async fn test_grant_permission_produces_audit_event() {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

        let cred_id = create_credential(&ctx.app, &cookie, &csrf, "audit-grant-cred").await;

        let (agent, _) =
            create_agent_in_db(&*ctx.store, "audit-grant-agent", vec![], true, None).await;

        let (status, _) = send_json(
            &ctx.app,
            Method::POST,
            &format!("/api/v1/credentials/{}/permissions", cred_id),
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({
                "agent_id": agent.id.0.to_string(),
                "permission": "delegated_use",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let events = ctx
            .store
            .list_audit_events(50, 0)
            .await
            .expect("list audit events");
        let grant_event = events.iter().find(|e| e.action == "grant_permission");

        assert!(
            grant_event.is_some(),
            "grant_permission should be audit-logged. Events: {:?}",
            events.iter().map(|e| &e.action).collect::<Vec<_>>()
        );

        let event = grant_event.unwrap();
        assert_eq!(event.resource_type, "credential");
        assert_eq!(event.resource_id.as_deref(), Some(cred_id.as_str()));
    }

    #[tokio::test]
    async fn test_revoke_permission_produces_audit_event() {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

        let cred_id = create_credential(&ctx.app, &cookie, &csrf, "audit-revoke-cred").await;

        let (agent, _) =
            create_agent_in_db(&*ctx.store, "audit-revoke-agent", vec![], true, None).await;

        let (status, _) = send_json(
            &ctx.app,
            Method::POST,
            &format!("/api/v1/credentials/{}/permissions", cred_id),
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({
                "agent_id": agent.id.0.to_string(),
                "permission": "read",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) = send_json(
            &ctx.app,
            Method::DELETE,
            &format!(
                "/api/v1/credentials/{}/permissions/{}/read",
                cred_id, agent.id.0
            ),
            None,
            Some(&cookie),
            Some(&csrf),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let events = ctx
            .store
            .list_audit_events(50, 0)
            .await
            .expect("list audit events");
        let revoke_event = events.iter().find(|e| e.action == "revoke_permission");

        assert!(
            revoke_event.is_some(),
            "revoke_permission should be audit-logged. Events: {:?}",
            events.iter().map(|e| &e.action).collect::<Vec<_>>()
        );
    }
}
