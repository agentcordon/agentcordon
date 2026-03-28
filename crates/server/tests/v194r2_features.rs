//! Consolidated integration tests for v1.9.4 R2 features.
//!
//! Merged from: v194r2_agent_device_display.rs, v194r2_audit_filters.rs,
//! v194r2_demo_disable.rs

mod agent_device_display {
    //! v1.9.4 R2 — Workspace Display Tests (Item #8)
    //!
    //! Verifies that the workspace API returns workspace details correctly.

    use crate::common;

    use axum::http::{Method, StatusCode};

    use agent_cordon_core::domain::user::UserRole;
    use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
    use agent_cordon_core::storage::Store;
    use agent_cordon_server::test_helpers::TestAppBuilder;

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    async fn setup_admin(
        app: &axum::Router,
        store: &(dyn Store + Send + Sync),
    ) -> (String, String) {
        common::create_user_in_db(
            store,
            "device-display-admin",
            common::TEST_PASSWORD,
            UserRole::Admin,
            false,
            true,
        )
        .await;
        let cookie =
            common::login_user_combined(app, "device-display-admin", common::TEST_PASSWORD).await;
        let csrf = common::extract_csrf_from_cookie(&cookie).unwrap();
        (cookie, csrf)
    }

    // ===========================================================================
    // 8A. Happy Path
    // ===========================================================================

    /// Workspace returns expected fields.
    #[tokio::test]
    async fn test_workspace_shows_details() {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

        // Create workspace
        let now = chrono::Utc::now();
        let workspace = Workspace {
            id: WorkspaceId(uuid::Uuid::new_v4()),
            name: "system-workspace-test".to_string(),
            enabled: true,
            status: WorkspaceStatus::Active,
            pk_hash: None,
            encryption_public_key: None,
            tags: vec![],
            owner_id: None,
            parent_id: None,
            tool_name: None,
            created_at: now,
            updated_at: now,
        };
        ctx.store
            .create_workspace(&workspace)
            .await
            .expect("create workspace");

        // GET workspace detail
        let (status, body) = common::send_json(
            &ctx.app,
            Method::GET,
            &format!("/api/v1/workspaces/{}", workspace.id.0),
            None,
            Some(&cookie),
            Some(&csrf),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "get workspace: {}", body);

        let data = &body["data"];
        assert_eq!(data["name"].as_str(), Some("system-workspace-test"));
    }

    /// Workspace created via with_agent shows in list.
    #[tokio::test]
    async fn test_workspace_list_includes_entries() {
        let ctx = TestAppBuilder::new()
            .with_admin()
            .with_agent("listed-agent", &["viewer"])
            .build()
            .await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

        // GET workspace list
        let (status, body) = common::send_json(
            &ctx.app,
            Method::GET,
            "/api/v1/workspaces",
            None,
            Some(&cookie),
            Some(&csrf),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "list workspaces: {}", body);

        let workspaces = body["data"].as_array().expect("workspaces array");
        assert!(
            workspaces
                .iter()
                .any(|w| w["name"].as_str() == Some("listed-agent")),
            "should find listed-agent in response"
        );
    }
}

mod audit_filters {
    //! v1.9.4 R2 — Audit Additive Filter Tests (Item #6)
    //!
    //! Verifies the backend audit filter API supports filtering by action,
    //! decision, event_type, workspace_name, and combined (AND) filters with pagination.

    use crate::common;

    use axum::http::{Method, StatusCode};

    use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
    use agent_cordon_core::domain::user::UserRole;
    use agent_cordon_core::domain::workspace::WorkspaceId;
    use agent_cordon_core::storage::Store;
    use agent_cordon_server::test_helpers::TestAppBuilder;

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    async fn setup_admin(
        app: &axum::Router,
        store: &(dyn Store + Send + Sync),
    ) -> (String, String) {
        common::create_user_in_db(
            store,
            "audit-filter-admin",
            common::TEST_PASSWORD,
            UserRole::Admin,
            false,
            true,
        )
        .await;
        let cookie =
            common::login_user_combined(app, "audit-filter-admin", common::TEST_PASSWORD).await;
        let csrf = common::extract_csrf_from_cookie(&cookie).unwrap();
        (cookie, csrf)
    }

    /// Seed several audit events with distinct field values for filter testing.
    async fn seed_audit_events(store: &(dyn Store + Send + Sync)) {
        let events = vec![
            AuditEvent::builder(AuditEventType::WorkspaceCreated)
                .action("create_agent")
                .resource("agent", "agent-1")
                .workspace_actor(&WorkspaceId(uuid::Uuid::new_v4()), "filter-agent-a")
                .decision(AuditDecision::Permit, Some("test"))
                .build(),
            AuditEvent::builder(AuditEventType::CredentialCreated)
                .action("create_credential")
                .resource("credential", "cred-1")
                .decision(AuditDecision::Permit, Some("test"))
                .build(),
            AuditEvent::builder(AuditEventType::CredentialAccessRequested)
                .action("access_credential")
                .resource("credential", "cred-1")
                .decision(AuditDecision::Forbid, Some("policy denied"))
                .build(),
            AuditEvent::builder(AuditEventType::WorkspaceCreated)
                .action("create_agent")
                .resource("agent", "agent-2")
                .workspace_actor(&WorkspaceId(uuid::Uuid::new_v4()), "filter-agent-b")
                .decision(AuditDecision::Permit, Some("test"))
                .build(),
            AuditEvent::builder(AuditEventType::CredentialCreated)
                .action("create_credential")
                .resource("credential", "cred-2")
                .decision(AuditDecision::Permit, Some("test"))
                .build(),
        ];

        for event in &events {
            store
                .append_audit_event(event)
                .await
                .expect("seed audit event");
        }
    }

    /// Query audit events via the API with the given query string suffix.
    async fn query_audit(
        app: &axum::Router,
        query: &str,
        cookie: &str,
        csrf: &str,
    ) -> (StatusCode, serde_json::Value) {
        let uri = format!("/api/v1/audit?{}", query);
        common::send_json(app, Method::GET, &uri, None, Some(cookie), Some(csrf), None).await
    }

    // ===========================================================================
    // 6A. Happy Path
    // ===========================================================================

    /// GET /api/v1/audit?action=create_agent returns only matching events.
    #[tokio::test]
    async fn test_filter_by_action() {
        let ctx = TestAppBuilder::new().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;
        seed_audit_events(&*ctx.store).await;

        let (status, body) = query_audit(&ctx.app, "action=create_agent", &cookie, &csrf).await;
        assert_eq!(status, StatusCode::OK);

        let events = body["data"].as_array().expect("events array");
        assert!(
            !events.is_empty(),
            "should return events matching action=create_agent"
        );
        for event in events {
            assert_eq!(
                event["action"].as_str(),
                Some("create_agent"),
                "all events should have action=create_agent"
            );
        }
    }

    /// GET /api/v1/audit?decision=permit returns only permit-decision events.
    #[tokio::test]
    async fn test_filter_by_decision() {
        let ctx = TestAppBuilder::new().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;
        seed_audit_events(&*ctx.store).await;

        let (status, body) = query_audit(&ctx.app, "decision=permit", &cookie, &csrf).await;
        assert_eq!(status, StatusCode::OK);

        let events = body["data"].as_array().expect("events array");
        assert!(
            !events.is_empty(),
            "should return events matching decision=permit"
        );
        for event in events {
            assert_eq!(
                event["decision"].as_str(),
                Some("permit"),
                "all events should have decision=permit"
            );
        }
    }

    /// GET /api/v1/audit?event_type=workspace_created returns only matching events.
    #[tokio::test]
    async fn test_filter_by_event_type() {
        let ctx = TestAppBuilder::new().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;
        seed_audit_events(&*ctx.store).await;

        let (status, body) =
            query_audit(&ctx.app, "event_type=workspace_created", &cookie, &csrf).await;
        assert_eq!(status, StatusCode::OK);

        let events = body["data"].as_array().expect("events array");
        assert!(
            !events.is_empty(),
            "should return events matching event_type=workspace_created"
        );
        for event in events {
            assert_eq!(
                event["event_type"].as_str(),
                Some("workspace_created"),
                "all events should have event_type=workspace_created"
            );
        }
    }

    /// GET /api/v1/audit?workspace_name=filter-agent-a returns only that workspace's events.
    #[tokio::test]
    async fn test_filter_by_workspace_name() {
        let ctx = TestAppBuilder::new().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;
        seed_audit_events(&*ctx.store).await;

        let (status, body) =
            query_audit(&ctx.app, "workspace_name=filter-agent-a", &cookie, &csrf).await;
        assert_eq!(status, StatusCode::OK);

        let events = body["data"].as_array().expect("events array");
        assert!(
            !events.is_empty(),
            "should return events for workspace_name=filter-agent-a"
        );
        for event in events {
            assert_eq!(
                event["workspace_name"].as_str(),
                Some("filter-agent-a"),
                "all events should have workspace_name=filter-agent-a"
            );
        }
    }

    /// Combined filters are AND: action + resource_type.
    #[tokio::test]
    async fn test_multiple_filters() {
        let ctx = TestAppBuilder::new().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;
        seed_audit_events(&*ctx.store).await;

        let (status, body) = query_audit(
            &ctx.app,
            "action=create_credential&resource_type=credential",
            &cookie,
            &csrf,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let events = body["data"].as_array().expect("events array");
        assert!(
            !events.is_empty(),
            "combined filter should return matching events"
        );
        for event in events {
            assert_eq!(event["action"].as_str(), Some("create_credential"));
            assert_eq!(event["resource_type"].as_str(), Some("credential"));
        }
    }

    /// No filters returns all events.
    #[tokio::test]
    async fn test_empty_filter_returns_all() {
        let ctx = TestAppBuilder::new().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;
        seed_audit_events(&*ctx.store).await;

        let (status, body) = query_audit(&ctx.app, "limit=50", &cookie, &csrf).await;
        assert_eq!(status, StatusCode::OK);

        let events = body["data"].as_array().expect("events array");
        assert!(
            events.len() >= 5,
            "no filter should return all events, got {}",
            events.len()
        );
    }

    /// Non-matching filter returns empty list (not error).
    #[tokio::test]
    async fn test_invalid_filter_value() {
        let ctx = TestAppBuilder::new().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;
        seed_audit_events(&*ctx.store).await;

        let (status, body) = query_audit(&ctx.app, "event_type=NonExistent", &cookie, &csrf).await;
        assert_eq!(status, StatusCode::OK);

        let events = body["data"].as_array().expect("events array");
        assert!(
            events.is_empty(),
            "non-matching filter should return empty list, got {} events",
            events.len()
        );
    }

    // ===========================================================================
    // 6B. Retry/Idempotency
    // ===========================================================================

    /// Same filter query returns same results. No side effects from filtering.
    #[tokio::test]
    async fn test_audit_filter_same_request_twice() {
        let ctx = TestAppBuilder::new().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;
        seed_audit_events(&*ctx.store).await;

        let (s1, b1) = query_audit(&ctx.app, "action=create_agent", &cookie, &csrf).await;
        let (s2, b2) = query_audit(&ctx.app, "action=create_agent", &cookie, &csrf).await;

        assert_eq!(s1, s2);
        let e1 = b1["data"].as_array().expect("events 1");
        let e2 = b2["data"].as_array().expect("events 2");
        assert_eq!(e1.len(), e2.len(), "same filter should return same count");
    }

    // ===========================================================================
    // 6C. Error Handling
    // ===========================================================================

    /// Unknown query params are ignored, returns unfiltered results.
    #[tokio::test]
    async fn test_audit_filter_invalid_param_ignored() {
        let ctx = TestAppBuilder::new().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;
        seed_audit_events(&*ctx.store).await;

        let (status, body) = query_audit(&ctx.app, "bogus=foo&limit=50", &cookie, &csrf).await;
        if status == StatusCode::OK {
            let events = body["data"].as_array().expect("events array");
            assert!(
                events.len() >= 5,
                "unknown param should be ignored, returning all events"
            );
        } else {
            assert!(
                status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
                "unexpected status for unknown param: {}",
                status
            );
        }
    }

    // ===========================================================================
    // 6D. Cross-Feature
    // ===========================================================================

    /// Pagination works with filters.
    #[tokio::test]
    async fn test_filter_with_pagination() {
        let ctx = TestAppBuilder::new().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;
        seed_audit_events(&*ctx.store).await;

        let (status, body) = query_audit(
            &ctx.app,
            "resource_type=credential&limit=1&offset=0",
            &cookie,
            &csrf,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let page1 = body["data"].as_array().expect("page 1");
        assert_eq!(page1.len(), 1, "limit=1 should return exactly 1 event");

        let (status2, body2) = query_audit(
            &ctx.app,
            "resource_type=credential&limit=1&offset=1",
            &cookie,
            &csrf,
        )
        .await;
        assert_eq!(status2, StatusCode::OK);

        let page2 = body2["data"].as_array().expect("page 2");
        assert_eq!(page2.len(), 1, "second page should also return 1 event");

        if !page1.is_empty() && !page2.is_empty() {
            assert_ne!(
                page1[0]["id"], page2[0]["id"],
                "paginated results should be different events"
            );
        }
    }

    /// Filtered results count matches expected number.
    #[tokio::test]
    async fn test_audit_filter_preserves_count() {
        let ctx = TestAppBuilder::new().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;
        seed_audit_events(&*ctx.store).await;

        let (status, body) = query_audit(&ctx.app, "decision=forbid", &cookie, &csrf).await;
        assert_eq!(status, StatusCode::OK);

        let events = body["data"].as_array().expect("events array");
        assert_eq!(
            events.len(),
            1,
            "should have exactly 1 forbid event, got {}",
            events.len()
        );
    }

    // ===========================================================================
    // 6E. Security
    // ===========================================================================

    /// Filter endpoint requires authentication.
    #[tokio::test]
    async fn test_audit_filter_requires_auth() {
        let ctx = TestAppBuilder::new().build().await;

        let (status, _body) = common::send_json(
            &ctx.app,
            Method::GET,
            "/api/v1/audit?event_type=workspace_created",
            None,
            None,
            None,
            None,
        )
        .await;
        assert!(
            status == StatusCode::UNAUTHORIZED
                || status == StatusCode::FORBIDDEN
                || status == StatusCode::FOUND
                || status == StatusCode::SEE_OTHER,
            "unauthenticated filter query should return 401/403/302, got {}",
            status
        );
    }
}

mod demo_disable {
    //! v1.9.4 R2 — Demo Disable Tests (Item #7)
    //!
    //! Verifies the DELETE /api/v1/demo endpoint: removes demo seed data,
    //! preserves non-demo entities, emits audit events, and is idempotent.

    use crate::common;

    use axum::http::{Method, StatusCode};

    use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
    use agent_cordon_core::domain::user::UserRole;
    use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
    use agent_cordon_core::storage::Store;
    use agent_cordon_server::test_helpers::TestAppBuilder;

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    #[allow(dead_code)]
    async fn setup_admin_with_demo() -> (
        agent_cordon_server::test_helpers::TestContext,
        String,
        String,
    ) {
        let ctx = TestAppBuilder::new()
            .with_admin()
            .with_config(|c| {
                c.seed_demo = true;
            })
            .build()
            .await;

        common::create_user_in_db(
            &*ctx.store,
            "demo-admin",
            common::TEST_PASSWORD,
            UserRole::Admin,
            false,
            true,
        )
        .await;
        let cookie =
            common::login_user_combined(&ctx.app, "demo-admin", common::TEST_PASSWORD).await;
        let csrf = common::extract_csrf_from_cookie(&cookie).unwrap();
        (ctx, cookie, csrf)
    }

    /// Seed demo data manually (workspace + credential) for tests where AGTCRDN_SEED_DEMO
    /// may not create the data automatically via config.
    async fn seed_demo_data(store: &(dyn Store + Send + Sync)) {
        let now = chrono::Utc::now();

        let workspace = Workspace {
            id: WorkspaceId(uuid::Uuid::new_v4()),
            name: "demo-workspace".to_string(),
            enabled: true,
            status: WorkspaceStatus::Active,
            pk_hash: None,
            encryption_public_key: None,
            tags: vec!["demo".to_string()],
            owner_id: None,
            parent_id: None,
            tool_name: None,
            created_at: now,
            updated_at: now,
        };
        store
            .create_workspace(&workspace)
            .await
            .expect("create demo workspace");

        let cred = StoredCredential {
            id: CredentialId(uuid::Uuid::new_v4()),
            name: "demo-api-key".to_string(),
            service: "demo".to_string(),
            encrypted_value: vec![0u8; 32],
            nonce: vec![0u8; 12],
            scopes: vec![],
            metadata: serde_json::json!({}),
            created_by: None,
            created_by_user: None,
            created_at: now,
            updated_at: now,
            allowed_url_pattern: None,
            expires_at: None,
            transform_script: None,
            transform_name: None,
            vault: "default".to_string(),
            credential_type: "generic".to_string(),
            tags: vec!["demo".to_string()],
            description: None,
            target_identity: None,
            key_version: 1,
        };
        store
            .store_credential(&cred)
            .await
            .expect("create demo credential");
    }

    async fn setup_admin_seeded() -> (
        agent_cordon_server::test_helpers::TestContext,
        String,
        String,
    ) {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        seed_demo_data(&*ctx.store).await;

        common::create_user_in_db(
            &*ctx.store,
            "demo-admin",
            common::TEST_PASSWORD,
            UserRole::Admin,
            false,
            true,
        )
        .await;
        let cookie =
            common::login_user_combined(&ctx.app, "demo-admin", common::TEST_PASSWORD).await;
        let csrf = common::extract_csrf_from_cookie(&cookie).unwrap();
        (ctx, cookie, csrf)
    }

    // ===========================================================================
    // 7A. Happy Path
    // ===========================================================================

    /// DELETE /api/v1/demo with admin session → 200 OK.
    #[tokio::test]
    async fn test_delete_demo_returns_200() {
        let (ctx, cookie, csrf) = setup_admin_seeded().await;

        let (status, _body) = common::send_json(
            &ctx.app,
            Method::DELETE,
            "/api/v1/demo",
            None,
            Some(&cookie),
            Some(&csrf),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "DELETE /api/v1/demo should return 200"
        );
    }

    /// After DELETE, demo-workspace no longer exists.
    #[tokio::test]
    async fn test_delete_demo_removes_workspace() {
        let (ctx, cookie, csrf) = setup_admin_seeded().await;

        let (status, _) = common::send_json(
            &ctx.app,
            Method::DELETE,
            "/api/v1/demo",
            None,
            Some(&cookie),
            Some(&csrf),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // v2.0: demo seed creates "demo-workspace" (not "demo-agent")
        let workspace_old = ctx
            .store
            .get_workspace_by_name("demo-agent")
            .await
            .expect("query workspace");
        let workspace_new = ctx
            .store
            .get_workspace_by_name("demo-workspace")
            .await
            .expect("query workspace");
        assert!(
            workspace_old.is_none() && workspace_new.is_none(),
            "demo workspace should be removed after DELETE /api/v1/demo"
        );
    }

    /// After DELETE, demo-api-key credential no longer exists.
    #[tokio::test]
    async fn test_delete_demo_removes_credential() {
        let (ctx, cookie, csrf) = setup_admin_seeded().await;

        let (status, _) = common::send_json(
            &ctx.app,
            Method::DELETE,
            "/api/v1/demo",
            None,
            Some(&cookie),
            Some(&csrf),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let cred = ctx
            .store
            .get_credential_by_name("demo-api-key")
            .await
            .expect("query credential");
        assert!(
            cred.is_none(),
            "demo-api-key should be removed after DELETE /api/v1/demo"
        );
    }

    /// DELETE preserves audit events (they are not deleted).
    #[tokio::test]
    async fn test_delete_demo_preserves_audit_events() {
        let (ctx, cookie, csrf) = setup_admin_seeded().await;

        let events_before = ctx
            .store
            .list_audit_events(50, 0)
            .await
            .expect("list events before");
        let count_before = events_before.len();

        let (status, _) = common::send_json(
            &ctx.app,
            Method::DELETE,
            "/api/v1/demo",
            None,
            Some(&cookie),
            Some(&csrf),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let events_after = ctx
            .store
            .list_audit_events(50, 0)
            .await
            .expect("list events after");
        assert!(
            events_after.len() >= count_before,
            "audit events should be preserved after demo deletion"
        );
    }

    /// DELETE emits an audit event.
    #[tokio::test]
    async fn test_delete_demo_emits_audit_event() {
        let (ctx, cookie, csrf) = setup_admin_seeded().await;

        let (status, _) = common::send_json(
            &ctx.app,
            Method::DELETE,
            "/api/v1/demo",
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
            .expect("list events");
        let demo_event = events.iter().find(|e| {
            e.action.contains("demo")
                || e.action.contains("delete_demo")
                || e.action.contains("disable_demo")
                || format!("{:?}", e.event_type)
                    .to_lowercase()
                    .contains("demo")
        });
        assert!(
            demo_event.is_some(),
            "should find audit event for demo deletion, actions: {:?}",
            events.iter().map(|e| e.action.as_str()).collect::<Vec<_>>()
        );
    }

    // ===========================================================================
    // 7B. Retry/Idempotency
    // ===========================================================================

    /// Second DELETE returns 200 (idempotent, no error if already deleted).
    #[tokio::test]
    async fn test_delete_demo_idempotent() {
        let (ctx, cookie, csrf) = setup_admin_seeded().await;

        let (s1, _) = common::send_json(
            &ctx.app,
            Method::DELETE,
            "/api/v1/demo",
            None,
            Some(&cookie),
            Some(&csrf),
            None,
        )
        .await;
        assert_eq!(s1, StatusCode::OK);

        let (s2, _) = common::send_json(
            &ctx.app,
            Method::DELETE,
            "/api/v1/demo",
            None,
            Some(&cookie),
            Some(&csrf),
            None,
        )
        .await;
        assert!(
            s2 == StatusCode::OK || s2 == StatusCode::NOT_FOUND,
            "second DELETE should return 200 or 404, got {}",
            s2
        );
    }

    /// DELETE without demo seed data is graceful.
    #[tokio::test]
    async fn test_delete_demo_when_no_seed() {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        common::create_user_in_db(
            &*ctx.store,
            "demo-admin-noseed",
            common::TEST_PASSWORD,
            UserRole::Admin,
            false,
            true,
        )
        .await;
        let cookie =
            common::login_user_combined(&ctx.app, "demo-admin-noseed", common::TEST_PASSWORD).await;
        let csrf = common::extract_csrf_from_cookie(&cookie).unwrap();

        let (status, _body) = common::send_json(
            &ctx.app,
            Method::DELETE,
            "/api/v1/demo",
            None,
            Some(&cookie),
            Some(&csrf),
            None,
        )
        .await;
        assert!(
            status == StatusCode::OK || status == StatusCode::NOT_FOUND,
            "DELETE without demo seed should return 200 or 404 (graceful), got {}",
            status
        );
    }

    // ===========================================================================
    // 7C. Error Handling
    // ===========================================================================

    /// DELETE without session → 401/302.
    #[tokio::test]
    async fn test_delete_demo_unauthenticated() {
        let ctx = TestAppBuilder::new().with_admin().build().await;

        let (status, _body) =
            common::send_json_auto_csrf(&ctx.app, Method::DELETE, "/api/v1/demo", None, None, None)
                .await;
        assert!(
            status == StatusCode::UNAUTHORIZED
                || status == StatusCode::FORBIDDEN
                || status == StatusCode::FOUND
                || status == StatusCode::SEE_OTHER
                || status == StatusCode::NOT_FOUND,
            "unauthenticated DELETE should return 401/403/302/404, got {}",
            status
        );
    }

    // ===========================================================================
    // 7D. Cross-Feature
    // ===========================================================================

    /// DELETE demo does not affect real (non-demo) workspaces/credentials.
    #[tokio::test]
    async fn test_delete_demo_does_not_affect_real_data() {
        let (ctx, cookie, csrf) = setup_admin_seeded().await;

        let now = chrono::Utc::now();
        let real_workspace = Workspace {
            id: WorkspaceId(uuid::Uuid::new_v4()),
            name: "real-production-agent".to_string(),
            enabled: true,
            status: WorkspaceStatus::Active,
            pk_hash: None,
            encryption_public_key: None,
            tags: vec!["production".to_string()],
            owner_id: None,
            parent_id: None,
            tool_name: None,
            created_at: now,
            updated_at: now,
        };
        ctx.store
            .create_workspace(&real_workspace)
            .await
            .expect("create real workspace");

        let (status, _) = common::send_json(
            &ctx.app,
            Method::DELETE,
            "/api/v1/demo",
            None,
            Some(&cookie),
            Some(&csrf),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let workspace = ctx
            .store
            .get_workspace_by_name("real-production-agent")
            .await
            .expect("query workspace");
        assert!(
            workspace.is_some(),
            "real workspace should be preserved after demo deletion"
        );
    }

    /// GET /api/v1/demo/try-it returns 404 after deletion.
    #[tokio::test]
    async fn test_try_it_404_after_demo_deleted() {
        let (ctx, cookie, csrf) = setup_admin_seeded().await;

        let (status, _) = common::send_json(
            &ctx.app,
            Method::DELETE,
            "/api/v1/demo",
            None,
            Some(&cookie),
            Some(&csrf),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = common::send_json(
            &ctx.app,
            Method::GET,
            "/api/v1/demo/try-it",
            None,
            Some(&cookie),
            Some(&csrf),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "try-it should return 404 after demo deleted: {}",
            body
        );
    }

    // ===========================================================================
    // 7E. Security
    // ===========================================================================

    /// Audit event for demo deletion includes actor identity.
    #[tokio::test]
    async fn test_delete_demo_audit_includes_actor() {
        let (ctx, cookie, csrf) = setup_admin_seeded().await;

        let (status, _) = common::send_json(
            &ctx.app,
            Method::DELETE,
            "/api/v1/demo",
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
            .expect("list events");
        let demo_event = events.iter().find(|e| {
            e.action.contains("demo")
                || e.action.contains("delete_demo")
                || e.action.contains("disable_demo")
                || format!("{:?}", e.event_type)
                    .to_lowercase()
                    .contains("demo")
        });

        if let Some(event) = demo_event {
            let has_actor = event.user_id.is_some()
                || event.user_name.is_some()
                || event.metadata.get("user_id").is_some()
                || event.metadata.get("username").is_some();
            assert!(
                has_actor,
                "demo deletion audit event should include actor identity"
            );
        }
    }
}
