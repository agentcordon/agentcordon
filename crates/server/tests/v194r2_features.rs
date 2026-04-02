//! Consolidated integration tests for v1.9.4 R2 features.
//!
//! Merged from: v194r2_agent_device_display.rs, v194r2_audit_filters.rs

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
