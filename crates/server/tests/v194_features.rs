//! Consolidated integration tests for v1.9.4 features.
//!
//! Merged from: v194_advanced_mode.rs, v194_llm_exposed.rs, v194_settings_audit.rs

mod advanced_mode {
    //! v1.9.4 — Advanced Mode Toggle Tests (Items #2 and #14)
    //!
    //! Verifies the full round-trip of toggling show_advanced: PUT API → page
    //! reload → nav reflects the new state. Also verifies the dashboard Devices
    //! card visibility based on advanced mode.

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

    /// Create a test context with a user and return (ctx, cookie).
    /// The user starts with show_advanced = false (simple mode).
    async fn setup_simple() -> (agent_cordon_server::test_helpers::TestContext, String) {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let user = common::create_test_user(
            &*ctx.store,
            "adv-mode-user",
            common::TEST_PASSWORD,
            UserRole::Admin,
        )
        .await;

        let mut updated = user.clone();
        updated.show_advanced = false;
        ctx.store
            .update_user(&updated)
            .await
            .expect("set simple mode");

        let cookie =
            common::login_user_combined(&ctx.app, "adv-mode-user", common::TEST_PASSWORD).await;
        (ctx, cookie)
    }

    /// Create a test context with a user and return (ctx, cookie).
    /// The user starts with show_advanced = true (advanced mode).
    async fn setup_advanced() -> (agent_cordon_server::test_helpers::TestContext, String) {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let user = common::create_test_user(
            &*ctx.store,
            "adv-mode-user",
            common::TEST_PASSWORD,
            UserRole::Admin,
        )
        .await;

        let mut updated = user.clone();
        updated.show_advanced = true;
        ctx.store
            .update_user(&updated)
            .await
            .expect("set advanced mode");

        let cookie =
            common::login_user_combined(&ctx.app, "adv-mode-user", common::TEST_PASSWORD).await;
        (ctx, cookie)
    }

    // ===========================================================================
    // Item #2: Advanced Mode Toggle
    // ===========================================================================

    /// PUT enable → GET dashboard → nav has /devices, /mcp-servers.
    #[tokio::test]
    async fn test_toggle_advanced_mode_on_reflects_in_nav() {
        let (ctx, cookie) = setup_simple().await;

        // Toggle advanced mode ON via API
        let (status, _body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::PUT,
            "/api/v1/settings/advanced-mode",
            None,
            Some(&cookie),
            Some(json!({ "enabled": true })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "toggle on should succeed");

        // Verify nav now has advanced links
        let (status, html) = get_html(&ctx.app, "/dashboard", &cookie).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            html.contains("/workspaces"),
            "advanced mode ON: nav should contain /workspaces link"
        );
        assert!(
            html.contains("/mcp-servers"),
            "advanced mode ON: nav should contain /mcp-servers link"
        );
    }

    /// PUT disable → GET dashboard → nav still shows all links (nav no longer gated by advanced mode).
    #[tokio::test]
    async fn test_toggle_advanced_mode_off_hides_nav() {
        let (ctx, cookie) = setup_advanced().await;

        // Toggle advanced mode OFF via API
        let (status, _body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::PUT,
            "/api/v1/settings/advanced-mode",
            None,
            Some(&cookie),
            Some(json!({ "enabled": false })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "toggle off should succeed");

        // Nav always shows all items regardless of show_advanced setting
        let (status, html) = get_html(&ctx.app, "/dashboard", &cookie).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            html.contains("/mcp-servers"),
            "nav should always contain MCP Servers link regardless of advanced mode"
        );
    }

    /// Settings page reflects current show_advanced state.
    #[tokio::test]
    async fn test_settings_page_shows_current_state() {
        let (ctx, cookie) = setup_advanced().await;

        // With advanced mode ON, settings should reflect true
        let (status, html) = get_html(&ctx.app, "/settings", &cookie).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            html.contains("advancedMode: true") || html.contains("advancedMode:true"),
            "settings should show advancedMode: true when show_advanced=true"
        );

        // Toggle OFF
        let (status, _) = common::send_json_auto_csrf(
            &ctx.app,
            Method::PUT,
            "/api/v1/settings/advanced-mode",
            None,
            Some(&cookie),
            Some(json!({ "enabled": false })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Settings should now reflect false
        let (status, html) = get_html(&ctx.app, "/settings", &cookie).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            html.contains("advancedMode: false") || html.contains("advancedMode:false"),
            "settings should show advancedMode: false after toggling off"
        );
    }

    /// Toggle on → off → verify same as initial state.
    #[tokio::test]
    async fn test_toggle_advanced_twice_returns_to_original() {
        let (ctx, cookie) = setup_simple().await;

        // Capture initial nav state
        let (_, initial_html) = get_html(&ctx.app, "/dashboard", &cookie).await;
        let initial_has_devices_nav = initial_html.contains(r#"href="/devices" class="nav-link"#);

        // Toggle ON
        common::send_json_auto_csrf(
            &ctx.app,
            Method::PUT,
            "/api/v1/settings/advanced-mode",
            None,
            Some(&cookie),
            Some(json!({ "enabled": true })),
        )
        .await;

        // Toggle OFF (back to original)
        common::send_json_auto_csrf(
            &ctx.app,
            Method::PUT,
            "/api/v1/settings/advanced-mode",
            None,
            Some(&cookie),
            Some(json!({ "enabled": false })),
        )
        .await;

        // Verify same as initial
        let (_, final_html) = get_html(&ctx.app, "/dashboard", &cookie).await;
        let final_has_devices_nav = final_html.contains(r#"href="/devices" class="nav-link"#);
        assert_eq!(
            initial_has_devices_nav, final_has_devices_nav,
            "after toggle on→off, nav should match initial state"
        );
    }

    /// Already true, PUT true → 200, no change.
    #[tokio::test]
    async fn test_toggle_same_value_is_noop() {
        let (ctx, cookie) = setup_advanced().await;

        // PUT true again (already true)
        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::PUT,
            "/api/v1/settings/advanced-mode",
            None,
            Some(&cookie),
            Some(json!({ "enabled": true })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "idempotent toggle should succeed: {:?}",
            body
        );
        assert_eq!(
            body["data"]["show_advanced"],
            json!(true),
            "response should confirm show_advanced is still true"
        );
    }

    /// Invalid payload → 400 or 422.
    #[tokio::test]
    async fn test_toggle_invalid_body_returns_400() {
        let (ctx, cookie) = setup_simple().await;

        // Send invalid body (missing 'enabled' field)
        let (status, _body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::PUT,
            "/api/v1/settings/advanced-mode",
            None,
            Some(&cookie),
            Some(json!({})),
        )
        .await;
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
            "invalid body should return 400 or 422, got {}",
            status
        );

        // Send non-boolean value
        let (status2, _body2) = common::send_json_auto_csrf(
            &ctx.app,
            Method::PUT,
            "/api/v1/settings/advanced-mode",
            None,
            Some(&cookie),
            Some(json!({ "enabled": "not-a-bool" })),
        )
        .await;
        assert!(
            status2 == StatusCode::BAD_REQUEST || status2 == StatusCode::UNPROCESSABLE_ENTITY,
            "non-boolean 'enabled' should return 400 or 422, got {}",
            status2
        );
    }

    /// No session → 401 or redirect to login.
    #[tokio::test]
    async fn test_toggle_unauthenticated_returns_401() {
        let ctx = TestAppBuilder::new().with_admin().build().await;

        let (status, _body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::PUT,
            "/api/v1/settings/advanced-mode",
            None,
            None, // no cookie
            Some(json!({ "enabled": true })),
        )
        .await;
        assert!(
            status == StatusCode::UNAUTHORIZED
                || status == StatusCode::FOUND
                || status == StatusCode::SEE_OTHER,
            "unauthenticated PUT should return 401 or redirect, got {}",
            status
        );
    }

    /// show_advanced=false, GET /api/v1/devices → still 200. API not gated by UI preference.
    #[tokio::test]
    async fn test_advanced_mode_off_api_still_works() {
        let (ctx, cookie) = setup_simple().await;

        let (status, _body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            "/api/v1/workspaces",
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "API should not be gated by show_advanced preference"
        );
    }

    /// show_advanced=false, GET /workspaces → still 200 (hidden from nav, not blocked).
    #[tokio::test]
    async fn test_advanced_mode_off_direct_url_still_works() {
        let (ctx, cookie) = setup_simple().await;

        let (status, _body) = get_html(&ctx.app, "/workspaces", &cookie).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "direct URL to /workspaces should work even with show_advanced=false"
        );
    }

    // ===========================================================================
    // Item #14: Dashboard Devices Card Visibility
    // ===========================================================================

    /// Nav always shows all items regardless of show_advanced setting.
    #[tokio::test]
    async fn test_dashboard_devices_card_hidden_in_simple_mode() {
        let (ctx, cookie) = setup_simple().await;

        let (status, html) = get_html(&ctx.app, "/dashboard", &cookie).await;
        assert_eq!(status, StatusCode::OK);

        // Nav now always shows all items
        assert!(
            html.contains("/mcp-servers"),
            "nav should always contain links regardless of show_advanced"
        );
    }

    /// show_advanced=true → dashboard should have Workspaces link visible.
    #[tokio::test]
    async fn test_dashboard_devices_card_visible_in_advanced_mode() {
        let (ctx, cookie) = setup_advanced().await;

        let (status, html) = get_html(&ctx.app, "/dashboard", &cookie).await;
        assert_eq!(status, StatusCode::OK);

        assert!(
            html.contains(r#"href="/workspaces""#),
            "advanced mode: dashboard should have Workspaces link"
        );
    }

    /// All dashboard cards and nav links are always visible regardless of mode.
    #[tokio::test]
    async fn test_dashboard_all_cards_match_nav_visibility() {
        let (ctx, cookie) = setup_simple().await;

        let (status, html) = get_html(&ctx.app, "/dashboard", &cookie).await;
        assert_eq!(status, StatusCode::OK);

        // Nav always shows all items now
        assert!(
            html.contains("/mcp-servers"),
            "nav should always contain /mcp-servers link"
        );

        assert!(
            html.contains("/credentials"),
            "dashboard should show core feature links"
        );
    }
}

mod llm_exposed {
    //! v1.9.4 — LLM Exposed Tag Tests (Item #5)
    //!
    //! Verifies that admin-created credentials do NOT get the `llm_exposed` tag,
    //! while agent-created credentials DO. Also tests tag persistence through
    //! updates and cross-feature interactions.

    use axum::body::Body;
    use axum::http::{header, Method, Request, StatusCode};
    use http_body_util::BodyExt;
    use serde_json::json;
    use tower::ServiceExt;

    use agent_cordon_core::domain::user::UserRole;
    use agent_cordon_core::storage::Store;
    use agent_cordon_server::test_helpers::TestAppBuilder;

    use crate::common::*;

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    async fn setup_admin(
        app: &axum::Router,
        store: &(dyn Store + Send + Sync),
    ) -> (String, String) {
        // Use root user so Cedar owner-scoping doesn't block access to
        // agent-created credentials (which have no user owner).
        create_user_in_db(
            store,
            "llm-v194-admin",
            TEST_PASSWORD,
            UserRole::Admin,
            true,
            true,
        )
        .await;
        let cookie = login_user_combined(app, "llm-v194-admin", TEST_PASSWORD).await;
        let csrf = extract_csrf_from_cookie(&cookie).unwrap();
        (cookie, csrf)
    }

    /// Send a request with workspace JWT auth (Authorization: Bearer).
    ///
    /// In v2.0, device+agent dual auth is replaced by single workspace JWT auth.
    async fn send_device_and_agent_auth(
        app: &axum::Router,
        method: Method,
        uri: &str,
        _device_key: &p256::ecdsa::SigningKey,
        _device_id: &str,
        agent_jwt: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder().method(method).uri(uri);
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {}", agent_jwt));

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
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));
        (status, json)
    }

    // ===========================================================================
    // 5A. Happy Path
    // ===========================================================================

    /// Admin creates credential with no tags → should NOT have llm_exposed.
    #[tokio::test]
    async fn test_admin_created_credential_no_llm_exposed() {
        let ctx = TestAppBuilder::new().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

        let (status, body) = send_json(
            &ctx.app,
            Method::POST,
            "/api/v1/credentials",
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({
                "name": "admin-no-llm",
                "service": "github",
                "secret_value": "ghp_admin_secret_123",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "create credential: {}", body);

        let tags = body["data"]["tags"].as_array().expect("tags");
        let tag_strs: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
        assert!(
            !tag_strs.contains(&"llm_exposed"),
            "admin-created credential should NOT have llm_exposed tag, got: {:?}",
            tag_strs
        );
    }

    /// Admin creates credential with explicit tags → only those tags, no llm_exposed.
    #[tokio::test]
    async fn test_admin_created_credential_with_explicit_tags() {
        let ctx = TestAppBuilder::new().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

        let (status, body) = send_json(
            &ctx.app,
            Method::POST,
            "/api/v1/credentials",
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({
                "name": "admin-tagged",
                "service": "github",
                "secret_value": "ghp_admin_tagged_123",
                "tags": ["production"],
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "create credential: {}", body);

        let tags = body["data"]["tags"].as_array().expect("tags");
        let tag_strs: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
        assert!(
            tag_strs.contains(&"production"),
            "should have production tag"
        );
        assert!(
            !tag_strs.contains(&"llm_exposed"),
            "admin-created credential should NOT have llm_exposed, got: {:?}",
            tag_strs
        );
    }

    /// Agent stores credential via agent-store → should have llm_exposed tag.
    #[tokio::test]
    async fn test_agent_created_credential_has_llm_exposed() {
        let ctx = TestAppBuilder::new().with_admin().build().await;

        let agent = ctx.admin_agent.as_ref().expect("admin agent");
        let agent_jwt = issue_agent_jwt(&ctx.state, agent);

        let (status, body) = send_device_and_agent_auth(
            &ctx.app,
            Method::POST,
            "/api/v1/credentials/agent-store",
            ctx.admin_signing_key(),
            ctx.admin_device_id(),
            &agent_jwt,
            Some(json!({
                "name": "agent-llm-v194",
                "service": "openai",
                "secret_value": "sk-test-secret",
                "agent_id": agent.id.0.to_string(),
                "agent_name": agent.name,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "agent-store: {}", body);

        let tags = body["data"]["tags"].as_array().expect("tags");
        let tag_strs: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
        assert!(
            tag_strs.contains(&"llm_exposed"),
            "agent-created credential should have llm_exposed, got: {:?}",
            tag_strs
        );
    }

    // ===========================================================================
    // 5B. Retry/Idempotency
    // ===========================================================================

    /// Update credential (name change) → tags unchanged.
    #[tokio::test]
    async fn test_update_credential_preserves_tags() {
        let ctx = TestAppBuilder::new().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

        let (status, body) = send_json(
            &ctx.app,
            Method::POST,
            "/api/v1/credentials",
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({
                "name": "preserve-tags-test",
                "service": "github",
                "secret_value": "ghp_test_123",
                "tags": ["production"],
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "create: {}", body);
        let cred_id = body["data"]["id"].as_str().expect("credential id");

        let (status, body) = send_json(
            &ctx.app,
            Method::PUT,
            &format!("/api/v1/credentials/{}", cred_id),
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({
                "name": "preserve-tags-test-updated",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "update: {}", body);

        let (status, body) = send_json(
            &ctx.app,
            Method::GET,
            &format!("/api/v1/credentials/{}", cred_id),
            None,
            Some(&cookie),
            Some(&csrf),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "get: {}", body);

        let tags = body["data"]["tags"].as_array().expect("tags");
        let tag_strs: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
        assert!(
            tag_strs.contains(&"production"),
            "production tag should persist"
        );
        assert!(
            !tag_strs.contains(&"llm_exposed"),
            "no llm_exposed should appear"
        );
    }

    /// Update credential secret → no llm_exposed tag injected.
    #[tokio::test]
    async fn test_update_credential_does_not_inject_llm_exposed() {
        let ctx = TestAppBuilder::new().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

        let (status, body) = send_json(
            &ctx.app,
            Method::POST,
            "/api/v1/credentials",
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({
                "name": "no-inject-test",
                "service": "github",
                "secret_value": "ghp_original_secret",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "create: {}", body);
        let cred_id = body["data"]["id"].as_str().expect("credential id");

        let (status, body) = send_json(
            &ctx.app,
            Method::PUT,
            &format!("/api/v1/credentials/{}", cred_id),
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({
                "secret_value": "ghp_new_secret_value",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "update: {}", body);

        let (status, body) = send_json(
            &ctx.app,
            Method::GET,
            &format!("/api/v1/credentials/{}", cred_id),
            None,
            Some(&cookie),
            Some(&csrf),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "get: {}", body);

        let tags = body["data"]["tags"].as_array().expect("tags");
        let tag_strs: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
        assert!(
            !tag_strs.contains(&"llm_exposed"),
            "updating secret should not inject llm_exposed, got: {:?}",
            tag_strs
        );
    }

    // ===========================================================================
    // 5D. Cross-Feature
    // ===========================================================================

    /// Mixed creds: only agent-created should have llm_exposed in list.
    #[tokio::test]
    async fn test_credential_list_shows_correct_llm_exposed() {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

        let (status, _) = send_json(
            &ctx.app,
            Method::POST,
            "/api/v1/credentials",
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({
                "name": "admin-list-cred",
                "service": "github",
                "secret_value": "ghp_admin_123",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let agent = ctx.admin_agent.as_ref().expect("admin agent");
        let agent_jwt = issue_agent_jwt(&ctx.state, agent);
        let (status, _) = send_device_and_agent_auth(
            &ctx.app,
            Method::POST,
            "/api/v1/credentials/agent-store",
            ctx.admin_signing_key(),
            ctx.admin_device_id(),
            &agent_jwt,
            Some(json!({
                "name": "agent-list-cred",
                "service": "openai",
                "secret_value": "sk-test",
                "agent_id": agent.id.0.to_string(),
                "agent_name": agent.name,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = send_json(
            &ctx.app,
            Method::GET,
            "/api/v1/credentials",
            None,
            Some(&cookie),
            Some(&csrf),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "list: {}", body);

        let creds = body["data"].as_array().expect("credentials array");

        let admin_cred = creds
            .iter()
            .find(|c| c["name"].as_str() == Some("admin-list-cred"));
        let agent_cred = creds
            .iter()
            .find(|c| c["name"].as_str() == Some("agent-list-cred"));

        assert!(
            admin_cred.is_some(),
            "admin credential should appear in list"
        );
        assert!(
            agent_cred.is_some(),
            "agent credential should appear in list"
        );

        let empty_vec = vec![];
        let admin_tags: Vec<&str> = admin_cred.unwrap()["tags"]
            .as_array()
            .unwrap_or(&empty_vec)
            .iter()
            .filter_map(|t| t.as_str())
            .collect();
        assert!(
            !admin_tags.contains(&"llm_exposed"),
            "admin cred in list should NOT have llm_exposed"
        );

        let empty_vec2 = vec![];
        let agent_tags: Vec<&str> = agent_cred.unwrap()["tags"]
            .as_array()
            .unwrap_or(&empty_vec2)
            .iter()
            .filter_map(|t| t.as_str())
            .collect();
        assert!(
            agent_tags.contains(&"llm_exposed"),
            "agent cred in list should have llm_exposed"
        );
    }

    /// Stats endpoint reflects correct llm_exposed count.
    #[tokio::test]
    async fn test_llm_exposed_stats_accurate() {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

        let (status, _) = send_json(
            &ctx.app,
            Method::POST,
            "/api/v1/credentials",
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({
                "name": "stats-admin-cred",
                "service": "github",
                "secret_value": "ghp_stats_123",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let agent = ctx.admin_agent.as_ref().expect("admin agent");
        let agent_jwt = issue_agent_jwt(&ctx.state, agent);
        let (status, _) = send_device_and_agent_auth(
            &ctx.app,
            Method::POST,
            "/api/v1/credentials/agent-store",
            ctx.admin_signing_key(),
            ctx.admin_device_id(),
            &agent_jwt,
            Some(json!({
                "name": "stats-agent-cred",
                "service": "openai",
                "secret_value": "sk-stats-test",
                "agent_id": agent.id.0.to_string(),
                "agent_name": agent.name,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = send_json(
            &ctx.app,
            Method::GET,
            "/api/v1/stats",
            None,
            Some(&cookie),
            Some(&csrf),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "stats: {}", body);

        let llm_exposed = body["data"]["credentials"]["llm_exposed"]
            .as_u64()
            .expect("llm_exposed count");
        assert_eq!(
            llm_exposed, 1,
            "only agent cred should be llm_exposed, got {}",
            llm_exposed
        );
    }

    // ===========================================================================
    // 5E. Security
    // ===========================================================================

    /// Admin can remove llm_exposed tag from agent-created credential.
    #[tokio::test]
    async fn test_admin_can_remove_llm_exposed_tag() {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

        let agent = ctx.admin_agent.as_ref().expect("admin agent");
        let agent_jwt = issue_agent_jwt(&ctx.state, agent);
        let (status, body) = send_device_and_agent_auth(
            &ctx.app,
            Method::POST,
            "/api/v1/credentials/agent-store",
            ctx.admin_signing_key(),
            ctx.admin_device_id(),
            &agent_jwt,
            Some(json!({
                "name": "admin-remove-llm-test",
                "service": "openai",
                "secret_value": "sk-remove-test",
                "agent_id": agent.id.0.to_string(),
                "agent_name": agent.name,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "agent-store: {}", body);
        let cred_id = body["data"]["id"].as_str().expect("credential id");

        let tags = body["data"]["tags"].as_array().expect("tags");
        let tag_strs: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
        assert!(
            tag_strs.contains(&"llm_exposed"),
            "agent-created credential should initially have llm_exposed"
        );

        let (status, _body) = send_json(
            &ctx.app,
            Method::PUT,
            &format!("/api/v1/credentials/{}", cred_id),
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({
                "tags": [],
            })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "admin should be able to update tags"
        );

        let (status, body) = send_json(
            &ctx.app,
            Method::GET,
            &format!("/api/v1/credentials/{}", cred_id),
            None,
            Some(&cookie),
            Some(&csrf),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "get: {}", body);

        let tags = body["data"]["tags"].as_array().expect("tags");
        let tag_strs: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
        assert!(
            !tag_strs.contains(&"llm_exposed"),
            "admin should be able to remove llm_exposed tag, got: {:?}",
            tag_strs
        );
    }
}

mod settings_audit {
    //! v1.9.4 — Settings Audit Event Tests (Item #12)
    //!
    //! Verifies that toggling `show_advanced` via
    //! `PUT /api/v1/settings/advanced-mode` emits a proper audit event with
    //! old/new values, actor identity, and correct event type.

    use axum::http::{Method, StatusCode};
    use serde_json::json;

    use agent_cordon_core::domain::user::UserRole;
    use agent_cordon_core::storage::Store;
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
            "audit-settings-admin",
            TEST_PASSWORD,
            UserRole::Admin,
            false,
            true,
        )
        .await;
        let cookie = login_user_combined(app, "audit-settings-admin", TEST_PASSWORD).await;
        let csrf = extract_csrf_from_cookie(&cookie).unwrap();
        (cookie, csrf)
    }

    // ===========================================================================
    // 12A. Happy Path
    // ===========================================================================

    /// PUT toggle → audit event exists with type settings_updated.
    #[tokio::test]
    async fn test_toggle_advanced_mode_emits_audit_event() {
        let ctx = TestAppBuilder::new().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

        let (status, _) = send_json(
            &ctx.app,
            Method::PUT,
            "/api/v1/settings/advanced-mode",
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({ "enabled": true })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "toggle should succeed");

        let events = ctx
            .store
            .list_audit_events(20, 0)
            .await
            .expect("list audit events");
        let settings_event = events.iter().find(|e| e.action == "settings_updated");
        assert!(
            settings_event.is_some(),
            "should find audit event with action 'settings_updated', events: {:?}",
            events.iter().map(|e| e.action.as_str()).collect::<Vec<_>>()
        );
    }

    /// Audit event metadata includes old and new value.
    #[tokio::test]
    async fn test_audit_event_contains_old_and_new_value() {
        let ctx = TestAppBuilder::new().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

        let (status, _) = send_json(
            &ctx.app,
            Method::PUT,
            "/api/v1/settings/advanced-mode",
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({ "enabled": false })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) = send_json(
            &ctx.app,
            Method::PUT,
            "/api/v1/settings/advanced-mode",
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({ "enabled": true })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let events = ctx
            .store
            .list_audit_events(20, 0)
            .await
            .expect("list audit events");
        let settings_events: Vec<_> = events
            .iter()
            .filter(|e| e.action == "settings_updated")
            .collect();
        assert!(
            !settings_events.is_empty(),
            "should have settings_updated events"
        );

        let latest = &settings_events[0];
        let details = &latest.metadata;
        assert_eq!(
            details.get("setting").and_then(|v| v.as_str()),
            Some("show_advanced"),
            "event should reference 'show_advanced' setting"
        );
        assert_eq!(
            details.get("old_value"),
            Some(&json!(false)),
            "old_value should be false"
        );
        assert_eq!(
            details.get("new_value"),
            Some(&json!(true)),
            "new_value should be true"
        );
    }

    // ===========================================================================
    // 12B. Retry/Idempotency
    // ===========================================================================

    /// Two toggles → two separate audit events.
    #[tokio::test]
    async fn test_toggle_twice_creates_two_events() {
        let ctx = TestAppBuilder::new().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

        let (status, _) = send_json(
            &ctx.app,
            Method::PUT,
            "/api/v1/settings/advanced-mode",
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({ "enabled": false })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) = send_json(
            &ctx.app,
            Method::PUT,
            "/api/v1/settings/advanced-mode",
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({ "enabled": true })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let events = ctx
            .store
            .list_audit_events(50, 0)
            .await
            .expect("list audit events");
        let settings_count = events
            .iter()
            .filter(|e| e.action == "settings_updated")
            .count();
        assert!(
            settings_count >= 2,
            "should have at least 2 settings_updated events, got {}",
            settings_count
        );
    }

    // ===========================================================================
    // 12C. Error Handling
    // ===========================================================================

    /// Invalid PUT → no audit event created.
    #[tokio::test]
    async fn test_failed_toggle_no_audit_event() {
        let ctx = TestAppBuilder::new().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

        let events_before = ctx
            .store
            .list_audit_events(50, 0)
            .await
            .expect("list events");
        let count_before = events_before
            .iter()
            .filter(|e| e.action == "settings_updated")
            .count();

        let (status, _) = send_json(
            &ctx.app,
            Method::PUT,
            "/api/v1/settings/advanced-mode",
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({})),
        )
        .await;
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
            "invalid body should fail, got {}",
            status
        );

        let events_after = ctx
            .store
            .list_audit_events(50, 0)
            .await
            .expect("list events");
        let count_after = events_after
            .iter()
            .filter(|e| e.action == "settings_updated")
            .count();
        assert_eq!(
            count_before, count_after,
            "failed toggle should not create audit event"
        );
    }

    // ===========================================================================
    // 12D. Cross-Feature
    // ===========================================================================

    /// Settings event appears in audit list via API.
    #[tokio::test]
    async fn test_settings_audit_visible_in_audit_page() {
        let ctx = TestAppBuilder::new().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

        let (status, _) = send_json(
            &ctx.app,
            Method::PUT,
            "/api/v1/settings/advanced-mode",
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({ "enabled": true })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = send_json(
            &ctx.app,
            Method::GET,
            "/api/v1/audit?limit=20",
            None,
            Some(&cookie),
            Some(&csrf),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "audit API: {}", body);

        let events = body["data"].as_array().expect("events array");
        let has_settings_event = events
            .iter()
            .any(|e| e.get("action").and_then(|v| v.as_str()) == Some("settings_updated"));
        assert!(
            has_settings_event,
            "settings_updated event should appear in audit API response"
        );
    }

    // ===========================================================================
    // 12E. Security
    // ===========================================================================

    /// Audit event includes user_id/username of who toggled.
    #[tokio::test]
    async fn test_settings_audit_includes_actor() {
        let ctx = TestAppBuilder::new().build().await;
        let (cookie, csrf) = setup_admin(&ctx.app, &*ctx.store).await;

        let (status, _) = send_json(
            &ctx.app,
            Method::PUT,
            "/api/v1/settings/advanced-mode",
            None,
            Some(&cookie),
            Some(&csrf),
            Some(json!({ "enabled": false })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let events = ctx
            .store
            .list_audit_events(20, 0)
            .await
            .expect("list events");
        let settings_event = events
            .iter()
            .find(|e| e.action == "settings_updated")
            .expect("should find settings_updated event");

        let has_actor = settings_event.user_id.is_some()
            || settings_event.user_name.is_some()
            || settings_event.metadata.get("user_id").is_some()
            || settings_event.metadata.get("username").is_some();
        assert!(
            has_actor,
            "audit event should include actor identity (user_id, user_name, or in metadata)"
        );
    }
}
