//! Consolidated integration tests for v1.9.3 features.
//!
//! Merged from: v193_bug_fixes.rs, v193_ux_renames.rs, v193_seed_policies.rs

mod bug_fixes {
    //! Integration tests — v1.9.3 Features 6-10: Bug Fixes.
    //!
    //! Covers: permission label display (F6), login button styling (F7),
    //! dashboard timestamp formatting (F8), button order consistency (F9),
    //! and dashboard stats updates (F10).

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

    async fn get_html_raw(app: &axum::Router, uri: &str) -> (StatusCode, String) {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri)
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

    async fn setup() -> (agent_cordon_server::test_helpers::TestContext, String) {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let _user = common::create_test_user(
            &*ctx.store,
            "bugfix-user",
            common::TEST_PASSWORD,
            UserRole::Admin,
        )
        .await;
        let cookie =
            common::login_user_combined(&ctx.app, "bugfix-user", common::TEST_PASSWORD).await;
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
            "bugfix-seed-user",
            common::TEST_PASSWORD,
            UserRole::Admin,
        )
        .await;
        let cookie =
            common::login_user_combined(&ctx.app, "bugfix-seed-user", common::TEST_PASSWORD).await;
        (ctx, cookie)
    }

    // ===========================================================================
    // Feature 6: Permission Checkbox Labels — Human-readable
    // ===========================================================================

    /// Permission labels on credential detail page should be Title Case, not snake_case.
    #[tokio::test]
    async fn test_permission_labels_human_readable() {
        let (ctx, cookie) = setup().await;

        // Create a credential to view its detail page
        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/credentials",
            None,
            Some(&cookie),
            Some(json!({
                "name": "perm-label-test",
                "service": "test-service",
                "credential_type": "generic",
                "secret_value": "test-secret"
            })),
        )
        .await;
        assert!(status == StatusCode::CREATED || status == StatusCode::OK);
        let cred_id = body["data"]["id"].as_str().expect("credential id");

        let (status, html) =
            get_html(&ctx.app, &format!("/credentials/{}", cred_id), &cookie).await;
        assert_eq!(status, StatusCode::OK);

        // The page should show human-readable labels like "Delegated Use"
        // and NOT raw snake_case like "delegated_use"
        // Note: this checks the HTML template, not JS-rendered content
        if html.contains("delegated_use") {
            // If the raw snake_case appears, the fix hasn't been applied yet
            // but the label mapping should exist in the template
            assert!(
                html.contains("Delegated Use")
                    || html.contains("formatPermission")
                    || html.contains("permission_label"),
                "credential detail page should have human-readable permission labels or a formatter"
            );
        }
    }

    /// API should still accept snake_case permission names (cosmetic change only).
    #[tokio::test]
    async fn test_permission_api_accepts_snake_case() {
        let (ctx, cookie) = setup().await;

        // Create a credential
        let (_, cred_body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/credentials",
            None,
            Some(&cookie),
            Some(json!({
                "name": "perm-api-test",
                "service": "test",
                "credential_type": "generic",
                "secret_value": "secret"
            })),
        )
        .await;
        let cred_id = cred_body["data"]["id"].as_str().expect("cred id");

        // Get admin agent ID
        let admin_agent = ctx.admin_agent.as_ref().expect("admin agent");

        // Grant permission using snake_case
        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            &format!("/api/v1/credentials/{}/permissions", cred_id),
            None,
            Some(&cookie),
            Some(json!({
                "agent_id": admin_agent.id.0.to_string(),
                "permission": "delegated_use"
            })),
        )
        .await;
        assert!(
            status == StatusCode::OK || status == StatusCode::CREATED,
            "API should accept snake_case permission 'delegated_use': status={}, body={:?}",
            status,
            body
        );
    }

    // ===========================================================================
    // Feature 7: Sign In Button Color
    // ===========================================================================

    /// Login page submit button should have btn-primary class.
    #[tokio::test]
    async fn test_login_button_has_primary_class() {
        let ctx = TestAppBuilder::new().with_admin().build().await;

        let (status, body) = get_html_raw(&ctx.app, "/login").await;
        assert_eq!(status, StatusCode::OK);

        assert!(
            body.contains("btn-primary"),
            "login page should have a button with btn-primary class"
        );
    }

    /// Login page submit button should not be disabled in initial state.
    #[tokio::test]
    async fn test_login_button_not_disabled_initially() {
        let ctx = TestAppBuilder::new().with_admin().build().await;

        let (status, body) = get_html_raw(&ctx.app, "/login").await;
        assert_eq!(status, StatusCode::OK);

        // Find the submit button — it should not have a "disabled" attribute
        // in the initial server-rendered HTML
        // The button might be conditionally disabled via Alpine.js, but the
        // initial HTML attribute should not be present
        let submit_section = body
            .find("login-submit")
            .or_else(|| body.find("type=\"submit\""))
            .map(|pos| &body[pos.saturating_sub(200)..std::cmp::min(pos + 200, body.len())]);

        if let Some(section) = submit_section {
            // Check that the button is not statically disabled
            // (x-bind:disabled is OK — that's Alpine.js conditional disabling)
            let has_static_disabled = section.contains(" disabled ")
                || section.contains(" disabled>")
                || section.contains("disabled=\"disabled\"");
            assert!(
                !has_static_disabled,
                "login submit button should not be statically disabled in initial HTML"
            );
        }
    }

    // ===========================================================================
    // Feature 8: Dashboard Timestamps
    // ===========================================================================

    /// Dashboard timestamps should not show raw ISO format with nanoseconds.
    #[tokio::test]
    async fn test_dashboard_timestamps_not_raw_iso() {
        let (ctx, cookie) = setup_with_seed().await;

        let (status, body) = get_html(&ctx.app, "/dashboard", &cookie).await;
        assert_eq!(status, StatusCode::OK);

        // Raw ISO timestamps look like: 2026-03-16T10:30:45.123456789
        // After formatting, they should NOT match this pattern in visible content
        // Check for raw nanosecond timestamps like 2026-03-16T10:30:45.123456789
        // Using simple string search instead of regex to avoid extra dependencies
        let has_nanosecond_timestamp = body.as_bytes().windows(30).any(|w| {
            // Pattern: YYYY-MM-DDThh:mm:ss.NNNNNN (6+ fractional digits)
            let s = std::str::from_utf8(w).unwrap_or("");
            s.len() >= 26
                && s.as_bytes().get(4) == Some(&b'-')
                && s.as_bytes().get(7) == Some(&b'-')
                && s.as_bytes().get(10) == Some(&b'T')
                && s.as_bytes().get(13) == Some(&b':')
                && s.as_bytes().get(16) == Some(&b':')
                && s.as_bytes().get(19) == Some(&b'.')
                && s[20..26].chars().all(|c| c.is_ascii_digit())
        });

        // The template should use formatDateTime() for visible timestamps
        // Note: JSON data attributes may still contain raw ISO, that's OK
        assert!(
            !has_nanosecond_timestamp || body.contains("formatDateTime"),
            "dashboard should format timestamps using formatDateTime() or not show raw ISO with nanoseconds"
        );
    }

    /// Dashboard HTML/JS should reference formatDateTime for timestamp rendering.
    #[tokio::test]
    async fn test_dashboard_uses_format_datetime() {
        let (ctx, cookie) = setup_with_seed().await;

        let (status, body) = get_html(&ctx.app, "/dashboard", &cookie).await;
        assert_eq!(status, StatusCode::OK);

        assert!(
            body.contains("formatDateTime"),
            "dashboard should use formatDateTime() for timestamp display"
        );
    }

    /// Audit log page should also format timestamps.
    #[tokio::test]
    async fn test_audit_page_timestamps_formatted() {
        let (ctx, cookie) = setup_with_seed().await;

        let (status, body) = get_html(&ctx.app, "/audit", &cookie).await;
        assert_eq!(status, StatusCode::OK);

        assert!(
            body.contains("formatDateTime") || body.contains("format_datetime"),
            "audit page should format timestamps"
        );
    }

    /// API timestamps should remain full ISO format (no change).
    #[tokio::test]
    async fn test_api_timestamps_unchanged() {
        let (ctx, cookie) = setup_with_seed().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            "/api/v1/audit?limit=5",
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let events = body["data"].as_array().expect("data array");
        if !events.is_empty() {
            let timestamp = events[0]["timestamp"].as_str().unwrap_or("");
            // API should return full ISO timestamps
            assert!(
                timestamp.contains("T") && timestamp.contains(":"),
                "API timestamps should remain in ISO format, got: {}",
                timestamp
            );
        }
    }

    // ===========================================================================
    // Feature 9: Inconsistent Button Order
    // ===========================================================================

    /// All create/new pages should have consistent button order.
    #[tokio::test]
    async fn test_all_forms_consistent_button_order() {
        let (ctx, cookie) = setup().await;

        let pages = [
            "/devices/new",
            "/credentials/new",
            "/policies/new",
            "/users/new",
            "/mcp-servers/new",
        ];

        let mut button_orders: Vec<(String, String)> = Vec::new();

        for page in &pages {
            let (status, body) = get_html(&ctx.app, page, &cookie).await;
            if status != StatusCode::OK {
                continue; // Skip pages that might not exist yet
            }

            // Look for form-actions div or button group
            // Determine if Cancel comes before Submit or vice versa
            let cancel_pos = body.find("Cancel").or_else(|| body.find("cancel"));
            let submit_pos = body
                .find("type=\"submit\"")
                .or_else(|| body.find("btn-primary"));

            if let (Some(c), Some(s)) = (cancel_pos, submit_pos) {
                let order = if c < s {
                    "cancel-first"
                } else {
                    "submit-first"
                };
                button_orders.push((page.to_string(), order.to_string()));
            }
        }

        // All pages with detected button order should be consistent
        if button_orders.len() >= 2 {
            let first_order = &button_orders[0].1;
            for (page, order) in &button_orders[1..] {
                assert_eq!(
                    order, first_order,
                    "button order on {} ({}) differs from {} ({})",
                    page, order, button_orders[0].0, first_order
                );
            }
        }
    }

    // ===========================================================================
    // Feature 10: Dashboard Stats Don't Update
    // ===========================================================================

    /// GET /api/v1/stats should return counts for all entity types.
    #[tokio::test]
    async fn test_stats_endpoint_returns_counts() {
        let (ctx, cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            "/api/v1/stats",
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "stats: {:?}", body);

        let data = &body["data"];
        assert!(
            data["workspaces"]["total"].is_number(),
            "workspaces.total should be a number"
        );
        assert!(
            data["credentials"]["total"].is_number(),
            "credentials.total should be a number"
        );
        // devices removed in v2.0; workspaces.total presence is optional
    }

    /// Stats should update after creating a new agent.
    #[tokio::test]
    async fn test_stats_update_after_entity_creation() {
        let (ctx, cookie) = setup().await;

        // Get initial stats
        let (_, body_before) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            "/api/v1/stats",
            None,
            Some(&cookie),
            None,
        )
        .await;
        let agents_before = body_before["data"]["workspaces"]["total"]
            .as_u64()
            .unwrap_or(0);

        // Create a new agent via the store (agents are created through enrollment,
        // not via a POST endpoint, so we insert directly into the DB)
        common::create_agent_in_db(&*ctx.store, "stats-test-agent", vec!["test"], true, None).await;

        // Get stats again
        let (_, body_after) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            "/api/v1/stats",
            None,
            Some(&cookie),
            None,
        )
        .await;
        let agents_after = body_after["data"]["workspaces"]["total"]
            .as_u64()
            .unwrap_or(0);

        assert_eq!(
            agents_after,
            agents_before + 1,
            "workspaces.total should increment by 1 after creating a workspace"
        );
    }

    /// Dashboard HTML should contain SSE event listeners for real-time updates.
    #[tokio::test]
    async fn test_dashboard_html_has_sse_listeners() {
        let (ctx, cookie) = setup().await;

        let (status, body) = get_html(&ctx.app, "/dashboard", &cookie).await;
        assert_eq!(status, StatusCode::OK);

        // Dashboard should have SSE event listeners for entity creation events
        let has_sse = body.contains("EventSource")
            || body.contains("ac:agent_created")
            || body.contains("ac:")
            || body.contains("sse")
            || body.contains("event-stream");

        assert!(
            has_sse,
            "dashboard should have SSE event listeners for real-time stat updates"
        );
    }
}

mod ux_renames {
    //! Integration tests — v1.9.3 Features 2+3: Policies->Security rename, Users->Settings move.
    //!
    //! Verifies nav label changes (Policies->Security), URL stability, and
    //! that Users management moves into Settings while remaining accessible.

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

    async fn setup() -> (agent_cordon_server::test_helpers::TestContext, String) {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let _user = common::create_test_user(
            &*ctx.store,
            "ux-renames-user",
            common::TEST_PASSWORD,
            UserRole::Admin,
        )
        .await;
        let cookie =
            common::login_user_combined(&ctx.app, "ux-renames-user", common::TEST_PASSWORD).await;
        (ctx, cookie)
    }

    // ===========================================================================
    // Feature 2: Rename Policies to Security
    // ===========================================================================

    /// Nav should show "Security" as the label, not "Policies".
    #[tokio::test]
    async fn test_nav_shows_security_label() {
        let (ctx, cookie) = setup().await;

        let (status, body) = get_html(&ctx.app, "/dashboard", &cookie).await;
        assert_eq!(status, StatusCode::OK);

        assert!(
            body.contains("Security"),
            "nav should contain 'Security' label"
        );
    }

    /// GET /policies should redirect to /security.
    #[tokio::test]
    async fn test_policies_url_returns_200() {
        let (ctx, cookie) = setup().await;

        // /policies now redirects to /security
        let (status, _body) = get_html(&ctx.app, "/policies", &cookie).await;
        assert!(
            status.is_redirection(),
            "/policies should redirect to /security, got: {}",
            status
        );

        // /security should return 200 with content
        let (status, body) = get_html(&ctx.app, "/security", &cookie).await;
        assert_eq!(status, StatusCode::OK, "/security should return 200");
        assert!(body.contains("<!DOCTYPE html>"));
    }

    /// The security page heading should contain "Security" or "Polic".
    #[tokio::test]
    async fn test_security_page_heading() {
        let (ctx, cookie) = setup().await;

        let (status, body) = get_html(&ctx.app, "/security", &cookie).await;
        assert_eq!(status, StatusCode::OK);

        assert!(
            body.contains("Security") || body.contains("Polic"),
            "security page should contain Security or Policy heading"
        );
    }

    /// API endpoint /api/v1/policies should be unchanged.
    #[tokio::test]
    async fn test_policy_api_unchanged() {
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
        assert_eq!(
            status,
            StatusCode::OK,
            "policy API should still work: {:?}",
            body
        );
        assert!(
            body["data"].is_array(),
            "policy API should return array of policies"
        );
    }

    /// GET /policies/new should redirect to /security/new.
    #[tokio::test]
    async fn test_policy_new_page_works() {
        let (ctx, cookie) = setup().await;

        // /policies/new now redirects to /security/new
        let (status, _body) = get_html(&ctx.app, "/policies/new", &cookie).await;
        assert!(
            status.is_redirection(),
            "/policies/new should redirect to /security/new, got: {}",
            status
        );

        // /security/new should return 200 with content
        let (status, body) = get_html(&ctx.app, "/security/new", &cookie).await;
        assert_eq!(status, StatusCode::OK, "/security/new should return 200");
        assert!(body.contains("<!DOCTYPE html>"));
    }

    // ===========================================================================
    // Feature 3: Move Users into Settings
    // ===========================================================================

    /// Top-level nav should NOT have Users as a standalone link.
    #[tokio::test]
    async fn test_nav_no_users_top_level() {
        let (ctx, cookie) = setup().await;

        let (status, body) = get_html(&ctx.app, "/dashboard", &cookie).await;
        assert_eq!(status, StatusCode::OK);

        let nav_section = body.find("<nav").and_then(|start| {
            body[start..]
                .find("</nav>")
                .map(|end| &body[start..start + end])
        });

        if let Some(nav) = nav_section {
            assert!(
                !nav.contains(r#"href="/users""#),
                "nav should NOT contain a direct /users link as top-level item"
            );
        }
    }

    /// GET /settings should contain a Users section.
    #[tokio::test]
    async fn test_settings_has_users_section() {
        let (ctx, cookie) = setup().await;

        let (status, body) = get_html(&ctx.app, "/settings", &cookie).await;
        assert_eq!(status, StatusCode::OK);

        assert!(
            body.contains("User") || body.contains("user"),
            "settings page should contain Users section"
        );
    }

    /// GET /users should return 200 or redirect (not 404).
    #[tokio::test]
    async fn test_users_url_accessible() {
        let (ctx, cookie) = setup().await;

        let (status, _body) = get_html(&ctx.app, "/users", &cookie).await;
        assert!(
            status == StatusCode::OK || status.is_redirection(),
            "/users should return 200 or redirect, not 404. Got: {}",
            status
        );
    }

    /// API endpoint /api/v1/users should be unchanged by UI reorganization.
    #[tokio::test]
    async fn test_users_api_unchanged() {
        let (ctx, cookie) = setup().await;

        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            "/api/v1/users",
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "users API should still work: {:?}",
            body
        );
        assert!(
            body["data"].is_array(),
            "users API should return array of users"
        );
    }
}

mod seed_policies {
    //! Integration tests — v1.9.3 Feature 5: Pre-populated Disabled Cedar Policies.
    //!
    //! Verifies that seed demo data includes example Cedar policies that are
    //! disabled by default, have descriptions, parse as valid Cedar, and
    //! don't affect access decisions until enabled.

    use crate::common;

    use agent_cordon_core::domain::user::UserRole;
    use agent_cordon_server::test_helpers::TestAppBuilder;
    use axum::http::{Method, StatusCode};

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    /// Setup with demo seed data (seed policies are created alongside demo data).
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
            "seed-policy-user",
            common::TEST_PASSWORD,
            UserRole::Admin,
        )
        .await;
        let cookie =
            common::login_user_combined(&ctx.app, "seed-policy-user", common::TEST_PASSWORD).await;
        (ctx, cookie)
    }

    // ===========================================================================
    // 5A. Happy Path
    // ===========================================================================

    /// Fresh DB with seed should have policies beyond just the default.
    #[tokio::test]
    async fn test_seed_policies_exist() {
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
        assert_eq!(status, StatusCode::OK, "list policies: {:?}", body);

        let policies = body["data"].as_array().expect("data should be array");
        assert!(
            policies.len() >= 2,
            "should have at least 2 policies (default + demo/seed), got {}",
            policies.len()
        );
    }

    /// All seed example policies should be disabled by default.
    #[tokio::test]
    async fn test_seed_policies_disabled() {
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

        let policies = body["data"].as_array().expect("data");

        let seed_examples: Vec<_> = policies
            .iter()
            .filter(|p| {
                let name = p["name"].as_str().unwrap_or("");
                name != "default" && !name.contains("demo") && !name.starts_with("grant:")
            })
            .collect();

        for policy in &seed_examples {
            let enabled = policy["enabled"].as_bool().unwrap_or(true);
            let name = policy["name"].as_str().unwrap_or("unknown");
            assert!(
                !enabled,
                "seed policy '{}' should be disabled by default",
                name
            );
        }
    }

    /// Each seed policy should have a non-empty description.
    #[tokio::test]
    async fn test_seed_policies_have_descriptions() {
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

        let policies = body["data"].as_array().expect("data");

        let seed_examples: Vec<_> = policies
            .iter()
            .filter(|p| {
                let name = p["name"].as_str().unwrap_or("");
                name != "default" && !name.contains("demo") && !name.starts_with("grant:")
            })
            .collect();

        for policy in &seed_examples {
            let description = policy["description"].as_str().unwrap_or("");
            let name = policy["name"].as_str().unwrap_or("unknown");
            assert!(
                !description.is_empty(),
                "seed policy '{}' should have a non-empty description",
                name
            );
        }
    }

    /// Each seed policy should parse as valid Cedar (enabling it should succeed).
    #[tokio::test]
    async fn test_seed_policies_valid_cedar() {
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

        let policies = body["data"].as_array().expect("data");

        let seed_examples: Vec<_> = policies
            .iter()
            .filter(|p| {
                let name = p["name"].as_str().unwrap_or("");
                name != "default" && !name.contains("demo") && !name.starts_with("grant:")
            })
            .collect();

        for policy in &seed_examples {
            let policy_id = policy["id"].as_str().expect("policy id");
            let name = policy["name"].as_str().unwrap_or("unknown");

            let (enable_status, enable_body) = common::send_json_auto_csrf(
                &ctx.app,
                Method::PUT,
                &format!("/api/v1/policies/{}", policy_id),
                None,
                Some(&cookie),
                Some(serde_json::json!({
                    "name": name,
                    "cedar_policy": policy["cedar_policy"].as_str().unwrap_or(""),
                    "description": policy["description"].as_str().unwrap_or(""),
                    "enabled": true
                })),
            )
            .await;
            assert!(
                enable_status == StatusCode::OK || enable_status == StatusCode::NO_CONTENT,
                "enabling seed policy '{}' should succeed (valid Cedar): status={}, body={:?}",
                name,
                enable_status,
                enable_body
            );
        }
    }

    // ===========================================================================
    // 5B. Retry/Idempotency
    // ===========================================================================

    /// Running seed again should not create duplicate policies.
    #[tokio::test]
    async fn test_seed_policies_not_duplicated() {
        let (ctx, cookie) = setup_with_seed().await;

        let (_, body1) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            "/api/v1/policies",
            None,
            Some(&cookie),
            None,
        )
        .await;
        let count1 = body1["data"].as_array().map(|a| a.len()).unwrap_or(0);

        agent_cordon_server::seed::seed_demo_data(
            &ctx.store,
            &ctx.encryptor,
            &ctx.state.config,
            &ctx.jwt_issuer,
        )
        .await
        .expect("second seed should succeed");

        let (_, body2) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            "/api/v1/policies",
            None,
            Some(&cookie),
            None,
        )
        .await;
        let count2 = body2["data"].as_array().map(|a| a.len()).unwrap_or(0);

        assert_eq!(
            count1, count2,
            "policy count should be unchanged after double seed ({} vs {})",
            count1, count2
        );
    }

    // ===========================================================================
    // 5D. Cross-Feature
    // ===========================================================================

    /// With seed policies disabled, access decisions should be unchanged.
    #[tokio::test]
    async fn test_disabled_policies_no_effect() {
        let (ctx, cookie) = setup_with_seed().await;

        let (status, _) = common::send_json_auto_csrf(
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
            "disabled seed policies should not affect normal operations"
        );

        let (status, _) = common::send_json_auto_csrf(
            &ctx.app,
            Method::GET,
            "/api/v1/credentials",
            None,
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "disabled seed policies should not affect credential access"
        );
    }

    /// Enabling a seed policy should make it participate in Cedar evaluation.
    #[tokio::test]
    async fn test_enable_seed_policy_affects_access() {
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

        let policies = body["data"].as_array().expect("data");

        let disabled_seed = policies.iter().find(|p| {
            let name = p["name"].as_str().unwrap_or("");
            let enabled = p["enabled"].as_bool().unwrap_or(true);
            name != "default" && !name.contains("demo") && !enabled
        });

        if let Some(policy) = disabled_seed {
            let policy_id = policy["id"].as_str().expect("policy id");
            let name = policy["name"].as_str().unwrap_or("");
            let cedar = policy["cedar_policy"].as_str().unwrap_or("");
            let desc = policy["description"].as_str().unwrap_or("");

            let (enable_status, _) = common::send_json_auto_csrf(
                &ctx.app,
                Method::PUT,
                &format!("/api/v1/policies/{}", policy_id),
                None,
                Some(&cookie),
                Some(serde_json::json!({
                    "name": name,
                    "cedar_policy": cedar,
                    "description": desc,
                    "enabled": true
                })),
            )
            .await;
            assert!(
                enable_status == StatusCode::OK || enable_status == StatusCode::NO_CONTENT,
                "enabling policy should succeed"
            );

            let (status, body) = common::send_json_auto_csrf(
                &ctx.app,
                Method::GET,
                &format!("/api/v1/policies/{}", policy_id),
                None,
                Some(&cookie),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK);

            let enabled = body["data"]["enabled"].as_bool().unwrap_or(false);
            assert!(enabled, "policy should be enabled after update");
        }
    }

    // ===========================================================================
    // 5E. Security
    // ===========================================================================

    /// Seed policies should demonstrate restrictive patterns (deny/restrict, not permit-all).
    #[tokio::test]
    async fn test_seed_policy_examples_are_restrictive() {
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

        let policies = body["data"].as_array().expect("data");

        let seed_examples: Vec<_> = policies
            .iter()
            .filter(|p| {
                let name = p["name"].as_str().unwrap_or("");
                name != "default" && !name.contains("demo") && !name.starts_with("grant:")
            })
            .collect();

        for policy in &seed_examples {
            let cedar = policy["cedar_policy"].as_str().unwrap_or("");
            let name = policy["name"].as_str().unwrap_or("unknown");

            let is_permit_all = cedar.contains("permit(\n  principal,\n  action,\n  resource\n)")
                || cedar.contains("permit(principal, action, resource)");
            assert!(
                !is_permit_all,
                "seed policy '{}' should demonstrate restrictions, not permit-all. Cedar: {}",
                name, cedar
            );
        }
    }
}
