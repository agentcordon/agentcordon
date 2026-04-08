//! Consolidated integration tests for v1.9.4 features.
//!
//! Merged from: v194_advanced_mode.rs, v194_llm_exposed.rs, v194_settings_audit.rs

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
        let agent_jwt = issue_agent_jwt(&ctx.state, agent).await;

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
        let agent_jwt = issue_agent_jwt(&ctx.state, agent).await;
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
        let agent_jwt = issue_agent_jwt(&ctx.state, agent).await;
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
        let agent_jwt = issue_agent_jwt(&ctx.state, agent).await;
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

