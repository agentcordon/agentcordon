//! Issue #10 — view and delete OAuth consent grants per workspace.
//!
//! Vertical TDD slices through the admin REST API + Cedar authz + storage cascade.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use agent_cordon_core::domain::user::{UserId, UserRole};
use agent_cordon_core::domain::workspace::Workspace;
use agent_cordon_core::oauth2::types::{
    OAuthAccessToken, OAuthClient, OAuthConsent, OAuthRefreshToken, OAuthScope,
};
use agent_cordon_core::storage::traits::AuditFilter;
use agent_cordon_core::storage::Store;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;

/// Seed an OAuth client tied to the workspace's `pk_hash` and return its
/// `client_id`. One client per workspace, matching production registration.
async fn seed_oauth_client(
    store: &dyn Store,
    workspace: &Workspace,
    created_by: &UserId,
) -> String {
    let pk_hash = workspace
        .pk_hash
        .clone()
        .unwrap_or_else(|| format!("test-pk-hash-{}", workspace.id.0));
    let client_id = format!("ac_cli_test_{}", workspace.id.0);
    let client = OAuthClient {
        id: uuid::Uuid::new_v4(),
        client_id: client_id.clone(),
        client_secret_hash: None,
        workspace_name: workspace.name.clone(),
        public_key_hash: pk_hash,
        redirect_uris: vec!["http://localhost:9999/callback".to_string()],
        allowed_scopes: vec![
            OAuthScope::CredentialsDiscover,
            OAuthScope::CredentialsVend,
            OAuthScope::McpInvoke,
        ],
        created_by_user: created_by.clone(),
        created_at: chrono::Utc::now(),
        revoked_at: None,
    };
    store
        .create_oauth_client(&client)
        .await
        .expect("seed oauth client");
    client_id
}

/// Slice 1 — RED: GET on a workspace with no consents returns 200 and an empty list.
#[tokio::test]
async fn get_consents_empty_workspace_returns_200_empty_list() {
    let ctx = TestAppBuilder::new()
        .with_agent("ws-no-consents", &[])
        .build()
        .await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let workspace = ctx.agents.get("ws-no-consents").expect("workspace");

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/workspaces/{}/consents", workspace.id.0),
        None,
        Some(&full_cookie),
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let data = body["data"].as_array().expect("data should be an array");
    assert!(data.is_empty(), "expected empty list, got: {data:?}");
}

/// Slice 2 — RED: GET returns the consent rows that exist for the workspace's client.
#[tokio::test]
async fn get_consents_returns_existing_grants() {
    let ctx = TestAppBuilder::new()
        .with_agent("ws-with-consent", &[])
        .build()
        .await;
    let admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let granting_user =
        create_test_user(&*ctx.store, "alice", TEST_PASSWORD, UserRole::Viewer).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let workspace = ctx.agents.get("ws-with-consent").expect("workspace");
    let client_id = seed_oauth_client(&*ctx.store, workspace, &admin.id).await;

    let consent = OAuthConsent {
        client_id: client_id.clone(),
        user_id: granting_user.id.clone(),
        scopes: vec![OAuthScope::CredentialsDiscover, OAuthScope::McpInvoke],
        granted_at: chrono::Utc::now(),
    };
    ctx.store
        .upsert_oauth_consent(&consent)
        .await
        .expect("seed consent");

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/workspaces/{}/consents", workspace.id.0),
        None,
        Some(&full_cookie),
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let data = body["data"].as_array().expect("data should be an array");
    assert_eq!(data.len(), 1, "expected one consent grant, got: {data:?}");
    let row = &data[0];
    assert_eq!(
        row["user_id"].as_str(),
        Some(granting_user.id.0.to_string().as_str())
    );
    let scopes = row["scopes"].as_array().expect("scopes array");
    assert_eq!(scopes.len(), 2);
}

/// Slice 3 — RED: the consent row carries the granting user's username
/// (server-enriched so the UI doesn't have to make per-row user lookups).
#[tokio::test]
async fn get_consents_enriches_username() {
    let ctx = TestAppBuilder::new()
        .with_agent("ws-username", &[])
        .build()
        .await;
    let admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let granter = create_test_user(
        &*ctx.store,
        "bob-the-granter",
        TEST_PASSWORD,
        UserRole::Viewer,
    )
    .await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let workspace = ctx.agents.get("ws-username").expect("workspace");
    let client_id = seed_oauth_client(&*ctx.store, workspace, &admin.id).await;
    ctx.store
        .upsert_oauth_consent(&OAuthConsent {
            client_id,
            user_id: granter.id.clone(),
            scopes: vec![OAuthScope::McpInvoke],
            granted_at: chrono::Utc::now(),
        })
        .await
        .expect("seed consent");

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/workspaces/{}/consents", workspace.id.0),
        None,
        Some(&full_cookie),
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    let row = &body["data"][0];
    // create_test_user sets display_name = "Test {username}"; enrichment
    // prefers display_name over the raw username, same as workspace owner
    // enrichment elsewhere in admin_api.
    assert_eq!(row["username"].as_str(), Some("Test bob-the-granter"));
}

/// Slice 5 — RED: admin DELETE removes the consent row and returns 204.
#[tokio::test]
async fn delete_consent_as_admin_removes_row_returns_204() {
    let ctx = TestAppBuilder::new()
        .with_agent("ws-delete", &[])
        .build()
        .await;
    let admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let granter = create_test_user(&*ctx.store, "carol", TEST_PASSWORD, UserRole::Viewer).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let workspace = ctx.agents.get("ws-delete").expect("workspace");
    let client_id = seed_oauth_client(&*ctx.store, workspace, &admin.id).await;
    ctx.store
        .upsert_oauth_consent(&OAuthConsent {
            client_id: client_id.clone(),
            user_id: granter.id.clone(),
            scopes: vec![OAuthScope::McpInvoke],
            granted_at: chrono::Utc::now(),
        })
        .await
        .expect("seed consent");
    let (status, _) = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!(
            "/api/v1/workspaces/{}/consents/{}",
            workspace.id.0, granter.id.0
        ),
        None,
        Some(&full_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let row = ctx
        .store
        .get_oauth_consent(&client_id, &granter.id)
        .await
        .expect("query consent");
    assert!(row.is_none(), "consent row should be deleted");
}

/// Slice 6 — RED: DELETE atomically revokes access AND refresh tokens for the
/// (client_id, user_id) pair. Tokens belonging to other users of the same
/// client are not touched.
#[tokio::test]
async fn delete_consent_revokes_access_and_refresh_tokens() {
    let ctx = TestAppBuilder::new()
        .with_agent("ws-cascade", &[])
        .build()
        .await;
    let admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let granter = create_test_user(&*ctx.store, "dave", TEST_PASSWORD, UserRole::Viewer).await;
    let bystander = create_test_user(&*ctx.store, "evelyn", TEST_PASSWORD, UserRole::Viewer).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let workspace = ctx.agents.get("ws-cascade").expect("workspace");
    let client_id = seed_oauth_client(&*ctx.store, workspace, &admin.id).await;

    ctx.store
        .upsert_oauth_consent(&OAuthConsent {
            client_id: client_id.clone(),
            user_id: granter.id.clone(),
            scopes: vec![OAuthScope::McpInvoke],
            granted_at: chrono::Utc::now(),
        })
        .await
        .expect("seed consent");

    let now = chrono::Utc::now();
    let exp = now + chrono::Duration::hours(1);
    let granter_at = OAuthAccessToken {
        token_hash: format!("hash-at-{}", granter.id.0),
        client_id: client_id.clone(),
        user_id: granter.id.clone(),
        scopes: vec![OAuthScope::McpInvoke],
        created_at: now,
        expires_at: exp,
        revoked_at: None,
    };
    let bystander_at = OAuthAccessToken {
        token_hash: format!("hash-at-{}", bystander.id.0),
        client_id: client_id.clone(),
        user_id: bystander.id.clone(),
        scopes: vec![OAuthScope::McpInvoke],
        created_at: now,
        expires_at: exp,
        revoked_at: None,
    };
    ctx.store
        .create_oauth_access_token(&granter_at)
        .await
        .unwrap();
    ctx.store
        .create_oauth_access_token(&bystander_at)
        .await
        .unwrap();

    let granter_rt = OAuthRefreshToken {
        token_hash: format!("hash-rt-{}", granter.id.0),
        client_id: client_id.clone(),
        user_id: granter.id.clone(),
        scopes: vec![OAuthScope::McpInvoke],
        access_token_hash: granter_at.token_hash.clone(),
        created_at: now,
        expires_at: exp,
        revoked_at: None,
    };
    ctx.store
        .create_oauth_refresh_token(&granter_rt)
        .await
        .unwrap();

    let (status, _) = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!(
            "/api/v1/workspaces/{}/consents/{}",
            workspace.id.0, granter.id.0
        ),
        None,
        Some(&full_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Granter tokens revoked.
    let at = ctx
        .store
        .get_oauth_access_token(&granter_at.token_hash)
        .await
        .unwrap()
        .expect("access token row");
    assert!(
        at.revoked_at.is_some(),
        "granter access token must be revoked"
    );

    let rt = ctx
        .store
        .get_oauth_refresh_token(&granter_rt.token_hash)
        .await
        .unwrap()
        .expect("refresh token row");
    assert!(
        rt.revoked_at.is_some(),
        "granter refresh token must be revoked"
    );

    // Bystander token untouched.
    let other = ctx
        .store
        .get_oauth_access_token(&bystander_at.token_hash)
        .await
        .unwrap()
        .expect("bystander access token row");
    assert!(
        other.revoked_at.is_none(),
        "bystander access token must NOT be revoked"
    );
}

/// Slice 7 — RED: DELETE emits a `ConsentRevoked` audit event carrying actor,
/// resource, and the token-revocation counts.
#[tokio::test]
async fn delete_consent_emits_consent_revoked_audit_event() {
    let ctx = TestAppBuilder::new()
        .with_agent("ws-audit", &[])
        .build()
        .await;
    let admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let granter = create_test_user(&*ctx.store, "frank", TEST_PASSWORD, UserRole::Viewer).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let workspace = ctx.agents.get("ws-audit").expect("workspace");
    let client_id = seed_oauth_client(&*ctx.store, workspace, &admin.id).await;
    ctx.store
        .upsert_oauth_consent(&OAuthConsent {
            client_id: client_id.clone(),
            user_id: granter.id.clone(),
            scopes: vec![OAuthScope::McpInvoke],
            granted_at: chrono::Utc::now(),
        })
        .await
        .expect("seed consent");

    let _ = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!(
            "/api/v1/workspaces/{}/consents/{}",
            workspace.id.0, granter.id.0
        ),
        None,
        Some(&full_cookie),
        None,
    )
    .await;

    let events = ctx
        .store
        .list_audit_events_filtered(&AuditFilter {
            limit: 100,
            event_type: Some("consent_revoked".to_string()),
            ..Default::default()
        })
        .await
        .expect("list audit events");
    assert_eq!(events.len(), 1, "expected one ConsentRevoked event");
    let ev = &events[0];
    assert_eq!(ev.resource_type, "oauth_consent");
    assert!(
        ev.resource_id.as_deref() == Some(granter.id.0.to_string().as_str()),
        "audit resource_id should be the revoked user_id, got {:?}",
        ev.resource_id
    );
}

/// Slice 9 — RED: a non-admin (viewer-role) user can DELETE *their own*
/// consent grant via the Cedar `manage_consents` self-permit rule.
#[tokio::test]
async fn delete_own_consent_as_viewer_succeeds() {
    let ctx = TestAppBuilder::new()
        .with_agent("ws-self", &[])
        .build()
        .await;
    let admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let viewer = create_test_user(&*ctx.store, "gina", TEST_PASSWORD, UserRole::Viewer).await;
    let (cookie, csrf) = login_user(&ctx.app, "gina", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let workspace = ctx.agents.get("ws-self").expect("workspace");
    let client_id = seed_oauth_client(&*ctx.store, workspace, &admin.id).await;
    ctx.store
        .upsert_oauth_consent(&OAuthConsent {
            client_id: client_id.clone(),
            user_id: viewer.id.clone(),
            scopes: vec![OAuthScope::McpInvoke],
            granted_at: chrono::Utc::now(),
        })
        .await
        .expect("seed consent");

    let (status, _) = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!(
            "/api/v1/workspaces/{}/consents/{}",
            workspace.id.0, viewer.id.0
        ),
        None,
        Some(&full_cookie),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "viewer should be able to delete own consent"
    );

    let row = ctx
        .store
        .get_oauth_consent(&client_id, &viewer.id)
        .await
        .expect("query consent");
    assert!(row.is_none(), "consent row should be deleted");
}

/// Slice 10 — RED: a non-admin viewer is forbidden from deleting *someone
/// else's* consent grant. Distinguishes self-permit from blanket permit.
#[tokio::test]
async fn delete_other_users_consent_as_viewer_is_forbidden() {
    let ctx = TestAppBuilder::new()
        .with_agent("ws-other", &[])
        .build()
        .await;
    let admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let _viewer = create_test_user(&*ctx.store, "harry", TEST_PASSWORD, UserRole::Viewer).await;
    let granter = create_test_user(&*ctx.store, "iris", TEST_PASSWORD, UserRole::Viewer).await;
    let (cookie, csrf) = login_user(&ctx.app, "harry", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let workspace = ctx.agents.get("ws-other").expect("workspace");
    let client_id = seed_oauth_client(&*ctx.store, workspace, &admin.id).await;
    ctx.store
        .upsert_oauth_consent(&OAuthConsent {
            client_id: client_id.clone(),
            user_id: granter.id.clone(),
            scopes: vec![OAuthScope::McpInvoke],
            granted_at: chrono::Utc::now(),
        })
        .await
        .expect("seed consent");

    let (status, _) = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!(
            "/api/v1/workspaces/{}/consents/{}",
            workspace.id.0, granter.id.0
        ),
        None,
        Some(&full_cookie),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer must not delete others' consent"
    );

    let row = ctx
        .store
        .get_oauth_consent(&client_id, &granter.id)
        .await
        .expect("query consent");
    assert!(row.is_some(), "consent row must still exist");
}

/// Slice 11 — UI: the workspace detail page renders a "Consents" tab that
/// wires up to `/api/v1/workspaces/{id}/consents`.
#[tokio::test]
async fn workspace_detail_page_renders_consents_tab() {
    let ctx = TestAppBuilder::new().with_agent("ws-ui", &[]).build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let workspace = ctx.agents.get("ws-ui").expect("workspace");

    let resp = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/workspaces/{}/detail-partial", workspace.id.0))
                .header(header::COOKIE, &full_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    assert!(
        body.contains(">Consents</button>"),
        "expected a Consents tab button in detail.html, body length {}",
        body.len()
    );
    assert!(
        body.contains("loadConsents()"),
        "expected loadConsents() wiring in detail.html",
    );
    assert!(
        body.contains("/consents'") || body.contains("/consents/'"),
        "expected the consents API path baked into the JS calls",
    );
}

/// Slice 8 — RED: DELETE on a `(workspace, user_id)` with no consent returns 404.
#[tokio::test]
async fn delete_nonexistent_consent_returns_404() {
    let ctx = TestAppBuilder::new()
        .with_agent("ws-404", &[])
        .build()
        .await;
    let admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_user(&ctx.app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    let workspace = ctx.agents.get("ws-404").expect("workspace");
    let _client_id = seed_oauth_client(&*ctx.store, workspace, &admin.id).await;

    let phantom_user_id = uuid::Uuid::new_v4();
    let (status, _) = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!(
            "/api/v1/workspaces/{}/consents/{}",
            workspace.id.0, phantom_user_id
        ),
        None,
        Some(&full_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
