//! Who may do what: authorization rules that hold across routes.
//!
//! Each test sets up two principals and checks that the one without the
//! right is refused while the one with it is not.

use axum::http::{Method, StatusCode};
use serde_json::json;

use crate::common::*;
use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;

const NEW_PASSWORD: &str = "a-brand-new-password-42";

/// Only root may change root's password. An ordinary admin holds
/// manage-users, which is not enough.
#[tokio::test]
async fn non_root_admin_cannot_change_root_password() {
    let ctx = TestAppBuilder::new().build().await;
    let root = create_root_user(&*ctx.store, "the-root", TEST_PASSWORD).await;
    create_user_in_db(
        &*ctx.store,
        "plain-admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let admin_cookie = login_user_combined(&ctx.app, "plain-admin", TEST_PASSWORD).await;

    let (status, _) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/users/{}/change-password", root.id.0),
        None,
        Some(&admin_cookie),
        Some(json!({ "new_password": NEW_PASSWORD })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Root's original password still works.
    let (status, _) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        None,
        None,
        Some(json!({ "username": "the-root", "password": TEST_PASSWORD })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "root login with the old password");
}

/// Submit the browser consent form as the given session, registering
/// `pk_hash` as a new workspace. Returns the response status and headers.
async fn post_consent_new_workspace(
    app: &axum::Router,
    session_cookie: &str,
    session_hash_key: &[u8; 32],
    pk_hash: &str,
) -> (StatusCode, Vec<(String, String)>) {
    use axum::body::Body;
    use axum::http::{header, Request};
    use tower::ServiceExt;

    let consent_csrf = compute_consent_csrf(session_cookie, session_hash_key);
    let form = format!(
        "client_id=&redirect_uri={}&scope=credentials:discover&state=s1\
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256\
         &decision=approve&csrf_token={}&public_key_hash={}&workspace_name=hijack&is_new_workspace=true",
        urlencoding::encode("http://localhost:9999/callback"),
        urlencoding::encode(&consent_csrf),
        pk_hash,
    );
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/oauth/authorize")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, session_cookie)
        .body(Body::from(form))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    (status, headers)
}

/// The browser consent flow creates workspaces and OAuth clients, the same
/// privilege the device-flow approve route gates on. A signed-in viewer
/// presenting another workspace's key hash must be refused, and that
/// workspace must keep working.
#[tokio::test]
async fn viewer_cannot_reregister_another_workspace_via_consent() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let victim = ctx.admin_agent.as_ref().unwrap().clone();
    let victim_pk_hash = victim.pk_hash.clone().expect("victim has a key hash");
    let victim_token = ctx_admin_jwt(&ctx).await;

    create_user_in_db(
        &*ctx.store,
        "consent-viewer",
        TEST_PASSWORD,
        UserRole::Viewer,
        false,
        true,
    )
    .await;
    let (viewer_session, _) = login_user(&ctx.app, "consent-viewer", TEST_PASSWORD).await;

    let (status, headers) = post_consent_new_workspace(
        &ctx.app,
        &viewer_session,
        &ctx.state.crypto.session_hash_key,
        &victim_pk_hash,
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "headers: {headers:?}");

    let (status, _) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces/mcp-servers",
        Some(&victim_token),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "victim's token still works");
}

/// Revocation is final. Re-registering the same key hash through the
/// consent form, even by an admin, must not flip the workspace back to
/// active or mint it a new client.
#[tokio::test]
async fn reregistering_a_revoked_workspace_is_refused() {
    use agent_cordon_core::domain::workspace::{WorkspaceId, WorkspaceStatus};

    let ctx = TestAppBuilder::new().with_admin().build().await;
    let victim = ctx.admin_agent.as_ref().unwrap().clone();
    let pk_hash = victim.pk_hash.clone().expect("victim has a key hash");

    create_root_user(&*ctx.store, "rereg-root", TEST_PASSWORD).await;
    let (root_session, _) = login_user(&ctx.app, "rereg-root", TEST_PASSWORD).await;
    let root_cookie = login_user_combined(&ctx.app, "rereg-root", TEST_PASSWORD).await;

    let (status, _) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/workspaces/{}/revoke", victim.id.0),
        None,
        Some(&root_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke");

    let (status, headers) = post_consent_new_workspace(
        &ctx.app,
        &root_session,
        &ctx.state.crypto.session_hash_key,
        &pk_hash,
    )
    .await;
    assert!(
        status.is_client_error(),
        "re-registration of a revoked key hash must be refused, got {status}: {headers:?}"
    );

    let after = ctx
        .store
        .get_workspace(&WorkspaceId(victim.id.0))
        .await
        .unwrap()
        .expect("workspace row still exists");
    assert_eq!(after.status, WorkspaceStatus::Revoked, "stays revoked");
    assert!(!after.is_active(), "stays inactive");
}

/// Create an active workspace owned by `owner`, returning its key hash.
async fn owned_workspace(
    ctx: &agent_cordon_server::test_helpers::TestContext,
    owner: &agent_cordon_core::domain::user::User,
    name: &str,
) -> String {
    use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
    let pk_hash = format!("{:0>64}", format!("{:x}", uuid::Uuid::new_v4().as_u128()));
    let now = chrono::Utc::now();
    ctx.store
        .create_workspace(&Workspace {
            id: WorkspaceId(uuid::Uuid::new_v4()),
            name: name.to_string(),
            status: WorkspaceStatus::Active,
            pk_hash: Some(pk_hash.clone()),
            encryption_public_key: None,
            tags: vec![],
            owner_id: Some(owner.id.clone()),
            parent_id: None,
            tool_name: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("create workspace");
    pk_hash
}

/// An operator holds manage-workspaces but does not own this workspace.
/// Re-registering its key hash would hand them its grants; refused. The
/// owner can re-register their own.
#[tokio::test]
async fn operator_cannot_reregister_a_workspace_they_do_not_own() {
    let ctx = TestAppBuilder::new().build().await;
    let owner = create_user_in_db(
        &*ctx.store,
        "ws-owner",
        TEST_PASSWORD,
        UserRole::Operator,
        false,
        true,
    )
    .await;
    create_user_in_db(
        &*ctx.store,
        "other-operator",
        TEST_PASSWORD,
        UserRole::Operator,
        false,
        true,
    )
    .await;
    let pk_hash = owned_workspace(&ctx, &owner, "owned-ws").await;

    let (other_session, _) = login_user(&ctx.app, "other-operator", TEST_PASSWORD).await;
    let (status, headers) = post_consent_new_workspace(
        &ctx.app,
        &other_session,
        &ctx.state.crypto.session_hash_key,
        &pk_hash,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "non-owner: {headers:?}");

    let (owner_session, _) = login_user(&ctx.app, "ws-owner", TEST_PASSWORD).await;
    let (status, headers) = post_consent_new_workspace(
        &ctx.app,
        &owner_session,
        &ctx.state.crypto.session_hash_key,
        &pk_hash,
    )
    .await;
    assert_eq!(status, StatusCode::FOUND, "owner: {headers:?}");
}

async fn get_page(app: &axum::Router, uri: &str, cookie: &str) -> StatusCode {
    use axum::body::Body;
    use axum::http::{header, Request};
    use tower::ServiceExt;
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap();
    app.clone().oneshot(req).await.unwrap().status()
}

/// The admin UI shows a credential, policy, or workspace only through the
/// JSON detail endpoints (the server-rendered panel fragments are gone), so
/// a viewer who cannot GET a resource through the API sees nothing of it.
#[tokio::test]
async fn viewer_cannot_read_resource_detail_endpoints_they_cannot_read() {
    use agent_cordon_core::domain::policy::StoredPolicy;

    let ctx = TestAppBuilder::new().with_admin().build().await;
    create_root_user(&*ctx.store, "panel-root", TEST_PASSWORD).await;
    create_user_in_db(
        &*ctx.store,
        "panel-viewer",
        TEST_PASSWORD,
        UserRole::Viewer,
        false,
        true,
    )
    .await;
    let root_cookie = login_user_combined(&ctx.app, "panel-root", TEST_PASSWORD).await;
    let viewer_cookie = login_user_combined(&ctx.app, "panel-viewer", TEST_PASSWORD).await;

    // Root's credential.
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&root_cookie),
        Some(json!({ "name": "root-secret", "service": "svc", "secret_value": "s" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create: {body}");
    let cred_id = body["data"]["id"].as_str().unwrap().to_string();

    let policy_id = ctx
        .store
        .list_policies()
        .await
        .unwrap()
        .first()
        .map(|p: &StoredPolicy| p.id.0.to_string())
        .expect("the seeded default policy");
    let workspace_id = ctx.admin_agent.as_ref().unwrap().id.0.to_string();

    for uri in [
        format!("/api/v1/credentials/{cred_id}"),
        format!("/api/v1/policies/{policy_id}"),
        format!("/api/v1/workspaces/{workspace_id}"),
    ] {
        assert_eq!(
            get_page(&ctx.app, &uri, &root_cookie).await,
            StatusCode::OK,
            "root reads {uri}"
        );
        assert_eq!(
            get_page(&ctx.app, &uri, &viewer_cookie).await,
            StatusCode::FORBIDDEN,
            "viewer is refused {uri}"
        );
    }
}

/// Operators manage the workspaces they own. Holding manage-workspaces
/// does not extend to other users' workspaces; admins reach everything.
#[tokio::test]
async fn operator_manages_only_workspaces_they_own() {
    let ctx = TestAppBuilder::new().build().await;
    let owner = create_user_in_db(
        &*ctx.store,
        "ws-owner-op",
        TEST_PASSWORD,
        UserRole::Operator,
        false,
        true,
    )
    .await;
    create_user_in_db(
        &*ctx.store,
        "other-op",
        TEST_PASSWORD,
        UserRole::Operator,
        false,
        true,
    )
    .await;
    create_user_in_db(
        &*ctx.store,
        "an-admin",
        TEST_PASSWORD,
        UserRole::Admin,
        false,
        true,
    )
    .await;
    let pk_hash = owned_workspace(&ctx, &owner, "owned-by-op").await;
    let ws = ctx
        .store
        .get_workspace_by_pk_hash(&pk_hash)
        .await
        .unwrap()
        .unwrap();
    let uri = format!("/api/v1/workspaces/{}", ws.id.0);

    let other = login_user_combined(&ctx.app, "other-op", TEST_PASSWORD).await;
    let (status, _) = send_json(&ctx.app, Method::GET, &uri, None, Some(&other), None, None).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "non-owner operator cannot read"
    );
    let (status, _) = send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &uri,
        None,
        Some(&other),
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "non-owner operator cannot update"
    );

    let owner_cookie = login_user_combined(&ctx.app, "ws-owner-op", TEST_PASSWORD).await;
    let (status, _) = send_json(
        &ctx.app,
        Method::GET,
        &uri,
        None,
        Some(&owner_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner reads");
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &uri,
        None,
        Some(&owner_cookie),
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner updates: {body}");

    let admin = login_user_combined(&ctx.app, "an-admin", TEST_PASSWORD).await;
    let (status, _) = send_json(&ctx.app, Method::GET, &uri, None, Some(&admin), None, None).await;
    assert_eq!(status, StatusCode::OK, "admin reads any workspace");
}
