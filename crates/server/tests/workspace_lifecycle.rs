//! Workspace lifecycle: what a workspace's credentials can do after the
//! workspace is disabled or revoked.
//!
//! Every test drives the real router. The observable is whether a bearer
//! token that worked a moment ago still works after a lifecycle change.

use axum::http::{Method, StatusCode};

use crate::common::*;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

/// A route any registered workspace may call with its own token.
const WORKSPACE_ROUTE: &str = "/api/v1/workspaces/mcp-servers";

struct Lifecycle {
    ctx: TestContext,
    workspace_id: String,
    /// Bearer token minted for the workspace before any lifecycle change.
    token: String,
    /// Combined session + CSRF cookie for an admin user.
    admin_cookie: String,
}

async fn registered_workspace_with_token() -> Lifecycle {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let workspace_id = ctx
        .admin_agent
        .as_ref()
        .expect("with_admin creates a workspace")
        .id
        .0
        .to_string();
    let token = ctx_admin_jwt(&ctx).await;
    create_root_user(&*ctx.store, "lifecycle-root", TEST_PASSWORD).await;
    let admin_cookie = login_user_combined(&ctx.app, "lifecycle-root", TEST_PASSWORD).await;
    Lifecycle {
        ctx,
        workspace_id,
        token,
        admin_cookie,
    }
}

async fn call_as_workspace(lc: &Lifecycle) -> StatusCode {
    let (status, _) = send_json(
        &lc.ctx.app,
        Method::GET,
        WORKSPACE_ROUTE,
        Some(&lc.token),
        None,
        None,
        None,
    )
    .await;
    status
}

/// Revoking a workspace cuts off its existing access token.
#[tokio::test]
async fn revoked_workspace_token_is_rejected() {
    let lc = registered_workspace_with_token().await;
    assert_eq!(
        call_as_workspace(&lc).await,
        StatusCode::OK,
        "token works before revoke"
    );

    let (status, body) = send_json_auto_csrf(
        &lc.ctx.app,
        Method::POST,
        &format!("/api/v1/workspaces/{}/revoke", lc.workspace_id),
        None,
        Some(&lc.admin_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke: {body}");

    let after = call_as_workspace(&lc).await;
    assert!(
        after == StatusCode::UNAUTHORIZED || after == StatusCode::FORBIDDEN,
        "revoked workspace's token must be rejected, got {after}"
    );
}

/// Revocation is final, and revoking twice says so instead of pretending
/// to act on a dead identity.
#[tokio::test]
async fn revoking_twice_is_a_conflict() {
    let lc = registered_workspace_with_token().await;
    let uri = format!("/api/v1/workspaces/{}/revoke", lc.workspace_id);

    let (status, body) = send_json_auto_csrf(
        &lc.ctx.app,
        Method::POST,
        &uri,
        None,
        Some(&lc.admin_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "first revoke: {body}");
    assert_eq!(body["data"]["revoked"], true);

    let (status, body) = send_json_auto_csrf(
        &lc.ctx.app,
        Method::POST,
        &uri,
        None,
        Some(&lc.admin_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "second revoke: {body}");
}

/// Mint a refresh token for the workspace's OAuth client, the way the token
/// endpoint would have during registration. Returns the raw refresh token and
/// the client id it belongs to.
async fn mint_refresh_token(lc: &Lifecycle) -> (String, String) {
    use agent_cordon_core::oauth2::tokens::{generate_refresh_token, hash_token};
    use agent_cordon_core::oauth2::types::{OAuthRefreshToken, OAuthScope};

    let pk_hash = lc
        .ctx
        .admin_agent
        .as_ref()
        .and_then(|a| a.pk_hash.clone())
        .expect("workspace has a key hash");
    let client = lc
        .ctx
        .store
        .get_oauth_client_by_public_key_hash(&pk_hash)
        .await
        .expect("lookup")
        .expect("workspace has an OAuth client");
    let (raw, hash) = generate_refresh_token();
    let now = chrono::Utc::now();
    lc.ctx
        .store
        .create_oauth_refresh_token(&OAuthRefreshToken {
            family_id: hash.clone(),
            token_hash: hash,
            client_id: client.client_id.clone(),
            user_id: client.created_by_user.clone(),
            scopes: vec![OAuthScope::CredentialsDiscover],
            access_token_hash: hash_token(&lc.token),
            created_at: now,
            expires_at: now + chrono::Duration::days(30),
            revoked_at: None,
        })
        .await
        .expect("store refresh token");
    (raw, client.client_id)
}

async fn refresh(
    lc: &Lifecycle,
    refresh_token: &str,
    client_id: &str,
) -> (StatusCode, serde_json::Value) {
    use axum::body::Body;
    use axum::http::{header, Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let form =
        format!("grant_type=refresh_token&refresh_token={refresh_token}&client_id={client_id}");
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/oauth/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form))
        .unwrap();
    let resp = lc.ctx.app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn viewer_cookie(lc: &Lifecycle) -> String {
    use agent_cordon_core::domain::user::UserRole;
    create_user_in_db(
        &*lc.ctx.store,
        "lifecycle-viewer",
        TEST_PASSWORD,
        UserRole::Viewer,
        false,
        true,
    )
    .await;
    login_user_combined(&lc.ctx.app, "lifecycle-viewer", TEST_PASSWORD).await
}

/// A signed-in user without the manage-workspaces permission cannot revoke
/// someone else's workspace, and the workspace keeps working.
#[tokio::test]
async fn viewer_cannot_revoke_a_workspace() {
    let lc = registered_workspace_with_token().await;
    let viewer = viewer_cookie(&lc).await;

    let (status, _) = send_json_auto_csrf(
        &lc.ctx.app,
        Method::POST,
        &format!("/api/v1/workspaces/{}/revoke", lc.workspace_id),
        None,
        Some(&viewer),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        call_as_workspace(&lc).await,
        StatusCode::OK,
        "workspace must be untouched by the refused revoke"
    );
}

/// A viewer cannot enumerate every workspace's key hash.
#[tokio::test]
async fn viewer_cannot_list_workspaces() {
    let lc = registered_workspace_with_token().await;
    let viewer = viewer_cookie(&lc).await;

    let (status, _) = send_json(
        &lc.ctx.app,
        Method::GET,
        "/api/v1/workspaces",
        None,
        Some(&viewer),
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Refresh tokens rotate: using one yields a successor and retires the
/// original. Presenting a retired token again means it leaked, so the
/// whole family, successor included, is revoked (RFC 6819 §5.2.2.3).
#[tokio::test]
async fn replayed_refresh_token_revokes_its_family() {
    let lc = registered_workspace_with_token().await;
    let (rt1, client_id) = mint_refresh_token(&lc).await;

    let (status, body) = refresh(&lc, &rt1, &client_id).await;
    assert_eq!(status, StatusCode::OK, "first rotation: {body}");
    let rt2 = body["refresh_token"]
        .as_str()
        .expect("successor refresh token")
        .to_string();

    let (status, body) = refresh(&lc, &rt1, &client_id).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "replay of rt1: {body}");
    assert_eq!(body["error"], "invalid_grant");

    let (status, body) = refresh(&lc, &rt2, &client_id).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "successor must be dead after the replay: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");
}

/// Revoking a workspace also kills its refresh token, so it cannot mint a
/// fresh access token and come back.
#[tokio::test]
async fn revoked_workspace_cannot_refresh() {
    let lc = registered_workspace_with_token().await;
    let (refresh_token, client_id) = mint_refresh_token(&lc).await;

    let (status, body) = send_json_auto_csrf(
        &lc.ctx.app,
        Method::POST,
        &format!("/api/v1/workspaces/{}/revoke", lc.workspace_id),
        None,
        Some(&lc.admin_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke: {body}");

    let (status, body) = refresh(&lc, &refresh_token, &client_id).await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
        "refresh after revoke must fail, got {status}: {body}"
    );
    let err = body["error"].as_str().unwrap_or("");
    assert!(
        err == "invalid_grant" || err == "invalid_client",
        "expected an OAuth error, got {body}"
    );
}

/// A token is bound to its workspace by id. Resolving through the key hash
/// meant a rotated or re-registered key re-pointed every existing token, or
/// orphaned it: the workspace had not changed, only its key.
#[tokio::test]
async fn bearer_token_follows_its_workspace_by_id_not_by_key_hash() {
    let lc = registered_workspace_with_token().await;
    assert_eq!(call_as_workspace(&lc).await, StatusCode::OK, "control");

    let id = agent_cordon_core::domain::workspace::WorkspaceId(
        uuid::Uuid::parse_str(&lc.workspace_id).unwrap(),
    );
    let mut rotated = lc
        .ctx
        .store
        .get_workspace(&id)
        .await
        .expect("lookup")
        .expect("workspace exists");
    rotated.pk_hash = Some("f".repeat(64));
    lc.ctx
        .store
        .update_workspace(&rotated)
        .await
        .expect("rotate key hash");

    assert_eq!(
        call_as_workspace(&lc).await,
        StatusCode::OK,
        "the workspace is unchanged, so its token still resolves to it"
    );
}

/// Enable and disable are status transitions, not a flag beside the status.
/// A disabled workspace's token is refused; re-enabling restores it.
#[tokio::test]
async fn disabling_a_workspace_is_a_status_transition_that_cuts_its_token() {
    let lc = registered_workspace_with_token().await;
    let uri = format!("/api/v1/workspaces/{}", lc.workspace_id);

    let (status, body) = send_json_auto_csrf(
        &lc.ctx.app,
        Method::PUT,
        &uri,
        None,
        Some(&lc.admin_cookie),
        Some(serde_json::json!({ "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "disable: {body}");
    assert_eq!(body["data"]["computed_status"], "disabled");
    assert_eq!(body["data"]["enabled"], false);
    assert_eq!(call_as_workspace(&lc).await, StatusCode::FORBIDDEN);

    let (status, body) = send_json_auto_csrf(
        &lc.ctx.app,
        Method::PUT,
        &uri,
        None,
        Some(&lc.admin_cookie),
        Some(serde_json::json!({ "enabled": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "enable: {body}");
    assert_eq!(body["data"]["computed_status"], "active");
    assert_eq!(body["data"]["enabled"], true);
    assert_eq!(call_as_workspace(&lc).await, StatusCode::OK);
}

/// Revocation is final: the enable toggle cannot bring a revoked workspace back.
#[tokio::test]
async fn a_revoked_workspace_cannot_be_re_enabled() {
    let lc = registered_workspace_with_token().await;
    let (status, body) = send_json_auto_csrf(
        &lc.ctx.app,
        Method::POST,
        &format!("/api/v1/workspaces/{}/revoke", lc.workspace_id),
        None,
        Some(&lc.admin_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke: {body}");

    let uri = format!("/api/v1/workspaces/{}", lc.workspace_id);
    let (status, body) = send_json_auto_csrf(
        &lc.ctx.app,
        Method::PUT,
        &uri,
        None,
        Some(&lc.admin_cookie),
        Some(serde_json::json!({ "enabled": true })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "re-enable: {body}");

    let (status, body) = send_json(
        &lc.ctx.app,
        Method::GET,
        &uri,
        None,
        Some(&lc.admin_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["computed_status"], "revoked");
    assert_eq!(body["data"]["enabled"], false);
}
