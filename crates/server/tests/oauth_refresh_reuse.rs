//! Presenting a rotated refresh token kills the whole family, and says so.
//!
//! Rotation retires the presented token, so a token that comes back has
//! either leaked or lost a race with a thief. RFC 6819 §5.2.2.3 says to
//! assume the worst: revoke every refresh and access token descended from
//! the same grant. That is invisible to the client — it just gets
//! `invalid_grant` — so the audit row is the only place an operator can see
//! it happened, and its fields are what this test pins, along with the
//! access tokens the revocation has to take with it.
//! `workspace_lifecycle::replayed_refresh_token_revokes_its_family` covers
//! the same replay from the workspace's side, without the audit shape.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use agent_cordon_core::storage::AuditFilter;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

use crate::common::{
    compute_consent_csrf, create_root_user, extract_csrf_from_cookie, login_user_combined,
    send_json_auto_csrf, TEST_PASSWORD,
};

const PK_HASH: &str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
const REDIRECT_URI: &str = "http://localhost:9876/callback";
/// The RFC 7636 example verifier and its S256 challenge.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn challenge() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(VERIFIER.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

async fn post_form(app: &Router, uri: &str, body: &str) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(json!(null)),
    )
}

struct Grant {
    client_id: String,
    client_secret: String,
    access_token: String,
    refresh_token: String,
}

/// Register a client, walk the consent flow, and exchange the code. The
/// workspace the key hash names has to exist for the access token to
/// authenticate anything, so it is created first.
async fn grant(ctx: &TestContext, cookie: &str) -> Grant {
    use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
    let now = chrono::Utc::now();
    ctx.store
        .create_workspace(&Workspace {
            id: WorkspaceId(uuid::Uuid::new_v4()),
            name: "reuse-workspace".to_string(),
            status: WorkspaceStatus::Active,
            pk_hash: Some(PK_HASH.to_string()),
            encryption_public_key: None,
            tags: vec![],
            owner_id: None,
            parent_id: None,
            tool_name: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("create workspace");

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/oauth/clients",
        None,
        Some(cookie),
        Some(json!({
            "workspace_name": "reuse-workspace",
            "public_key_hash": PK_HASH,
            "scopes": ["credentials:discover"],
            "redirect_uris": [REDIRECT_URI],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "register client: {body}");
    let client_id = body["data"]["client_id"].as_str().unwrap().to_string();
    let client_secret = body["data"]["client_secret"].as_str().unwrap().to_string();

    let consent_csrf = compute_consent_csrf(cookie, &ctx.state.crypto.session_hash_key);
    let form = format!(
        "client_id={}&redirect_uri={}&scope=credentials:discover&state=s\
         &code_challenge={}&code_challenge_method=S256&decision=approve&csrf_token={}",
        urlencoding::encode(&client_id),
        urlencoding::encode(REDIRECT_URI),
        urlencoding::encode(&challenge()),
        urlencoding::encode(&consent_csrf),
    );
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/oauth/authorize")
        .header(header::COOKIE, cookie)
        .header(
            "x-csrf-token",
            extract_csrf_from_cookie(cookie).unwrap_or_default(),
        )
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form))
        .unwrap();
    let response = ctx.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FOUND, "consent redirect");
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("Location")
        .to_string();
    let code = url::Url::parse(&location)
        .expect("parse redirect")
        .query_pairs()
        .find(|(k, _)| k == "code")
        .expect("code")
        .1
        .to_string();

    let form = format!(
        "grant_type=authorization_code&code={}&client_id={}&client_secret={}\
         &redirect_uri={}&code_verifier={}",
        urlencoding::encode(&code),
        urlencoding::encode(&client_id),
        urlencoding::encode(&client_secret),
        urlencoding::encode(REDIRECT_URI),
        urlencoding::encode(VERIFIER),
    );
    let (status, body) = post_form(&ctx.app, "/api/v1/oauth/token", &form).await;
    assert_eq!(status, StatusCode::OK, "code exchange: {body}");
    Grant {
        client_id,
        client_secret,
        access_token: body["access_token"].as_str().unwrap().to_string(),
        refresh_token: body["refresh_token"].as_str().unwrap().to_string(),
    }
}

fn refresh_form(g: &Grant, refresh_token: &str) -> String {
    format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret={}",
        urlencoding::encode(refresh_token),
        urlencoding::encode(&g.client_id),
        urlencoding::encode(&g.client_secret),
    )
}

/// Does this bearer token still authenticate?
async fn bearer_works(ctx: &TestContext, token: &str) -> bool {
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/credentials")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let status = ctx.app.clone().oneshot(request).await.unwrap().status();
    status != StatusCode::UNAUTHORIZED
}

async fn audit_rows(ctx: &TestContext, event_type: &str) -> Vec<Value> {
    ctx.store
        .list_audit_events_filtered(&AuditFilter {
            limit: 200,
            event_type: Some(event_type.to_string()),
            ..Default::default()
        })
        .await
        .expect("audit list")
        .into_iter()
        .map(|e| serde_json::to_value(e).expect("audit event serializes"))
        .collect()
}

#[tokio::test]
async fn a_replayed_refresh_token_revokes_its_whole_family_and_is_audited() {
    let ctx = TestAppBuilder::new().build().await;
    create_root_user(&*ctx.store, "reuse-root", TEST_PASSWORD).await;
    let cookie = login_user_combined(&ctx.app, "reuse-root", TEST_PASSWORD).await;
    let g = grant(&ctx, &cookie).await;

    // One honest rotation.
    let (status, body) = post_form(
        &ctx.app,
        "/api/v1/oauth/token",
        &refresh_form(&g, &g.refresh_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "first refresh: {body}");
    let rotated_refresh = body["refresh_token"].as_str().unwrap().to_string();
    let rotated_access = body["access_token"].as_str().unwrap().to_string();
    assert_ne!(
        rotated_refresh, g.refresh_token,
        "rotation issues a new token"
    );
    assert!(
        bearer_works(&ctx, &rotated_access).await,
        "the rotated access token works before the replay"
    );

    // The retired token comes back.
    let (status, body) = post_form(
        &ctx.app,
        "/api/v1/oauth/token",
        &refresh_form(&g, &g.refresh_token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "replay: {body}");
    assert_eq!(body["error"], "invalid_grant", "{body}");

    // The client sees only `invalid_grant`; the audit row is where an
    // operator learns a token leaked.
    let rows = audit_rows(&ctx, "oauth2_token_acquired").await;
    let reuse: Vec<&Value> = rows
        .iter()
        .filter(|e| e["action"] == "oauth_refresh_token_reuse_detected")
        .collect();
    assert_eq!(
        reuse.len(),
        1,
        "exactly one reuse row for one replay: {rows:#?}"
    );
    let row = reuse[0];
    assert_eq!(row["decision"], "forbid", "{row}");
    assert_eq!(
        row["decision_reason"], "refresh token family revoked",
        "the row names what was done about it: {row}"
    );
    assert_eq!(row["resource_type"], "oauth_client", "{row}");
    assert_eq!(
        row["metadata"]["client_id"], g.client_id,
        "the row names the client whose token was replayed: {row}"
    );
    assert!(
        row["metadata"]["family_id"]
            .as_str()
            .is_some_and(|f| !f.is_empty()),
        "the row names the family it revoked: {row}"
    );

    // Everything descended from the grant is dead, including the successor
    // the legitimate client is holding. Without family revocation the thief's
    // replay fails but the leaked chain keeps working.
    assert!(
        !bearer_works(&ctx, &rotated_access).await,
        "the access token minted alongside the family is revoked too"
    );
    assert!(
        !bearer_works(&ctx, &g.access_token).await,
        "so is the access token from the original grant"
    );
    let (status, body) = post_form(
        &ctx.app,
        "/api/v1/oauth/token",
        &refresh_form(&g, &rotated_refresh),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the successor refresh token is revoked with the family: {body}"
    );

    // And that presentation is itself a replay of a dead token, so it is
    // recorded too: every attempt on a revoked family leaves a row.
    let reuse_rows = audit_rows(&ctx, "oauth2_token_acquired")
        .await
        .into_iter()
        .filter(|e| e["action"] == "oauth_refresh_token_reuse_detected")
        .count();
    assert_eq!(
        reuse_rows, 2,
        "each presentation of a dead token is audited"
    );
}
