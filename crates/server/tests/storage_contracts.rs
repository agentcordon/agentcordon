//! Store contracts observed at the HTTP boundary.
//!
//! Two properties of the store that a client can see:
//!
//! 1. Error mapping. A constraint the database rejects (a duplicate row, a
//!    dangling reference) answers 409, and a missing row answers 404, on
//!    every route, because the SQLite backend maps the driver's errors in
//!    one place instead of per method.
//! 2. Atomicity. A write that has to happen in two steps (consume a code
//!    then mint tokens, archive a secret then replace it, delete a client
//!    then insert its replacement) is one transaction: when the second step
//!    fails, the first is not visible either.
//!
//! The failure in (2) is injected with a SQLite trigger created on a second
//! connection to the same file-backed database, which is why these tests
//! build the app over a store they own.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::storage::Store;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

use crate::common::*;

const PK_HASH_A: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const REDIRECT_URI: &str = "http://localhost:9876/callback";

async fn login(app: &Router, username: &str) -> (String, String) {
    let (session, csrf) = login_user(app, username, TEST_PASSWORD).await;
    (combined_cookie(&session, &csrf), csrf)
}

// ===========================================================================
// 1. Error mapping
// ===========================================================================

/// Sharing a vault with a user it is already shared with violates the
/// `vault_shares` unique constraint. The route has no pre-check; the store
/// answers, and it must answer Conflict, not an internal error.
#[tokio::test]
async fn sharing_a_vault_with_the_same_user_twice_is_a_409_not_a_500() {
    let ctx = TestAppBuilder::new().build().await;
    create_test_user(&*ctx.store, "vault-owner", TEST_PASSWORD, UserRole::Admin).await;
    let viewer =
        create_test_user(&*ctx.store, "vault-viewer", TEST_PASSWORD, UserRole::Viewer).await;
    let (cookie, csrf) = login(&ctx.app, "vault-owner").await;

    // Owning the vault is what lets the owner share it.
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/vaults",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({ "name": "team-a" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create vault: {body}");
    let vault_id = body["data"]["id"].as_str().expect("vault id").to_string();

    let share = json!({ "user_id": viewer.id.0.to_string(), "permission": "read" });
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/vaults/{vault_id}/shares"),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(share.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "first share: {body}");

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/vaults/{vault_id}/shares"),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(share),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "second share: {body}");
}

/// Dynamic client registration only pre-checks for a live client on the key
/// hash. A revoked client still holds the unique `public_key_hash`, so the
/// insert is what fails; that is a Conflict.
#[tokio::test]
async fn registering_a_client_for_a_revoked_key_hash_is_a_409_not_a_500() {
    let ctx = TestAppBuilder::new().build().await;
    create_root_user(&*ctx.store, "admin", TEST_PASSWORD).await;
    let (cookie, csrf) = login(&ctx.app, "admin").await;

    let register = json!({
        "workspace_name": "revoked-ws",
        "public_key_hash": PK_HASH_A,
        "scopes": ["credentials:discover"],
        "redirect_uris": [REDIRECT_URI],
    });
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/oauth/clients",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(register.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "register: {body}");
    let client_id = body["data"]["client_id"].as_str().expect("client_id");
    ctx.store
        .revoke_oauth_client(client_id)
        .await
        .expect("revoke");

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/oauth/clients",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(register),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "re-register: {body}");
}

// ===========================================================================
// 2. Atomicity
// ===========================================================================

/// An app over a file-backed store, plus a second connection to the same
/// file through which a test can install a trigger that makes one statement
/// fail. The directory lives as long as the harness.
struct FaultInjectingApp {
    ctx: TestContext,
    raw: agent_cordon_core::storage::sqlite::rusqlite::Connection,
    _dir: tempfile::TempDir,
}

impl FaultInjectingApp {
    async fn build() -> Self {
        use agent_cordon_core::domain::policy::{PolicyId, StoredPolicy};
        use agent_cordon_core::storage::sqlite::SqliteStore;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("store.db");
        let path_str = path.to_str().expect("utf-8 path");
        let store = SqliteStore::new(path_str).await.expect("open store");
        store.run_migrations().await.expect("migrate");
        let store: Arc<dyn Store + Send + Sync> = Arc::new(store);

        // `with_store` skips the seed the builder does for a fresh store.
        let now = chrono::Utc::now();
        store
            .store_policy(&StoredPolicy {
                id: PolicyId(uuid::Uuid::new_v4()),
                name: "default".to_string(),
                description: None,
                cedar_policy: include_str!("../../../policies/default.cedar").to_string(),
                enabled: true,
                is_system: false,
                created_at: now,
                updated_at: now,
            })
            .await
            .expect("seed policy");

        let ctx = TestAppBuilder::new().with_store(store).build().await;
        let raw = agent_cordon_core::storage::sqlite::rusqlite::Connection::open(path_str)
            .expect("second connection");
        Self {
            ctx,
            raw,
            _dir: dir,
        }
    }

    /// Make the next statement of `kind` on `table` fail.
    fn fail(&self, kind: &str, table: &str) {
        self.raw
            .execute_batch(&format!(
                "CREATE TRIGGER injected_fault BEFORE {kind} ON {table} \
                 BEGIN SELECT RAISE(ABORT, 'injected fault'); END;"
            ))
            .expect("install trigger");
    }

    fn heal(&self) {
        self.raw
            .execute_batch("DROP TRIGGER injected_fault;")
            .expect("drop trigger");
    }

    fn count(&self, sql: &str) -> i64 {
        self.raw
            .query_row(sql, [], |r| r.get(0))
            .expect("count query")
    }
}

async fn post_form(
    app: &Router,
    uri: &str,
    body: &str,
    cookie: Option<&str>,
) -> (StatusCode, Value, Option<String>) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(c) = cookie {
        builder = builder.header(header::COOKIE, c);
        if let Some(csrf) = extract_csrf_from_cookie(c) {
            builder = builder.header("x-csrf-token", csrf);
        }
    }
    let req = builder.body(Body::from(body.to_string())).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json, location)
}

const BOOTSTRAP_CLIENT_ID: &str = "agentcordon-broker";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Issue a device code for a new workspace and approve it through the UI,
/// which mints the workspace's OAuth client. Returns the plaintext device
/// code and its user code.
async fn approved_device_code(app: &Router, session_cookie: &str, csrf: &str) -> String {
    let issue = format!(
        "client_id={BOOTSTRAP_CLIENT_ID}&scope=credentials:discover&\
         workspace_name=atomic-ws&public_key_hash={PK_HASH_A}"
    );
    let (status, body, _) = post_form(app, "/api/v1/oauth/device/code", &issue, None).await;
    assert_eq!(status, StatusCode::OK, "issue: {body}");
    let device_code = body["device_code"].as_str().unwrap().to_string();
    let user_code = body["user_code"].as_str().unwrap().to_string();

    let activate = format!(
        "csrf_token={}&user_code={}&decision=approve",
        urlencoding::encode(csrf),
        urlencoding::encode(&user_code),
    );
    let (status, _, _) = post_form(app, "/activate", &activate, Some(session_cookie)).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "approve");
    device_code
}

/// Device-code exchange: consuming the code and minting its tokens is one
/// transaction. When the mint fails the code is still approved, so the
/// broker's next poll can succeed; it is not burned.
#[tokio::test]
async fn a_failed_token_mint_leaves_the_device_code_approved() {
    let harness = FaultInjectingApp::build().await;
    let ctx = &harness.ctx;
    create_test_user(&*ctx.store, "approver", TEST_PASSWORD, UserRole::Admin).await;
    let (session_cookie, _) = login_user(&ctx.app, "approver", TEST_PASSWORD).await;
    let csrf = compute_consent_csrf(&session_cookie, &ctx.state.crypto.session_hash_key);
    let device_code = approved_device_code(&ctx.app, &session_cookie, &csrf).await;
    let exchange = format!(
        "grant_type={DEVICE_GRANT}&client_id={BOOTSTRAP_CLIENT_ID}&device_code={device_code}"
    );

    harness.fail("INSERT", "oauth_refresh_tokens");
    let (status, body, _) = post_form(&ctx.app, "/api/v1/oauth/token", &exchange, None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(
        harness.count("SELECT COUNT(*) FROM device_codes WHERE status = 'consumed'"),
        0,
        "the code is not consumed when its tokens were not minted"
    );
    assert_eq!(
        harness.count("SELECT COUNT(*) FROM oauth_access_tokens"),
        0,
        "no access token survives a rolled-back mint"
    );

    harness.heal();
    let (status, body, _) = post_form(&ctx.app, "/api/v1/oauth/token", &exchange, None).await;
    assert_eq!(status, StatusCode::OK, "retry after the fault: {body}");
    assert!(body["access_token"].is_string());

    let (status, body, _) = post_form(&ctx.app, "/api/v1/oauth/token", &exchange, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["error"], "invalid_grant",
        "a consumed code stays consumed"
    );
    assert_eq!(
        harness.count("SELECT COUNT(*) FROM oauth_access_tokens"),
        1,
        "the second exchange minted nothing"
    );
}

fn pkce() -> (String, String) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier.to_string(), challenge)
}

fn query_param(location: &str, key: &str) -> Option<String> {
    let url = url::Url::parse(location)
        .or_else(|_| url::Url::parse(&format!("http://localhost{location}")))
        .ok()?;
    url.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.to_string())
}

/// Register a confidential client and walk the consent form to an
/// authorization code. Returns (client_id, client_secret, code, verifier).
async fn issued_auth_code(
    app: &Router,
    cookie: &str,
    csrf: &str,
    session_hash_key: &[u8; 32],
) -> (String, String, String, String) {
    let (status, body) = send_json(
        app,
        Method::POST,
        "/api/v1/oauth/clients",
        None,
        Some(cookie),
        Some(csrf),
        Some(json!({
            "workspace_name": "code-ws",
            "public_key_hash": PK_HASH_A,
            "scopes": ["credentials:discover"],
            "redirect_uris": [REDIRECT_URI],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "register: {body}");
    let client_id = body["data"]["client_id"].as_str().unwrap().to_string();
    let client_secret = body["data"]["client_secret"].as_str().unwrap().to_string();

    let (verifier, challenge) = pkce();
    let consent_csrf = compute_consent_csrf(cookie, session_hash_key);
    let form = format!(
        "client_id={}&redirect_uri={}&scope=credentials:discover&state=s&code_challenge={}&\
         code_challenge_method=S256&decision=approve&csrf_token={}",
        urlencoding::encode(&client_id),
        urlencoding::encode(REDIRECT_URI),
        urlencoding::encode(&challenge),
        urlencoding::encode(&consent_csrf),
    );
    let (status, _, location) =
        post_form(app, "/api/v1/oauth/authorize", &form, Some(cookie)).await;
    assert_eq!(status, StatusCode::FOUND, "consent");
    let code = query_param(&location.expect("redirect"), "code").expect("code");
    (client_id, client_secret, code, verifier)
}

/// Authorization-code exchange: the code is consumed in the transaction
/// that mints its tokens, so a failed mint leaves it usable once more.
#[tokio::test]
async fn a_failed_token_mint_leaves_the_auth_code_unconsumed() {
    let harness = FaultInjectingApp::build().await;
    let ctx = &harness.ctx;
    create_root_user(&*ctx.store, "admin", TEST_PASSWORD).await;
    let (cookie, csrf) = login(&ctx.app, "admin").await;
    let (client_id, client_secret, code, verifier) =
        issued_auth_code(&ctx.app, &cookie, &csrf, &ctx.state.crypto.session_hash_key).await;
    let exchange = format!(
        "grant_type=authorization_code&code={}&client_id={}&client_secret={}&redirect_uri={}&code_verifier={}",
        urlencoding::encode(&code),
        urlencoding::encode(&client_id),
        urlencoding::encode(&client_secret),
        urlencoding::encode(REDIRECT_URI),
        urlencoding::encode(&verifier),
    );

    harness.fail("INSERT", "oauth_refresh_tokens");
    let (status, body, _) = post_form(&ctx.app, "/api/v1/oauth/token", &exchange, None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(
        harness.count("SELECT COUNT(*) FROM oauth_auth_codes WHERE consumed_at IS NOT NULL"),
        0,
        "the code is not consumed when its tokens were not minted"
    );
    assert_eq!(harness.count("SELECT COUNT(*) FROM oauth_access_tokens"), 0);

    harness.heal();
    let (status, body, _) = post_form(&ctx.app, "/api/v1/oauth/token", &exchange, None).await;
    assert_eq!(status, StatusCode::OK, "retry after the fault: {body}");

    let (status, body, _) = post_form(&ctx.app, "/api/v1/oauth/token", &exchange, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(
        harness.count("SELECT COUNT(*) FROM oauth_access_tokens"),
        1,
        "a second exchange of a consumed code mints nothing"
    );
}

async fn create_credential(ctx: &TestContext, cookie: &str, csrf: &str) -> String {
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(cookie),
        Some(csrf),
        Some(json!({
            "name": "rotated",
            "service": "svc",
            "secret_value": "first-secret",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create: {body}");
    body["data"]["id"].as_str().expect("id").to_string()
}

async fn history_len(ctx: &TestContext, cookie: &str, csrf: &str, cred_id: &str) -> usize {
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{cred_id}/secret-history"),
        None,
        Some(cookie),
        Some(csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "history: {body}");
    body["data"].as_array().expect("array").len()
}

/// Secret rotation: archiving the old ciphertext and writing the new one is
/// one transaction. A rotation whose write fails leaves no history row and
/// the old ciphertext in place.
#[tokio::test]
async fn a_failed_secret_write_leaves_no_history_row_and_the_old_ciphertext() {
    let harness = FaultInjectingApp::build().await;
    let ctx = &harness.ctx;
    create_test_user(&*ctx.store, "owner", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login(&ctx.app, "owner").await;
    let cred_id = create_credential(ctx, &cookie, &csrf).await;
    let before = harness.count(&format!(
        "SELECT length(encrypted_value) FROM credentials WHERE id = '{cred_id}'"
    ));

    harness.fail("UPDATE", "credentials");
    let (status, body) = send_json(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/credentials/{cred_id}"),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({ "secret_value": "a-much-longer-second-secret-value" })),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(
        harness.count("SELECT COUNT(*) FROM credential_secret_history"),
        0,
        "no history row without the matching secret write"
    );
    let after = harness.count(&format!(
        "SELECT length(encrypted_value) FROM credentials WHERE id = '{cred_id}'"
    ));
    assert_eq!(before, after, "the ciphertext is unchanged");

    harness.heal();
    let (status, body) = send_json(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/credentials/{cred_id}"),
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({ "secret_value": "a-much-longer-second-secret-value" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rotate after the fault: {body}");
    assert_eq!(history_len(ctx, &cookie, &csrf, &cred_id).await, 1);
}

/// Consent-flow re-registration: the old client for a key hash is deleted
/// in the transaction that inserts the new one. When the insert fails the
/// old client and its tokens are still there.
#[tokio::test]
async fn a_failed_reregistration_keeps_the_old_client_and_its_tokens() {
    let harness = FaultInjectingApp::build().await;
    let ctx = &harness.ctx;
    create_root_user(&*ctx.store, "admin", TEST_PASSWORD).await;
    let (cookie, _csrf) = login(&ctx.app, "admin").await;

    // First registration through the consent form, and one token on it.
    let (_, challenge) = pkce();
    let consent_csrf = compute_consent_csrf(&cookie, &ctx.state.crypto.session_hash_key);
    let form = format!(
        "client_id=&redirect_uri={}&scope=credentials:discover&state=s&code_challenge={}&\
         code_challenge_method=S256&decision=approve&csrf_token={}&public_key_hash={}&\
         workspace_name=consent-ws&is_new_workspace=true",
        urlencoding::encode(REDIRECT_URI),
        urlencoding::encode(&challenge),
        urlencoding::encode(&consent_csrf),
        PK_HASH_A,
    );
    let (status, _, location) =
        post_form(&ctx.app, "/api/v1/oauth/authorize", &form, Some(&cookie)).await;
    assert_eq!(status, StatusCode::FOUND, "first registration");
    let location = location.expect("redirect");
    let first_client_id = query_param(&location, "client_id").expect("client_id in callback");
    let old_client = ctx
        .store
        .get_oauth_client_by_client_id(&first_client_id)
        .await
        .expect("lookup")
        .expect("client exists");
    let now = chrono::Utc::now();
    ctx.store
        .create_oauth_access_token(&agent_cordon_core::oauth2::types::OAuthAccessToken {
            token_hash: "tok-1".to_string(),
            client_id: first_client_id.clone(),
            user_id: old_client.created_by_user.clone(),
            scopes: vec![],
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            revoked_at: None,
        })
        .await
        .expect("token on the old client");

    harness.fail("INSERT", "oauth_clients");
    let (status, _, location) =
        post_form(&ctx.app, "/api/v1/oauth/authorize", &form, Some(&cookie)).await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "the consent form reports errors by redirect"
    );
    let location = location.expect("redirect");
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("server_error"),
        "{location}"
    );
    assert_eq!(
        harness.count(&format!(
            "SELECT COUNT(*) FROM oauth_clients WHERE client_id = '{first_client_id}'"
        )),
        1,
        "the old client survives a failed replacement"
    );
    assert_eq!(
        harness.count("SELECT COUNT(*) FROM oauth_access_tokens WHERE token_hash = 'tok-1'"),
        1,
        "and so do its tokens"
    );

    harness.heal();
    let (status, _, location) =
        post_form(&ctx.app, "/api/v1/oauth/authorize", &form, Some(&cookie)).await;
    assert_eq!(status, StatusCode::FOUND, "re-registration after the fault");
    let second_client_id =
        query_param(&location.expect("redirect"), "client_id").expect("client_id");
    assert_ne!(second_client_id, first_client_id);
    assert_eq!(
        harness.count(&format!(
            "SELECT COUNT(*) FROM oauth_clients WHERE public_key_hash = '{PK_HASH_A}'"
        )),
        1,
        "one client per key hash"
    );
    assert_eq!(
        harness.count("SELECT COUNT(*) FROM oauth_access_tokens WHERE token_hash = 'tok-1'"),
        0,
        "the replaced client's tokens went with it"
    );
}

// ===========================================================================
// 3. Audit event names
// ===========================================================================

/// `AuditEventType`'s `OAuthProvider*` variants used to serialize as
/// `o_auth_provider_…` — serde's snake_case rule splits the `OAuth` acronym —
/// so the name in the API matched nothing anyone would write
/// (uat/artifacts/fresh-user-docker.md F-16). New rows carry
/// `oauth_provider_…`; rows already on disk carry the old spelling and must
/// still read back.
#[tokio::test]
async fn oauth_provider_audit_events_write_the_new_name_and_read_the_old_one() {
    use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};

    let harness = FaultInjectingApp::build().await;

    // A row written today.
    harness
        .ctx
        .store
        .append_audit_event(
            &AuditEvent::builder(AuditEventType::OAuthProviderClientCreated)
                .action("create")
                .resource("oauth_provider_client", "provider-1")
                .decision(AuditDecision::Permit, None)
                .build(),
        )
        .await
        .expect("append audit event");

    assert_eq!(
        harness.count(
            "SELECT COUNT(*) FROM audit_events \
             WHERE event_type = 'oauth_provider_client_created'"
        ),
        1,
        "a new row is stored under the unmangled name"
    );

    // A row an older build left behind, under the mangled name.
    harness
        .raw
        .execute_batch(
            "INSERT INTO audit_events \
             (id, timestamp, correlation_id, event_type, action, resource_type, decision) \
             VALUES ('11111111-1111-1111-1111-111111111111', '2026-01-01T00:00:00Z', \
                     'corr-old', 'o_auth_provider_discovery_failed', 'discover', \
                     'oauth_provider_client', 'error')",
        )
        .expect("seed a legacy audit row");

    let events = harness
        .ctx
        .store
        .list_audit_events(50, 0)
        .await
        .expect("list audit events");
    let names: Vec<String> = events
        .iter()
        .map(|e| serde_json::to_value(&e.event_type).unwrap().to_string())
        .collect();
    assert!(
        names
            .iter()
            .any(|n| n == "\"oauth_provider_client_created\""),
        "the new row reads back under the new name; got {names:?}"
    );
    assert!(
        names
            .iter()
            .any(|n| n == "\"oauth_provider_discovery_failed\""),
        "the legacy row still reads back, under the new name; got {names:?}"
    );
}
