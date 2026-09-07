//! Upgrading a real v0.3.3 install.
//!
//! Every other migration test seeds its own rows at version N-1 and applies
//! N. That proves each step in isolation; it does not prove that a database
//! an operator actually has — written by the v0.3.3 binary, sealed under a
//! v0.3.3 master secret, holding v0.3.3 password hashes, OAuth tokens and
//! ciphertext — still works after all of 013 through 020 have run.
//!
//! `tests/fixtures/v0.3.3/agent-cordon.db` is that database: produced by the
//! v0.3.3 server and populated through its own admin API (see the README
//! there). These tests copy it into a temp directory, boot the current server
//! over it — migrations and all — and check that nothing an operator would
//! notice was lost:
//!
//! * the users still log in with their v0.3.3 passwords, and the viewer is
//!   still a viewer;
//! * the workspace's Ed25519 identity still names it, and the access token
//!   v0.3.3 issued still vends;
//! * the credential and its rotation history still decrypt, to the same
//!   plaintext that went in;
//! * the refresh token still rotates (migration 016 rebinds tokens by
//!   workspace id rather than invalidating them);
//! * the audit trail survives;
//! * and the weak v0.3.3 master secret keeps its legacy derivation instead of
//!   being stretched out from under its own ciphertext.
//!
//! One thing a static fixture cannot carry is a live token: v0.3.3's token
//! lifetimes are hard-coded constants, so the tokens in the file expire
//! fifteen minutes and thirty days after it was made.
//! [`place_tokens_in_their_v033_window`] shifts them into their own window on
//! the copy, preserving those lifetimes exactly, so these tests measure the
//! upgrade rather than the calendar.

use std::path::{Path, PathBuf};

use agent_cordon_core::storage::sqlite::rusqlite;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

use crate::common::{login_user_combined, send_json, send_json_auto_csrf};

// ---------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v0.3.3")
}

fn manifest() -> Value {
    let raw = std::fs::read_to_string(fixture_dir().join("fixture.json")).expect("fixture.json");
    serde_json::from_str(&raw).expect("fixture.json parses")
}

/// A current-release server booted over a copy of the v0.3.3 database.
struct Upgraded {
    ctx: TestContext,
    manifest: Value,
    db_path: PathBuf,
    _dir: tempfile::TempDir,
}

/// Put the fixture's OAuth tokens back inside their own validity window,
/// on the copy, before the server opens it.
///
/// v0.3.3 hard-codes its token lifetimes (`ACCESS_TOKEN_TTL_SECS = 900`,
/// refresh = 30 days) with no way to configure them, so a checked-in
/// database's tokens are stale a quarter of an hour after it is made. That
/// is a property of wall-clock time, not of the upgrade: no migration reads
/// or writes an expiry, and a real operator upgrades while their tokens are
/// still live.
///
/// So every token timestamp moves by one offset — the age of the fixture,
/// measured from the instant v0.3.3 minted the access token. Each token
/// keeps the exact lifetime v0.3.3 gave it (the interval between its
/// `created_at` and `expires_at` is unchanged), and nothing else in the row
/// moves: not the token hash, not the client binding, not the scopes. The
/// vend and refresh below therefore still turn on what the migrations did,
/// and the test cannot rot, however long the fixture sits in the tree.
/// `the_fixture_carries_the_v033_token_lifetimes` pins the lifetimes this
/// preserves.
fn place_tokens_in_their_v033_window(db_path: &Path) {
    use agent_cordon_core::domain::time::{format_timestamp, parse_timestamp};

    let conn = rusqlite::Connection::open(db_path).expect("open the copy");
    let minted_at: String = conn
        .query_row(
            "SELECT created_at FROM oauth_access_tokens ORDER BY created_at LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("the fixture holds a v0.3.3 access token");
    let age = chrono::Utc::now() - parse_timestamp(&minted_at).expect("stored timestamp");

    for table in ["oauth_access_tokens", "oauth_refresh_tokens"] {
        let rows: Vec<(String, String, String)> = {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT token_hash, created_at, expires_at FROM {table}"
                ))
                .expect("prepare");
            let rows = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .expect("query")
                .map(|r| r.expect("row"))
                .collect();
            rows
        };
        for (token_hash, created_at, expires_at) in rows {
            let shift = |stamp: &str| {
                format_timestamp(&(parse_timestamp(stamp).expect("stored timestamp") + age))
            };
            conn.execute(
                &format!(
                    "UPDATE {table} SET created_at = ?1, expires_at = ?2 WHERE token_hash = ?3"
                ),
                rusqlite::params![shift(&created_at), shift(&expires_at), token_hash],
            )
            .expect("shift the token into its window");
        }
    }
}

impl Upgraded {
    /// Copy the fixture out of the source tree and boot over the copy. The
    /// copy is what the migrations rewrite; the checked-in file stays at
    /// schema version 12.
    async fn boot() -> Self {
        let manifest = manifest();
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("agent-cordon.db");
        std::fs::copy(fixture_dir().join("agent-cordon.db"), &db_path).expect("copy fixture db");
        place_tokens_in_their_v033_window(&db_path);

        let secret = manifest["master_secret"].as_str().expect("master_secret");
        let ctx = TestAppBuilder::new()
            .with_master_secret(secret, 1)
            .with_sqlite_file(db_path.to_str().expect("utf-8 path"))
            .build()
            .await;

        Self {
            ctx,
            manifest,
            db_path,
            _dir: dir,
        }
    }

    fn raw(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(&self.db_path).expect("second connection to the upgraded db")
    }

    fn user(&self, which: &str) -> (String, String) {
        let user = &self.manifest["users"][which];
        (
            user["username"].as_str().expect("username").to_string(),
            user["password"].as_str().expect("password").to_string(),
        )
    }

    async fn login(&self, which: &str) -> String {
        let (username, password) = self.user(which);
        login_user_combined(&self.ctx.app, &username, &password).await
    }
}

/// POST a form body, the way the token endpoint is called.
async fn send_form(app: &axum::Router, uri: &str, body: &str) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));
    (status, json)
}

/// A broker's ECIES key pair: the private scalar, and the public key
/// base64url-encoded the way the vend endpoint wants it. The fixture
/// workspace was registered through the device flow, which stores no
/// encryption key, so a vend has to carry the broker's own.
fn broker_ecies_key() -> (Vec<u8>, String) {
    let secret = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let point =
        p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&secret.public_key(), false);
    (
        secret.to_bytes().to_vec(),
        URL_SAFE_NO_PAD.encode(point.as_bytes()),
    )
}

/// Open a vend envelope the way the broker does, returning the credential
/// material the server sealed inside it.
async fn open_envelope(private_key: &[u8], envelope: &Value) -> Value {
    use agent_cordon_core::crypto::ecies::CredentialEnvelopeDecryptor;
    use agent_cordon_core::crypto::ecies::{EciesEncryptor, EncryptedEnvelope};
    use base64::engine::general_purpose::STANDARD;

    let field = |name: &str| {
        STANDARD
            .decode(envelope[name].as_str().unwrap_or_else(|| {
                panic!("envelope field {name} missing: {envelope}");
            }))
            .expect("base64")
    };
    let sealed = EncryptedEnvelope {
        version: envelope["version"].as_u64().expect("version") as u8,
        ephemeral_public_key: field("ephemeral_public_key"),
        ciphertext: field("ciphertext"),
        nonce: field("nonce"),
        aad: field("aad"),
    };
    let plaintext = EciesEncryptor::new()
        .decrypt_envelope(private_key, &sealed)
        .await
        .expect("the broker can open the envelope");
    serde_json::from_slice(&plaintext).expect("credential material is JSON")
}

// ---------------------------------------------------------------------------
// The fixture's own clock
// ---------------------------------------------------------------------------

/// The checked-in database holds tokens v0.3.3 minted at a fixed instant,
/// under lifetimes v0.3.3 hard-codes. This reads the file as it sits in the
/// tree — no shift, no server — and pins both lifetimes, so a regenerated
/// fixture that changed them is caught here rather than by a puzzling
/// expiry failure elsewhere, and so a reader can see that
/// `place_tokens_in_their_v033_window` moves the clock and nothing else.
#[test]
fn the_fixture_carries_the_v033_token_lifetimes() {
    use agent_cordon_core::domain::time::parse_timestamp;

    let conn = rusqlite::Connection::open(fixture_dir().join("agent-cordon.db"))
        .expect("open the checked-in fixture");
    let lifetime = |table: &str| {
        let (created, expires): (String, String) = conn
            .query_row(
                &format!("SELECT created_at, expires_at FROM {table} LIMIT 1"),
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("token row");
        parse_timestamp(&expires).expect("expires_at")
            - parse_timestamp(&created).expect("created_at")
    };

    assert_eq!(
        lifetime("oauth_access_tokens").num_seconds(),
        900,
        "v0.3.3's ACCESS_TOKEN_TTL_SECS"
    );
    assert_eq!(
        lifetime("oauth_refresh_tokens").num_days(),
        30,
        "v0.3.3's REFRESH_TOKEN_TTL_SECS"
    );
}

// ---------------------------------------------------------------------------
// Migrations
// ---------------------------------------------------------------------------

/// The fixture stops at 12. Booting over it must apply 013 through 020 and
/// leave the schema those migrations describe.
#[tokio::test]
async fn every_migration_after_v033_applies_to_a_real_v033_database() {
    let up = Upgraded::boot().await;
    let raw = up.raw();

    let mut stmt = raw
        .prepare("SELECT version FROM schema_migrations ORDER BY version")
        .expect("prepare");
    let applied: Vec<i64> = stmt
        .query_map([], |row| row.get(0))
        .expect("query")
        .map(|v| v.expect("row"))
        .collect();
    for version in 1..=20 {
        assert!(
            applied.contains(&version),
            "migration {version} must be applied, got {applied:?}"
        );
    }

    // 015: refresh tokens carry a family, existing rows rooting their own.
    let family: Option<String> = raw
        .query_row(
            "SELECT family_id FROM oauth_refresh_tokens LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("family_id column exists");
    assert!(family.is_some(), "the v0.3.3 refresh token got a family");

    // 016: the token and its client are bound to the workspace by id.
    let workspace_id = up.manifest["workspace"]["id"]
        .as_str()
        .expect("workspace id");
    let bound: String = raw
        .query_row(
            "SELECT workspace_id FROM oauth_access_tokens LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("workspace_id column exists");
    assert_eq!(
        bound, workspace_id,
        "the access token was backfilled to its workspace"
    );

    // 017: an enabled v0.3.3 workspace is active, not disabled.
    let status: String = raw
        .query_row("SELECT status FROM workspaces LIMIT 1", [], |row| {
            row.get(0)
        })
        .expect("status");
    assert_eq!(status, "active", "the workspace kept its lifecycle state");

    // 019: history rows carry the key version that sealed them.
    let key_version: i64 = raw
        .query_row(
            "SELECT key_version FROM credential_secret_history LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("key_version column exists");
    assert_eq!(key_version, 1, "v0.3.3 rows backfill to key version 1");

    // 020: the dead tables are gone.
    for table in [
        "workspace_used_jtis",
        "workspace_registrations",
        "provisioning_tokens",
        "crypto_state",
    ] {
        let count: i64 = raw
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .expect("sqlite_master");
        assert_eq!(count, 0, "{table} must be dropped by migration 020");
    }

    // 013 restores MCP↔workspace bindings; the fixture's must still be there.
    let bindings: i64 = raw
        .query_row("SELECT count(*) FROM mcp_server_workspaces", [], |row| {
            row.get(0)
        })
        .expect("bindings");
    assert_eq!(bindings, 1, "the MCP binding survived the upgrade");
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

/// Password hashes written by v0.3.3 still verify, for the root account, an
/// admin, and a viewer.
#[tokio::test]
async fn the_v033_users_still_log_in_with_their_v033_passwords() {
    let up = Upgraded::boot().await;

    for which in ["root", "admin", "viewer"] {
        let (username, password) = up.user(which);
        let (status, body) = send_json(
            &up.ctx.app,
            Method::POST,
            "/api/v1/auth/login",
            None,
            None,
            None,
            Some(json!({ "username": username, "password": password })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{which} login failed: {body}");
    }
}

/// The viewer is still a viewer: it reads, and it is refused a write only an
/// admin may make.
#[tokio::test]
async fn the_v033_viewer_role_still_holds() {
    let up = Upgraded::boot().await;
    let cookie = up.login("viewer").await;

    let (status, body) = send_json(
        &up.ctx.app,
        Method::GET,
        "/api/v1/auth/me",
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["role"], "viewer", "{body}");

    let (status, body) = send_json_auto_csrf(
        &up.ctx.app,
        Method::POST,
        "/api/v1/users",
        None,
        Some(&cookie),
        Some(json!({
            "username": "smuggled-in",
            "password": "smuggled-in-password",
            "role": "admin",
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a viewer must not create users: {body}"
    );
}

// ---------------------------------------------------------------------------
// The workspace and its tokens
// ---------------------------------------------------------------------------

/// The workspace's Ed25519 key still names it — the hash the v0.3.3 device
/// flow bound is the hash of the key file in the fixture directory, and it is
/// still on the workspace row — and the access token issued against that
/// identity still authenticates and vends.
#[tokio::test]
async fn the_v033_workspace_key_still_names_the_workspace_and_its_token_still_vends() {
    let up = Upgraded::boot().await;
    let workspace = &up.manifest["workspace"];

    // The key really is the workspace's: hash the public key from the seed.
    let seed = hex::decode(
        workspace["ed25519_seed_hex"]
            .as_str()
            .expect("ed25519 seed"),
    )
    .expect("hex seed");
    let signing_key =
        ed25519_dalek::SigningKey::from_bytes(&seed.try_into().expect("32-byte seed"));
    let pk_hash = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(signing_key.verifying_key().as_bytes()))
    };
    assert_eq!(
        pk_hash,
        workspace["pk_hash"].as_str().expect("pk_hash"),
        "the fixture key is the one the device flow bound"
    );

    let stored: Option<String> = up
        .raw()
        .query_row("SELECT pk_hash FROM workspaces LIMIT 1", [], |row| {
            row.get(0)
        })
        .expect("pk_hash");
    assert_eq!(
        stored.as_deref(),
        Some(pk_hash.as_str()),
        "the upgrade must not re-point or drop the workspace's identity"
    );

    // And the token that identity holds still vends, against a target the
    // credential's pattern allows.
    let access_token = up.manifest["oauth"]["access_token"]
        .as_str()
        .expect("access token");
    let name = up.manifest["credentials"]["plain"]["name"]
        .as_str()
        .expect("credential name");
    let (broker_private, broker_public) = broker_ecies_key();
    let (status, body) = send_json(
        &up.ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/vend-device/{name}"),
        Some(access_token),
        None,
        None,
        Some(json!({
            "method": "GET",
            "target_url": "https://api.example.com/v1/things",
            "broker_public_key": broker_public,
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the v0.3.3 access token must still vend: {body}"
    );

    // The envelope opens, and holds the secret v0.3.3 sealed.
    let material = open_envelope(&broker_private, &body["data"]["encrypted_envelope"]).await;
    assert_eq!(
        material["value"], up.manifest["credentials"]["plain"]["secret"],
        "the vended secret is the one stored under v0.3.3: {material}"
    );

    // The credential's v0.3.3 URL pattern came through the upgrade and is
    // now enforced on the vend itself.
    assert_eq!(
        body["data"]["allowed_url_pattern"],
        up.manifest["credentials"]["plain"]["allowed_url_pattern"],
        "{body}"
    );
    let (_, broker_public) = broker_ecies_key();
    let (status, body) = send_json(
        &up.ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/vend-device/{name}"),
        Some(access_token),
        None,
        None,
        Some(json!({
            "method": "GET",
            "target_url": "https://evil.example/steal",
            "broker_public_key": broker_public,
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the v0.3.3 pattern is enforced after the upgrade: {body}"
    );
}

/// Migration 016 rebinds tokens by workspace id rather than invalidating
/// them, so the rotating refresh token v0.3.3 issued still rotates.
#[tokio::test]
async fn the_v033_refresh_token_still_rotates() {
    let up = Upgraded::boot().await;
    let refresh = up.manifest["oauth"]["refresh_token"]
        .as_str()
        .expect("refresh token");
    let client_id = up.manifest["oauth"]["client_id"]
        .as_str()
        .expect("client id");

    let form = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}",
        urlencoding::encode(refresh),
        urlencoding::encode(client_id),
    );
    let (status, body) = send_form(&up.ctx.app, "/api/v1/oauth/token", &form).await;
    assert_eq!(status, StatusCode::OK, "refresh after upgrade: {body}");
    let rotated = body["access_token"]
        .as_str()
        .expect("access token")
        .to_string();
    assert!(body["refresh_token"].as_str().is_some(), "{body}");
    assert_ne!(
        body["refresh_token"].as_str(),
        Some(refresh),
        "rotation issues a new refresh token"
    );

    // The token the rotation minted carries the same workspace binding, so
    // it reaches the same v0.3.3 credential material.
    let name = up.manifest["credentials"]["plain"]["name"]
        .as_str()
        .expect("credential name");
    let (broker_private, broker_public) = broker_ecies_key();
    let (status, body) = send_json(
        &up.ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/vend-device/{name}"),
        Some(&rotated),
        None,
        None,
        Some(json!({
            "method": "GET",
            "target_url": "https://api.example.com/v1/things",
            "broker_public_key": broker_public,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the rotated token vends: {body}");
    let material = open_envelope(&broker_private, &body["data"]["encrypted_envelope"]).await;
    assert_eq!(
        material["value"], up.manifest["credentials"]["plain"]["secret"],
        "the rotated token reaches the v0.3.3 secret: {material}"
    );
}

// ---------------------------------------------------------------------------
// Ciphertext
// ---------------------------------------------------------------------------

/// The credential v0.3.3 sealed still opens, to the same plaintext.
#[tokio::test]
async fn a_credential_sealed_under_v033_still_decrypts_to_what_went_in() {
    let up = Upgraded::boot().await;
    let cookie = up.login("root").await;
    let credential = &up.manifest["credentials"]["plain"];

    let (status, body) = send_json_auto_csrf(
        &up.ctx.app,
        Method::POST,
        &format!(
            "/api/v1/credentials/{}/reveal",
            credential["id"].as_str().expect("credential id")
        ),
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "reveal after upgrade: {body}");
    assert_eq!(
        body["data"]["secret_value"], credential["secret"],
        "the plaintext must survive the upgrade unchanged"
    );
}

/// A rotation-history row written by v0.3.3 still decrypts: restore the most
/// recent archived secret and read it back.
#[tokio::test]
async fn a_v033_rotation_history_entry_still_decrypts() {
    let up = Upgraded::boot().await;
    let cookie = up.login("root").await;
    let credential = &up.manifest["credentials"]["rotated"];
    let id = credential["id"].as_str().expect("credential id");

    let (status, body) = send_json(
        &up.ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{id}/secret-history"),
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "history: {body}");
    let entries = body["data"].as_array().expect("history rows").clone();
    assert_eq!(entries.len(), 2, "the two v0.3.3 rotations are still there");

    // Newest first: the entry archived when v3 was written holds v2.
    let newest = entries[0]["id"].as_str().expect("history id");
    let (status, body) = send_json_auto_csrf(
        &up.ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{id}/secret-history/{newest}/restore"),
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "restore: {body}");

    let (status, body) = send_json_auto_csrf(
        &up.ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{id}/reveal"),
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "reveal restored: {body}");
    assert_eq!(
        body["data"]["secret_value"], credential["history_newest_first"][0],
        "the archived secret decrypts to what v0.3.3 archived"
    );
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/// Migration 020 drops tables. The audit trail is not one of them: every row
/// is still stored, and every row the list endpoint shows by default (it
/// hides `policy_evaluated`) is still readable, the v0.3.3 vend included.
#[tokio::test]
async fn the_v033_audit_trail_survives_the_upgrade() {
    let up = Upgraded::boot().await;
    let stored: u64 = up
        .raw()
        .query_row("SELECT count(*) FROM audit_events", [], |row| row.get(0))
        .expect("audit count");
    let expected_stored = up.manifest["row_counts"]["audit_events"]
        .as_u64()
        .expect("audit count");
    assert!(
        stored >= expected_stored,
        "all {expected_stored} v0.3.3 audit rows must survive, got {stored}"
    );

    let cookie = up.login("root").await;
    let expected_listed = up.manifest["row_counts"]["audit_events_excluding_policy_evaluated"]
        .as_u64()
        .expect("listable audit count");
    let (status, body) = send_json(
        &up.ctx.app,
        Method::GET,
        "/api/v1/audit?limit=500",
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows = body["data"].as_array().expect("audit rows");
    assert!(
        rows.len() as u64 >= expected_listed,
        "the {expected_listed} listable v0.3.3 audit events must still be readable, got {}",
        rows.len()
    );
    assert!(
        rows.iter()
            .any(|row| row["event_type"] == "credential_vended"
                || row["action"] == "vend_credential"),
        "the v0.3.3 vend is still in the trail: {body}"
    );
}

// ---------------------------------------------------------------------------
// The master secret
// ---------------------------------------------------------------------------

/// The v0.3.3 secret is weak by the rule introduced after it, and v0.3.3 fed
/// it to HKDF unchanged. Stretching it now would orphan every credential in
/// the database, so the upgrade must keep the legacy derivation, write no
/// salt file, and warn instead. `docs/master-key.md` names the fix.
#[tokio::test]
async fn a_weak_v033_master_secret_keeps_its_legacy_derivation() {
    let up = Upgraded::boot().await;

    let warning = up
        .ctx
        .master_secret_warning
        .as_deref()
        .expect("an upgrade on a weak secret warns rather than re-keying");
    assert!(warning.contains("AGTCRDN_MASTER_SECRET"), "{warning}");
    assert!(warning.contains("rotate"), "{warning}");

    let salt_file = up.db_path.parent().expect("db dir").join(".master-salt");
    assert!(
        !salt_file.exists(),
        "no salt may be written next to an existing install: it would change the key"
    );

    // And the key it kept is the one the ciphertext needs.
    let cookie = up.login("root").await;
    let credential = &up.manifest["credentials"]["plain"];
    let (status, body) = send_json_auto_csrf(
        &up.ctx.app,
        Method::POST,
        &format!(
            "/api/v1/credentials/{}/reveal",
            credential["id"].as_str().expect("credential id")
        ),
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["secret_value"], credential["secret"]);
}
