//! Master-secret rotation through the versioned key ring.
//!
//! The runbook in `docs/master-key.md` is: set the new secret, bump
//! `AGTCRDN_MASTER_KEY_VERSION`, keep the old secret in
//! `AGTCRDN_PREVIOUS_MASTER_SECRET`, restart, call `rotate-key`, drop the
//! previous secret, restart. Each app below is one restart of that runbook
//! over the same store.

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use serde_json::json;

use agent_cordon_core::domain::credential::CredentialId;
use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::storage::Store;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

use crate::common::*;

const S1: &str = "first-master-secret-with-16+chars";
const S2: &str = "second-master-secret-with-16+chars";
const ADMIN: &str = "ring-admin";

async fn login_admin(ctx: &TestContext) -> (String, String) {
    let (cookie, csrf) = login_user(&ctx.app, ADMIN, TEST_PASSWORD).await;
    (combined_cookie(&cookie, &csrf), csrf)
}

async fn create_credential(ctx: &TestContext, cookie: &str, csrf: &str, secret: &str) -> String {
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(cookie),
        Some(csrf),
        Some(json!({
            "name": "ring-cred",
            "service": "ring-test",
            "secret_value": secret,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create credential: {body}");
    body["data"]["id"]
        .as_str()
        .expect("credential id")
        .to_string()
}

async fn rotate_secret(ctx: &TestContext, cookie: &str, csrf: &str, cred_id: &str, secret: &str) {
    let (status, body) = send_json(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/credentials/{cred_id}"),
        None,
        Some(cookie),
        Some(csrf),
        Some(json!({ "secret_value": secret })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rotate secret: {body}");
}

async fn reveal(
    ctx: &TestContext,
    cookie: &str,
    csrf: &str,
    cred_id: &str,
) -> (StatusCode, String) {
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{cred_id}/reveal"),
        None,
        Some(cookie),
        Some(csrf),
        None,
    )
    .await;
    let value = body["data"]["secret_value"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    (status, value)
}

async fn history_ids(ctx: &TestContext, cookie: &str, csrf: &str, cred_id: &str) -> Vec<String> {
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
    assert_eq!(status, StatusCode::OK, "list history: {body}");
    body["data"]
        .as_array()
        .expect("history array")
        .iter()
        .map(|e| e["id"].as_str().expect("history id").to_string())
        .collect()
}

async fn restore(ctx: &TestContext, cookie: &str, csrf: &str, cred_id: &str, history_id: &str) {
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{cred_id}/secret-history/{history_id}/restore"),
        None,
        Some(cookie),
        Some(csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "restore {history_id}: {body}");
}

async fn key_version_of(store: &Arc<dyn Store + Send + Sync>, cred_id: &str) -> i64 {
    store
        .get_credential(&CredentialId(cred_id.parse().expect("uuid")))
        .await
        .expect("get credential")
        .expect("credential exists")
        .key_version
}

/// Rotation runbook end to end: a rollover window where both secrets
/// decrypt, `rotate-key` moving every credential and history row to the
/// new version, and the old secret being droppable afterwards.
#[tokio::test]
async fn master_secret_rotation_keeps_credentials_and_history_readable() {
    // ---- App A: secret S1, version 1. Creates a credential and one history row.
    let app_a = TestAppBuilder::new()
        .with_master_secret(S1, 1)
        .build()
        .await;
    create_test_user(&*app_a.store, ADMIN, TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_admin(&app_a).await;
    let cred_id = create_credential(&app_a, &cookie, &csrf, "original").await;
    rotate_secret(&app_a, &cookie, &csrf, &cred_id, "rotated").await;
    assert_eq!(key_version_of(&app_a.store, &cred_id).await, 1);
    let store = app_a.store.clone();

    // ---- App C (no previous secret) before rotate-key: nothing decrypts.
    let app_c = TestAppBuilder::new()
        .with_store(store.clone())
        .with_master_secret(S2, 2)
        .build()
        .await;
    let (cookie_c, csrf_c) = login_admin(&app_c).await;
    let (status, _) = reveal(&app_c, &cookie_c, &csrf_c, &cred_id).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a ring holding only S2 must not decrypt a row sealed under S1"
    );

    // ---- App B: secret S2 version 2, previous S1. The rollover window.
    let app_b = TestAppBuilder::new()
        .with_store(store.clone())
        .with_master_secret(S2, 2)
        .with_previous_master_secret(S1)
        .build()
        .await;
    let (cookie_b, csrf_b) = login_admin(&app_b).await;

    let (status, value) = reveal(&app_b, &cookie_b, &csrf_b, &cred_id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value, "rotated", "previous secret decrypts during rollover");

    let ids = history_ids(&app_b, &cookie_b, &csrf_b, &cred_id).await;
    assert_eq!(ids.len(), 1);
    restore(&app_b, &cookie_b, &csrf_b, &cred_id, &ids[0]).await;
    let (status, value) = reveal(&app_b, &cookie_b, &csrf_b, &cred_id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value, "original", "restored history row decrypts");
    assert_eq!(
        key_version_of(&store, &cred_id).await,
        1,
        "a restored row keeps the version it was sealed under"
    );

    // ---- rotate-key on app B moves everything to version 2.
    let (status, body) = send_json(
        &app_b.app,
        Method::POST,
        "/api/v1/admin/rotate-key",
        None,
        Some(&cookie_b),
        Some(&csrf_b),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rotate-key: {body}");
    assert_eq!(body["data"]["key_version"], 2);
    assert_eq!(body["data"]["re_encrypted_count"], 1);
    assert_eq!(body["data"]["total_credentials"], 1);
    assert_eq!(body["data"]["history_re_encrypted_count"], 2);
    assert_eq!(body["data"]["total_history_entries"], 2);
    assert_eq!(body["data"]["errors"].as_array().map(Vec::len), Some(0));
    assert_eq!(key_version_of(&store, &cred_id).await, 2);

    // ---- App C (still no previous secret) after rotate-key: everything reads.
    let (status, value) = reveal(&app_c, &cookie_c, &csrf_c, &cred_id).await;
    assert_eq!(status, StatusCode::OK, "S2 alone decrypts after rotate-key");
    assert_eq!(value, "original");

    let ids = history_ids(&app_c, &cookie_c, &csrf_c, &cred_id).await;
    assert_eq!(ids.len(), 2);
    // The newest entry holds "rotated" (archived by the restore on app B).
    restore(&app_c, &cookie_c, &csrf_c, &cred_id, &ids[0]).await;
    let (status, value) = reveal(&app_c, &cookie_c, &csrf_c, &cred_id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value, "rotated", "history re-encrypted under v2 restores");
    assert_eq!(key_version_of(&store, &cred_id).await, 2);
}

/// A credential created under version 2 is written with that version; a
/// secret rotation through PUT stamps the new ciphertext with the current
/// version and the archived one with the version it was sealed under.
#[tokio::test]
async fn new_rows_carry_the_current_key_version() {
    let app = TestAppBuilder::new()
        .with_master_secret(S2, 2)
        .build()
        .await;
    create_test_user(&*app.store, ADMIN, TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_admin(&app).await;
    let cred_id = create_credential(&app, &cookie, &csrf, "v2-secret").await;
    assert_eq!(key_version_of(&app.store, &cred_id).await, 2);

    rotate_secret(&app, &cookie, &csrf, &cred_id, "v2-secret-2").await;
    assert_eq!(key_version_of(&app.store, &cred_id).await, 2);
    let (status, value) = reveal(&app, &cookie, &csrf, &cred_id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value, "v2-secret-2");
}

// ---------------------------------------------------------------------------
// The re-seal has an audit event of its own
// ---------------------------------------------------------------------------

/// Read every audit row of one type, newest first.
async fn rows_of_type(ctx: &TestContext, event_type: &str) -> Vec<serde_json::Value> {
    ctx.store
        .list_audit_events_filtered(&agent_cordon_core::storage::AuditFilter {
            limit: 200,
            event_type: Some(event_type.to_string()),
            ..Default::default()
        })
        .await
        .expect("audit list")
        .into_iter()
        .map(|e| serde_json::to_value(e).expect("serialize"))
        .collect()
}

/// The row a re-seal wrote used to be typed `credential_secret_rotated` —
/// the same event a human rotating one credential's secret writes. The two
/// answer different questions ("who changed this secret?" and "has anyone
/// re-sealed this store?") and the only thing telling them apart was the
/// Resource column reading `system`, which meant eyeballing the log.
#[tokio::test]
async fn a_reseal_is_audited_as_a_master_key_reseal_not_a_secret_rotation() {
    let app = TestAppBuilder::new()
        .with_master_secret(S1, 1)
        .build()
        .await;
    create_test_user(&*app.store, ADMIN, TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_admin(&app).await;
    let cred_id = create_credential(&app, &cookie, &csrf, "original").await;
    // One genuine secret rotation, so both event types are present and have
    // to be told apart.
    rotate_secret(&app, &cookie, &csrf, &cred_id, "rotated").await;
    let rotations_before = rows_of_type(&app, "credential_secret_rotated").await.len();
    assert_eq!(rotations_before, 1, "the rotation itself is audited");

    let (status, body) = send_json(
        &app.app,
        Method::POST,
        "/api/v1/admin/rotate-key",
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rotate-key: {body}");

    let reseals = rows_of_type(&app, "master_key_resealed").await;
    assert_eq!(
        reseals.len(),
        1,
        "the re-seal writes one row of its own: {reseals:#?}"
    );
    let row = &reseals[0];
    assert_eq!(row["action"], "rotate_encryption_key", "{row}");
    assert_eq!(row["resource_type"], "system", "{row}");
    assert_eq!(row["decision"], "permit", "{row}");
    assert_eq!(
        row["metadata"]["key_version"], 1,
        "the row names the key version everything is now sealed under: {row}"
    );
    assert_eq!(row["metadata"]["re_encrypted_count"], 1, "{row}");
    assert_eq!(row["metadata"]["history_re_encrypted_count"], 1, "{row}");
    assert_eq!(row["metadata"]["error_count"], 0, "{row}");

    assert_eq!(
        rows_of_type(&app, "credential_secret_rotated").await.len(),
        rotations_before,
        "a re-seal is not a secret rotation and must not add one"
    );
}
