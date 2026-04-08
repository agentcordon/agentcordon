//! Integration test for the OAuth2 refresh-token rotation endpoint.
//!
//! Covers the end-to-end server path used by the broker when an upstream
//! OAuth2 provider rotates a refresh token:
//!   `POST /api/v1/workspaces/mcp/rotate-refresh-token`
//!
//! Protects against regression of the bug where a rotated refresh token was
//! discarded and the credential was left holding a dead token.

use axum::http::{Method, StatusCode};
use uuid::Uuid;

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::agent::AgentId;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_server::test_helpers::TestAppBuilder;
use serde_json::json;

use crate::common::*;

/// Seed an `oauth2_user_authorization` credential owned by the given workspace,
/// encrypted with the credential ID as AAD (matching the rotation handler's
/// encryption layout).
async fn seed_oauth2_user_credential(
    ctx: &agent_cordon_server::test_helpers::TestContext,
    workspace_uuid: Uuid,
    name: &str,
    initial_refresh_token: &str,
) -> CredentialId {
    let cred_id = CredentialId(Uuid::new_v4());
    let (ciphertext, nonce) = ctx
        .encryptor
        .encrypt(
            initial_refresh_token.as_bytes(),
            cred_id.0.to_string().as_bytes(),
        )
        .expect("encrypt initial refresh token");
    let now = chrono::Utc::now();
    let cred = StoredCredential {
        id: cred_id.clone(),
        name: name.to_string(),
        service: "notion".to_string(),
        encrypted_value: ciphertext,
        nonce,
        scopes: vec![],
        metadata: serde_json::json!({}),
        // `created_by` is the workspace that owns the credential. The
        // rotation route looks credentials up by (workspace_id, name), so
        // this field determines whether the caller can rotate it.
        created_by: Some(AgentId(workspace_uuid)),
        created_by_user: None,
        created_at: now,
        updated_at: now,
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: None,
        transform_name: Some("bearer".to_string()),
        vault: "default".to_string(),
        credential_type: "oauth2_user_authorization".to_string(),
        tags: vec![],
        description: Some("integration test oauth2 credential".to_string()),
        target_identity: None,
        key_version: 1,
    };
    ctx.store
        .store_credential(&cred)
        .await
        .expect("store credential");
    cred_id
}

/// Fetch a credential from the store and decrypt its secret value using the
/// credential ID as AAD.
async fn decrypt_stored_secret(
    ctx: &agent_cordon_server::test_helpers::TestContext,
    cred_id: &CredentialId,
) -> String {
    let cred = ctx
        .store
        .get_credential(cred_id)
        .await
        .expect("get credential")
        .expect("credential still present");
    let plaintext = ctx
        .encryptor
        .decrypt(
            &cred.encrypted_value,
            &cred.nonce,
            cred_id.0.to_string().as_bytes(),
        )
        .expect("decrypt refresh token");
    String::from_utf8(plaintext).expect("refresh token is valid utf-8")
}

/// End-to-end happy path: two sequential rotations both persist and the
/// stored credential reflects the latest value after each.
#[tokio::test]
async fn rotate_refresh_token_persists_two_sequential_rotations() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx
        .admin_agent
        .as_ref()
        .expect("admin workspace must exist");
    let ws_uuid = ws.id.0;

    let cred_id = seed_oauth2_user_credential(&ctx, ws_uuid, "notion-oauth", "REFRESH-V1").await;

    // Sanity: initial value decrypts to V1 before any rotation.
    assert_eq!(decrypt_stored_secret(&ctx, &cred_id).await, "REFRESH-V1");

    let jwt = ctx_admin_jwt(&ctx).await;

    // -- Rotation #1 --------------------------------------------------------
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/workspaces/mcp/rotate-refresh-token",
        Some(&jwt),
        None,
        None,
        Some(json!({
            "credential_name": "notion-oauth",
            "new_refresh_token": "REFRESH-V2",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "first rotation failed: {}", body);
    assert_eq!(body["data"]["rotated"].as_bool(), Some(true));

    // Credential in storage now decrypts to V2.
    assert_eq!(
        decrypt_stored_secret(&ctx, &cred_id).await,
        "REFRESH-V2",
        "first rotation did not persist"
    );

    // -- Rotation #2 --------------------------------------------------------
    // Simulates a second upstream refresh that again rotates the token. This
    // is the critical regression check: the previous bug left the credential
    // holding a dead V1 token after the first refresh consumed it, so this
    // second rotation would previously be rejected with `invalid_grant`.
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/workspaces/mcp/rotate-refresh-token",
        Some(&jwt),
        None,
        None,
        Some(json!({
            "credential_name": "notion-oauth",
            "new_refresh_token": "REFRESH-V3",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "second rotation failed: {}", body);
    assert_eq!(body["data"]["rotated"].as_bool(), Some(true));

    assert_eq!(
        decrypt_stored_secret(&ctx, &cred_id).await,
        "REFRESH-V3",
        "second rotation did not persist"
    );
}

/// Cross-workspace isolation: WS-B cannot rotate a credential owned by WS-A.
/// The response must be 404 (not-found oracle) — NOT 403 — so that the
/// endpoint cannot be used to probe for foreign credential names.
#[tokio::test]
async fn rotate_refresh_token_rejects_foreign_workspace() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws-b", &[])
        .build()
        .await;

    let ws_a = ctx.admin_agent.as_ref().unwrap();
    let cred_id = seed_oauth2_user_credential(&ctx, ws_a.id.0, "ws-a-oauth", "ORIGINAL").await;

    // WS-B attempts to rotate WS-A's credential.
    let jwt_b = ctx_agent_jwt(&ctx, "ws-b").await;
    let (status, _body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/workspaces/mcp/rotate-refresh-token",
        Some(&jwt_b),
        None,
        None,
        Some(json!({
            "credential_name": "ws-a-oauth",
            "new_refresh_token": "ATTACKER-REPLACEMENT",
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "foreign workspace must see 404, not 403 (no name oracle)"
    );

    // Credential must still decrypt to the ORIGINAL value.
    assert_eq!(
        decrypt_stored_secret(&ctx, &cred_id).await,
        "ORIGINAL",
        "cross-workspace rotation must not mutate storage"
    );
}
