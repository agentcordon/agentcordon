//! Integration tests for credential bug fixes:
//!
//! - B-006: Unique credential names — duplicate name returns 409
//! - B-007: Credential update (PUT) — update fields, verify changes, verify credential_type
//!   and secret_value cannot be changed, Cedar policy check
//! - B-008: Agent credential discovery — non-admin agent can list their permitted credentials
//!
//! These tests spin up the full Axum router with an in-memory SQLite store
//! and exercise the endpoints end-to-end using `tower::ServiceExt` (no TCP).

use crate::common::*;

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use axum::Router;
use serde_json::json;
use uuid::Uuid;

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::agent::Agent;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::storage::Store;

use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Build the full test app. Returns (router, store, state).
async fn setup_test_app() -> (
    Router,
    Arc<dyn Store + Send + Sync>,
    agent_cordon_server::state::AppState,
) {
    let ctx = TestAppBuilder::new().build().await;
    (ctx.app, ctx.store, ctx.state)
}

/// Login and return (combined_cookie, csrf_token) for backward compatibility with this file.
async fn login_combined(app: &Router, username: &str, password: &str) -> (String, String) {
    let (session, csrf) = login_user(app, username, password).await;
    (combined_cookie(&session, &csrf), csrf)
}

/// Store a credential directly in the DB owned by the given agent.
/// Grants read permission to the owner.
async fn store_test_credential(
    state: &agent_cordon_server::state::AppState,
    owner: &Agent,
    name: &str,
) -> CredentialId {
    let now = chrono::Utc::now();
    let cred_id = CredentialId(Uuid::new_v4());
    let (encrypted, nonce) = state
        .encryptor
        .encrypt(b"test-secret-value", cred_id.0.to_string().as_bytes())
        .expect("encrypt");
    let cred = StoredCredential {
        id: cred_id.clone(),
        name: name.to_string(),
        service: "test-service".to_string(),
        encrypted_value: encrypted,
        nonce,
        scopes: vec!["read".to_string()],
        metadata: json!({}),
        created_by: Some(owner.id.clone()),
        created_by_user: None,
        created_at: now,
        updated_at: now,
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: None,
        transform_name: None,
        vault: "default".to_string(),
        credential_type: "generic".to_string(),
        tags: vec![],
        description: None,
        target_identity: None,
        key_version: 1,
    };
    state
        .store
        .store_credential(&cred)
        .await
        .expect("store credential");

    // Grant all permissions to the owner agent
    for perm in &["read", "write", "delete", "delegated_use"] {
        grant_cedar_permission(state, &cred_id, &owner.id, perm).await;
    }

    cred_id
}

// ===========================================================================
// Tests: B-006 — Duplicate credential names are allowed (names are labels)
// ===========================================================================

#[tokio::test]
async fn test_duplicate_credential_name_allowed() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_combined(&app, "admin", TEST_PASSWORD).await;

    // Create first credential
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "shared-name",
            "service": "github",
            "secret_value": "ghp_test1111111111"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "first credential: {}", body);

    // Create second credential with the same name — should succeed
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "shared-name",
            "service": "slack",
            "secret_value": "xoxb-test2222222222"
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "duplicate name should succeed — names are labels, UUID is the key: {}",
        body
    );
}

#[tokio::test]
async fn test_different_credential_names_succeed() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_combined(&app, "admin", TEST_PASSWORD).await;

    // Create two credentials with different names — should both succeed
    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "cred-alpha",
            "service": "github",
            "secret_value": "ghp_test1111111111"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "cred-beta",
            "service": "github",
            "secret_value": "ghp_test2222222222"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ===========================================================================
// Tests: B-007 — Credential Update (PUT)
// ===========================================================================

#[tokio::test]
async fn test_update_credential_fields() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_combined(&app, "admin", TEST_PASSWORD).await;

    // Create a credential
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "update-me-cred",
            "service": "github",
            "secret_value": "ghp_test1111111111",
            "scopes": ["repo"],
            "tags": ["dev"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create: {}", body);
    let cred_id = body["data"]["id"].as_str().unwrap().to_string();

    // Update the credential
    let update_uri = format!("/api/v1/credentials/{}", cred_id);
    let (status, body) = send_json(
        &app,
        Method::PUT,
        &update_uri,
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "updated-cred-name",
            "service": "gitlab",
            "scopes": ["repo", "workflow"],
            "tags": ["dev", "staging"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "update: {}", body);
    let data = &body["data"];
    assert_eq!(data["name"], "updated-cred-name");
    assert_eq!(data["service"], "gitlab");

    // Verify via GET
    let (status, body) = send_json(
        &app,
        Method::GET,
        &update_uri,
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "get: {}", body);
    assert_eq!(body["data"]["name"], "updated-cred-name");
    assert_eq!(body["data"]["service"], "gitlab");
}

#[tokio::test]
async fn test_update_credential_name_uniqueness_check() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_combined(&app, "admin", TEST_PASSWORD).await;

    // Create two credentials
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "cred-one",
            "service": "github",
            "secret_value": "ghp_aaaa"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cred1_id = body["data"]["id"].as_str().unwrap().to_string();

    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "cred-two",
            "service": "slack",
            "secret_value": "xoxb_bbbb"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Rename cred-one to cred-two — names are not unique, this should succeed
    let update_uri = format!("/api/v1/credentials/{}", cred1_id);
    let (status, body) = send_json(
        &app,
        Method::PUT,
        &update_uri,
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "cred-two"
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "rename to existing name should succeed — names are labels: {}",
        body
    );
}

#[tokio::test]
async fn test_update_credential_nonexistent_returns_404() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_combined(&app, "admin", TEST_PASSWORD).await;

    let fake_id = Uuid::new_v4();
    let update_uri = format!("/api/v1/credentials/{}", fake_id);
    let (status, body) = send_json(
        &app,
        Method::PUT,
        &update_uri,
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "nonexistent-update"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "response: {}", body);
}

#[tokio::test]
async fn test_update_credential_policy_check_viewer_denied() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let _viewer = create_test_user(&*store, "viewer", TEST_PASSWORD, UserRole::Viewer).await;
    let (admin_cookie, admin_csrf) = login_combined(&app, "admin", TEST_PASSWORD).await;
    let (viewer_cookie, viewer_csrf) = login_combined(&app, "viewer", TEST_PASSWORD).await;

    // Create a credential as admin
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&admin_cookie),
        Some(&admin_csrf),
        Some(json!({
            "name": "admin-only-cred",
            "service": "github",
            "secret_value": "ghp_secret"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cred_id = body["data"]["id"].as_str().unwrap().to_string();

    // Try to update as viewer — should be denied by Cedar policy
    let update_uri = format!("/api/v1/credentials/{}", cred_id);
    let (status, body) = send_json(
        &app,
        Method::PUT,
        &update_uri,
        None,
        Some(&viewer_cookie),
        Some(&viewer_csrf),
        Some(json!({
            "name": "viewer-renamed"
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer should not be able to update: {}",
        body
    );
}

// ===========================================================================
// Tests: B-008 — Agent Credential Discovery
// ===========================================================================

#[tokio::test]
async fn test_agent_lists_only_permitted_credentials() {
    let (app, store, state) = setup_test_app().await;

    // Create two agents: one admin (to create credentials) and one non-admin (to test discovery)
    let (admin_agent, _admin_key) =
        create_agent_in_db(&*store, "admin-agent", vec!["admin"], true, None).await;
    let (viewer_agent, viewer_key) =
        create_agent_in_db(&*store, "viewer-agent", vec!["viewer"], true, None).await;

    // Create two credentials owned by admin
    let cred_a = store_test_credential(&state, &admin_agent, "cred-accessible").await;
    let _cred_b = store_test_credential(&state, &admin_agent, "cred-hidden").await;

    // Grant read permission on cred-accessible to the viewer agent via Cedar policy
    grant_cedar_permission(&state, &cred_a, &viewer_agent.id, "read").await;

    // Setup device + get JWT for viewer agent
    let qda = quick_device_setup(&state, &viewer_agent, &viewer_key).await;

    // Viewer agent lists credentials — should only see cred-accessible
    let (status, body) = send_json_dual_auth(
        &app,
        Method::GET,
        "/api/v1/credentials",
        &qda.device_signing_key,
        &qda.device_id,
        &qda.agent_jwt,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "agent list: {}", body);
    let creds = body["data"].as_array().expect("data should be an array");

    // The viewer agent should see cred-accessible (via explicit permission grant)
    let accessible_names: Vec<&str> = creds.iter().filter_map(|c| c["name"].as_str()).collect();

    assert!(
        accessible_names.contains(&"cred-accessible"),
        "viewer agent should see cred-accessible via explicit grant, got: {:?}",
        accessible_names
    );

    // Owner-scoped policies: cred-hidden is NOT visible because the viewer agent
    // has no ownership match and no explicit grant for it.
    assert!(
        !accessible_names.contains(&"cred-hidden"),
        "viewer agent should NOT see cred-hidden (no ownership or grant), got: {:?}",
        accessible_names
    );
}

#[tokio::test]
async fn test_agent_with_no_permissions_sees_empty_list() {
    let (app, store, state) = setup_test_app().await;

    // Create an admin agent that owns credentials
    let (admin_agent, _admin_key) =
        create_agent_in_db(&*store, "admin-agent-2", vec!["admin"], true, None).await;
    // Create a viewer agent with no permissions
    let (viewer_agent, viewer_key) =
        create_agent_in_db(&*store, "viewer-agent-2", vec!["viewer"], true, None).await;

    // Create a credential owned by admin
    let _cred = store_test_credential(&state, &admin_agent, "admin-only-cred").await;

    // Setup device + get JWT for viewer agent
    let qda = quick_device_setup(&state, &viewer_agent, &viewer_key).await;

    // Owner-scoped policies: agent with no ownership match and no explicit grants
    // should see an empty credential list.
    let (status, body) = send_json_dual_auth(
        &app,
        Method::GET,
        "/api/v1/credentials",
        &qda.device_signing_key,
        &qda.device_id,
        &qda.agent_jwt,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "agent list: {}", body);
    let creds = body["data"].as_array().expect("data should be an array");
    assert!(
        creds.is_empty(),
        "agent with no ownership or grants should see empty list, got: {:?}",
        creds
    );
}

#[tokio::test]
async fn test_user_lists_all_credentials_via_policy() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_combined(&app, "admin", TEST_PASSWORD).await;

    // Create a couple of credentials as admin user
    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "user-list-cred-1",
            "service": "github",
            "secret_value": "ghp_aaaa"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "user-list-cred-2",
            "service": "slack",
            "secret_value": "xoxb_bbbb"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Admin user lists all credentials — should see both
    let (status, body) = send_json(
        &app,
        Method::GET,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "admin list: {}", body);
    let creds = body["data"].as_array().expect("data should be an array");
    assert!(
        creds.len() >= 2,
        "admin should see at least 2 credentials, got: {}",
        creds.len()
    );
}

// ===========================================================================
// Tests: Credential Secret Reveal (POST /credentials/{id}/reveal)
// ===========================================================================

#[tokio::test]
async fn test_reveal_credential_admin_user_success() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_combined(&app, "admin", TEST_PASSWORD).await;

    // Create a credential via API
    let secret = "ghp_super_secret_token_12345";
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({
            "name": "reveal-test-cred",
            "service": "github",
            "secret_value": secret
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create: {}", body);
    let cred_id = body["data"]["id"].as_str().unwrap().to_string();

    // Reveal the secret
    let reveal_uri = format!("/api/v1/credentials/{}/reveal", cred_id);
    let (status, body) = send_json(
        &app,
        Method::POST,
        &reveal_uri,
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "reveal: {}", body);
    assert_eq!(
        body["data"]["secret_value"].as_str().unwrap(),
        secret,
        "revealed secret should match original"
    );
}

#[tokio::test]
async fn test_reveal_credential_viewer_denied() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let _viewer = create_test_user(&*store, "viewer", TEST_PASSWORD, UserRole::Viewer).await;
    let (admin_cookie, admin_csrf) = login_combined(&app, "admin", TEST_PASSWORD).await;
    let (viewer_cookie, viewer_csrf) = login_combined(&app, "viewer", TEST_PASSWORD).await;

    // Create a credential as admin
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&admin_cookie),
        Some(&admin_csrf),
        Some(json!({
            "name": "viewer-cant-reveal",
            "service": "github",
            "secret_value": "ghp_secret_value"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cred_id = body["data"]["id"].as_str().unwrap().to_string();

    // Viewer tries to reveal — should get 404 (not 403, to avoid leaking credential existence)
    let reveal_uri = format!("/api/v1/credentials/{}/reveal", cred_id);
    let (status, _body) = send_json(
        &app,
        Method::POST,
        &reveal_uri,
        None,
        Some(&viewer_cookie),
        Some(&viewer_csrf),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "viewer should be denied reveal (returns 404)"
    );
}

#[tokio::test]
async fn test_reveal_credential_agent_denied() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (admin_cookie, admin_csrf) = login_combined(&app, "admin", TEST_PASSWORD).await;

    // Create a credential as admin
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&admin_cookie),
        Some(&admin_csrf),
        Some(json!({
            "name": "agent-cant-reveal",
            "service": "github",
            "secret_value": "ghp_agent_test"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cred_id = body["data"]["id"].as_str().unwrap().to_string();

    // Create an admin-tagged agent
    let (_agent, agent_key) =
        create_agent_in_db(&*store, "admin-agent-reveal", vec!["admin"], true, None).await;

    // Agent tries to reveal — should be denied (endpoint uses AuthenticatedUser extractor)
    let reveal_uri = format!("/api/v1/credentials/{}/reveal", cred_id);
    let (status, _body) = send_json(
        &app,
        Method::POST,
        &reveal_uri,
        Some(&agent_key),
        None,
        None,
        None,
    )
    .await;
    // Agent auth won't work because the endpoint requires AuthenticatedUser (session cookie).
    // Without a session cookie, the request is rejected as unauthorized.
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "agent should be denied access to reveal endpoint"
    );
}

#[tokio::test]
async fn test_reveal_credential_nonexistent_returns_404() {
    let (app, store, _state) = setup_test_app().await;
    let _admin = create_test_user(&*store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let (cookie, csrf) = login_combined(&app, "admin", TEST_PASSWORD).await;

    let fake_id = Uuid::new_v4();
    let reveal_uri = format!("/api/v1/credentials/{}/reveal", fake_id);
    let (status, _body) = send_json(
        &app,
        Method::POST,
        &reveal_uri,
        None,
        Some(&cookie),
        Some(&csrf),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_reveal_credential_operator_success() {
    let (app, store, _state) = setup_test_app().await;
    let _operator = create_test_user(&*store, "operator", TEST_PASSWORD, UserRole::Operator).await;
    let (op_cookie, op_csrf) = login_combined(&app, "operator", TEST_PASSWORD).await;

    // Operator creates their OWN credential (owner-scoped unprotect policy)
    let secret = "op-secret-value-xyz";
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&op_cookie),
        Some(&op_csrf),
        Some(json!({
            "name": "op-reveal-cred",
            "service": "slack",
            "secret_value": secret
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "operator create: {}", body);
    let cred_id = body["data"]["id"].as_str().unwrap().to_string();

    // Operator reveals their own credential — should succeed
    let reveal_uri = format!("/api/v1/credentials/{}/reveal", cred_id);
    let (status, body) = send_json(
        &app,
        Method::POST,
        &reveal_uri,
        None,
        Some(&op_cookie),
        Some(&op_csrf),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "operator reveal own credential: {}",
        body
    );
    assert_eq!(
        body["data"]["secret_value"].as_str().unwrap(),
        secret,
        "operator should see the correct secret for own credential"
    );
}
