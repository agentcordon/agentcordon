//! v3.1.1 — Credential name scoping tests.
//!
//! Credential names are no longer unique (migration 006 dropped unique indexes).
//! Vend-by-name now uses Cedar-filtered matching: list all credentials, filter
//! by name, evaluate Cedar authorization, return the authorized one (or 300 if
//! ambiguous).

use crate::common::*;

use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::http::{Method, StatusCode};
use serde_json::json;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a credential via the admin API, returning (id, status).
async fn create_credential_as(
    app: &axum::Router,
    cookie: &str,
    csrf: &str,
    name: &str,
    service: &str,
    secret: &str,
) -> (StatusCode, serde_json::Value) {
    send_json(
        app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(cookie),
        Some(csrf),
        Some(json!({
            "name": name,
            "service": service,
            "secret_value": secret
        })),
    )
    .await
}

/// Store a credential directly in the DB (bypassing API) and return its ID.
/// Does NOT create any Cedar policy — caller must grant permissions separately.
async fn store_raw_credential(
    state: &agent_cordon_server::state::AppState,
    name: &str,
    service: &str,
    secret: &str,
) -> CredentialId {
    use agent_cordon_core::crypto::SecretEncryptor;

    let now = chrono::Utc::now();
    let cred_id = CredentialId(uuid::Uuid::new_v4());
    let (encrypted, nonce) = state
        .encryptor
        .encrypt(secret.as_bytes(), cred_id.0.to_string().as_bytes())
        .expect("encrypt");
    let cred = StoredCredential {
        id: cred_id.clone(),
        name: name.to_string(),
        service: service.to_string(),
        encrypted_value: encrypted,
        nonce,
        scopes: vec![],
        metadata: json!({}),
        created_by: None,
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
        description: Some(format!("{} credential", service)),
        target_identity: None,
        key_version: 1,
    };
    state
        .store
        .store_credential(&cred)
        .await
        .expect("store credential");
    cred_id
}

/// Grant vend_credential permission to a workspace for a specific credential.
async fn grant_vend_permission(
    state: &agent_cordon_server::state::AppState,
    cred_id: &CredentialId,
    workspace_id: &agent_cordon_core::domain::workspace::WorkspaceId,
) {
    grant_cedar_permission(state, cred_id, workspace_id, "delegated_use").await;
}

// ===========================================================================
// 1. Two users can create credentials with the same name
// ===========================================================================

#[tokio::test]
async fn test_two_users_same_credential_name() {
    let ctx = TestAppBuilder::new().build().await;

    // Create two admin users
    let _user_a =
        create_test_user(&*ctx.store, "alice", TEST_PASSWORD, UserRole::Admin).await;
    let _user_b =
        create_test_user(&*ctx.store, "bob", TEST_PASSWORD, UserRole::Admin).await;

    let cookie_a = login_user_combined(&ctx.app, "alice", TEST_PASSWORD).await;
    let cookie_b = login_user_combined(&ctx.app, "bob", TEST_PASSWORD).await;
    let csrf_a = extract_csrf_from_cookie(&cookie_a).unwrap();
    let csrf_b = extract_csrf_from_cookie(&cookie_b).unwrap();

    // Alice creates "github-pat"
    let (status_a, body_a) = create_credential_as(
        &ctx.app,
        &cookie_a,
        &csrf_a,
        "github-pat",
        "github",
        "ghp_alice_secret",
    )
    .await;
    assert_eq!(status_a, StatusCode::OK, "alice create: {}", body_a);
    let id_a = body_a["data"]["id"].as_str().unwrap().to_string();

    // Bob creates "github-pat" — same name, should succeed
    let (status_b, body_b) = create_credential_as(
        &ctx.app,
        &cookie_b,
        &csrf_b,
        "github-pat",
        "github",
        "ghp_bob_secret",
    )
    .await;
    assert_eq!(status_b, StatusCode::OK, "bob create: {}", body_b);
    let id_b = body_b["data"]["id"].as_str().unwrap().to_string();

    // Different UUIDs
    assert_ne!(id_a, id_b, "credentials should have different UUIDs");
}

// ===========================================================================
// 2. Same user can create duplicate-named credentials
// ===========================================================================

#[tokio::test]
async fn test_same_user_duplicate_name_succeeds() {
    let ctx = TestAppBuilder::new().build().await;

    let _user = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin", TEST_PASSWORD).await;
    let csrf = extract_csrf_from_cookie(&cookie).unwrap();

    let (s1, b1) = create_credential_as(
        &ctx.app,
        &cookie,
        &csrf,
        "github-pat",
        "github",
        "ghp_first",
    )
    .await;
    assert_eq!(s1, StatusCode::OK, "first create: {}", b1);
    let id1 = b1["data"]["id"].as_str().unwrap().to_string();

    let (s2, b2) = create_credential_as(
        &ctx.app,
        &cookie,
        &csrf,
        "github-pat",
        "github",
        "ghp_second",
    )
    .await;
    assert_eq!(s2, StatusCode::OK, "second create: {}", b2);
    let id2 = b2["data"]["id"].as_str().unwrap().to_string();

    assert_ne!(id1, id2, "duplicate names must produce distinct credentials");
}

// ===========================================================================
// 3. Vend resolves the authorized credential
// ===========================================================================

#[tokio::test]
async fn test_vend_resolves_authorized_credential() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws-requester", &[])
        .build()
        .await;

    let ws = ctx.agents.get("ws-requester").unwrap();

    // Create two credentials with the same name
    let cred_a = store_raw_credential(&ctx.state, "shared-cred", "github", "secret-a").await;
    let cred_b = store_raw_credential(&ctx.state, "shared-cred", "slack", "secret-b").await;

    // Grant vend permission only for cred_a to ws-requester
    grant_vend_permission(&ctx.state, &cred_a, &ws.id).await;

    let jwt = ctx_agent_jwt(&ctx, "ws-requester").await;

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/vend-device/shared-cred",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "vend should resolve to the single authorized credential: {}",
        body
    );
    // Should get back a vend response with a vend_id
    assert!(
        body["data"]["vend_id"].as_str().is_some(),
        "response should contain vend_id: {}",
        body
    );

    // Verify it was cred_a that was vended (not cred_b)
    // We can't directly see the cred ID in the vend response, but we know
    // cred_b was NOT authorized so if vend succeeded it must be cred_a.
    let _ = cred_b; // used above for setup
}

// ===========================================================================
// 4. Vend ambiguous returns 300
// ===========================================================================

#[tokio::test]
async fn test_vend_ambiguous_returns_300() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws-ambiguous", &[])
        .build()
        .await;

    let ws = ctx.agents.get("ws-ambiguous").unwrap();

    // Create two credentials with the same name
    let cred_a = store_raw_credential(&ctx.state, "ambig-cred", "github", "secret-a").await;
    let cred_b = store_raw_credential(&ctx.state, "ambig-cred", "slack", "secret-b").await;

    // Grant vend permission for BOTH
    grant_vend_permission(&ctx.state, &cred_a, &ws.id).await;
    grant_vend_permission(&ctx.state, &cred_b, &ws.id).await;

    let jwt = ctx_agent_jwt(&ctx, "ws-ambiguous").await;

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/vend-device/ambig-cred",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::MULTIPLE_CHOICES,
        "ambiguous vend should return 300: {}",
        body
    );
}

// ===========================================================================
// 5. Vend no match returns 404
// ===========================================================================

#[tokio::test]
async fn test_vend_no_match_returns_404() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws-nomatch", &[])
        .build()
        .await;

    let jwt = ctx_agent_jwt(&ctx, "ws-nomatch").await;

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/vend-device/nonexistent-credential",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "vend for nonexistent credential should return 404: {}",
        body
    );
}

// ===========================================================================
// 6. Rename to existing name succeeds
// ===========================================================================

#[tokio::test]
async fn test_rename_to_existing_name_succeeds() {
    let ctx = TestAppBuilder::new().build().await;

    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin", TEST_PASSWORD).await;
    let csrf = extract_csrf_from_cookie(&cookie).unwrap();

    // Create cred-a and cred-b
    let (s1, b1) = create_credential_as(
        &ctx.app,
        &cookie,
        &csrf,
        "cred-a",
        "github",
        "ghp_aaaa",
    )
    .await;
    assert_eq!(s1, StatusCode::OK, "create cred-a: {}", b1);
    let id_a = b1["data"]["id"].as_str().unwrap().to_string();

    let (s2, b2) = create_credential_as(
        &ctx.app,
        &cookie,
        &csrf,
        "cred-b",
        "slack",
        "xoxb_bbbb",
    )
    .await;
    assert_eq!(s2, StatusCode::OK, "create cred-b: {}", b2);

    // Rename cred-a to "cred-b" — should succeed since names are not unique
    let update_uri = format!("/api/v1/credentials/{}", id_a);
    let (status, body) = send_json(
        &ctx.app,
        Method::PUT,
        &update_uri,
        None,
        Some(&cookie),
        Some(&csrf),
        Some(json!({ "name": "cred-b" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "rename to existing name should succeed: {}",
        body
    );
    assert_eq!(body["data"]["name"], "cred-b");
}

// ===========================================================================
// 7. 300 response contains candidates with correct fields
// ===========================================================================

#[tokio::test]
async fn test_300_response_contains_candidates() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws-candidates", &[])
        .build()
        .await;

    let ws = ctx.agents.get("ws-candidates").unwrap();

    let cred_a = store_raw_credential(&ctx.state, "multi-cred", "github", "secret-a").await;
    let cred_b = store_raw_credential(&ctx.state, "multi-cred", "slack", "secret-b").await;

    grant_vend_permission(&ctx.state, &cred_a, &ws.id).await;
    grant_vend_permission(&ctx.state, &cred_b, &ws.id).await;

    let jwt = ctx_agent_jwt(&ctx, "ws-candidates").await;

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/vend-device/multi-cred",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::MULTIPLE_CHOICES, "should be 300: {}", body);

    // Verify candidates structure
    let candidates = body["error"]["candidates"]
        .as_array()
        .expect("response should have error.candidates array");
    assert_eq!(candidates.len(), 2, "should have 2 candidates");

    for candidate in candidates {
        assert!(
            candidate["id"].as_str().is_some(),
            "candidate must have id: {}",
            candidate
        );
        assert!(
            candidate["name"].as_str().is_some(),
            "candidate must have name: {}",
            candidate
        );
        assert!(
            candidate["service"].as_str().is_some(),
            "candidate must have service: {}",
            candidate
        );
        // description may be null but key should exist
        assert!(
            candidate.get("description").is_some(),
            "candidate must have description field: {}",
            candidate
        );
    }

    // Verify the candidate IDs match the credentials we created
    let candidate_ids: Vec<&str> = candidates
        .iter()
        .filter_map(|c| c["id"].as_str())
        .collect();
    assert!(
        candidate_ids.contains(&cred_a.0.to_string().as_str()),
        "candidates should include cred_a"
    );
    assert!(
        candidate_ids.contains(&cred_b.0.to_string().as_str()),
        "candidates should include cred_b"
    );
}

// ===========================================================================
// 8. 300 candidates only includes authorized credentials
// ===========================================================================

#[tokio::test]
async fn test_300_candidates_only_authorized() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws-filtered", &[])
        .build()
        .await;

    let ws = ctx.agents.get("ws-filtered").unwrap();

    // Create 3 credentials with the same name
    let cred_a = store_raw_credential(&ctx.state, "filtered-cred", "github", "secret-a").await;
    let cred_b = store_raw_credential(&ctx.state, "filtered-cred", "slack", "secret-b").await;
    let cred_c = store_raw_credential(&ctx.state, "filtered-cred", "jira", "secret-c").await;

    // Grant vend permission to only 2 of 3
    grant_vend_permission(&ctx.state, &cred_a, &ws.id).await;
    grant_vend_permission(&ctx.state, &cred_b, &ws.id).await;
    // cred_c is NOT authorized

    let jwt = ctx_agent_jwt(&ctx, "ws-filtered").await;

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/vend-device/filtered-cred",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::MULTIPLE_CHOICES,
        "should be 300 with 2 authorized matches: {}",
        body
    );

    let candidates = body["error"]["candidates"]
        .as_array()
        .expect("should have candidates");
    assert_eq!(
        candidates.len(),
        2,
        "should have exactly 2 candidates (not 3): {:?}",
        candidates
    );

    let candidate_ids: Vec<&str> = candidates
        .iter()
        .filter_map(|c| c["id"].as_str())
        .collect();
    assert!(
        candidate_ids.contains(&cred_a.0.to_string().as_str()),
        "candidates should include cred_a"
    );
    assert!(
        candidate_ids.contains(&cred_b.0.to_string().as_str()),
        "candidates should include cred_b"
    );
    assert!(
        !candidate_ids.contains(&cred_c.0.to_string().as_str()),
        "candidates should NOT include unauthorized cred_c"
    );
}

// ===========================================================================
// 9. Vend unauthorized matches are invisible (not 300)
// ===========================================================================

/// Create 3 credentials all named "github-pat". Grant workspace access to only
/// 1 of them. Vend by name → should return the single authorized credential
/// (200), NOT a 300. The workspace should have no indication that the other 2
/// exist. Unauthorized credentials are completely invisible in resolution.
#[tokio::test]
async fn test_vend_unauthorized_matches_invisible() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws-invisible", &[])
        .build()
        .await;

    let ws = ctx.agents.get("ws-invisible").unwrap();

    // Create 3 credentials with the same name
    let cred_a = store_raw_credential(&ctx.state, "github-pat", "github", "secret-a").await;
    let cred_b = store_raw_credential(&ctx.state, "github-pat", "gitlab", "secret-b").await;
    let cred_c = store_raw_credential(&ctx.state, "github-pat", "bitbucket", "secret-c").await;

    // Grant vend permission ONLY for cred_a
    grant_vend_permission(&ctx.state, &cred_a, &ws.id).await;

    let jwt = ctx_agent_jwt(&ctx, "ws-invisible").await;

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/vend-device/github-pat",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;

    // Should be 200 (single vend), NOT 300 (ambiguous)
    assert_eq!(
        status,
        StatusCode::OK,
        "workspace should see only the 1 authorized credential, got: {}",
        body
    );
    assert!(
        body["data"]["vend_id"].as_str().is_some(),
        "response should contain vend_id: {}",
        body
    );

    // The other 2 credentials are invisible — no indication they exist
    let _ = (cred_b, cred_c);
}

// ===========================================================================
// 10. Vend expired credential that is authorized
// ===========================================================================

/// Create an expired credential, grant workspace access. Vend by name should
/// fail with a forbidden/expired error, NOT 404. The credential is found and
/// authorized, but can't be vended because it's expired. Expiry is checked
/// after Cedar authorization, not before.
#[tokio::test]
async fn test_vend_expired_credential_authorized() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws-expired", &[])
        .build()
        .await;

    let ws = ctx.agents.get("ws-expired").unwrap();

    // Store a credential with a past expires_at
    let cred_id = {
        use agent_cordon_core::crypto::SecretEncryptor;

        let cred_id = CredentialId(uuid::Uuid::new_v4());
        let (encrypted, nonce) = ctx
            .state
            .encryptor
            .encrypt(
                b"expired-secret",
                cred_id.0.to_string().as_bytes(),
            )
            .expect("encrypt");
        let now = chrono::Utc::now();
        let past = now - chrono::Duration::hours(24);
        let cred = StoredCredential {
            id: cred_id.clone(),
            name: "github-pat".to_string(),
            service: "github".to_string(),
            encrypted_value: encrypted,
            nonce,
            scopes: vec![],
            metadata: json!({}),
            created_by: None,
            created_by_user: None,
            created_at: now,
            updated_at: now,
            allowed_url_pattern: None,
            expires_at: Some(past),
            transform_script: None,
            transform_name: None,
            vault: "default".to_string(),
            credential_type: "generic".to_string(),
            tags: vec![],
            description: Some("expired credential".to_string()),
            target_identity: None,
            key_version: 1,
        };
        ctx.state
            .store
            .store_credential(&cred)
            .await
            .expect("store expired credential");
        cred_id
    };

    // Grant vend permission
    grant_vend_permission(&ctx.state, &cred_id, &ws.id).await;

    let jwt = ctx_agent_jwt(&ctx, "ws-expired").await;

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/vend-device/github-pat",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;

    // Should NOT be 404 — the credential exists and is authorized.
    // Should fail because it's expired (403 Forbidden).
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "expired credential should NOT return 404: {}",
        body
    );
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "expired credential should return 403: {}",
        body
    );
}

// ===========================================================================
// 11. List credentials with duplicate names
// ===========================================================================

/// Call GET /api/v1/credentials when two credentials with the same name exist.
/// Verify both appear in the response with distinct UUIDs.
#[tokio::test]
async fn test_list_credentials_duplicate_names() {
    let ctx = TestAppBuilder::new().build().await;

    let _admin =
        create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin", TEST_PASSWORD).await;
    let csrf = extract_csrf_from_cookie(&cookie).unwrap();

    // Create two credentials with the same name
    let (s1, b1) = create_credential_as(
        &ctx.app,
        &cookie,
        &csrf,
        "dup-name",
        "github",
        "ghp_first",
    )
    .await;
    assert_eq!(s1, StatusCode::OK, "first create: {}", b1);
    let id1 = b1["data"]["id"].as_str().unwrap().to_string();

    let (s2, b2) = create_credential_as(
        &ctx.app,
        &cookie,
        &csrf,
        "dup-name",
        "slack",
        "xoxb_second",
    )
    .await;
    assert_eq!(s2, StatusCode::OK, "second create: {}", b2);
    let id2 = b2["data"]["id"].as_str().unwrap().to_string();

    assert_ne!(id1, id2);

    // List all credentials
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list: {}", body);

    let creds = body["data"].as_array().expect("data should be array");
    let matching: Vec<&serde_json::Value> = creds
        .iter()
        .filter(|c| c["name"].as_str() == Some("dup-name"))
        .collect();
    assert_eq!(
        matching.len(),
        2,
        "both duplicate-named credentials should appear in list"
    );

    let listed_ids: Vec<&str> = matching
        .iter()
        .filter_map(|c| c["id"].as_str())
        .collect();
    assert!(listed_ids.contains(&id1.as_str()), "should include first credential");
    assert!(listed_ids.contains(&id2.as_str()), "should include second credential");
}

// ===========================================================================
// 12. by-name endpoint with duplicates
// ===========================================================================

/// Call GET /api/v1/credentials/by-name/{name} when two credentials with that
/// name exist. Documents current behavior (returns one arbitrarily).
///
/// NOTE: SEC flagged this as a known limitation — the by-name endpoint uses
/// `get_credential_by_name` which returns a single result. When duplicates
/// exist, the returned credential is non-deterministic (depends on DB ordering).
#[tokio::test]
async fn test_by_name_endpoint_with_duplicates() {
    let ctx = TestAppBuilder::new().build().await;

    let _admin =
        create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let cookie = login_user_combined(&ctx.app, "admin", TEST_PASSWORD).await;
    let csrf = extract_csrf_from_cookie(&cookie).unwrap();

    // Create two credentials with the same name
    let (s1, b1) = create_credential_as(
        &ctx.app,
        &cookie,
        &csrf,
        "byname-dup",
        "github",
        "ghp_first",
    )
    .await;
    assert_eq!(s1, StatusCode::OK, "first create: {}", b1);
    let id1 = b1["data"]["id"].as_str().unwrap().to_string();

    let (s2, b2) = create_credential_as(
        &ctx.app,
        &cookie,
        &csrf,
        "byname-dup",
        "slack",
        "xoxb_second",
    )
    .await;
    assert_eq!(s2, StatusCode::OK, "second create: {}", b2);
    let id2 = b2["data"]["id"].as_str().unwrap().to_string();

    // GET by name — now returns 300 MultipleChoices when both are authorized
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials/by-name/byname-dup",
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::MULTIPLE_CHOICES,
        "by-name lookup with duplicates should return 300: {}",
        body
    );

    // Verify candidates contain both credentials
    let candidates = body["error"]["candidates"]
        .as_array()
        .expect("should have candidates array");
    assert_eq!(candidates.len(), 2, "should have 2 candidates");
    let candidate_ids: Vec<&str> = candidates
        .iter()
        .filter_map(|c| c["id"].as_str())
        .collect();
    assert!(candidate_ids.contains(&id1.as_str()), "should contain id1");
    assert!(candidate_ids.contains(&id2.as_str()), "should contain id2");
}

// ===========================================================================
// 13. 300 not returned when only one is authorized
// ===========================================================================

/// Create 3 credentials named "github-pat". Grant workspace access to exactly 1.
/// Vend by name → 200 (single vend with encrypted_envelope), NOT 300.
/// Explicitly asserts the response is a successful vend response.
#[tokio::test]
async fn test_300_not_returned_when_one_authorized() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws-single-auth", &[])
        .build()
        .await;

    let ws = ctx.agents.get("ws-single-auth").unwrap();

    let cred_a = store_raw_credential(&ctx.state, "github-pat", "github", "secret-a").await;
    let cred_b = store_raw_credential(&ctx.state, "github-pat", "gitlab", "secret-b").await;
    let cred_c = store_raw_credential(&ctx.state, "github-pat", "bitbucket", "secret-c").await;

    // Grant vend permission for ONLY cred_a
    grant_vend_permission(&ctx.state, &cred_a, &ws.id).await;

    let jwt = ctx_agent_jwt(&ctx, "ws-single-auth").await;

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/vend-device/github-pat",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;

    // Must NOT be 300
    assert_ne!(
        status,
        StatusCode::MULTIPLE_CHOICES,
        "should not return 300 when only 1 is authorized: {}",
        body
    );
    // Must be 200 with a vend response
    assert_eq!(status, StatusCode::OK, "should be 200: {}", body);
    assert!(
        body["data"]["vend_id"].as_str().is_some(),
        "response should contain vend_id: {}",
        body
    );
    assert!(
        body["data"]["encrypted_envelope"].is_object(),
        "response should contain encrypted_envelope: {}",
        body
    );

    let _ = (cred_b, cred_c);
}

// ===========================================================================
// 14. Vend by URL-encoded name with spaces
// ===========================================================================

/// Create a credential named "my api key" (with spaces). Vend by name with the
/// URL-encoded path → should resolve correctly.
#[tokio::test]
async fn test_vend_name_url_encoded() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws-urlenc", &[])
        .build()
        .await;

    let ws = ctx.agents.get("ws-urlenc").unwrap();

    let cred = store_raw_credential(&ctx.state, "my api key", "github", "secret-spaces").await;
    grant_vend_permission(&ctx.state, &cred, &ws.id).await;

    let jwt = ctx_agent_jwt(&ctx, "ws-urlenc").await;

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/vend-device/my%20api%20key",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "URL-encoded name should resolve correctly: {}",
        body
    );
    assert!(
        body["data"]["vend_id"].as_str().is_some(),
        "response should contain vend_id: {}",
        body
    );
}
