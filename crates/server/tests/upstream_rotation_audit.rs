//! A provider-rotated refresh token is archived and audited.
//!
//! The server, not the broker, runs the upstream `refresh_token` exchange,
//! so when a provider rotates the refresh token the new one is written on
//! the server. That write replaces a long-lived secret behind the operator's
//! back: without a history row the previous token is gone, and without an
//! audit row nothing records that it changed. Both are asserted here through
//! the sync route and the admin API, against a wiremock token endpoint.

use axum::http::{Method, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde_json::{json, Value};
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::mcp::{McpAuthMethod, McpServer, McpServerId, McpTransport};
use agent_cordon_core::domain::oauth_provider_client::{
    OAuthProviderClient, OAuthProviderClientId, RegistrationSource,
};
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_core::storage::AuditFilter;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

use crate::common::{
    create_root_user, ctx_admin_jwt, grant_cedar_permission, login_user_combined, send_json,
    send_json_auto_csrf, TEST_PASSWORD,
};

const REFRESH_TOKEN: &str = "REFRESH-TOKEN-original";
const ROTATED_REFRESH_TOKEN: &str = "REFRESH-TOKEN-rotated-by-provider";
const PROVIDER_CLIENT_SECRET: &str = "PROVIDER-CLIENT-SECRET";

async fn seed_provider_client(ctx: &TestContext, as_url: &str) {
    let id = OAuthProviderClientId(Uuid::new_v4());
    let (encrypted, nonce) = ctx
        .encryptor
        .encrypt(
            PROVIDER_CLIENT_SECRET.as_bytes(),
            id.0.to_string().as_bytes(),
        )
        .expect("encrypt client secret");
    let now = chrono::Utc::now();
    ctx.store
        .create_oauth_provider_client(&OAuthProviderClient {
            id,
            authorization_server_url: as_url.to_string(),
            issuer: None,
            authorize_endpoint: format!("{as_url}/authorize"),
            token_endpoint: format!("{as_url}/token"),
            registration_endpoint: None,
            code_challenge_methods_supported: vec![],
            token_endpoint_auth_methods_supported: vec![],
            scopes_supported: vec![],
            client_id: "provider-client-id".to_string(),
            encrypted_client_secret: Some(encrypted),
            nonce: Some(nonce),
            requested_scopes: String::new(),
            registration_source: RegistrationSource::Manual,
            client_id_issued_at: None,
            client_secret_expires_at: None,
            registration_access_token_encrypted: None,
            registration_access_token_nonce: None,
            registration_client_uri: None,
            label: "test provider".to_string(),
            enabled: true,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("create provider client");
}

async fn seed_credential(ctx: &TestContext, name: &str, provider: &MockServer) -> CredentialId {
    let cred_id = CredentialId(Uuid::new_v4());
    let (ciphertext, nonce) = ctx
        .encryptor
        .encrypt(REFRESH_TOKEN.as_bytes(), cred_id.0.to_string().as_bytes())
        .expect("encrypt secret");
    let now = chrono::Utc::now();
    ctx.store
        .store_credential(&StoredCredential {
            id: cred_id.clone(),
            name: name.to_string(),
            service: "upstream".to_string(),
            encrypted_value: ciphertext,
            nonce,
            scopes: vec![],
            metadata: json!({
                "oauth2_token_url": format!("{}/token", provider.uri()),
                "oauth2_client_id": "provider-client-id",
                "authorization_server_url": provider.uri(),
            }),
            created_by: None,
            created_by_user: None,
            created_at: now,
            updated_at: now,
            allowed_url_pattern: None,
            expires_at: None,
            transform_script: None,
            transform_name: Some("bearer".to_string()),
            vault_id: agent_cordon_core::domain::vault::DEFAULT_VAULT_ID.to_string(),
            vault_name: "default".to_string(),
            credential_type: "oauth2_user_authorization".to_string(),
            tags: vec![],
            description: None,
            target_identity: None,
            key_version: 1,
        })
        .await
        .expect("store credential");
    cred_id
}

async fn seed_mcp_server(ctx: &TestContext, workspace_id: &WorkspaceId, cred: &CredentialId) {
    let now = chrono::Utc::now();
    let server = McpServer {
        id: McpServerId(Uuid::new_v4()),
        workspace_id: Some(workspace_id.clone()),
        name: "rotating".to_string(),
        upstream_url: "https://mcp.example.com/rotating".to_string(),
        transport: McpTransport::Sse,
        allowed_tools: Some(vec!["tool_a".to_string()]),
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials: Some(vec![cred.clone()]),
        auth_method: McpAuthMethod::OAuth2,
        template_key: None,
        discovered_tools: None,
        created_by_user: None,
    };
    ctx.store.create_mcp_server(&server).await.expect("create");
    ctx.store
        .add_mcp_server_workspace(&server.id, workspace_id, None)
        .await
        .expect("bind");
    grant_cedar_permission(&ctx.state, cred, workspace_id, "delegated_use").await;
}

/// Run the broker's MCP sync, which is what triggers the upstream exchange.
async fn sync(ctx: &TestContext) -> (StatusCode, Value) {
    let secret_key = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let broker_pub =
        URL_SAFE_NO_PAD.encode(secret_key.public_key().to_encoded_point(false).as_bytes());
    let jwt = ctx_admin_jwt(ctx).await;
    let uri = format!(
        "/api/v1/workspaces/mcp-servers?include_credentials=true&broker_public_key={broker_pub}"
    );
    send_json(&ctx.app, Method::GET, &uri, Some(&jwt), None, None, None).await
}

async fn rotation_rows(ctx: &TestContext) -> Vec<Value> {
    ctx.store
        .list_audit_events_filtered(&AuditFilter {
            limit: 200,
            event_type: Some("credential_secret_rotated".to_string()),
            ..Default::default()
        })
        .await
        .expect("audit list")
        .into_iter()
        .map(|e| serde_json::to_value(e).expect("serialize"))
        .collect()
}

fn token_response(refresh: Option<&str>) -> Value {
    let mut body = json!({
        "access_token": "UPSTREAM-ACCESS-1",
        "token_type": "Bearer",
        "expires_in": 3600,
    });
    if let Some(r) = refresh {
        body["refresh_token"] = json!(r);
    }
    body
}

#[tokio::test]
async fn a_provider_rotated_refresh_token_is_archived_and_audited() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap().clone();
    let provider = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(token_response(Some(ROTATED_REFRESH_TOKEN))),
        )
        .mount(&provider)
        .await;

    seed_provider_client(&ctx, &provider.uri()).await;
    let cred_id = seed_credential(&ctx, "notion-oauth", &provider).await;
    seed_mcp_server(&ctx, &ws.id, &cred_id).await;

    let (status, body) = sync(&ctx).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The audit row is what tells an operator a stored secret changed.
    let rows = rotation_rows(&ctx).await;
    let row = rows
        .iter()
        .find(|e| e["resource_id"] == cred_id.0.to_string())
        .unwrap_or_else(|| panic!("a credential_secret_rotated row: {rows:#?}"));
    assert_eq!(
        row["action"], "oauth2_refresh_token_rotated",
        "the action says the provider rotated it, not a human: {row}"
    );
    assert_eq!(row["resource_type"], "credential", "{row}");
    assert_eq!(row["decision"], "permit", "{row}");
    assert_eq!(row["decision_reason"], "oauth2_refresh_rotation", "{row}");
    assert_eq!(
        row["workspace_id"],
        ws.id.0.to_string(),
        "the row names the workspace whose sync triggered the exchange: {row}"
    );
    assert_eq!(row["metadata"]["credential_name"], "notion-oauth", "{row}");
    assert_eq!(
        row["metadata"]["credential_type"], "oauth2_user_authorization",
        "{row}"
    );
    assert_eq!(
        row["metadata"]["rotation_source"], "oauth2_provider",
        "{row}"
    );
    for secret in [REFRESH_TOKEN, ROTATED_REFRESH_TOKEN, PROVIDER_CLIENT_SECRET] {
        assert!(
            !row.to_string().contains(secret),
            "the audit row must not carry {secret}: {row}"
        );
    }

    // The previous token is archived, not dropped: rotating a secret the
    // operator did not choose has to be undoable.
    create_root_user(&*ctx.store, "rot-root", TEST_PASSWORD).await;
    let cookie = login_user_combined(&ctx.app, "rot-root", TEST_PASSWORD).await;
    let (status, history) = send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}/secret-history", cred_id.0),
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "secret history: {history}");
    let entries = history["data"].as_array().expect("history array");
    assert_eq!(
        entries.len(),
        1,
        "the superseded refresh token is archived: {history}"
    );
    assert!(
        !history.to_string().contains(REFRESH_TOKEN),
        "the history listing must not carry the archived secret: {history}"
    );
}

/// A provider that returns no `refresh_token` has rotated nothing. Writing a
/// rotation row anyway would make the audit log claim a secret changed on
/// every sync.
#[tokio::test]
async fn a_refresh_without_a_new_token_is_not_recorded_as_a_rotation() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap().clone();
    let provider = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_response(None)))
        .mount(&provider)
        .await;

    seed_provider_client(&ctx, &provider.uri()).await;
    let cred_id = seed_credential(&ctx, "notion-oauth", &provider).await;
    seed_mcp_server(&ctx, &ws.id, &cred_id).await;

    let (status, body) = sync(&ctx).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let rows = rotation_rows(&ctx).await;
    assert!(
        rows.is_empty(),
        "nothing rotated, so nothing is recorded: {rows:#?}"
    );
}
