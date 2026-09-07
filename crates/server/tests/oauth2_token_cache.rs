//! The upstream OAuth2 token cache is shared, not per-clone.
//!
//! `OAuth2TokenManager` is cloned into `Services`, into `AppState`, and again
//! by axum for every request. If the cache is a bare `DashMap` each of those
//! clones is a deep copy, so a cached token is never seen again: every vend
//! and every MCP sync re-runs the exchange at the provider's token endpoint,
//! and for a delegated credential that means rotating the refresh token on
//! every sync tick.
//!
//! These tests pin the observable consequence at the server HTTP boundary:
//! two requests inside a token's lifetime produce one exchange.

use axum::http::{Method, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde_json::{json, Value};
use uuid::Uuid;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::mcp::{McpAuthMethod, McpServer, McpServerId, McpTransport};
use agent_cordon_core::domain::oauth_provider_client::{
    OAuthProviderClient, OAuthProviderClientId, RegistrationSource,
};
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

use crate::common::{ctx_admin_jwt, grant_cedar_permission, send_json};

const REFRESH_TOKEN: &str = "REFRESH-TOKEN-original";
const ROTATED_ONCE: &str = "REFRESH-TOKEN-rotated-once";
const PROVIDER_CLIENT_SECRET: &str = "PROVIDER-CLIENT-SECRET";
const CC_CLIENT_SECRET: &str = "CC-CLIENT-SECRET";

fn broker_public_key() -> String {
    let secret_key = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let point = secret_key.public_key().to_encoded_point(false);
    URL_SAFE_NO_PAD.encode(point.as_bytes())
}

async fn seed_credential(
    ctx: &TestContext,
    name: &str,
    credential_type: &str,
    secret: &str,
    metadata: Value,
) -> CredentialId {
    let cred_id = CredentialId(Uuid::new_v4());
    let (ciphertext, nonce) = ctx
        .encryptor
        .encrypt(secret.as_bytes(), cred_id.0.to_string().as_bytes())
        .expect("encrypt secret");
    let now = chrono::Utc::now();
    let cred = StoredCredential {
        id: cred_id.clone(),
        name: name.to_string(),
        service: "upstream".to_string(),
        encrypted_value: ciphertext,
        nonce,
        scopes: vec![],
        metadata,
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
        credential_type: credential_type.to_string(),
        tags: vec![],
        description: None,
        target_identity: None,
        key_version: 1,
    };
    ctx.store.store_credential(&cred).await.expect("store");
    cred_id
}

async fn seed_provider_client(ctx: &TestContext, as_url: &str, token_endpoint: &str) {
    let id = OAuthProviderClientId(Uuid::new_v4());
    let (encrypted, nonce) = ctx
        .encryptor
        .encrypt(
            PROVIDER_CLIENT_SECRET.as_bytes(),
            id.0.to_string().as_bytes(),
        )
        .expect("encrypt client secret");
    let now = chrono::Utc::now();
    let client = OAuthProviderClient {
        id,
        authorization_server_url: as_url.to_string(),
        issuer: None,
        authorize_endpoint: format!("{as_url}/authorize"),
        token_endpoint: token_endpoint.to_string(),
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
    };
    ctx.store
        .create_oauth_provider_client(&client)
        .await
        .expect("create provider client");
}

async fn seed_mcp_server(
    ctx: &TestContext,
    workspace_id: &WorkspaceId,
    name: &str,
    credential: &CredentialId,
) {
    let now = chrono::Utc::now();
    let server = McpServer {
        id: McpServerId(Uuid::new_v4()),
        workspace_id: Some(workspace_id.clone()),
        name: name.to_string(),
        upstream_url: format!("https://mcp.example.com/{name}"),
        transport: McpTransport::Sse,
        allowed_tools: Some(vec!["tool_a".to_string()]),
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials: Some(vec![credential.clone()]),
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
    grant_cedar_permission(&ctx.state, credential, workspace_id, "delegated_use").await;
}

async fn sync(ctx: &TestContext, broker_pub: &str) -> (StatusCode, Value) {
    let jwt = ctx_admin_jwt(ctx).await;
    let uri = format!(
        "/api/v1/workspaces/mcp-servers?include_credentials=true&broker_public_key={broker_pub}"
    );
    send_json(&ctx.app, Method::GET, &uri, Some(&jwt), None, None, None).await
}

async fn stored_secret(ctx: &TestContext, cred_id: &CredentialId) -> String {
    let cred = ctx
        .store
        .get_credential(cred_id)
        .await
        .expect("get")
        .expect("present");
    let plaintext = ctx
        .state
        .crypto
        .key_ring
        .decrypt_versioned(
            &cred.encrypted_value,
            &cred.nonce,
            cred_id.0.to_string().as_bytes(),
            cred.key_version,
        )
        .expect("decrypt");
    String::from_utf8(plaintext).unwrap()
}

/// Two vends of the same `oauth2_client_credentials` credential inside the
/// token's lifetime run exactly one `client_credentials` exchange: the
/// second vend is served from the shared cache.
#[tokio::test]
async fn two_vends_inside_the_token_lifetime_run_one_exchange() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap();
    let provider = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=client_credentials"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "CC-ACCESS-cached",
            "token_type": "Bearer",
            "expires_in": 900,
        })))
        .expect(1)
        .mount(&provider)
        .await;

    let cred_id = seed_credential(
        &ctx,
        "graph-app",
        "oauth2_client_credentials",
        CC_CLIENT_SECRET,
        json!({
            "oauth2_client_id": "app-client-id",
            "oauth2_token_endpoint": format!("{}/token", provider.uri()),
        }),
    )
    .await;
    grant_cedar_permission(&ctx.state, &cred_id, &ws.id, "delegated_use").await;

    let jwt = ctx_admin_jwt(&ctx).await;
    for attempt in 1..=2 {
        let (status, body) = send_json(
            &ctx.app,
            Method::POST,
            "/api/v1/credentials/vend-device/graph-app",
            Some(&jwt),
            None,
            None,
            Some(json!({
                "broker_public_key": broker_public_key(),
                "method": "GET",
                "target_url": "https://graph.microsoft.com/v1.0/me",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "vend {attempt}: {body}");
    }

    // wiremock verifies `expect(1)` when the server drops; assert eagerly so
    // the failure names the count.
    let exchanges = provider
        .received_requests()
        .await
        .expect("recorded requests")
        .len();
    assert_eq!(
        exchanges, 1,
        "the second vend must reuse the cached token, not re-exchange"
    );
}

/// Two MCP syncs inside the access token's lifetime run one `refresh_token`
/// grant, so the provider rotates the refresh token once — not once per
/// sync tick.
#[tokio::test]
async fn two_mcp_syncs_inside_the_token_lifetime_rotate_the_refresh_token_once() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap();
    let provider = MockServer::start().await;

    // The first grant, with the original refresh token, rotates it once.
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains(format!(
            "refresh_token={REFRESH_TOKEN}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "UPSTREAM-ACCESS-cached",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": ROTATED_ONCE,
        })))
        .expect(1)
        .mount(&provider)
        .await;

    // A second grant would present the rotated token. It must never happen.
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains(format!(
            "refresh_token={ROTATED_ONCE}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "UPSTREAM-ACCESS-second",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "REFRESH-TOKEN-rotated-twice",
        })))
        .expect(0)
        .mount(&provider)
        .await;

    seed_provider_client(&ctx, &provider.uri(), &format!("{}/token", provider.uri())).await;
    let cred_id = seed_credential(
        &ctx,
        "notion-oauth",
        "oauth2_user_authorization",
        REFRESH_TOKEN,
        json!({
            "oauth2_token_url": format!("{}/token", provider.uri()),
            "oauth2_client_id": "provider-client-id",
            "authorization_server_url": provider.uri(),
        }),
    )
    .await;
    seed_mcp_server(&ctx, &ws.id, "notion", &cred_id).await;

    let broker_pub = broker_public_key();
    for attempt in 1..=2 {
        let (status, body) = sync(&ctx, &broker_pub).await;
        assert_eq!(status, StatusCode::OK, "sync {attempt}: {body}");
        let entry = body["data"]["servers"]
            .as_array()
            .expect("servers")
            .iter()
            .find(|s| s["name"] == "notion")
            .expect("notion entry");
        assert!(
            entry.get("credential_error").is_none(),
            "sync {attempt}: {entry}"
        );
    }

    let exchanges = provider
        .received_requests()
        .await
        .expect("recorded requests")
        .len();
    assert_eq!(
        exchanges, 1,
        "the second sync must reuse the cached access token"
    );
    assert_eq!(
        stored_secret(&ctx, &cred_id).await,
        ROTATED_ONCE,
        "the refresh token rotated exactly once"
    );
}
