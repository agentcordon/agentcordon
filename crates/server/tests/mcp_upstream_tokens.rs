//! Secrets stay on the server: MCP sync and the vend path ship short-lived
//! upstream access tokens, never the refresh token or the provider client
//! secret that produced them.
//!
//! The server performs the upstream `refresh_token` and `client_credentials`
//! exchanges itself, against a wiremock token endpoint here, and the ECIES
//! envelope plaintext carries only `{value: <access token>, expires_at}`.

use axum::http::{Method, StatusCode};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde_json::{json, Value};
use uuid::Uuid;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use agent_cordon_core::crypto::ecies::{
    CredentialEnvelopeDecryptor, EciesEncryptor, EncryptedEnvelope,
};
use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::mcp::{McpAuthMethod, McpServer, McpServerId, McpTransport};
use agent_cordon_core::domain::oauth_provider_client::{
    OAuthProviderClient, OAuthProviderClientId, RegistrationSource,
};
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

use crate::common::{ctx_admin_jwt, grant_cedar_permission, send_json};

const REFRESH_TOKEN: &str = "REFRESH-TOKEN-must-stay-on-server";
const ROTATED_REFRESH_TOKEN: &str = "REFRESH-TOKEN-rotated-by-provider";
const PROVIDER_CLIENT_SECRET: &str = "PROVIDER-CLIENT-SECRET-must-stay-on-server";
const CC_CLIENT_SECRET: &str = "CC-CLIENT-SECRET-must-stay-on-server";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn broker_keypair() -> (p256::SecretKey, String) {
    let secret_key = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let point = secret_key.public_key().to_encoded_point(false);
    (secret_key, URL_SAFE_NO_PAD.encode(point.as_bytes()))
}

/// Open an `encrypted_envelope` object from a sync or vend response with the
/// broker's private key and parse the plaintext as JSON.
async fn open_envelope(secret_key: &p256::SecretKey, enc: &Value) -> Value {
    let envelope = EncryptedEnvelope {
        version: enc["version"].as_u64().unwrap() as u8,
        ephemeral_public_key: STANDARD
            .decode(enc["ephemeral_public_key"].as_str().unwrap())
            .unwrap(),
        ciphertext: STANDARD
            .decode(enc["ciphertext"].as_str().unwrap())
            .unwrap(),
        nonce: STANDARD.decode(enc["nonce"].as_str().unwrap()).unwrap(),
        aad: STANDARD.decode(enc["aad"].as_str().unwrap()).unwrap(),
    };
    let plaintext = EciesEncryptor
        .decrypt_envelope(&secret_key.to_bytes(), &envelope)
        .await
        .expect("ECIES decrypt");
    serde_json::from_slice(&plaintext).expect("plaintext is JSON")
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

/// The OAuth provider client row that owns an `oauth2_user_authorization`
/// credential; its client secret is sealed under the row id, as the admin
/// API does it.
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

fn server_entry<'a>(body: &'a Value, name: &str) -> &'a Value {
    body["data"]["servers"]
        .as_array()
        .expect("servers")
        .iter()
        .find(|s| s["name"] == name)
        .unwrap_or_else(|| panic!("server {name} in {body}"))
}

async fn decrypt_stored(ctx: &TestContext, cred_id: &CredentialId) -> String {
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

fn user_authorization_metadata(provider: &MockServer) -> Value {
    json!({
        "oauth2_token_url": format!("{}/token", provider.uri()),
        "oauth2_client_id": "provider-client-id",
        "authorization_server_url": provider.uri(),
    })
}

// ---------------------------------------------------------------------------
// MCP sync: refresh-token grant runs on the server
// ---------------------------------------------------------------------------

/// The sync envelope carries the upstream access token the server obtained
/// with the stored refresh token, plus its expiry. Neither the refresh token
/// (old or rotated) nor the provider client secret appears anywhere in the
/// response, and the rotated refresh token is persisted on the server.
#[tokio::test]
async fn mcp_sync_vends_upstream_access_token_and_keeps_refresh_token_on_server() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap();
    let provider = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains(format!(
            "refresh_token={REFRESH_TOKEN}"
        )))
        .and(body_string_contains(format!(
            "client_secret={PROVIDER_CLIENT_SECRET}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "UPSTREAM-ACCESS-1",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": ROTATED_REFRESH_TOKEN,
        })))
        .expect(1)
        .mount(&provider)
        .await;

    seed_provider_client(&ctx, &provider.uri(), &format!("{}/token", provider.uri())).await;
    let cred_id = seed_credential(
        &ctx,
        "notion-oauth",
        "oauth2_user_authorization",
        REFRESH_TOKEN,
        user_authorization_metadata(&provider),
    )
    .await;
    seed_mcp_server(&ctx, &ws.id, "notion", &cred_id).await;

    let (secret_key, broker_pub) = broker_keypair();
    let (status, body) = sync(&ctx, &broker_pub).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let entry = server_entry(&body, "notion");
    assert!(
        entry.get("credential_error").is_none(),
        "no error expected: {entry}"
    );
    let envelope = &entry["credential_envelopes"][0];
    assert_eq!(envelope["credential_type"], "oauth2_user_authorization");

    let plaintext = open_envelope(&secret_key, &envelope["encrypted_envelope"]).await;
    assert_eq!(plaintext["value"], "UPSTREAM-ACCESS-1", "{plaintext}");
    let expires_at = plaintext["expires_at"]
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .expect("expires_at is RFC 3339");
    let ttl = expires_at.with_timezone(&chrono::Utc) - chrono::Utc::now();
    assert!(
        ttl > chrono::Duration::minutes(50) && ttl <= chrono::Duration::hours(1),
        "expiry follows expires_in: {ttl}"
    );

    for secret in [REFRESH_TOKEN, ROTATED_REFRESH_TOKEN, PROVIDER_CLIENT_SECRET] {
        assert!(
            !plaintext.to_string().contains(secret),
            "envelope plaintext must not carry {secret}: {plaintext}"
        );
        assert!(
            !body.to_string().contains(secret),
            "response must not carry {secret}"
        );
    }
    assert!(
        plaintext.get("metadata").is_none_or(|m| m
            .as_object()
            .is_none_or(|o| !o.contains_key("oauth2_client_secret"))),
        "no client secret in metadata: {plaintext}"
    );

    assert_eq!(
        decrypt_stored(&ctx, &cred_id).await,
        ROTATED_REFRESH_TOKEN,
        "the rotated refresh token is persisted server-side"
    );
}

/// A failing token endpoint marks that server's entry with an error and
/// leaves the rest of the sync intact.
#[tokio::test]
async fn mcp_sync_reports_upstream_token_failure_per_server() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap();
    let provider = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(500).set_body_string("provider down"))
        .mount(&provider)
        .await;

    seed_provider_client(&ctx, &provider.uri(), &format!("{}/token", provider.uri())).await;
    let broken = seed_credential(
        &ctx,
        "broken-oauth",
        "oauth2_user_authorization",
        REFRESH_TOKEN,
        user_authorization_metadata(&provider),
    )
    .await;
    seed_mcp_server(&ctx, &ws.id, "broken", &broken).await;

    let healthy = seed_credential(&ctx, "plain-token", "generic", "ghp_plain", json!({})).await;
    seed_mcp_server(&ctx, &ws.id, "healthy", &healthy).await;

    let (secret_key, broker_pub) = broker_keypair();
    let (status, body) = sync(&ctx, &broker_pub).await;
    assert_eq!(status, StatusCode::OK, "whole sync must not fail: {body}");

    let broken_entry = server_entry(&body, "broken");
    assert!(
        broken_entry["credential_envelopes"].is_null(),
        "no envelope for the failed exchange: {broken_entry}"
    );
    let error = broken_entry["credential_error"]
        .as_str()
        .expect("credential_error string");
    assert!(
        error.contains("broken-oauth"),
        "names the credential: {error}"
    );
    assert!(!error.contains(REFRESH_TOKEN));
    assert!(!error.contains(PROVIDER_CLIENT_SECRET));

    let healthy_entry = server_entry(&body, "healthy");
    let plaintext = open_envelope(
        &secret_key,
        &healthy_entry["credential_envelopes"][0]["encrypted_envelope"],
    )
    .await;
    assert_eq!(plaintext["value"], "ghp_plain");
}

/// Client-credentials apps are exchanged on the server too: the envelope
/// carries the access token, and the client secret never leaves.
#[tokio::test]
async fn mcp_sync_exchanges_client_credentials_server_side() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap();
    let provider = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains(format!(
            "client_secret={CC_CLIENT_SECRET}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "CC-ACCESS-1",
            "token_type": "Bearer",
            "expires_in": 600,
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
            "oauth2_scopes": "https://graph.microsoft.com/.default",
        }),
    )
    .await;
    seed_mcp_server(&ctx, &ws.id, "graph", &cred_id).await;

    let (secret_key, broker_pub) = broker_keypair();
    let (status, body) = sync(&ctx, &broker_pub).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let envelope = &server_entry(&body, "graph")["credential_envelopes"][0];
    assert_eq!(envelope["credential_type"], "oauth2_client_credentials");
    let plaintext = open_envelope(&secret_key, &envelope["encrypted_envelope"]).await;
    assert_eq!(plaintext["value"], "CC-ACCESS-1", "{plaintext}");
    assert!(plaintext["expires_at"].is_string(), "{plaintext}");
    assert!(!plaintext.to_string().contains(CC_CLIENT_SECRET));
    assert!(!body.to_string().contains(CC_CLIENT_SECRET));
}

// ---------------------------------------------------------------------------
// Vend: client-credentials exchange runs on the server
// ---------------------------------------------------------------------------

/// Vending an `oauth2_client_credentials` credential hands the broker the
/// access token the server exchanged for, with its expiry, not the secret.
#[tokio::test]
async fn vend_exchanges_client_credentials_server_side() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap();
    let provider = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains("client_id=app-client-id"))
        .and(body_string_contains(format!(
            "client_secret={CC_CLIENT_SECRET}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "CC-ACCESS-vend",
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

    let (secret_key, broker_pub) = broker_keypair();
    let jwt = ctx_admin_jwt(&ctx).await;
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/vend-device/graph-app",
        Some(&jwt),
        None,
        None,
        Some(json!({
            "broker_public_key": broker_pub,
            "method": "GET",
            "target_url": "https://graph.microsoft.com/v1.0/me",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["credential_type"], "oauth2_client_credentials");

    let plaintext = open_envelope(&secret_key, &body["data"]["encrypted_envelope"]).await;
    assert_eq!(plaintext["value"], "CC-ACCESS-vend", "{plaintext}");
    let expires_at = plaintext["expires_at"]
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .expect("expires_at is RFC 3339");
    assert!(expires_at.with_timezone(&chrono::Utc) > chrono::Utc::now());
    assert!(!plaintext.to_string().contains(CC_CLIENT_SECRET));
    assert!(!body.to_string().contains(CC_CLIENT_SECRET));
}

// ---------------------------------------------------------------------------
// Outbound identity: the server names its real version to a provider
// ---------------------------------------------------------------------------

/// Every outbound call the control plane makes carries
/// `AgentCordon/<this build's version>`. It used to say `AgentCordon/0.1`, a
/// version that had not existed for many releases, so a provider-side log or
/// rate-limit rule keyed on the user agent was reading a frozen number — and
/// the broker, which gets this right, disagreed with the server about which
/// AgentCordon a deployment was running.
#[tokio::test]
async fn client_credentials_exchange_identifies_the_running_server_version() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap();
    let provider = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "CC-ACCESS-ua",
            "token_type": "Bearer",
            "expires_in": 600,
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

    let (_secret_key, broker_pub) = broker_keypair();
    let jwt = ctx_admin_jwt(&ctx).await;
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/vend-device/graph-app",
        Some(&jwt),
        None,
        None,
        Some(json!({
            "broker_public_key": broker_pub,
            "method": "GET",
            "target_url": "https://graph.microsoft.com/v1.0/me",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let exchange = &provider.received_requests().await.expect("requests")[0];
    let user_agent = exchange
        .headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .expect("the token exchange carries a user agent");
    assert_eq!(
        user_agent,
        format!("AgentCordon/{}", env!("CARGO_PKG_VERSION")),
        "the provider must see the version this server actually is"
    );
}
