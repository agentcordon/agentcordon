//! D12 — the documented `api_key_header` / `api_key_query` credential types.
//!
//! `docs/credential-encryption.md` § "Credential Types" and
//! `docs/cli-reference.md` § "Credential Types and Transforms" both document a
//! credential whose `metadata.header_name` selects a custom header (or whose
//! `metadata.param_name` selects a query parameter). The broker's
//! `credential_transform` implements both. This file covers the server half:
//! the type must be creatable, its metadata must be required, and the metadata
//! must reach the broker inside the sealed envelope — the broker cannot inject
//! `X-API-Key: …` if it never learns the header's name.

use crate::common;

use agent_cordon_core::crypto::ecies::{
    CredentialEnvelopeDecryptor, EciesEncryptor, EncryptedEnvelope,
};
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::mcp::{McpAuthMethod, McpServer, McpServerId, McpTransport};
use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_core::storage::Store;
use agent_cordon_server::templates::McpServerTemplate;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};
use axum::http::{Method, StatusCode};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{body_string_contains, header, method as wm_method};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn admin_session(ctx: &TestContext, username: &str) -> (String, String) {
    common::create_test_user(
        &*ctx.store,
        username,
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let (session, csrf) = common::login_user(&ctx.app, username, common::TEST_PASSWORD).await;
    (common::combined_cookie(&session, &csrf), csrf)
}

async fn post_credential(
    ctx: &TestContext,
    cookie: &str,
    csrf: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    common::send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(cookie),
        Some(csrf),
        Some(body),
    )
    .await
}

fn generate_broker_keypair() -> (p256::SecretKey, String) {
    use p256::elliptic_curve::rand_core::OsRng;
    let secret_key = p256::SecretKey::random(&mut OsRng);
    let point = secret_key.public_key().to_encoded_point(false);
    (secret_key, URL_SAFE_NO_PAD.encode(point.as_bytes()))
}

/// Store an `api_key_header` credential directly, with its metadata.
async fn store_api_key_header_credential(
    ctx: &TestContext,
    name: &str,
    secret: &str,
    header_name: &str,
) -> CredentialId {
    use agent_cordon_core::crypto::SecretEncryptor;
    let cred_id = CredentialId(Uuid::new_v4());
    let (ciphertext, nonce) = ctx
        .encryptor
        .encrypt(secret.as_bytes(), cred_id.0.to_string().as_bytes())
        .expect("encrypt secret");
    let now = chrono::Utc::now();
    let cred = StoredCredential {
        id: cred_id.clone(),
        name: name.to_string(),
        service: "test-service".to_string(),
        encrypted_value: ciphertext,
        nonce,
        scopes: vec![],
        metadata: json!({ "header_name": header_name }),
        created_by: None,
        created_by_user: None,
        created_at: now,
        updated_at: now,
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: None,
        transform_name: None,
        vault_id: agent_cordon_core::domain::vault::DEFAULT_VAULT_ID.to_string(),
        vault_name: "default".to_string(),
        credential_type: "api_key_header".to_string(),
        tags: vec![],
        description: None,
        target_identity: None,
        key_version: 1,
    };
    ctx.store
        .store_credential(&cred)
        .await
        .expect("store credential");
    cred_id
}

async fn create_mcp_server_with_cred(
    store: &(dyn Store + Send + Sync),
    workspace_id: &WorkspaceId,
    name: &str,
    cred_id: &CredentialId,
) -> McpServerId {
    let now = chrono::Utc::now();
    let server = McpServer {
        id: McpServerId(Uuid::new_v4()),
        workspace_id: Some(workspace_id.clone()),
        name: name.to_string(),
        upstream_url: format!("https://api.example.com/{}", name),
        transport: McpTransport::Http,
        allowed_tools: Some(vec!["tool_a".to_string()]),
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials: Some(vec![cred_id.clone()]),
        auth_method: McpAuthMethod::ApiKey,
        template_key: None,
        discovered_tools: None,
        created_by_user: None,
    };
    store
        .create_mcp_server(&server)
        .await
        .expect("create MCP server");
    store
        .add_mcp_server_workspace(&server.id, workspace_id, None)
        .await
        .expect("bind MCP server");
    server.id
}

// ===========================================================================
// 1. The documented types are creatable
// ===========================================================================

#[tokio::test]
async fn test_api_key_header_credential_can_be_created() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = admin_session(&ctx, "d12-admin-header").await;

    let (status, body) = post_credential(
        &ctx,
        &cookie,
        &csrf,
        json!({
            "name": "weather-key",
            "service": "weather",
            "secret_value": "sk-weather-123",
            "credential_type": "api_key_header",
            "metadata": { "header_name": "X-API-Key" }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "create api_key_header: {}", body);
    assert_eq!(
        body["data"]["credential_type"], "api_key_header",
        "the stored type must be the documented one: {}",
        body
    );
}

#[tokio::test]
async fn test_api_key_query_credential_can_be_created() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = admin_session(&ctx, "d12-admin-query").await;

    let (status, body) = post_credential(
        &ctx,
        &cookie,
        &csrf,
        json!({
            "name": "maps-key",
            "service": "maps",
            "secret_value": "sk-maps-123",
            "credential_type": "api_key_query",
            "metadata": { "param_name": "api_key" }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "create api_key_query: {}", body);
    assert_eq!(
        body["data"]["credential_type"], "api_key_query",
        "the stored type must be the documented one: {}",
        body
    );
}

// ===========================================================================
// 2. The metadata the injection needs is required at creation time
// ===========================================================================

#[tokio::test]
async fn test_api_key_header_credential_requires_header_name() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = admin_session(&ctx, "d12-admin-noheader").await;

    let (status, body) = post_credential(
        &ctx,
        &cookie,
        &csrf,
        json!({
            "name": "weather-key-bad",
            "service": "weather",
            "secret_value": "sk-weather-123",
            "credential_type": "api_key_header"
        }),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "api_key_header without header_name must be refused: {}",
        body
    );
}

#[tokio::test]
async fn test_api_key_query_credential_requires_param_name() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = admin_session(&ctx, "d12-admin-noparam").await;

    let (status, body) = post_credential(
        &ctx,
        &cookie,
        &csrf,
        json!({
            "name": "maps-key-bad",
            "service": "maps",
            "secret_value": "sk-maps-123",
            "credential_type": "api_key_query",
            "metadata": {}
        }),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "api_key_query without param_name must be refused: {}",
        body
    );
}

// ===========================================================================
// 3. The metadata reaches the broker inside the sealed envelope
// ===========================================================================

#[tokio::test]
async fn test_mcp_sync_envelope_carries_credential_metadata() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().unwrap();

    let cred_id =
        store_api_key_header_credential(&ctx, "weather-key", "sk-weather-123", "X-API-Key").await;
    let _server_id =
        create_mcp_server_with_cred(&*ctx.store, &ws.id, "weather-mcp", &cred_id).await;
    common::grant_cedar_permission(&ctx.state, &cred_id, &ws.id, "delegated_use").await;

    let (secret_key, broker_pub) = generate_broker_keypair();
    let jwt = common::ctx_admin_jwt(&ctx).await;
    let uri = format!(
        "/api/v1/workspaces/mcp-servers?include_credentials=true&broker_public_key={}",
        broker_pub
    );
    let (status, body) =
        common::send_json(&ctx.app, Method::GET, &uri, Some(&jwt), None, None, None).await;
    assert_eq!(status, StatusCode::OK, "sync: {}", body);

    let server = body["data"]["servers"]
        .as_array()
        .expect("servers array")
        .iter()
        .find(|s| s["name"].as_str() == Some("weather-mcp"))
        .expect("weather-mcp entry")
        .clone();
    let enc = &server["credential_envelopes"]
        .as_array()
        .expect("credential_envelopes")[0]["encrypted_envelope"];

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
        .expect("decrypt envelope");
    let material: serde_json::Value = serde_json::from_slice(&plaintext).expect("material is JSON");

    assert_eq!(
        material["value"].as_str(),
        Some("sk-weather-123"),
        "the secret must still be there: {}",
        material
    );
    assert_eq!(
        material["metadata"]["header_name"].as_str(),
        Some("X-API-Key"),
        "the broker cannot inject a custom header it never learns the name of: {}",
        material
    );
}

// ===========================================================================
// 4. Provisioning an `api_key` marketplace template honours its placement
// ===========================================================================
//
// `docs/granting-mcp-server-access.md` § "Step 1 / Option A" says provisioning
// "creates the MCP server record, optionally creates or links a credential".
// It used to create that credential as `generic` + `bearer` whatever the
// server asked for, so an MCP server that requires `X-API-Key: <key>` could
// not be installed from the marketplace at all. A template now declares where
// its key goes; absent that, the bearer default is unchanged.

fn api_key_template(
    key: &str,
    api_key_header: Option<&str>,
    api_key_query: Option<&str>,
) -> McpServerTemplate {
    McpServerTemplate {
        key: key.to_string(),
        name: format!("Mock {key}"),
        description: "Synthetic API-key MCP template used by integration tests.".to_string(),
        // Port 1 refuses instantly: tool discovery fails non-fatally, which is
        // what we want — this test is about the credential, not discovery.
        upstream_url: format!("http://127.0.0.1:1/{key}"),
        transport: "http".to_string(),
        auth_method: "api_key".to_string(),
        credential_template_key: None,
        api_key_header: api_key_header.map(str::to_string),
        api_key_query: api_key_query.map(str::to_string),
        category: "testing".to_string(),
        tags: vec!["test".to_string()],
        icon: "beaker".to_string(),
        sort_order: 9999,
        oauth2_authorize_url: None,
        oauth2_token_url: None,
        oauth2_scopes: None,
        oauth2_app_credential_template_key: None,
        oauth2_resource_url: None,
        oauth2_prefer_dcr: None,
    }
}

/// Provision `template_key` into the context's admin workspace with an inline
/// secret, and return the credential the provision created.
async fn provision_with_secret(
    ctx: &TestContext,
    cookie: &str,
    template_key: &str,
    secret: &str,
) -> StoredCredential {
    let ws = ctx
        .admin_agent
        .as_ref()
        .expect("admin workspace")
        .id
        .clone();
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/provision",
        None,
        Some(cookie),
        Some(json!({
            "template_key": template_key,
            "workspace_id": ws.0.to_string(),
            "secret_value": secret,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "provision: {body}");

    let cred_id = body["data"]["required_credentials"]
        .as_array()
        .and_then(|c| c.first())
        .and_then(|c| c.as_str())
        .unwrap_or_else(|| panic!("provision must create a credential: {body}"));
    ctx.store
        .get_credential(&CredentialId(
            Uuid::parse_str(cred_id).expect("credential id"),
        ))
        .await
        .expect("load credential")
        .expect("credential row")
}

#[tokio::test]
async fn test_provisioning_a_header_template_creates_an_api_key_header_credential() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_mcp_template(api_key_template(
            "mock-apikey-header",
            Some("X-API-Key"),
            None,
        ))
        .build()
        .await;
    let (cookie, _csrf) = admin_session(&ctx, "d12-provision-header").await;

    let cred = provision_with_secret(&ctx, &cookie, "mock-apikey-header", "sk-mock-123").await;

    assert_eq!(
        cred.credential_type, "api_key_header",
        "a template asking for a custom header must not get a bearer credential"
    );
    assert_eq!(
        cred.metadata["header_name"].as_str(),
        Some("X-API-Key"),
        "the broker names the header from metadata.header_name: {}",
        cred.metadata
    );
    assert_eq!(
        cred.transform_name, None,
        "the api_key_header type carries its own injection; a bearer transform would double up"
    );
}

#[tokio::test]
async fn test_provisioning_a_query_template_creates_an_api_key_query_credential() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_mcp_template(api_key_template("mock-apikey-query", None, Some("api_key")))
        .build()
        .await;
    let (cookie, _csrf) = admin_session(&ctx, "d12-provision-query").await;

    let cred = provision_with_secret(&ctx, &cookie, "mock-apikey-query", "sk-mock-456").await;

    assert_eq!(cred.credential_type, "api_key_query");
    assert_eq!(
        cred.metadata["param_name"].as_str(),
        Some("api_key"),
        "the broker names the parameter from metadata.param_name: {}",
        cred.metadata
    );
    assert_eq!(cred.transform_name, None);
}

/// A template that declares no placement keeps the bearer behaviour every
/// shipped marketplace template relies on.
#[tokio::test]
async fn test_provisioning_without_a_placement_still_creates_a_bearer_credential() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_mcp_template(api_key_template("mock-apikey-bearer", None, None))
        .build()
        .await;
    let (cookie, _csrf) = admin_session(&ctx, "d12-provision-bearer").await;

    let cred = provision_with_secret(&ctx, &cookie, "mock-apikey-bearer", "sk-mock-789").await;

    assert_eq!(cred.credential_type, "generic");
    assert_eq!(cred.transform_name.as_deref(), Some("bearer"));
}

/// The placement must survive all the way into the sealed envelope the broker
/// syncs, or the broker has a typed credential whose header it cannot name.
#[tokio::test]
async fn test_provisioned_header_credential_reaches_the_broker_with_its_metadata() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_mcp_template(api_key_template(
            "mock-apikey-sync",
            Some("X-API-Key"),
            None,
        ))
        .build()
        .await;
    let (cookie, _csrf) = admin_session(&ctx, "d12-provision-sync").await;
    let ws = ctx
        .admin_agent
        .as_ref()
        .expect("admin workspace")
        .id
        .clone();

    let cred = provision_with_secret(&ctx, &cookie, "mock-apikey-sync", "sk-mock-sync").await;
    common::grant_cedar_permission(&ctx.state, &cred.id, &ws, "delegated_use").await;

    let (secret_key, broker_pub) = generate_broker_keypair();
    let jwt = common::ctx_admin_jwt(&ctx).await;
    let uri = format!(
        "/api/v1/workspaces/mcp-servers?include_credentials=true&broker_public_key={}",
        broker_pub
    );
    let (status, body) =
        common::send_json(&ctx.app, Method::GET, &uri, Some(&jwt), None, None, None).await;
    assert_eq!(status, StatusCode::OK, "sync: {body}");

    let server = body["data"]["servers"]
        .as_array()
        .expect("servers array")
        .iter()
        .find(|s| s["name"].as_str() == Some("mock-apikey-sync"))
        .unwrap_or_else(|| panic!("provisioned server must be synced: {body}"))
        .clone();
    let entry = &server["credential_envelopes"]
        .as_array()
        .expect("credential_envelopes")[0];
    assert_eq!(
        entry["credential_type"].as_str(),
        Some("api_key_header"),
        "the broker picks its injection from the type it is sent: {entry}"
    );
    let enc = &entry["encrypted_envelope"];

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
        .expect("decrypt envelope");
    let material: serde_json::Value = serde_json::from_slice(&plaintext).expect("material is JSON");

    assert_eq!(material["value"].as_str(), Some("sk-mock-sync"));
    assert_eq!(
        material["metadata"]["header_name"].as_str(),
        Some("X-API-Key"),
        "the broker cannot inject a custom header it never learns the name of: {material}"
    );
}

/// Tool discovery must present the key the way the template says, or an
/// upstream that only accepts `X-API-Key` answers the provisioning probe with
/// 401 — which provisioning reads as "wrong key pasted" and rolls the whole
/// install back. This is the marketplace install of an `X-API-Key` server,
/// end to end at the HTTP seam.
#[tokio::test]
async fn test_provisioning_probes_a_header_template_with_its_custom_header() {
    let upstream = MockServer::start().await;
    // The handshake answers only for a request carrying the key in the header
    // the template names; anything else falls through to the catch-all 401.
    Mock::given(wm_method("POST"))
        .and(body_string_contains("\"method\":\"initialize\""))
        .and(header("X-API-Key", "sk-header-only"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "mock-mcp", "version": "1.0" },
            }
        })))
        .mount(&upstream)
        .await;
    Mock::given(wm_method("POST"))
        .and(body_string_contains("notifications/initialized"))
        .and(header("X-API-Key", "sk-header-only"))
        .respond_with(ResponseTemplate::new(202))
        .mount(&upstream)
        .await;
    Mock::given(wm_method("POST"))
        .and(body_string_contains("\"method\":\"tools/list\""))
        .and(header("X-API-Key", "sk-header-only"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": { "tools": [{ "name": "echo", "description": "Echo it back" }] }
        })))
        .mount(&upstream)
        .await;
    Mock::given(wm_method("POST"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&upstream)
        .await;

    let mut template = api_key_template("mock-apikey-probe", Some("X-API-Key"), None);
    template.upstream_url = upstream.uri();
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_mcp_template(template)
        .with_config(|c| c.proxy_allow_loopback = true)
        .build()
        .await;
    let (cookie, _csrf) = admin_session(&ctx, "d12-provision-probe").await;
    let ws = ctx
        .admin_agent
        .as_ref()
        .expect("admin workspace")
        .id
        .clone();

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/provision",
        None,
        Some(&cookie),
        Some(json!({
            "template_key": "mock-apikey-probe",
            "workspace_id": ws.0.to_string(),
            "secret_value": "sk-header-only",
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an X-API-Key server must be installable from the marketplace: {body}"
    );
    let server_id = body["data"]["id"].as_str().expect("server id").to_string();

    let (status, detail) = common::send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/mcp-servers/{server_id}"),
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{detail}");
    let tools = detail["data"]["tools"].as_array().expect("tools array");
    assert!(
        tools.iter().any(|t| t["name"].as_str() == Some("echo")),
        "discovery reached the upstream with the custom header: {detail}"
    );
}
