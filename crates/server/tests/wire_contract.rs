//! The server↔broker wire contract, exercised against the real routes.
//!
//! Every request body, form and query string here is produced by
//! *serialising* the shared type in [`agent_cordon_core::wire`] — the same
//! value the broker's `ServerClient` puts on the socket — and every response
//! is read back by *deserialising* into the shared type the broker's client
//! deserialises into. Nothing in this file names a JSON field as a string.
//!
//! Sharing the type already makes a rename a compile error. These tests
//! cover what the type alone does not: that the serde attributes on both
//! halves still line up over the real route (the `{"data": ...}` envelope,
//! `skip_serializing_if`, the fields the broker tolerates being absent), and
//! that the form/query encodings the broker emits are accepted as sent.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt;

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::credential::{CredentialId, CredentialSummary, StoredCredential};
use agent_cordon_core::domain::mcp::{
    McpAuthMethod, McpServer, McpServerId, McpTool, McpTransport,
};
use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_core::storage::Store;
use agent_cordon_core::wire::credentials::{VendRequest, VendResponse};
use agent_cordon_core::wire::mcp::{
    McpAuthorizeRequest, McpAuthorizeResponse, McpServerSyncResponse, McpSyncQuery,
    McpToolSyncEntry,
};
use agent_cordon_core::wire::oauth::{
    device_poll_errors, grant_types, DeviceAuthorizationRequest, DeviceAuthorizationResponse,
    OAuthErrorBody, TokenRequest, TokenResponse,
};
use agent_cordon_core::wire::ApiEnvelope;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

use crate::common::{
    compute_consent_csrf, create_user_in_db, ctx_agent_jwt, grant_cedar_permission, login_user,
    send_json, TEST_PASSWORD,
};

const BOOTSTRAP_CLIENT_ID: &str = "agentcordon-broker";
const TEST_PK_HASH: &str = "2222222222222222222222222222222222222222222222222222222222222222";

// ---------------------------------------------------------------------------
// Transport helpers. `send_json` covers the JSON routes; the OAuth endpoints
// take forms, and the broker builds those forms by serialising the shared
// request type, so these do too.
// ---------------------------------------------------------------------------

/// Serialise a shared request type the way `reqwest`'s `.form()` does and
/// POST it, so the bytes under test are the bytes the broker sends.
async fn post_wire_form<T: serde::Serialize>(
    app: &Router,
    uri: &str,
    form: &T,
    cookie: Option<&str>,
) -> (StatusCode, Vec<u8>) {
    let encoded = serde_urlencoded::to_string(form).expect("serialise form");
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(c) = cookie {
        builder = builder.header(header::COOKIE, c);
    }
    let resp = app
        .clone()
        .oneshot(builder.body(Body::from(encoded)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, bytes.to_vec())
}

async fn post_form_str(
    app: &Router,
    uri: &str,
    body: &str,
    cookie: Option<&str>,
) -> (StatusCode, Vec<u8>) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(c) = cookie {
        builder = builder.header(header::COOKIE, c);
    }
    let resp = app
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, bytes.to_vec())
}

/// Deserialise a response body into the type the broker deserialises into,
/// failing with the body text so a contract break is readable.
fn read<T: serde::de::DeserializeOwned>(what: &str, bytes: &[u8]) -> T {
    serde_json::from_slice(bytes).unwrap_or_else(|e| {
        panic!(
            "{what} does not deserialise into the shared wire type: {e}\nbody: {}",
            String::from_utf8_lossy(bytes)
        )
    })
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

async fn stored_credential(
    ctx: &TestContext,
    name: &str,
    pattern: Option<&str>,
    transform_name: Option<&str>,
) -> CredentialId {
    let now = chrono::Utc::now();
    let cred_id = CredentialId(uuid::Uuid::new_v4());
    let (encrypted, nonce) = ctx
        .state
        .crypto
        .key_ring
        .encrypt(b"s3cret", cred_id.0.to_string().as_bytes())
        .expect("encrypt");
    let cred = StoredCredential {
        id: cred_id.clone(),
        name: name.to_string(),
        service: "github".to_string(),
        encrypted_value: encrypted,
        nonce,
        scopes: vec!["repo".to_string()],
        metadata: serde_json::json!({}),
        created_by: None,
        created_by_user: None,
        created_at: now,
        updated_at: now,
        allowed_url_pattern: pattern.map(str::to_string),
        expires_at: None,
        transform_script: None,
        transform_name: transform_name.map(str::to_string),
        vault_id: agent_cordon_core::domain::vault::DEFAULT_VAULT_ID.to_string(),
        vault_name: "default".to_string(),
        credential_type: "generic".to_string(),
        tags: vec![],
        description: None,
        target_identity: None,
        key_version: 1,
    };
    ctx.store.store_credential(&cred).await.expect("store");
    cred_id
}

async fn mcp_server_bound_to(
    store: &(dyn Store + Send + Sync),
    workspace_id: &WorkspaceId,
    name: &str,
    required_credentials: Option<Vec<CredentialId>>,
) {
    mcp_server_from_template(store, workspace_id, name, required_credentials, None).await
}

/// Same, provisioned from a catalog template — the template is where an MCP
/// server's human-readable description comes from.
async fn mcp_server_from_template(
    store: &(dyn Store + Send + Sync),
    workspace_id: &WorkspaceId,
    name: &str,
    required_credentials: Option<Vec<CredentialId>>,
    template_key: Option<&str>,
) {
    let now = chrono::Utc::now();
    let server = McpServer {
        id: McpServerId(uuid::Uuid::new_v4()),
        workspace_id: Some(workspace_id.clone()),
        name: name.to_string(),
        upstream_url: format!("https://mcp.example.com/{name}"),
        transport: McpTransport::Sse,
        allowed_tools: Some(vec!["forecast".to_string()]),
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials,
        auth_method: McpAuthMethod::ApiKey,
        template_key: template_key.map(str::to_string),
        discovered_tools: Some(vec![McpTool {
            name: "forecast".to_string(),
            description: Some("tomorrow".to_string()),
            input_schema: Some(serde_json::json!({"type": "object"})),
        }]),
        created_by_user: None,
    };
    store.create_mcp_server(&server).await.expect("create mcp");
    store
        .add_mcp_server_workspace(&server.id, workspace_id, None)
        .await
        .expect("bind mcp to workspace");
}

fn broker_public_key() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let secret = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    URL_SAFE_NO_PAD.encode(secret.public_key().to_encoded_point(false).as_bytes())
}

// ---------------------------------------------------------------------------
// OAuth: device code + token
// ---------------------------------------------------------------------------

/// The broker's enrollment round-trip, in the shared types end to end: the
/// device-code form it serialises, the authorization response it parses, the
/// token form it serialises for the device_code grant, and the token
/// response it parses — including the `client_id` it must persist.
#[tokio::test]
async fn device_flow_speaks_the_shared_oauth_wire_types() {
    let ctx = TestAppBuilder::new().build().await;
    create_user_in_db(
        &*ctx.store,
        "approver",
        TEST_PASSWORD,
        UserRole::Operator,
        false,
        true,
    )
    .await;
    let (session_cookie, _csrf) = login_user(&ctx.app, "approver", TEST_PASSWORD).await;

    // 1. Exactly what ServerClient::request_device_code puts on the wire.
    let request = DeviceAuthorizationRequest {
        client_id: Some(BOOTSTRAP_CLIENT_ID.to_string()),
        scope: Some("credentials:discover credentials:vend".to_string()),
        workspace_name: Some("wire-contract-ws".to_string()),
        public_key_hash: Some(TEST_PK_HASH.to_string()),
    };
    let (status, bytes) =
        post_wire_form(&ctx.app, "/api/v1/oauth/device/code", &request, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "device/code refused the broker's own form encoding: {}",
        String::from_utf8_lossy(&bytes)
    );
    let device: DeviceAuthorizationResponse = read("device authorization response", &bytes);
    assert!(!device.device_code.is_empty());
    assert!(
        device.verification_uri_complete.is_some(),
        "the broker shows this URL; the server must send it"
    );
    assert!(
        device.interval.is_some_and(|i| i > 0),
        "the broker's poll loop sleeps on interval"
    );
    assert!(device.expires_in > 0);

    // 2. Polling before approval: the RFC 8628 §3.5 error body the broker's
    //    state machine branches on.
    let poll = TokenRequest {
        grant_type: Some(grant_types::DEVICE_CODE.to_string()),
        device_code: Some(device.device_code.clone()),
        client_id: Some(BOOTSTRAP_CLIENT_ID.to_string()),
        ..TokenRequest::default()
    };
    let (status, bytes) = post_wire_form(&ctx.app, "/api/v1/oauth/token", &poll, None).await;
    assert!(status.is_client_error(), "pending poll must be a 4xx");
    let err: OAuthErrorBody = read("token error body", &bytes);
    assert_eq!(err.error, device_poll_errors::AUTHORIZATION_PENDING);

    // 3. Approve in the browser, then exchange with the same serialised form.
    let csrf = compute_consent_csrf(&session_cookie, &ctx.state.crypto.session_hash_key);
    let activate = format!(
        "csrf_token={}&user_code={}&decision=approve",
        urlencoding::encode(&csrf),
        urlencoding::encode(&device.user_code),
    );
    let (status, _) = post_form_str(&ctx.app, "/activate", &activate, Some(&session_cookie)).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "approve");

    let (status, bytes) = post_wire_form(&ctx.app, "/api/v1/oauth/token", &poll, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "token exchange: {}",
        String::from_utf8_lossy(&bytes)
    );
    let token: TokenResponse = read("token response", &bytes);
    assert_eq!(token.token_type, "Bearer");
    assert!(token.expires_in > 0);
    assert!(
        token.scope.is_some(),
        "the broker splits scope into the workspace's cached scopes"
    );
    assert_ne!(
        token.client_id.as_deref(),
        Some(BOOTSTRAP_CLIENT_ID),
        "the broker must be handed the per-workspace client_id, not the bootstrap one"
    );
    assert!(token.client_id.is_some());
    let refresh_token = token.refresh_token.expect("refresh token");

    // 4. Refresh with the client_id the broker just persisted.
    let refresh = TokenRequest {
        grant_type: Some(grant_types::REFRESH_TOKEN.to_string()),
        refresh_token: Some(refresh_token),
        client_id: token.client_id.clone(),
        ..TokenRequest::default()
    };
    let (status, bytes) = post_wire_form(&ctx.app, "/api/v1/oauth/token", &refresh, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "refresh: {}",
        String::from_utf8_lossy(&bytes)
    );
    let refreshed: TokenResponse = read("refreshed token response", &bytes);
    assert_eq!(refreshed.client_id, token.client_id);
}

// ---------------------------------------------------------------------------
// Credentials: vend + list
// ---------------------------------------------------------------------------

/// The vend round-trip in the shared types: the request body the broker
/// serialises, and the response it reads the injection metadata out of.
#[tokio::test]
async fn vend_speaks_the_shared_credential_wire_types() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws", &[])
        .build()
        .await;
    let cred_id =
        stored_credential(&ctx, "gh", Some("https://api.github.com/*"), Some("bearer")).await;
    let ws = ctx.agents.get("ws").expect("agent");
    grant_cedar_permission(&ctx.state, &cred_id, &ws.id, "delegated_use").await;
    let jwt = ctx_agent_jwt(&ctx, "ws").await;

    let request = VendRequest {
        broker_public_key: Some(broker_public_key()),
        method: Some("GET".to_string()),
        target_url: Some("https://api.github.com/repos/x".to_string()),
    };
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/vend-device/gh",
        Some(&jwt),
        None,
        None,
        Some(serde_json::to_value(&request).expect("serialise vend request")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let vend: ApiEnvelope<VendResponse> = serde_json::from_value(body.clone())
        .unwrap_or_else(|e| panic!("vend response does not deserialise: {e}\nbody: {body}"));
    let vend = vend.data;
    assert_eq!(vend.credential_type, "generic");
    assert_eq!(
        vend.transform_name.as_deref(),
        Some("bearer"),
        "the broker picks the injection transform from this field"
    );
    assert_eq!(
        vend.allowed_url_pattern.as_deref(),
        Some("https://api.github.com/*"),
        "the broker re-checks the target against this pattern before injecting"
    );
    assert!(!vend.vend_id.is_empty());
    assert_eq!(vend.encrypted_envelope.version, 1);
    assert!(!vend.encrypted_envelope.ephemeral_public_key.is_empty());
    assert!(!vend.encrypted_envelope.ciphertext.is_empty());
    assert!(!vend.encrypted_envelope.nonce.is_empty());
    assert!(!vend.encrypted_envelope.aad.is_empty());
}

/// An unbound credential vends with `allowed_url_pattern` absent, which the
/// broker reads as "unbound" — so the field must survive as `None`, not as a
/// deserialisation failure.
#[tokio::test]
async fn vend_of_an_unbound_credential_deserialises_with_no_pattern() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws", &[])
        .build()
        .await;
    let cred_id = stored_credential(&ctx, "open", None, None).await;
    let ws = ctx.agents.get("ws").expect("agent");
    grant_cedar_permission(&ctx.state, &cred_id, &ws.id, "delegated_use").await;
    let jwt = ctx_agent_jwt(&ctx, "ws").await;

    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials/vend-device/open",
        Some(&jwt),
        None,
        None,
        Some(
            serde_json::to_value(VendRequest {
                broker_public_key: Some(broker_public_key()),
                ..VendRequest::default()
            })
            .expect("serialise"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let vend: ApiEnvelope<VendResponse> = serde_json::from_value(body.clone())
        .unwrap_or_else(|e| panic!("vend response does not deserialise: {e}\nbody: {body}"));
    assert_eq!(vend.data.allowed_url_pattern, None);
    assert_eq!(vend.data.transform_name, None);
}

/// `GET /api/v1/credentials` is the domain's own `CredentialSummary`. The
/// broker reads it back into that type, so the list must round-trip.
#[tokio::test]
async fn credential_list_deserialises_into_the_domain_summary() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws", &["credentials:discover"])
        .build()
        .await;
    let ws = ctx.agents.get("ws").expect("agent").clone();
    let cred_id = stored_credential(&ctx, "gh", None, Some("bearer")).await;
    grant_cedar_permission(&ctx.state, &cred_id, &ws.id, "read").await;
    let jwt = ctx_agent_jwt(&ctx, "ws").await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let listed: ApiEnvelope<Vec<CredentialSummary>> = serde_json::from_value(body.clone())
        .unwrap_or_else(|e| panic!("credential list does not deserialise: {e}\nbody: {body}"));
    let gh = listed
        .data
        .iter()
        .find(|c| c.name == "gh")
        .expect("the granted credential must be listed");
    assert_eq!(gh.id, cred_id);
    assert_eq!(gh.service, "github");
    assert_eq!(gh.credential_type, "generic");
    assert_eq!(gh.vault_name, "default");
    assert_eq!(
        gh.vault_id,
        agent_cordon_core::domain::vault::DEFAULT_VAULT_ID
    );
    assert!(!gh.expired);
}

// ---------------------------------------------------------------------------
// MCP: sync, tools, authorize
// ---------------------------------------------------------------------------

/// The MCP sync round-trip: the query string the broker serialises, and the
/// server list (with sealed credential envelopes) it reads back.
#[tokio::test]
async fn mcp_sync_speaks_the_shared_mcp_wire_types() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().expect("admin agent").clone();
    let cred_id = stored_credential(&ctx, "weather-key", None, Some("bearer")).await;
    mcp_server_bound_to(&*ctx.store, &ws.id, "weather", Some(vec![cred_id.clone()])).await;
    grant_cedar_permission(&ctx.state, &cred_id, &ws.id, "delegated_use").await;
    let jwt = crate::common::ctx_admin_jwt(&ctx).await;

    // Exactly the query ServerClient::list_mcp_servers_with_credentials sends.
    let query = McpSyncQuery {
        include_credentials: true,
        broker_public_key: Some(broker_public_key()),
    };
    let uri = format!(
        "/api/v1/workspaces/mcp-servers?{}",
        serde_urlencoded::to_string(&query).expect("serialise query")
    );
    let (status, body) = send_json(&ctx.app, Method::GET, &uri, Some(&jwt), None, None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let synced: ApiEnvelope<McpServerSyncResponse> = serde_json::from_value(body.clone())
        .unwrap_or_else(|e| panic!("mcp sync does not deserialise: {e}\nbody: {body}"));
    let weather = synced
        .data
        .servers
        .iter()
        .find(|s| s.name == "weather")
        .expect("the bound server must be synced");
    assert!(weather.enabled);
    assert_eq!(weather.transport, "sse");
    assert_eq!(weather.auth_method, "api_key");
    assert_eq!(weather.tools, vec!["forecast".to_string()]);
    assert!(weather.url.is_some());
    assert_eq!(weather.credential_error, None);

    let envelopes = weather
        .credential_envelopes
        .as_ref()
        .expect("include_credentials=true must seal the required credential");
    let env = envelopes.first().expect("one envelope");
    assert_eq!(env.credential_name, "weather-key");
    assert_eq!(
        env.transform_name.as_deref(),
        Some("bearer"),
        "the broker injects the MCP credential with this transform"
    );
    assert_eq!(env.encrypted_envelope.version, 1);
    assert!(!env.encrypted_envelope.ciphertext.is_empty());

    // The default query (no credentials) is the same type with everything
    // off, and must still be accepted — it serialises to an empty string.
    let default_query =
        serde_urlencoded::to_string(McpSyncQuery::default()).expect("serialise default query");
    assert_eq!(
        default_query, "",
        "a plain listing must send no query parameters"
    );
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces/mcp-servers",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let plain: ApiEnvelope<McpServerSyncResponse> = serde_json::from_value(body.clone())
        .unwrap_or_else(|e| panic!("plain mcp sync does not deserialise: {e}\nbody: {body}"));
    assert!(plain
        .data
        .servers
        .iter()
        .all(|s| s.credential_envelopes.is_none()));
}

/// `GET /api/v1/workspaces/mcp-tools` is a bare list in the envelope; the
/// broker appends its own live-discovery results to the same type.
#[tokio::test]
async fn mcp_tools_deserialise_into_the_shared_tool_entry() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().expect("admin agent").clone();
    mcp_server_bound_to(&*ctx.store, &ws.id, "weather", None).await;
    let jwt = crate::common::ctx_admin_jwt(&ctx).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces/mcp-tools",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let tools: ApiEnvelope<Vec<McpToolSyncEntry>> = serde_json::from_value(body.clone())
        .unwrap_or_else(|e| panic!("mcp tools do not deserialise: {e}\nbody: {body}"));
    let forecast = tools
        .data
        .iter()
        .find(|t| t.tool == "forecast")
        .expect("discovered tool must be listed");
    assert_eq!(forecast.server, "weather");
    assert_eq!(forecast.description.as_deref(), Some("tomorrow"));
    assert!(forecast.input_schema.is_some());
}

/// The MCP authorization round-trip. The broker gates every tool call on
/// `decision`, so the value it compares against is part of the contract.
#[tokio::test]
async fn mcp_authorize_speaks_the_shared_mcp_wire_types() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().expect("admin agent").clone();
    mcp_server_bound_to(&*ctx.store, &ws.id, "weather", None).await;
    let jwt = crate::common::ctx_admin_jwt(&ctx).await;

    let request = McpAuthorizeRequest {
        server_name: "weather".to_string(),
        tool_name: "forecast".to_string(),
    };
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/workspaces/mcp-authorize",
        Some(&jwt),
        None,
        None,
        Some(serde_json::to_value(&request).expect("serialise authorize request")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let decided: ApiEnvelope<McpAuthorizeResponse> = serde_json::from_value(body.clone())
        .unwrap_or_else(|e| panic!("mcp authorize does not deserialise: {e}\nbody: {body}"));
    assert!(
        decided.data.is_permit(),
        "admin workspace calling its own server: {}",
        decided.data.decision
    );
    assert!(!decided.data.correlation_id.is_empty());

    // An unknown server is refused, and the refusal uses the value the
    // broker's `is_permit` checks against.
    let unknown = McpAuthorizeRequest {
        server_name: "not-a-server".to_string(),
        tool_name: "forecast".to_string(),
    };
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/workspaces/mcp-authorize",
        Some(&jwt),
        None,
        None,
        Some(serde_json::to_value(&unknown).expect("serialise")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let decided: ApiEnvelope<McpAuthorizeResponse> =
        serde_json::from_value(body.clone()).expect("deserialise");
    assert_eq!(decided.data.decision, McpAuthorizeResponse::FORBID);
    assert!(!decided.data.is_permit());
}

/// An MCP server provisioned from the catalog has a description — the
/// template's — and the sync endpoint is the only way it can reach an agent.
/// Without it `agentcordon mcp-servers` prints `-` for every row and the
/// agent has nothing but the server's name to choose by.
#[tokio::test]
async fn mcp_sync_carries_the_servers_description() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let ws = ctx.admin_agent.as_ref().expect("admin agent").clone();
    let template = ctx
        .state
        .catalog
        .mcp_templates
        .first()
        .expect("the embedded catalog must ship at least one template")
        .clone();
    mcp_server_from_template(&*ctx.store, &ws.id, "catalogued", None, Some(&template.key)).await;
    mcp_server_bound_to(&*ctx.store, &ws.id, "hand-rolled", None).await;
    let jwt = crate::common::ctx_admin_jwt(&ctx).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/workspaces/mcp-servers",
        Some(&jwt),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let synced: ApiEnvelope<McpServerSyncResponse> = serde_json::from_value(body.clone())
        .unwrap_or_else(|e| panic!("mcp sync does not deserialise: {e}\nbody: {body}"));
    let catalogued = synced
        .data
        .servers
        .iter()
        .find(|s| s.name == "catalogued")
        .expect("catalogued server");
    assert_eq!(
        catalogued.description.as_deref(),
        Some(template.description.as_str()),
        "a server provisioned from the catalog must sync its template's description"
    );

    let hand_rolled = synced
        .data
        .servers
        .iter()
        .find(|s| s.name == "hand-rolled")
        .expect("hand-rolled server");
    assert_eq!(
        hand_rolled.description, None,
        "a server with no template has no description, and the field stays absent"
    );
}
