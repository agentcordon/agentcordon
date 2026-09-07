//! The server↔broker wire contract, from the broker's side of the socket.
//!
//! Every assertion here reads a request the broker actually sent by
//! *deserialising it into the server's own request type* from
//! [`agent_cordon_core::wire`], and every stubbed answer is produced by
//! *serialising the server's own response type*. Nothing in this file names
//! a JSON field as a string.
//!
//! Sharing the types already makes a rename a compile error. What these
//! tests add is the encoding: that what reqwest puts on the wire for a
//! shared form or query type is what the server's extractor would read
//! back, field for field, and that a response built from the server's type
//! is one the broker can act on.

use axum::http::StatusCode;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use agent_cordon_core::domain::credential::{CredentialId, CredentialSummary};
use agent_cordon_core::wire::credentials::{VendRequest, VendResponse};
use agent_cordon_core::wire::mcp::{
    McpAuthorizeRequest, McpAuthorizeResponse, McpCredentialEnvelope, McpServerSyncEntry,
    McpServerSyncResponse, McpSyncQuery,
};
use agent_cordon_core::wire::oauth::{grant_types, TokenRequest, TokenResponse};
use agent_cordon_core::wire::{ApiEnvelope, EncryptedEnvelopeWire};

use crate::common::{pattern_for, vend_envelope, vend_path, TestBroker, TestWorkspace};

const CRED: &str = "api-token";
const SECRET: &str = "tok-secret-value-1234567890";
const SYNC_PATH: &str = "/api/v1/workspaces/mcp-servers";
const AUTHORIZE_PATH: &str = "/api/v1/workspaces/mcp-authorize";
const TOKEN_PATH: &str = "/api/v1/oauth/token";

async fn setup() -> (TestBroker, TestWorkspace) {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, &["credentials:vend", "mcp:invoke"])
        .build()
        .await;
    (broker, ws)
}

/// Every request the broker sent to the fake server, in order.
async fn sent(broker: &TestBroker) -> Vec<wiremock::Request> {
    broker
        .server
        .received_requests()
        .await
        .expect("the fake server records requests")
}

/// The one request to `path`, read back as the server's request type.
fn body_as<T: serde::de::DeserializeOwned>(requests: &[wiremock::Request], p: &str) -> T {
    let req = requests
        .iter()
        .find(|r| r.url.path() == p)
        .unwrap_or_else(|| panic!("the broker never called {p}"));
    serde_json::from_slice(&req.body).unwrap_or_else(|e| {
        panic!(
            "what the broker sent to {p} does not deserialise into the server's request type: \
             {e}\nbody: {}",
            String::from_utf8_lossy(&req.body)
        )
    })
}

/// Ditto for a form-encoded body.
fn form_as<T: serde::de::DeserializeOwned>(requests: &[wiremock::Request], p: &str) -> T {
    let req = requests
        .iter()
        .find(|r| r.url.path() == p)
        .unwrap_or_else(|| panic!("the broker never called {p}"));
    serde_urlencoded::from_bytes(&req.body).unwrap_or_else(|e| {
        panic!(
            "the form the broker sent to {p} does not deserialise into the server's request \
             type: {e}\nbody: {}",
            String::from_utf8_lossy(&req.body)
        )
    })
}

/// A sync response built from the server's own types.
fn sync_response(servers: Vec<McpServerSyncEntry>) -> serde_json::Value {
    serde_json::to_value(ApiEnvelope::ok(McpServerSyncResponse { servers }))
        .expect("serialise sync response")
}

fn sync_entry(name: &str, url: &str) -> McpServerSyncEntry {
    McpServerSyncEntry {
        id: format!("srv-{name}"),
        name: name.to_string(),
        description: None,
        transport: "http".to_string(),
        url: Some(url.to_string()),
        tools: vec!["forecast".to_string()],
        enabled: true,
        required_credentials: None,
        auth_method: "none".to_string(),
        credential_envelopes: None,
        credential_error: None,
    }
}

async fn mount_authorize(broker: &TestBroker) {
    let body = serde_json::to_value(ApiEnvelope::ok(McpAuthorizeResponse {
        decision: McpAuthorizeResponse::PERMIT.to_string(),
        correlation_id: "corr-wire".to_string(),
    }))
    .expect("serialise authorize response");
    Mock::given(method("POST"))
        .and(path(AUTHORIZE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&broker.server)
        .await;
}

// ---------------------------------------------------------------------------
// Credential vend
// ---------------------------------------------------------------------------

/// The proxy's vend call is the server's `VendRequest`, and the answer the
/// broker acts on is the server's `VendResponse` — including the
/// `transform_name` that decides how the secret is injected.
#[tokio::test(flavor = "multi_thread")]
async fn vend_call_is_the_servers_vend_request_and_response() {
    let (broker, ws) = setup().await;
    let upstream = MockServer::start().await;
    let target = format!("{}/v1/items", upstream.uri());

    // The stub answer is the server's response type, serialised.
    let response = ApiEnvelope::ok(VendResponse {
        credential_type: "bearer".to_string(),
        transform_name: Some("bearer".to_string()),
        allowed_url_pattern: Some(pattern_for(&upstream)),
        encrypted_envelope: serde_json::from_value::<EncryptedEnvelopeWire>(
            vend_envelope(&broker, &serde_json::json!({ "value": SECRET })).await,
        )
        .expect("the harness envelope is the shared envelope type"),
        vend_id: "vnd_wire".to_string(),
    });
    Mock::given(method("POST"))
        .and(path(vend_path(CRED)))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::to_value(&response).expect("serialise vend response")),
        )
        .mount(&broker.server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/items"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&upstream)
        .await;

    let proxy_req = serde_json::json!({
        "method": "GET",
        "url": target,
        "credential": CRED,
    });
    let (status, body) = broker
        .send(ws.signed("POST", "/proxy", &proxy_req.to_string()))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // What the broker sent, read as the server's own request type.
    let requests = sent(&broker).await;
    let vend: VendRequest = body_as(&requests, &vend_path(CRED));
    assert_eq!(vend.method.as_deref(), Some("GET"));
    assert_eq!(
        vend.target_url.as_deref(),
        Some(target.as_str()),
        "the server binds the vend to this target, so it must arrive verbatim"
    );
    assert!(
        vend.broker_public_key.is_some_and(|k| !k.is_empty()),
        "the server seals the envelope to this key"
    );

    // The response was acted on: the bearer transform reached the upstream.
    let injected = upstream
        .received_requests()
        .await
        .expect("upstream records")
        .into_iter()
        .next()
        .expect("one upstream call");
    assert_eq!(
        injected
            .headers
            .get("authorization")
            .map(|v| v.to_str().unwrap().to_string()),
        Some(format!("Bearer {SECRET}")),
        "the broker read credential_type/transform_name out of the shared VendResponse"
    );
}

// ---------------------------------------------------------------------------
// MCP sync, listing and authorization
// ---------------------------------------------------------------------------

/// The sync call's query string is the server's `McpSyncQuery`: a plain
/// listing sends no parameters, and a credential-bearing sync sends both.
#[tokio::test(flavor = "multi_thread")]
async fn mcp_sync_query_is_the_servers_sync_query() {
    let (broker, ws) = setup().await;
    let upstream = MockServer::start().await;
    mount_authorize(&broker).await;
    Mock::given(method("GET"))
        .and(path(SYNC_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(sync_response(vec![sync_entry("weather", &upstream.uri())])),
        )
        .mount(&broker.server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "content": [{ "type": "text", "text": "sunny" }] }
        })))
        .mount(&upstream)
        .await;

    // A plain listing: no query parameters at all.
    let (status, body) = broker
        .send(ws.signed("POST", "/mcp/list-servers", "{}"))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let requests = sent(&broker).await;
    let plain = requests
        .iter()
        .find(|r| r.url.path() == SYNC_PATH)
        .expect("the broker synced");
    assert_eq!(
        plain.url.query(),
        None,
        "a plain listing must not send a query string"
    );

    // A tool call syncs for credentials, which is the same type with both
    // fields set.
    let call = serde_json::json!({ "server": "weather", "tool": "forecast" });
    let (status, body) = broker
        .send(ws.signed("POST", "/mcp/call", &call.to_string()))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let requests = sent(&broker).await;
    let with_creds = requests
        .iter()
        .filter(|r| r.url.path() == SYNC_PATH)
        .find_map(|r| r.url.query())
        .expect("the credential-bearing sync must carry a query string");
    let query: McpSyncQuery = serde_urlencoded::from_str(with_creds).unwrap_or_else(|e| {
        panic!("the sync query does not deserialise into the server's query type: {e}")
    });
    assert!(query.include_credentials);
    assert!(
        query.broker_public_key.is_some_and(|k| !k.is_empty()),
        "the server refuses include_credentials without a key to seal to"
    );
}

/// The tool-call gate is the server's `McpAuthorizeRequest`/`Response`: the
/// broker names the server and tool it is about to call, and proceeds only
/// on the decision value the shared type defines.
#[tokio::test(flavor = "multi_thread")]
async fn mcp_authorize_call_is_the_servers_request_and_response() {
    let (broker, ws) = setup().await;
    let upstream = MockServer::start().await;
    mount_authorize(&broker).await;
    Mock::given(method("GET"))
        .and(path(SYNC_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(sync_response(vec![sync_entry("weather", &upstream.uri())])),
        )
        .mount(&broker.server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "content": [{ "type": "text", "text": "sunny" }] }
        })))
        .mount(&upstream)
        .await;

    let call = serde_json::json!({ "server": "weather", "tool": "forecast" });
    let (status, body) = broker
        .send(ws.signed("POST", "/mcp/call", &call.to_string()))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["data"]["correlation_id"], "corr-wire",
        "the correlation id from the shared response is handed to the agent"
    );

    let requests = sent(&broker).await;
    let authorize: McpAuthorizeRequest = body_as(&requests, AUTHORIZE_PATH);
    assert_eq!(authorize.server_name, "weather");
    assert_eq!(authorize.tool_name, "forecast");
}

/// A `forbid` decision, serialised from the server's own type, stops the
/// call — so the broker and the server agree on the value, not just the
/// field name.
#[tokio::test(flavor = "multi_thread")]
async fn a_forbid_decision_from_the_shared_type_stops_the_call() {
    let (broker, ws) = setup().await;
    let upstream = MockServer::start().await;
    let body = serde_json::to_value(ApiEnvelope::ok(McpAuthorizeResponse {
        decision: McpAuthorizeResponse::FORBID.to_string(),
        correlation_id: "corr-forbid".to_string(),
    }))
    .expect("serialise");
    Mock::given(method("POST"))
        .and(path(AUTHORIZE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&broker.server)
        .await;
    Mock::given(method("GET"))
        .and(path(SYNC_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(sync_response(vec![sync_entry("weather", &upstream.uri())])),
        )
        .mount(&broker.server)
        .await;

    let call = serde_json::json!({ "server": "weather", "tool": "forecast" });
    let (status, body) = broker
        .send(ws.signed("POST", "/mcp/call", &call.to_string()))
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        upstream.received_requests().await.unwrap().is_empty(),
        "a forbidden tool call must never reach the upstream"
    );
}

/// An MCP server's description comes from the catalog template it was
/// provisioned from, reaches the broker on the sync entry, and is what
/// `agentcordon mcp-servers` prints in its DESCRIPTION column.
#[tokio::test(flavor = "multi_thread")]
async fn list_servers_surfaces_the_description_the_server_sent() {
    let (broker, ws) = setup().await;
    let mut described = sync_entry("weather", "https://mcp.example.com");
    described.description = Some("Forecasts and severe-weather alerts.".to_string());
    let undescribed = sync_entry("hand-rolled", "https://mcp.example.com/hand");

    Mock::given(method("GET"))
        .and(path(SYNC_PATH))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(sync_response(vec![described, undescribed])),
        )
        .mount(&broker.server)
        .await;

    let (status, body) = broker
        .send(ws.signed("POST", "/mcp/list-servers", "{}"))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let listed = body["data"].as_array().expect("a list of servers");
    let weather = listed
        .iter()
        .find(|s| s["name"] == "weather")
        .expect("weather");
    assert_eq!(
        weather["description"], "Forecasts and severe-weather alerts.",
        "the description the server synced must reach the agent"
    );
    let hand_rolled = listed
        .iter()
        .find(|s| s["name"] == "hand-rolled")
        .expect("hand-rolled");
    assert!(
        hand_rolled["description"].is_null(),
        "a server with no description stays null rather than borrowing another's"
    );
}

/// A sealed credential on a sync entry, built from the server's own types,
/// is decrypted and injected — the whole MCP credential path speaks the
/// shared envelope type.
#[tokio::test(flavor = "multi_thread")]
async fn a_sealed_credential_on_a_sync_entry_is_injected() {
    let (broker, ws) = setup().await;
    let upstream = MockServer::start().await;
    mount_authorize(&broker).await;

    let mut entry = sync_entry("weather", &upstream.uri());
    entry.auth_method = "api_key".to_string();
    entry.credential_envelopes = Some(vec![McpCredentialEnvelope {
        credential_name: "weather-key".to_string(),
        credential_type: "bearer".to_string(),
        transform_name: None,
        encrypted_envelope: serde_json::from_value::<EncryptedEnvelopeWire>(
            vend_envelope(&broker, &serde_json::json!({ "value": SECRET })).await,
        )
        .expect("shared envelope type"),
    }]);

    Mock::given(method("GET"))
        .and(path(SYNC_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(sync_response(vec![entry])))
        .mount(&broker.server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "content": [{ "type": "text", "text": "sunny" }] }
        })))
        .mount(&upstream)
        .await;

    let call = serde_json::json!({ "server": "weather", "tool": "forecast" });
    let (status, body) = broker
        .send(ws.signed("POST", "/mcp/call", &call.to_string()))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let injected = upstream
        .received_requests()
        .await
        .expect("upstream records")
        .into_iter()
        .next()
        .expect("one upstream call");
    assert_eq!(
        injected
            .headers
            .get("authorization")
            .map(|v| v.to_str().unwrap().to_string()),
        Some(format!("Bearer {SECRET}")),
        "the envelope the server sealed on the sync entry must reach the upstream"
    );
}

// ---------------------------------------------------------------------------
// OAuth token refresh
// ---------------------------------------------------------------------------

/// A 401 from the server drives a refresh, and that refresh is the server's
/// `TokenRequest`: the `refresh_token` grant, the rotated refresh token, and
/// the per-workspace `client_id` the broker persisted at enrollment.
#[tokio::test(flavor = "multi_thread")]
async fn token_refresh_is_the_servers_token_request() {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, &["credentials:discover"])
        .build()
        .await;
    let stale = format!("access-{}", &ws.pk_hash()[..8]);
    let expected_refresh = format!("refresh-{}", &ws.pk_hash()[..8]);
    let expected_client = format!("client-{}", &ws.pk_hash()[..8]);

    Mock::given(method("GET"))
        .and(path("/api/v1/credentials"))
        .and(wiremock::matchers::header(
            "authorization",
            format!("Bearer {stale}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(401))
        .mount(&broker.server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/credentials"))
        .and(wiremock::matchers::header(
            "authorization",
            "Bearer fresh-token",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "data": Vec::<serde_json::Value>::new() })),
        )
        .mount(&broker.server)
        .await;

    // The stub answer is the server's own token response type.
    let refreshed = TokenResponse {
        access_token: "fresh-token".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 900,
        refresh_token: Some("rotated-refresh".to_string()),
        scope: Some("credentials:discover".to_string()),
        client_id: Some(expected_client.clone()),
    };
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::to_value(&refreshed).expect("serialise")),
        )
        .mount(&broker.server)
        .await;

    let (status, body) = broker.send(ws.signed("GET", "/credentials", "")).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let requests = sent(&broker).await;
    let refresh: TokenRequest = form_as(&requests, TOKEN_PATH);
    assert_eq!(
        refresh.grant_type.as_deref(),
        Some(grant_types::REFRESH_TOKEN)
    );
    assert_eq!(refresh.refresh_token.as_deref(), Some(&*expected_refresh));
    assert_eq!(
        refresh.client_id.as_deref(),
        Some(&*expected_client),
        "the per-workspace client_id, not the bootstrap one — the server rejects the mismatch"
    );
    assert_eq!(
        refresh.device_code, None,
        "an unset field must be absent from the form, not sent empty"
    );
    assert_eq!(refresh.code, None);
    assert_eq!(refresh.client_secret, None);
}

// ---------------------------------------------------------------------------
// Credential listing
// ---------------------------------------------------------------------------

/// `GET /credentials` is a projection of the server's `CredentialSummary`,
/// not a passthrough: the agent gets what it needs to choose a credential
/// and nothing else. The server's summary also carries transform scripts,
/// metadata and ownership, which have no business reaching an agent.
#[tokio::test(flavor = "multi_thread")]
async fn credential_listing_projects_the_servers_summary() {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, &["credentials:discover"])
        .build()
        .await;

    let summary = CredentialSummary {
        id: CredentialId(uuid::Uuid::new_v4()),
        name: "gh".to_string(),
        service: "github".to_string(),
        scopes: vec!["repo".to_string()],
        metadata: serde_json::json!({ "header_name": "X-Api-Key" }),
        created_by: None,
        created_by_user: None,
        created_at: chrono::Utc::now(),
        allowed_url_pattern: Some("https://api.github.com/*".to_string()),
        expires_at: None,
        expired: false,
        transform_script: Some("fn transform(v) { v }".to_string()),
        transform_name: Some("bearer".to_string()),
        vault_id: agent_cordon_core::domain::vault::DEFAULT_VAULT_ID.to_string(),
        vault_name: "default".to_string(),
        credential_type: "generic".to_string(),
        tags: vec!["llm_exposed".to_string()],
        description: Some("internal note".to_string()),
        target_identity: None,
        owner_username: Some("alice".to_string()),
        access: None,
    };
    let body = serde_json::to_value(ApiEnvelope::ok(vec![&summary])).expect("serialise summary");
    Mock::given(method("GET"))
        .and(path("/api/v1/credentials"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&broker.server)
        .await;

    let (status, body) = broker.send(ws.signed("GET", "/credentials", "")).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let listed = body["data"].as_array().expect("a list");
    let entry = listed
        .first()
        .expect("one credential")
        .as_object()
        .expect("an object");

    // What an agent needs to pick a credential and predict the vend.
    assert_eq!(entry["name"], "gh");
    assert_eq!(entry["service"], "github");
    assert_eq!(entry["credential_type"], "generic");
    assert_eq!(entry["vault"], "default");
    assert_eq!(entry["allowed_url_pattern"], "https://api.github.com/*");
    assert_eq!(entry["expired"], false);
    assert_eq!(entry["id"], summary.id.0.to_string());

    // What it must not be handed.
    for withheld in [
        "transform_script",
        "transform_name",
        "metadata",
        "owner_username",
        "created_by_user",
        "description",
        "tags",
    ] {
        assert!(
            !entry.contains_key(withheld),
            "the broker must not forward `{withheld}` to an agent: {entry:?}"
        );
    }
}
