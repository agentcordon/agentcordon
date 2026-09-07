//! SSRF guard on the broker's MCP path, observed at the HTTP seam.
//!
//! The MCP tool-list probe and the tool call must refuse upstreams in
//! private or reserved ranges exactly as `/proxy` does, unless the broker
//! was started with `--proxy-allow-loopback`. Upstream token caches must be
//! keyed per workspace so two workspaces never share a token.

use std::collections::HashMap;

use axum::http::StatusCode;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use agentcordon_broker::state::{CachedCredential, CachedMcpServer};

use crate::common::{TestBroker, TestWorkspace};

/// A JSON-RPC `tools/list` result with one tool.
fn tools_list_body() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "tools": [ { "name": "echo", "description": "Echo", "inputSchema": {} } ] }
    })
}

/// The server's `/api/v1/workspaces/mcp-tools` answer: no tools known
/// server-side, so the broker probes every cached server itself.
async fn server_knows_no_tools(broker: &TestBroker) {
    Mock::given(method("GET"))
        .and(path("/api/v1/workspaces/mcp-tools"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": [] })))
        .mount(&broker.server)
        .await;
    // The sync endpoint is deliberately left unmocked: wiremock answers 404,
    // the on-demand sync fails, and the broker keeps the cache seeded below.
}

fn api_key_credential() -> CachedCredential {
    CachedCredential {
        credential_type: "api_key".to_string(),
        value: "k-1".to_string(),
        transform_name: None,
        metadata: HashMap::new(),
        expires_at: None,
    }
}

fn cached_server(id: &str, name: &str, url: &str, credential: CachedCredential) -> CachedMcpServer {
    CachedMcpServer {
        id: id.to_string(),
        name: name.to_string(),
        url: url.to_string(),
        transport: "http".to_string(),
        auth_method: "bearer".to_string(),
        tools: vec![],
        enabled: true,
        credential: Some(credential),
        last_synced: chrono::Utc::now(),
    }
}

/// Seed the broker's MCP cache for one workspace as a completed sync would.
async fn seed_mcp_server(broker: &TestBroker, ws: &TestWorkspace, server: CachedMcpServer) {
    broker
        .state
        .mcp_configs
        .write()
        .await
        .insert(ws.pk_hash(), vec![server]);
}

/// Loopback upstream, loopback not allowed: the tool-list probe is refused
/// with 400 before any request reaches the upstream.
#[tokio::test]
async fn list_tools_refuses_loopback_upstream_without_allow_loopback() {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, &["mcp:discover"])
        .allow_loopback(false)
        .build()
        .await;
    server_knows_no_tools(&broker).await;

    // wiremock binds 127.0.0.1, so this upstream *is* a loopback target.
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(tools_list_body()))
        .expect(0)
        .mount(&upstream)
        .await;

    let url = format!("{}/mcp", upstream.uri());
    seed_mcp_server(
        &broker,
        &ws,
        cached_server("srv-1", "loopback-mcp", &url, api_key_credential()),
    )
    .await;

    let (status, body) = broker
        .send(ws.signed("POST", "/mcp/list-tools", "{}"))
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"]["code"], "ssrf_blocked");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("loopback-mcp"),
        "error names the offending server: {body}"
    );
    assert!(
        upstream.received_requests().await.unwrap().is_empty(),
        "upstream must receive nothing"
    );
}

/// Link-local (cloud metadata) upstream: refused on tool-list with 400.
#[tokio::test]
async fn list_tools_refuses_link_local_upstream_without_allow_loopback() {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, &["mcp:discover"])
        .allow_loopback(false)
        .build()
        .await;
    server_knows_no_tools(&broker).await;

    seed_mcp_server(
        &broker,
        &ws,
        cached_server(
            "srv-2",
            "metadata-mcp",
            "http://169.254.169.254/latest/mcp",
            api_key_credential(),
        ),
    )
    .await;

    let (status, body) = broker
        .send(ws.signed("POST", "/mcp/list-tools", "{}"))
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"]["code"], "ssrf_blocked");
}

/// Same loopback upstream with `--proxy-allow-loopback`: the probe runs and
/// the upstream's tools come back, so the refusal above is the SSRF check
/// and nothing else.
#[tokio::test]
async fn list_tools_probes_loopback_upstream_when_allowed() {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, &["mcp:discover"])
        .allow_loopback(true)
        .build()
        .await;
    server_knows_no_tools(&broker).await;

    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(tools_list_body()))
        .expect(1)
        .mount(&upstream)
        .await;

    let url = format!("{}/mcp", upstream.uri());
    seed_mcp_server(
        &broker,
        &ws,
        cached_server("srv-1", "loopback-mcp", &url, api_key_credential()),
    )
    .await;

    let (status, body) = broker
        .send(ws.signed("POST", "/mcp/list-tools", "{}"))
        .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["data"][0]["server"], "loopback-mcp");
    assert_eq!(body["data"][0]["tool"], "echo");
}

/// Two workspaces bound to the same MCP server (same id, same name) each
/// hold their own upstream access token from their own sync envelope. The
/// token cached for one workspace must never be reused for the other.
#[tokio::test]
async fn upstream_token_cache_is_keyed_per_workspace() {
    let ws_a = TestWorkspace::generate();
    let ws_b = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws_a, &["mcp:discover"])
        .with_registered(&ws_b, &["mcp:discover"])
        .allow_loopback(true)
        .build()
        .await;
    server_knows_no_tools(&broker).await;

    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(tools_list_body()))
        .expect(2)
        .mount(&upstream)
        .await;

    let oauth_credential = |access_token: &str| CachedCredential {
        credential_type: "oauth2_user_authorization".to_string(),
        value: access_token.to_string(),
        transform_name: None,
        metadata: HashMap::new(),
        expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
    };
    let url = format!("{}/mcp", upstream.uri());
    seed_mcp_server(
        &broker,
        &ws_a,
        cached_server("srv-shared", "shared", &url, oauth_credential("token-A")),
    )
    .await;
    seed_mcp_server(
        &broker,
        &ws_b,
        cached_server("srv-shared", "shared", &url, oauth_credential("token-B")),
    )
    .await;

    let (status_a, body_a) = broker
        .send(ws_a.signed("POST", "/mcp/list-tools", "{}"))
        .await;
    assert_eq!(status_a, StatusCode::OK, "body: {body_a}");
    let (status_b, body_b) = broker
        .send(ws_b.signed("POST", "/mcp/list-tools", "{}"))
        .await;
    assert_eq!(status_b, StatusCode::OK, "body: {body_b}");

    let bearers: Vec<String> = upstream
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == "/mcp")
        .map(|r| {
            r.headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    assert_eq!(
        bearers,
        vec!["Bearer token-A".to_string(), "Bearer token-B".to_string()],
        "each workspace's probe must carry its own access token"
    );
}
