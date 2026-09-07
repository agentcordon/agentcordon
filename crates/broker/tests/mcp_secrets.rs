//! Secrets at the broker: the broker holds only the short-lived upstream
//! access token the server put in the sync (or vend) envelope. It never
//! sees a refresh token or a provider client secret, never calls a token
//! endpoint, and gets a fresh token by syncing again.

use std::collections::HashMap;

use axum::http::StatusCode;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use agentcordon_broker::state::{CachedCredential, CachedMcpServer};

use crate::common::{vend_envelope, TestBroker, TestWorkspace};

const SYNC_PATH: &str = "/api/v1/workspaces/mcp-servers";
const AUTHORIZE_PATH: &str = "/api/v1/workspaces/mcp-authorize";

async fn setup() -> (TestBroker, TestWorkspace, MockServer) {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, &["mcp:invoke", "credentials:vend"])
        .build()
        .await;
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(AUTHORIZE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "decision": "permit", "correlation_id": "corr-1" }
        })))
        .mount(&broker.server)
        .await;
    (broker, ws, upstream)
}

/// What the server returns from the sync endpoint: one OAuth-backed MCP
/// server whose envelope carries an access token and its expiry.
async fn sync_body(
    broker: &TestBroker,
    upstream: &MockServer,
    access_token: &str,
    expires_in: chrono::Duration,
) -> serde_json::Value {
    let expires_at = (chrono::Utc::now() + expires_in).to_rfc3339();
    let envelope = vend_envelope(
        broker,
        &serde_json::json!({ "value": access_token, "expires_at": expires_at }),
    )
    .await;
    serde_json::json!({
        "data": {
            "servers": [{
                "id": "srv-1",
                "name": "notion",
                "transport": "http",
                "url": upstream.uri(),
                "tools": ["search"],
                "enabled": true,
                "auth_method": "oauth2",
                "credential_envelopes": [{
                    "credential_name": "notion-oauth",
                    "credential_type": "oauth2_user_authorization",
                    "transform_name": "bearer",
                    "encrypted_envelope": envelope,
                }]
            }]
        }
    })
}

fn jsonrpc_result() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "content": [{ "type": "text", "text": "hello" }] }
    }))
}

async fn call_search(broker: &TestBroker, ws: &TestWorkspace) -> (StatusCode, serde_json::Value) {
    let body = serde_json::json!({ "server": "notion", "tool": "search", "arguments": {} });
    broker
        .send(ws.signed("POST", "/mcp/call", &body.to_string()))
        .await
}

/// Every request the broker made to the fake server, by path.
async fn server_paths(broker: &TestBroker) -> Vec<String> {
    broker
        .server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.url.path().to_string())
        .collect()
}

/// The token from the sync envelope is injected as a bearer. The broker's
/// only calls to the server are authorize and sync: no token endpoint, no
/// rotation callback.
#[tokio::test(flavor = "multi_thread")]
async fn mcp_call_injects_the_synced_access_token_and_calls_no_token_endpoint() {
    let (broker, ws, upstream) = setup().await;
    let body = sync_body(
        &broker,
        &upstream,
        "upstream-access-A",
        chrono::Duration::hours(1),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(SYNC_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .expect(1)
        .mount(&broker.server)
        .await;
    Mock::given(method("POST"))
        .and(header("authorization", "Bearer upstream-access-A"))
        .respond_with(jsonrpc_result())
        .expect(1)
        .mount(&upstream)
        .await;

    let (status, resp) = call_search(&broker, &ws).await;

    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(resp["data"]["content"][0]["text"], "hello");
    let paths = server_paths(&broker).await;
    assert!(
        paths.iter().all(|p| p == AUTHORIZE_PATH || p == SYNC_PATH),
        "broker must talk only to authorize and sync: {paths:?}"
    );
}

/// Put an already-synced entry for `notion` in the broker's cache, holding
/// an access token that expires in `expires_in`.
async fn seed_cached_token(
    broker: &TestBroker,
    ws: &TestWorkspace,
    upstream: &MockServer,
    access_token: &str,
    expires_in: chrono::Duration,
) {
    let server = CachedMcpServer {
        id: "srv-1".to_string(),
        name: "notion".to_string(),
        url: upstream.uri(),
        transport: "http".to_string(),
        auth_method: "oauth2".to_string(),
        tools: vec!["search".to_string()],
        enabled: true,
        credential: Some(CachedCredential {
            credential_type: "oauth2_user_authorization".to_string(),
            value: access_token.to_string(),
            transform_name: Some("bearer".to_string()),
            metadata: HashMap::new(),
            expires_at: Some(chrono::Utc::now() + expires_in),
        }),
        last_synced: chrono::Utc::now(),
    };
    broker
        .state
        .mcp_configs
        .write()
        .await
        .insert(ws.pk_hash(), vec![server]);
}

/// A cached token within 60s of expiry is not used: the broker syncs again
/// (once) and injects the token from the fresh envelope.
#[tokio::test(flavor = "multi_thread")]
async fn mcp_call_resyncs_when_the_cached_token_is_near_expiry() {
    let (broker, ws, upstream) = setup().await;
    seed_cached_token(
        &broker,
        &ws,
        &upstream,
        "upstream-access-A",
        chrono::Duration::seconds(30),
    )
    .await;
    let fresh = sync_body(
        &broker,
        &upstream,
        "upstream-access-B",
        chrono::Duration::hours(1),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(SYNC_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(fresh))
        .expect(1)
        .mount(&broker.server)
        .await;
    Mock::given(method("POST"))
        .and(header("authorization", "Bearer upstream-access-B"))
        .respond_with(jsonrpc_result())
        .expect(1)
        .mount(&upstream)
        .await;

    let (status, resp) = call_search(&broker, &ws).await;

    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(resp["data"]["content"][0]["text"], "hello");
}

/// A cached token with plenty of life left is used as-is: no sync.
#[tokio::test(flavor = "multi_thread")]
async fn mcp_call_uses_a_fresh_cached_token_without_syncing() {
    let (broker, ws, upstream) = setup().await;
    seed_cached_token(
        &broker,
        &ws,
        &upstream,
        "upstream-access-A",
        chrono::Duration::hours(1),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(SYNC_PATH))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&broker.server)
        .await;
    Mock::given(method("POST"))
        .and(header("authorization", "Bearer upstream-access-A"))
        .respond_with(jsonrpc_result())
        .expect(1)
        .mount(&upstream)
        .await;

    let (status, resp) = call_search(&broker, &ws).await;

    assert_eq!(status, StatusCode::OK, "{resp}");
}

/// An upstream 401 means the token is no longer good: the broker syncs
/// again and retries once with the new token.
#[tokio::test(flavor = "multi_thread")]
async fn mcp_call_resyncs_and_retries_once_after_upstream_401() {
    let (broker, ws, upstream) = setup().await;
    let first = sync_body(
        &broker,
        &upstream,
        "upstream-access-A",
        chrono::Duration::hours(1),
    )
    .await;
    let second = sync_body(
        &broker,
        &upstream,
        "upstream-access-B",
        chrono::Duration::hours(1),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(SYNC_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(first))
        .up_to_n_times(1)
        .mount(&broker.server)
        .await;
    Mock::given(method("GET"))
        .and(path(SYNC_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(second))
        .expect(1)
        .mount(&broker.server)
        .await;
    Mock::given(method("POST"))
        .and(header("authorization", "Bearer upstream-access-A"))
        .respond_with(ResponseTemplate::new(401).set_body_string("token revoked"))
        .expect(1)
        .mount(&upstream)
        .await;
    Mock::given(method("POST"))
        .and(header("authorization", "Bearer upstream-access-B"))
        .respond_with(jsonrpc_result())
        .expect(1)
        .mount(&upstream)
        .await;

    let (status, resp) = call_search(&broker, &ws).await;

    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(resp["data"]["content"][0]["text"], "hello");
}

// ---------------------------------------------------------------------------
// An upstream that echoes the injected credential must not reach the agent
// ---------------------------------------------------------------------------

const TOOLS_PATH: &str = "/api/v1/workspaces/mcp-tools";

/// An MCP server that echoes its `Authorization` header into the tool result
/// hands the agent the token unless the broker scans what it returns. The
/// same `LeakScanner` the proxy route uses covers the MCP route: every part
/// of the result, free text and nested JSON alike.
#[tokio::test(flavor = "multi_thread")]
async fn mcp_call_redacts_injected_token_echoed_by_the_upstream() {
    let (broker, ws, upstream) = setup().await;
    let body = sync_body(
        &broker,
        &upstream,
        "upstream-access-A",
        chrono::Duration::hours(1),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(SYNC_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&broker.server)
        .await;
    // The upstream mirrors the request it received, the way a debug endpoint
    // does: once in prose, once in a nested JSON field.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [
                    { "type": "text", "text": "you sent Authorization: Bearer upstream-access-A" },
                    { "type": "json", "json": { "echo": { "authorization": "Bearer upstream-access-A" } } }
                ]
            }
        })))
        .mount(&upstream)
        .await;

    let (status, resp) = call_search(&broker, &ws).await;

    assert_eq!(status, StatusCode::OK, "{resp}");
    let rendered = resp.to_string();
    assert!(
        !rendered.contains("upstream-access-A"),
        "the injected token must never reach the agent: {rendered}"
    );
    assert!(
        rendered.contains("[REDACTED]"),
        "the echoed token must be redacted, not dropped: {rendered}"
    );
}

/// The `tools/list` probe carries the same credential, so an echo in a tool
/// description leaks just as readily. It is scanned too.
#[tokio::test(flavor = "multi_thread")]
async fn mcp_list_tools_redacts_an_injected_token_echoed_by_the_upstream() {
    let (broker, ws, upstream) = setup().await;
    let body = sync_body(
        &broker,
        &upstream,
        "upstream-access-A",
        chrono::Duration::hours(1),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(SYNC_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&broker.server)
        .await;
    // The server knows of no tools, so the broker probes the upstream itself.
    Mock::given(method("GET"))
        .and(path(TOOLS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": [] })))
        .mount(&broker.server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [{
                    "name": "search",
                    "description": "called with Bearer upstream-access-A",
                    "inputSchema": { "type": "object", "title": "upstream-access-A" }
                }]
            }
        })))
        .mount(&upstream)
        .await;

    let (status, resp) = broker.send(ws.signed("POST", "/mcp/list-tools", "")).await;

    assert_eq!(status, StatusCode::OK, "{resp}");
    let rendered = resp.to_string();
    assert!(
        !rendered.contains("upstream-access-A"),
        "the probe's token must never reach the agent: {rendered}"
    );
    assert!(
        rendered.contains("[REDACTED]"),
        "the echoed token must be redacted, not dropped: {rendered}"
    );
}
