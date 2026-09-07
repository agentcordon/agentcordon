//! D12 — how an MCP server's API key reaches the upstream.
//!
//! The broker applies the credential the server sealed for it. A credential
//! typed `api_key_header` goes in the header its `metadata.header_name` names
//! and nowhere else; `api_key_query` becomes a query parameter; everything
//! else keeps the bearer it has always had. The upstream MCP here is a
//! wiremock server, so the assertion is on the request it actually received.

use axum::http::StatusCode;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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

/// One MCP server named `weather`, with one credential envelope whose sealed
/// material is `material` and whose declared type is `credential_type`.
async fn mount_sync(
    broker: &TestBroker,
    upstream: &MockServer,
    credential_type: &str,
    transform_name: serde_json::Value,
    material: serde_json::Value,
) {
    let envelope = vend_envelope(broker, &material).await;
    let body = serde_json::json!({
        "data": {
            "servers": [{
                "id": "srv-1",
                "name": "weather",
                "transport": "http",
                "url": upstream.uri(),
                "tools": ["forecast"],
                "enabled": true,
                "auth_method": "api_key",
                "credential_envelopes": [{
                    "credential_name": "weather-key",
                    "credential_type": credential_type,
                    "transform_name": transform_name,
                    "encrypted_envelope": envelope,
                }]
            }]
        }
    });
    Mock::given(method("GET"))
        .and(path(SYNC_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&broker.server)
        .await;
}

/// Accept any JSON-RPC POST and record it.
async fn mount_upstream(upstream: &MockServer) {
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "content": [{ "type": "text", "text": "sunny" }] }
        })))
        .mount(upstream)
        .await;
}

async fn call_forecast(broker: &TestBroker, ws: &TestWorkspace) -> (StatusCode, serde_json::Value) {
    let body = serde_json::json!({ "server": "weather", "tool": "forecast", "arguments": {} });
    broker
        .send(ws.signed("POST", "/mcp/call", &body.to_string()))
        .await
}

/// The single request the upstream received.
async fn upstream_request(upstream: &MockServer) -> wiremock::Request {
    let mut reqs = upstream.received_requests().await.unwrap_or_default();
    assert_eq!(reqs.len(), 1, "upstream must have been called exactly once");
    reqs.remove(0)
}

// ===========================================================================
// api_key_header — the key goes in the named header, not in Authorization
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn api_key_header_credential_sends_the_key_in_the_named_header() {
    let (broker, ws, upstream) = setup().await;
    mount_sync(
        &broker,
        &upstream,
        "api_key_header",
        serde_json::Value::Null,
        serde_json::json!({
            "value": "sk-weather-123",
            "metadata": { "header_name": "X-API-Key" }
        }),
    )
    .await;
    mount_upstream(&upstream).await;

    let (status, resp) = call_forecast(&broker, &ws).await;
    assert_eq!(status, StatusCode::OK, "{resp}");

    let req = upstream_request(&upstream).await;
    assert_eq!(
        req.headers
            .get("x-api-key")
            .map(|v| v.to_str().unwrap().to_string()),
        Some("sk-weather-123".to_string()),
        "the key must be in the header the credential names"
    );
    assert!(
        req.headers.get("authorization").is_none(),
        "an api_key_header credential must not also be sent as a bearer"
    );
}

// ===========================================================================
// api_key_query — the key becomes a query parameter
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn api_key_query_credential_appends_the_key_as_a_query_parameter() {
    let (broker, ws, upstream) = setup().await;
    mount_sync(
        &broker,
        &upstream,
        "api_key_query",
        serde_json::Value::Null,
        serde_json::json!({
            "value": "sk-maps-456",
            "metadata": { "param_name": "api_key" }
        }),
    )
    .await;
    mount_upstream(&upstream).await;

    let (status, resp) = call_forecast(&broker, &ws).await;
    assert_eq!(status, StatusCode::OK, "{resp}");

    let req = upstream_request(&upstream).await;
    let param = req
        .url
        .query_pairs()
        .find(|(k, _)| k == "api_key")
        .map(|(_, v)| v.to_string());
    assert_eq!(
        param,
        Some("sk-maps-456".to_string()),
        "the key must be appended as the named query parameter: {}",
        req.url
    );
    assert!(
        req.headers.get("authorization").is_none(),
        "an api_key_query credential must not also be sent as a bearer"
    );
}

// ===========================================================================
// generic + bearer — unchanged
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn generic_credential_with_a_bearer_transform_still_sends_a_bearer() {
    let (broker, ws, upstream) = setup().await;
    mount_sync(
        &broker,
        &upstream,
        "generic",
        serde_json::json!("bearer"),
        serde_json::json!({ "value": "ghp-token-789" }),
    )
    .await;
    mount_upstream(&upstream).await;

    let (status, resp) = call_forecast(&broker, &ws).await;
    assert_eq!(status, StatusCode::OK, "{resp}");

    let req = upstream_request(&upstream).await;
    assert_eq!(
        req.headers
            .get("authorization")
            .map(|v| v.to_str().unwrap().to_string()),
        Some("Bearer ghp-token-789".to_string()),
        "bearer injection must be unchanged"
    );
}

// ===========================================================================
// An echoed API key is redacted too — the needle is the key, not the bearer
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn an_api_key_echoed_by_the_upstream_is_redacted() {
    let (broker, ws, upstream) = setup().await;
    mount_sync(
        &broker,
        &upstream,
        "api_key_header",
        serde_json::Value::Null,
        serde_json::json!({
            "value": "sk-weather-123",
            "metadata": { "header_name": "X-API-Key" }
        }),
    )
    .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [
                    { "type": "text", "text": "authenticated as sk-weather-123" },
                    { "type": "json", "json": { "echo": { "x-api-key": "sk-weather-123" } } }
                ]
            }
        })))
        .mount(&upstream)
        .await;

    let (status, resp) = call_forecast(&broker, &ws).await;

    assert_eq!(status, StatusCode::OK, "{resp}");
    let rendered = resp.to_string();
    assert!(
        !rendered.contains("sk-weather-123"),
        "the injected API key must never reach the agent: {rendered}"
    );
    assert!(
        rendered.contains("[REDACTED]"),
        "the echoed key must be redacted, not dropped: {rendered}"
    );
}
