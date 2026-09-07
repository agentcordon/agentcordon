//! An MCP server's `allowed_tools` is an allow-list, and the broker honours it.
//!
//! The control plane narrows the tool set (`PUT /api/v1/mcp-servers/{id}`)
//! and hands the broker only the tools a workspace may use, flagged
//! authoritative. The broker's own `tools/list` probe exists for servers whose
//! tools the control plane does not know; run against a narrowed server it
//! would hand the agent every tool the operator excluded, including for a
//! server narrowed to no tools at all (uat S20, G-S20-1).

use std::collections::HashMap;

use axum::http::StatusCode;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use agentcordon_broker::state::{CachedCredential, CachedMcpServer};

use crate::common::{TestBroker, TestWorkspace};

const TOOLS_PATH: &str = "/api/v1/workspaces/mcp-tools";

/// The narrowed answer the control plane gives: one of the upstream's two
/// tools.
async fn server_knows_the_narrowed_tools(broker: &TestBroker, tools: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path(TOOLS_PATH))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": tools })),
        )
        .mount(&broker.server)
        .await;
}

/// An upstream that publishes both tools, and counts what asks it.
async fn upstream_with_two_tools() -> MockServer {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "tools": [
                { "name": "echo", "description": "Echo", "inputSchema": {} },
                { "name": "whoami", "description": "Who", "inputSchema": {} }
            ] }
        })))
        .mount(&upstream)
        .await;
    upstream
}

fn cached_server(url: &str, tools: Vec<String>, authoritative: bool) -> CachedMcpServer {
    CachedMcpServer {
        id: "srv-1".to_string(),
        name: "uat-none".to_string(),
        url: url.to_string(),
        transport: "http".to_string(),
        auth_method: "bearer".to_string(),
        tools,
        tools_are_authoritative: authoritative,
        enabled: true,
        credential: Some(CachedCredential {
            credential_type: "api_key".to_string(),
            value: "k-1".to_string(),
            transform_name: None,
            metadata: HashMap::new(),
            expires_at: None,
        }),
        last_synced: chrono::Utc::now(),
    }
}

async fn seed(broker: &TestBroker, ws: &TestWorkspace, server: CachedMcpServer) {
    broker
        .state
        .mcp_configs
        .write()
        .await
        .insert(ws.pk_hash(), vec![server]);
}

/// The narrowed set is what an agent sees. `mcp-tools`,
/// `agentcordon_mcp_tools` and an `--expose`d `tools/list` are all this
/// response.
#[tokio::test(flavor = "multi_thread")]
async fn list_tools_reports_only_the_tools_the_control_plane_allows() {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, &["mcp:discover"])
        .allow_loopback(true)
        .build()
        .await;
    let upstream = upstream_with_two_tools().await;
    server_knows_the_narrowed_tools(
        &broker,
        serde_json::json!([{ "server": "uat-none", "tool": "echo", "description": "Echo" }]),
    )
    .await;
    seed(
        &broker,
        &ws,
        cached_server(
            &format!("{}/mcp", upstream.uri()),
            vec!["echo".to_string()],
            true,
        ),
    )
    .await;

    let (status, body) = broker
        .send(ws.signed("POST", "/mcp/list-tools", "{}"))
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let tools: Vec<&str> = body["data"]
        .as_array()
        .expect("a tool list")
        .iter()
        .map(|t| t["tool"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(tools, vec!["echo"], "{body}");
    assert!(
        upstream.received_requests().await.unwrap().is_empty(),
        "the broker must not probe a server whose tool list the control plane owns"
    );
}

/// The case the probe would break loudest: a server narrowed to no tools has
/// nothing in the control plane's answer, which is exactly the shape the probe
/// treats as "nobody knows, go and ask". It must not ask.
#[tokio::test(flavor = "multi_thread")]
async fn a_server_narrowed_to_no_tools_is_not_probed_back_open() {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, &["mcp:discover"])
        .allow_loopback(true)
        .build()
        .await;
    let upstream = upstream_with_two_tools().await;
    server_knows_the_narrowed_tools(&broker, serde_json::json!([])).await;
    seed(
        &broker,
        &ws,
        cached_server(&format!("{}/mcp", upstream.uri()), vec![], true),
    )
    .await;

    let (status, body) = broker
        .send(ws.signed("POST", "/mcp/list-tools", "{}"))
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["data"].as_array().map(Vec::len),
        Some(0),
        "a server narrowed to no tools exposes none: {body}"
    );
    assert!(
        upstream.received_requests().await.unwrap().is_empty(),
        "and the upstream is never asked"
    );
}

/// The probe still exists, for the case it was built for: a server the
/// control plane has no tools for and has not narrowed.
#[tokio::test(flavor = "multi_thread")]
async fn an_unnarrowed_server_with_no_known_tools_is_still_probed() {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, &["mcp:discover"])
        .allow_loopback(true)
        .build()
        .await;
    let upstream = upstream_with_two_tools().await;
    server_knows_the_narrowed_tools(&broker, serde_json::json!([])).await;
    seed(
        &broker,
        &ws,
        cached_server(&format!("{}/mcp", upstream.uri()), vec![], false),
    )
    .await;

    let (status, body) = broker
        .send(ws.signed("POST", "/mcp/list-tools", "{}"))
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let tools: Vec<&str> = body["data"]
        .as_array()
        .expect("a tool list")
        .iter()
        .map(|t| t["tool"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(tools, vec!["echo", "whoami"], "{body}");
}
