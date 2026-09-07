//! The server is the only authority on what a workspace may do.
//!
//! Two halves of one rule. The broker no longer refuses from its own cached
//! copy of the token scopes, so a workspace whose cached scopes say nothing
//! still reaches the server on every route that asks the server something.
//! And when the server stops saying yes — the workspace was revoked or
//! disabled by an operator mid-session — the very next call on each of those
//! routes is refused, including the MCP routes that hold a warm cache of
//! servers, URLs and upstream tokens.

use axum::http::StatusCode;
use wiremock::matchers::{any, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::{pattern_for, vend_body, vend_envelope, vend_path, TestBroker, TestWorkspace};

const CREDENTIALS_PATH: &str = "/api/v1/credentials";
const AGENT_STORE_PATH: &str = "/api/v1/credentials/agent-store";
const MCP_SERVERS_PATH: &str = "/api/v1/workspaces/mcp-servers";
const MCP_TOOLS_PATH: &str = "/api/v1/workspaces/mcp-tools";
const MCP_AUTHORIZE_PATH: &str = "/api/v1/workspaces/mcp-authorize";

const CRED: &str = "api-token";
const SECRET: &str = "tok-secret-value-1234567890";
const SERVER_NAME: &str = "notion";

/// One entry for `GET /api/v1/workspaces/mcp-servers`, carrying the union of
/// what the plain listing and the credential-bearing sync both read out of
/// it, so a single mock serves both callers.
async fn mcp_servers_body(broker: &TestBroker, upstream: &MockServer) -> serde_json::Value {
    let envelope = vend_envelope(broker, &serde_json::json!({ "value": "upstream-access" })).await;
    serde_json::json!({
        "data": {
            "servers": [{
                "id": "srv-1",
                "name": SERVER_NAME,
                "description": "notes",
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

/// Every request the broker makes on behalf of a workspace, answered as the
/// server answers one whose status is no longer `Active`.
///
/// `crates/server/src/extractors/oauth.rs` refuses in the bearer extractor,
/// before any route runs, with `ApiError::Forbidden("workspace is <status>")`;
/// `ApiError`'s `IntoResponse` renders that as 403 and this envelope. Every
/// path the broker might call gets the same answer, because on the real
/// server every one of them goes through that extractor.
fn workspace_no_longer_active(status: &str) -> ResponseTemplate {
    ResponseTemplate::new(403).set_body_json(serde_json::json!({
        "error": {
            "code": "forbidden",
            "message": format!("workspace is {status}"),
        }
    }))
}

/// The four calls a route makes on the way to an upstream, all succeeding.
async fn server_grants(broker: &TestBroker, upstream: &MockServer) {
    let servers = mcp_servers_body(broker, upstream).await;
    let vend = vend_body(broker, "bearer", SECRET, Some(&pattern_for(upstream))).await;

    Mock::given(method("GET"))
        .and(path(CREDENTIALS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": [] })))
        .mount(&broker.server)
        .await;
    // The credential body a store returns is the server's own wire type;
    // these tests are about who decides, not about that shape, so the
    // answer only has to be a success the broker actually asked for.
    Mock::given(method("POST"))
        .and(path(AGENT_STORE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": {} })))
        .mount(&broker.server)
        .await;
    Mock::given(method("POST"))
        .and(path(vend_path(CRED)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": vend })))
        .mount(&broker.server)
        .await;
    Mock::given(method("GET"))
        .and(path(MCP_SERVERS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(servers))
        .mount(&broker.server)
        .await;
    Mock::given(method("GET"))
        .and(path(MCP_TOOLS_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [{ "server": SERVER_NAME, "tool": "search", "description": null,
                       "input_schema": null }]
        })))
        .mount(&broker.server)
        .await;
    Mock::given(method("POST"))
        .and(path(MCP_AUTHORIZE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "decision": "permit", "correlation_id": "corr-1" }
        })))
        .mount(&broker.server)
        .await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(upstream)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "content": [{ "type": "text", "text": "hello" }] }
        })))
        .mount(upstream)
        .await;
}

/// One broker route that asks the server something: how to call it, and the
/// server path that answer has to come from. `/status` is not here: it
/// answers from the broker's own registration and never calls the server.
struct Route {
    verb: &'static str,
    path: &'static str,
    body: String,
    /// The path on the server the broker must reach for this route.
    asks_server_for: &'static str,
}

fn server_backed_routes(upstream: &MockServer) -> Vec<Route> {
    vec![
        Route {
            verb: "GET",
            path: "/credentials",
            body: String::new(),
            asks_server_for: CREDENTIALS_PATH,
        },
        Route {
            verb: "POST",
            path: "/credentials/create",
            body: serde_json::json!({ "name": CRED, "secret_value": "s" }).to_string(),
            asks_server_for: AGENT_STORE_PATH,
        },
        Route {
            verb: "POST",
            path: "/proxy",
            body: serde_json::json!({
                "method": "GET",
                "url": format!("{}/v1/items", upstream.uri()),
                "credential": CRED,
            })
            .to_string(),
            asks_server_for: "/api/v1/credentials/vend-device/api-token",
        },
        Route {
            verb: "POST",
            path: "/mcp/list-servers",
            body: "{}".to_string(),
            asks_server_for: MCP_SERVERS_PATH,
        },
        Route {
            verb: "POST",
            path: "/mcp/list-tools",
            body: "{}".to_string(),
            asks_server_for: MCP_TOOLS_PATH,
        },
        Route {
            verb: "POST",
            path: "/mcp/call",
            body: serde_json::json!({ "server": SERVER_NAME, "tool": "search", "arguments": {} })
                .to_string(),
            asks_server_for: MCP_AUTHORIZE_PATH,
        },
    ]
}

/// Every path the broker asked the fake server for, in order.
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

// ---------------------------------------------------------------------------
// The broker does not pre-check its cached scopes
// ---------------------------------------------------------------------------

/// A workspace whose cached OAuth scopes are empty still reaches the server
/// on every server-backed route. The broker used to refuse these locally
/// from its own stale copy of the scopes; the decision belongs to the
/// server, which makes it from the token it issued. A surviving pre-check
/// would show up twice here: as a local 403, and as a server that was
/// never asked.
#[tokio::test(flavor = "multi_thread")]
async fn every_server_backed_route_forwards_despite_empty_cached_scopes() {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, &[])
        .build()
        .await;
    let upstream = MockServer::start().await;
    server_grants(&broker, &upstream).await;

    for route in server_backed_routes(&upstream) {
        let (status, resp) = broker
            .send(ws.signed(route.verb, route.path, &route.body))
            .await;
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "{} was refused by the broker itself: {resp}",
            route.path
        );
        let asked = server_paths(&broker).await;
        assert!(
            asked.iter().any(|p| p == route.asks_server_for),
            "{} did not ask the server for {} (asked: {asked:?})",
            route.path,
            route.asks_server_for
        );
    }
}

// ---------------------------------------------------------------------------
// Revoked or disabled at the server, mid-session
// ---------------------------------------------------------------------------

/// A workspace revoked at the server after the broker registered it is
/// refused on the next call to every server-backed route. The broker's own
/// state still holds a valid, unexpired token with full scopes, so nothing
/// local is doing the refusing.
#[tokio::test(flavor = "multi_thread")]
async fn revoked_workspace_is_refused_on_every_server_backed_route() {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(
            &ws,
            &["credentials:discover", "credentials:vend", "mcp:invoke"],
        )
        .build()
        .await;
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(workspace_no_longer_active("revoked"))
        .mount(&broker.server)
        .await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&upstream)
        .await;

    for route in server_backed_routes(&upstream) {
        let (status, resp) = broker
            .send(ws.signed(route.verb, route.path, &route.body))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{}: {resp}", route.path);
        assert_eq!(resp["error"]["code"], "forbidden", "{}: {resp}", route.path);
    }

    assert!(
        upstream.received_requests().await.unwrap().is_empty(),
        "no upstream may be reached for a revoked workspace"
    );
}

/// The same for a workspace an operator switched off rather than revoked,
/// and with the MCP cache already warm: a synced server, its URL and its
/// upstream access token are all in hand, and the broker still refuses
/// rather than serve the call from what it cached.
#[tokio::test(flavor = "multi_thread")]
async fn disabled_workspace_is_refused_even_with_a_warm_mcp_cache() {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, &["mcp:discover", "mcp:invoke"])
        .build()
        .await;
    let upstream = MockServer::start().await;
    server_grants(&broker, &upstream).await;

    // Warm the cache through the production path: a successful tool call
    // syncs the server's URL and upstream token into the broker.
    let call =
        serde_json::json!({ "server": SERVER_NAME, "tool": "search", "arguments": {} }).to_string();
    let (warm, resp) = broker.send(ws.signed("POST", "/mcp/call", &call)).await;
    assert_eq!(warm, StatusCode::OK, "cache warm-up failed: {resp}");
    let upstream_hits_while_active = upstream.received_requests().await.unwrap().len();

    // The operator disables the workspace. Every later answer is a refusal.
    broker.server.reset().await;
    Mock::given(any())
        .respond_with(workspace_no_longer_active("disabled"))
        .mount(&broker.server)
        .await;

    for (verb, route, body) in [
        ("POST", "/mcp/call", call.as_str()),
        ("POST", "/mcp/list-tools", "{}"),
        ("POST", "/mcp/list-servers", "{}"),
    ] {
        let (status, resp) = broker.send(ws.signed(verb, route, body)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{route}: {resp}");
        assert_eq!(resp["error"]["code"], "forbidden", "{route}: {resp}");
    }

    assert_eq!(
        upstream.received_requests().await.unwrap().len(),
        upstream_hits_while_active,
        "the warm cache must not serve a disabled workspace"
    );
}
