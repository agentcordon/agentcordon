//! Broker integration tests: one binary, modules below.
//!
//! Every test goes through the router built by `common::TestBroker`; the
//! harness signs requests as the CLI would and fakes the server with
//! `wiremock`. Add a module per surface (proxy, mcp, register, ...) as
//! behaviour lands.

mod bind;
mod channel;
mod common;
mod credentials;
mod mcp_allowed_tools;
mod mcp_api_key;
mod mcp_secrets;
mod no_provider_grant;
mod proxy;
mod proxy_ssrf;
mod restart;
mod server_authority;
mod ssrf;
mod tls;
mod wire_contract;

use axum::body::Body;
use axum::http::{Request, StatusCode};

use common::{TestBroker, TestWorkspace};

/// Harness smoke test: the router answers on the public health route.
#[tokio::test]
async fn health_reports_ok() {
    let broker = TestBroker::new().await;
    let (status, body) = broker
        .send(Request::get("/health").body(Body::empty()).unwrap())
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

/// `/health` reports the broker's own version.
///
/// It used to answer `"3.0.0"`, a number from a sequence the project left
/// behind. `docs/upgrading.md` makes "is this broker new enough?" an urgent
/// question — v0.4.0 changed the signed payload — and `/health` is where a
/// CLI or an operator asks it, so the number has to be this binary's.
#[tokio::test]
async fn health_reports_the_running_broker_version() {
    let broker = TestBroker::new().await;
    let (status, body) = broker
        .send(Request::get("/health").body(Body::empty()).unwrap())
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["version"].as_str(),
        Some(env!("CARGO_PKG_VERSION")),
        "/health must report the broker's own crate version"
    );
}

/// Harness smoke test: the auth middleware is on the path. An unsigned call
/// to a protected route is rejected before any handler runs.
#[tokio::test]
async fn unsigned_request_to_protected_route_is_unauthorized() {
    let broker = TestBroker::new().await;
    let (status, _) = broker
        .send(Request::get("/status").body(Body::empty()).unwrap())
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Harness smoke test: a request signed by a registered workspace key
/// reaches the handler and sees its own registration.
#[tokio::test]
async fn signed_request_from_registered_workspace_sees_status() {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, &["credentials:discover", "credentials:vend"])
        .build()
        .await;

    let (status, body) = broker.send(ws.signed("GET", "/status", "")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["registered"], true);
    assert_eq!(body["data"]["scopes"][1], "credentials:vend");
}
