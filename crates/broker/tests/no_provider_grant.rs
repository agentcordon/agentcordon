//! The broker never runs an OAuth grant against a provider.
//!
//! Delegated (`oauth2_user_authorization`) and app (`oauth2_client_credentials`)
//! credentials are exchanged on the server; the broker receives only the
//! short-lived upstream access token, sealed for its own key, and injects it
//! like any bearer. The tests here stand a second wiremock in for the
//! provider and prove it is never called — even when the material the
//! broker is handed still names a token endpoint, a client secret and a
//! refresh token, which is exactly what an older server used to ship.

use axum::http::StatusCode;
use wiremock::matchers::{any, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::{
    mock_vend_data, pattern_for, vend_body_with_metadata, vend_envelope, TestBroker, TestWorkspace,
};

const CRED: &str = "provider-token";
const SYNC_PATH: &str = "/api/v1/workspaces/mcp-servers";
const AUTHORIZE_PATH: &str = "/api/v1/workspaces/mcp-authorize";

/// A provider that answers nothing: any request to it fails the test when
/// the mock server is verified on drop.
async fn provider_that_must_not_be_called() -> MockServer {
    let provider = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "SHOULD-NEVER-BE-FETCHED",
            "token_type": "Bearer",
            "expires_in": 3600,
        })))
        .expect(0)
        .mount(&provider)
        .await;
    provider
}

/// The provider metadata an older server put in the envelope alongside the
/// secret. The broker must ignore all of it.
fn provider_metadata(provider: &MockServer) -> serde_json::Value {
    serde_json::json!({
        "token_endpoint": format!("{}/oauth/token", provider.uri()),
        "client_id": "provider-client-id",
        "client_secret": "provider-client-secret",
        "refresh_token": "provider-refresh-token",
    })
}

async fn assert_untouched(provider: &MockServer) {
    assert!(
        provider.received_requests().await.unwrap().is_empty(),
        "the broker must never call the provider"
    );
}

/// The upstream call the broker makes and the bearer it must carry.
async fn proxy_with_vended_token(credential_type: &str, access_token: &str) {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, &["credentials:vend"])
        .build()
        .await;
    let upstream = MockServer::start().await;
    let provider = provider_that_must_not_be_called().await;

    let data = vend_body_with_metadata(
        &broker,
        credential_type,
        access_token,
        provider_metadata(&provider),
        Some(&pattern_for(&upstream)),
    )
    .await;
    mock_vend_data(&broker, CRED, data).await;
    Mock::given(method("GET"))
        .and(path("/v1/items"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&upstream)
        .await;

    let request = serde_json::json!({
        "method": "GET",
        "url": format!("{}/v1/items", upstream.uri()),
        "credential": CRED,
    });
    let (status, body) = broker
        .send(ws.signed("POST", "/proxy", &request.to_string()))
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let sent = &upstream.received_requests().await.unwrap()[0];
    assert_eq!(
        sent.headers.get("authorization").unwrap(),
        format!("Bearer {access_token}").as_str(),
        "the vended access token is injected as-is"
    );
    assert_untouched(&provider).await;
}

/// A delegated credential: the vend succeeds, the upstream sees the access
/// token the server exchanged for, and the provider's token endpoint is
/// never called.
#[tokio::test(flavor = "multi_thread")]
async fn proxy_with_a_delegated_credential_never_calls_the_provider() {
    proxy_with_vended_token("oauth2_user_authorization", "delegated-access-token").await;
}

/// The same for an app (client-credentials) credential: the exchange
/// happened on the server, so the broker holds no client secret to spend.
#[tokio::test(flavor = "multi_thread")]
async fn proxy_with_an_app_credential_never_calls_the_provider() {
    proxy_with_vended_token("oauth2_client_credentials", "app-access-token").await;
}

/// The MCP path has the same invariant: the token in the sync envelope is
/// injected on the tool call, and the provider named in the envelope's
/// metadata is never contacted.
async fn mcp_call_with_synced_token(credential_type: &str, access_token: &str) {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, &["mcp:invoke"])
        .build()
        .await;
    let upstream = MockServer::start().await;
    let provider = provider_that_must_not_be_called().await;

    let envelope = vend_envelope(
        &broker,
        &serde_json::json!({
            "value": access_token,
            "metadata": provider_metadata(&provider),
            "expires_at": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        }),
    )
    .await;
    Mock::given(method("POST"))
        .and(path(AUTHORIZE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "decision": "permit", "correlation_id": "corr-1" }
        })))
        .mount(&broker.server)
        .await;
    Mock::given(method("GET"))
        .and(path(SYNC_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "servers": [{
                "id": "srv-1",
                "name": "notion",
                "transport": "http",
                "url": upstream.uri(),
                "tools": ["search"],
                "enabled": true,
                "auth_method": "oauth2",
                "credential_envelopes": [{
                    "credential_name": "notion-oauth",
                    "credential_type": credential_type,
                    "transform_name": "bearer",
                    "encrypted_envelope": envelope,
                }]
            }] }
        })))
        .mount(&broker.server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "content": [{ "type": "text", "text": "hello" }] }
        })))
        .expect(1)
        .mount(&upstream)
        .await;

    let call = serde_json::json!({ "server": "notion", "tool": "search", "arguments": {} });
    let (status, body) = broker
        .send(ws.signed("POST", "/mcp/call", &call.to_string()))
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let sent = &upstream.received_requests().await.unwrap()[0];
    assert_eq!(
        sent.headers.get("authorization").unwrap(),
        format!("Bearer {access_token}").as_str()
    );
    assert_untouched(&provider).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_call_with_a_delegated_credential_never_calls_the_provider() {
    mcp_call_with_synced_token("oauth2_user_authorization", "delegated-mcp-token").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_call_with_an_app_credential_never_calls_the_provider() {
    mcp_call_with_synced_token("oauth2_client_credentials", "app-mcp-token").await;
}
