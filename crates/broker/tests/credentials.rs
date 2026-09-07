//! `POST /credentials/create`: the broker's passthrough to the server's
//! `agent-store` route.
//!
//! The broker holds no opinion about a credential's contents — it forwards
//! the body and relays the summary — so what these tests pin is that the
//! forwarding is faithful. `agentcordon credentials create` grew an
//! `--allowed-url-pattern` flag precisely because a credential made this way
//! used to be unrestricted with no way to say otherwise; a broker that
//! dropped the field on the floor would put that back.

use axum::http::StatusCode;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

use crate::common::{TestBroker, TestWorkspace};

const AGENT_STORE_PATH: &str = "/api/v1/credentials/agent-store";

/// The server's answer to a successful store, shaped as its own
/// `CredentialSummary` fields the broker projects for an agent.
fn stored(name: &str, allowed_url_pattern: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "data": {
            "id": "0f9e1b3a-1111-4222-8333-444455556666",
            "name": name,
            "service": "github",
            "credential_type": "generic",
            "scopes": [],
            "allowed_url_pattern": allowed_url_pattern,
            "expires_at": null,
            "expired": false,
            "vault_id": "default",
            "vault_name": "default",
            "tags": ["llm_exposed"],
            "metadata": {},
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
    })
}

async fn create(
    broker: &TestBroker,
    ws: &TestWorkspace,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    broker
        .send(ws.signed("POST", "/credentials/create", &body.to_string()))
        .await
}

async fn setup() -> (TestBroker, TestWorkspace) {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, &["credentials:vend"])
        .build()
        .await;
    (broker, ws)
}

/// The pattern the CLI sends is in the request the broker makes.
#[tokio::test(flavor = "multi_thread")]
async fn create_forwards_the_allowed_url_pattern_to_the_server() {
    let (broker, ws) = setup().await;
    Mock::given(method("POST"))
        .and(path(AGENT_STORE_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(stored("fenced", Some("https://api.github.com/*"))),
        )
        .expect(1)
        .mount(&broker.server)
        .await;

    let (status, body) = create(
        &broker,
        &ws,
        serde_json::json!({
            "name": "fenced",
            "service": "github",
            "secret_value": "ghp_secret",
            "credential_type": "generic",
            "allowed_url_pattern": "https://api.github.com/*",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let sent: serde_json::Value = broker
        .server
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .find(|r| r.url.path() == AGENT_STORE_PATH)
        .map(|r| serde_json::from_slice(&r.body).expect("JSON body"))
        .expect("the broker called agent-store");

    assert_eq!(
        sent["allowed_url_pattern"], "https://api.github.com/*",
        "the broker must forward the pattern: {sent}"
    );

    // And the answer the agent gets names the fence it just asked for.
    assert_eq!(
        body["data"]["allowed_url_pattern"], "https://api.github.com/*",
        "{body}"
    );
}

/// Without a pattern the broker sends none, and the agent is told the
/// credential is unrestricted rather than left to assume.
#[tokio::test(flavor = "multi_thread")]
async fn create_without_a_pattern_sends_none_and_reports_none() {
    let (broker, ws) = setup().await;
    Mock::given(method("POST"))
        .and(path(AGENT_STORE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(stored("open", None)))
        .expect(1)
        .mount(&broker.server)
        .await;

    let (status, body) = create(
        &broker,
        &ws,
        serde_json::json!({
            "name": "open",
            "service": "github",
            "secret_value": "ghp_secret",
            "credential_type": "generic",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let sent: serde_json::Value = broker
        .server
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .find(|r| r.url.path() == AGENT_STORE_PATH)
        .map(|r| serde_json::from_slice(&r.body).expect("JSON body"))
        .expect("the broker called agent-store");

    assert!(
        sent.get("allowed_url_pattern").is_none(),
        "no pattern asked for, none sent: {sent}"
    );
    assert!(
        body["data"]["allowed_url_pattern"].is_null(),
        "the agent is told it is unrestricted: {body}"
    );
}
