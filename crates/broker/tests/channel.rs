//! The CLI-to-broker channel: replay protection on signed requests and on
//! `/register`, the published broker key on `/health`, the shared secret
//! for non-loopback deployments, and single-flight token refresh.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, ResponseTemplate};

use crate::common::{now_secs, TestBroker, TestWorkspace};

const SCOPES: &[&str] = &["credentials:discover", "credentials:vend"];

async fn registered() -> (TestBroker, TestWorkspace) {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, SCOPES)
        .build()
        .await;
    (broker, ws)
}

// ---------------------------------------------------------------------------
// Nonce on signed requests
// ---------------------------------------------------------------------------

/// Presenting the very same signed request twice is a replay: the second
/// copy is refused even though its signature and timestamp are still good.
#[tokio::test]
async fn replayed_signed_request_is_refused() {
    let (broker, ws) = registered().await;
    let nonce = agentcordon_identity::generate_nonce();
    let ts = now_secs();

    let (first, _) = broker
        .send(ws.signed_with_nonce("GET", "/status", "", ts, &nonce))
        .await;
    let (second, body) = broker
        .send(ws.signed_with_nonce("GET", "/status", "", ts, &nonce))
        .await;

    assert_eq!(first, StatusCode::OK);
    assert_eq!(second, StatusCode::UNAUTHORIZED, "{body}");
}

/// A second request with its own nonce is not a replay.
#[tokio::test]
async fn fresh_nonce_is_accepted() {
    let (broker, ws) = registered().await;

    let (first, _) = broker.send(ws.signed("GET", "/status", "")).await;
    let (second, _) = broker.send(ws.signed("GET", "/status", "")).await;

    assert_eq!(first, StatusCode::OK);
    assert_eq!(second, StatusCode::OK);
}

/// The nonce is part of what the CLI signs; a request that omits the
/// header cannot verify.
#[tokio::test]
async fn signed_request_without_nonce_header_is_unauthorized() {
    let (broker, ws) = registered().await;
    let mut req = ws.signed("GET", "/status", "");
    req.headers_mut().remove("X-AC-Nonce");

    let (status, _) = broker.send(req).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// A nonce is scoped to the key that used it: another workspace presenting
/// the same nonce value is not replaying anyone.
#[tokio::test]
async fn same_nonce_from_different_workspace_is_accepted() {
    let a = TestWorkspace::generate();
    let b = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&a, SCOPES)
        .with_registered(&b, SCOPES)
        .build()
        .await;
    let nonce = agentcordon_identity::generate_nonce();
    let ts = now_secs();

    let (first, _) = broker
        .send(a.signed_with_nonce("GET", "/status", "", ts, &nonce))
        .await;
    let (second, _) = broker
        .send(b.signed_with_nonce("GET", "/status", "", ts, &nonce))
        .await;

    assert_eq!(first, StatusCode::OK);
    assert_eq!(second, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Timestamp and nonce on /register
// ---------------------------------------------------------------------------

async fn mock_device_code(broker: &TestBroker) {
    Mock::given(method("POST"))
        .and(path("/api/v1/oauth/device/code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "device_code": "dc-secret",
            "user_code": "ABCD-EFGH",
            "verification_uri": format!("{}/activate", broker.server.uri()),
            "expires_in": 600,
            "interval": 5,
        })))
        .mount(&broker.server)
        .await;
}

fn register_request(body: &serde_json::Value) -> Request<Body> {
    Request::post("/register")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// The register body is self-signed with a timestamp and nonce; replaying
/// the identical body is refused.
#[tokio::test]
async fn replayed_register_body_is_refused() {
    let broker = TestBroker::new().await;
    mock_device_code(&broker).await;
    let ws = TestWorkspace::generate();
    let body = ws.register_body_at(
        "ws",
        SCOPES,
        now_secs(),
        &agentcordon_identity::generate_nonce(),
    );

    let (first, first_body) = broker.send(register_request(&body)).await;
    let (second, second_body) = broker.send(register_request(&body)).await;

    assert_eq!(first, StatusCode::OK, "{first_body}");
    assert_eq!(first_body["data"]["user_code"], "ABCD-EFGH");
    assert_eq!(second, StatusCode::UNAUTHORIZED, "{second_body}");
}

/// A register body signed outside the clock-skew window is refused before
/// the broker talks to the server.
#[tokio::test]
async fn stale_register_body_is_refused() {
    let broker = TestBroker::new().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/oauth/device/code"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&broker.server)
        .await;
    let ws = TestWorkspace::generate();
    let stale = now_secs() - agentcordon_identity::MAX_CLOCK_SKEW_SECS - 5;
    let body = ws.register_body_at("ws", SCOPES, stale, &agentcordon_identity::generate_nonce());

    let (status, resp) = broker.send(register_request(&body)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "{resp}");
}

/// A fresh register body (the CLI's normal path) is accepted.
#[tokio::test]
async fn fresh_register_body_is_accepted() {
    let broker = TestBroker::new().await;
    mock_device_code(&broker).await;
    let ws = TestWorkspace::generate();

    let (status, body) = broker
        .send(register_request(&ws.register_body("ws", SCOPES)))
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["status"], "awaiting_approval");
}

// ---------------------------------------------------------------------------
// Broker key on /health
// ---------------------------------------------------------------------------

/// `/health` publishes the broker's P-256 public key (uncompressed SEC1
/// point, base64url) and its SHA-256 fingerprint, so the CLI can pin it.
#[tokio::test]
async fn health_publishes_encryption_key_and_fingerprint() {
    let broker = TestBroker::new().await;

    let (status, body) = broker
        .send(Request::get("/health").body(Body::empty()).unwrap())
        .await;

    assert_eq!(status, StatusCode::OK);
    let key_b64 = body["encryption_public_key"]
        .as_str()
        .expect("encryption_public_key is a string");
    let key_bytes = URL_SAFE_NO_PAD.decode(key_b64).expect("base64url");
    let expected = broker
        .state
        .encryption_key
        .public_key()
        .to_encoded_point(false);
    assert_eq!(key_bytes, expected.as_bytes());
    assert_eq!(key_bytes.len(), 65);
    assert_eq!(key_bytes[0], 0x04, "uncompressed SEC1 point");
    assert_eq!(
        body["key_fingerprint"].as_str().unwrap(),
        hex::encode(Sha256::digest(&key_bytes))
    );
}

// ---------------------------------------------------------------------------
// Shared secret
// ---------------------------------------------------------------------------

const SECRET_HEADER: &str = "X-AgentCordon-Broker-Secret";

/// With a shared secret configured, a correctly signed request is still
/// refused unless it carries the secret.
#[tokio::test]
async fn shared_secret_required_on_signed_routes_when_configured() {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, SCOPES)
        .with_shared_secret("s3cret-value")
        .build()
        .await;

    let (without, _) = broker.send(ws.signed("GET", "/status", "")).await;
    let mut wrong = ws.signed("GET", "/status", "");
    wrong
        .headers_mut()
        .insert(SECRET_HEADER, "nope".parse().unwrap());
    let (wrong_status, _) = broker.send(wrong).await;
    let mut with = ws.signed("GET", "/status", "");
    with.headers_mut()
        .insert(SECRET_HEADER, "s3cret-value".parse().unwrap());
    let (with_status, body) = broker.send(with).await;

    assert_eq!(without, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong_status, StatusCode::UNAUTHORIZED);
    assert_eq!(with_status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["registered"], true);
}

/// `/register` is reachable without a workspace signature, so it needs the
/// shared secret too; `/health` stays open for discovery.
#[tokio::test]
async fn shared_secret_gates_register_but_not_health() {
    let broker = TestBroker::builder()
        .with_shared_secret("s3cret-value")
        .build()
        .await;
    mock_device_code(&broker).await;
    let ws = TestWorkspace::generate();

    let (health, _) = broker
        .send(Request::get("/health").body(Body::empty()).unwrap())
        .await;
    let (without, _) = broker
        .send(register_request(&ws.register_body("ws", SCOPES)))
        .await;
    let mut with = register_request(&ws.register_body("ws", SCOPES));
    with.headers_mut()
        .insert(SECRET_HEADER, "s3cret-value".parse().unwrap());
    let (with_status, body) = broker.send(with).await;

    assert_eq!(health, StatusCode::OK);
    assert_eq!(without, StatusCode::UNAUTHORIZED);
    assert_eq!(with_status, StatusCode::OK, "{body}");
}

/// Without a shared secret configured the header is not required (the
/// loopback default).
#[tokio::test]
async fn shared_secret_not_required_when_unconfigured() {
    let (broker, ws) = registered().await;
    let (status, _) = broker.send(ws.signed("GET", "/status", "")).await;
    assert_eq!(status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Single-flight token refresh
// ---------------------------------------------------------------------------

/// Two requests that both see a 401 from the server refresh the workspace
/// token once between them: the second waits for the first's refresh and
/// retries with the new token instead of spending the refresh token again.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_401s_refresh_the_token_once() {
    let (broker, ws) = registered().await;
    let old_token = format!("access-{}", &ws.pk_hash()[..8]);

    Mock::given(method("GET"))
        .and(path("/api/v1/credentials"))
        .and(header(
            "authorization",
            format!("Bearer {old_token}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "invalid_token"
        })))
        .mount(&broker.server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/credentials"))
        .and(header("authorization", "Bearer new-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": [] })))
        .mount(&broker.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/oauth/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_millis(200))
                .set_body_json(serde_json::json!({
                    "access_token": "new-token",
                    "token_type": "Bearer",
                    "expires_in": 900,
                    "refresh_token": "rotated-refresh",
                })),
        )
        .expect(1)
        .mount(&broker.server)
        .await;

    let (a, b) = tokio::join!(
        broker.send(ws.signed("GET", "/credentials", "")),
        broker.send(ws.signed("GET", "/credentials", "")),
    );

    assert_eq!(a.0, StatusCode::OK, "{}", a.1);
    assert_eq!(b.0, StatusCode::OK, "{}", b.1);
    // `expect(1)` on the token endpoint is verified when the mock server
    // drops at the end of the test.
}

// ---------------------------------------------------------------------------
// Whose signature it is, and when it was made
// ---------------------------------------------------------------------------

/// A perfectly signed request from a key the broker has never registered is
/// refused on every authenticated route, and nothing is asked of the server
/// on its behalf. Holding a key is not enrolment: the key has to have
/// completed a device flow.
#[tokio::test]
async fn signed_request_from_an_unregistered_key_is_refused() {
    let (broker, _known) = registered().await;
    let stranger = TestWorkspace::generate();
    let proxy_body = serde_json::json!({
        "method": "GET",
        "url": "https://api.example.com/v1/items",
        "credential": "api-token",
    })
    .to_string();

    for (method, route, body) in [
        ("GET", "/status", ""),
        ("GET", "/credentials", ""),
        ("POST", "/proxy", proxy_body.as_str()),
        ("POST", "/mcp/list-servers", "{}"),
        ("POST", "/mcp/call", r#"{"server":"s","tool":"t"}"#),
    ] {
        let (status, resp) = broker.send(stranger.signed(method, route, body)).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED, "{route}: {resp}");
        assert_eq!(
            resp["error"]["code"], "reregistration_required",
            "{route}: {resp}"
        );
    }

    assert!(
        broker.server.received_requests().await.unwrap().is_empty(),
        "an unregistered key must not reach the server on any route"
    );
}

/// A signature older than the skew window is refused even though it is a
/// genuine signature by a registered key carrying a nonce never seen
/// before: a captured request does not stay usable.
#[tokio::test]
async fn stale_timestamp_on_a_signed_request_is_refused() {
    let (broker, ws) = registered().await;
    let stale = now_secs() - agentcordon_identity::MAX_CLOCK_SKEW_SECS - 5;

    let (status, body) = broker.send(ws.signed_at("GET", "/status", "", stale)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["code"], "unauthorized");
}

/// A timestamp far enough ahead is refused too, so a caller cannot mint a
/// request now that becomes valid later.
#[tokio::test]
async fn future_timestamp_on_a_signed_request_is_refused() {
    let (broker, ws) = registered().await;
    let ahead = now_secs() + agentcordon_identity::MAX_CLOCK_SKEW_SECS + 5;

    let (status, body) = broker.send(ws.signed_at("GET", "/status", "", ahead)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

/// A timestamp just inside the window is accepted, so the two refusals
/// above are the window itself and not an accident of the harness clock.
#[tokio::test]
async fn timestamp_inside_the_skew_window_is_accepted() {
    let (broker, ws) = registered().await;
    let edge = now_secs() - agentcordon_identity::MAX_CLOCK_SKEW_SECS + 2;

    let (status, body) = broker.send(ws.signed_at("GET", "/status", "", edge)).await;

    assert_eq!(status, StatusCode::OK, "{body}");
}
