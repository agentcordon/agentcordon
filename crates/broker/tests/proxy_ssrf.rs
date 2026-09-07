//! The SSRF guard on `POST /proxy`, at the HTTP seam.
//!
//! Every other proxy test runs the broker with `--proxy-allow-loopback`,
//! which switches the guard off so a wiremock upstream on 127.0.0.1 is
//! reachable. These run it off, which is how the broker ships.
//!
//! The guard's verdict is decided after the vend, not before (ADR-0014): a
//! credential whose `allowed_url_pattern` names the target host with no
//! wildcard is the admin saying where the credential goes, and that pin
//! overrides the guard. Everything else — an unrestricted credential, a
//! wildcard fence — leaves the refusal standing, and the upstream receives
//! nothing.

use axum::http::StatusCode;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::{mock_vend, pattern_for, TestBroker, TestWorkspace};

const CRED: &str = "api-token";
const SECRET: &str = "tok-secret-value-1234567890";

/// A broker with the guard on (loopback not allowed), one registered
/// workspace, and a vend that hands back an unrestricted `generic`
/// credential — the case in which nothing vouches for the target and the
/// guard's refusal stands.
async fn guarded() -> (TestBroker, TestWorkspace) {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, &["credentials:vend"])
        .allow_loopback(false)
        .build()
        .await;
    mock_vend(&broker, CRED, "generic", SECRET, None).await;
    (broker, ws)
}

async fn proxy_to(
    broker: &TestBroker,
    ws: &TestWorkspace,
    url: &str,
) -> (StatusCode, serde_json::Value) {
    let body = serde_json::json!({ "method": "GET", "url": url, "credential": CRED });
    broker
        .send(ws.signed("POST", "/proxy", &body.to_string()))
        .await
}

fn message(body: &serde_json::Value) -> String {
    body["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// Every literal form of an address the broker must not reach: loopback,
/// RFC 1918, carrier-grade NAT, link-local (the cloud metadata endpoint),
/// the unspecified address, and the IPv6 loopback, unique-local,
/// link-local, IPv4-mapped and NAT64 forms that wrap them.
#[tokio::test(flavor = "multi_thread")]
async fn proxy_refuses_reserved_address_literals() {
    let (broker, ws) = guarded().await;

    for url in [
        "http://127.0.0.1:8080/v1/items",
        "http://127.0.0.2/v1/items",
        "http://0.0.0.0/v1/items",
        "http://10.0.0.1/v1/items",
        "http://172.16.0.1/v1/items",
        "http://192.168.1.1/v1/items",
        "http://100.64.0.1/v1/items",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://[::1]/v1/items",
        "http://[fd00::1]/v1/items",
        "http://[fe80::1]/v1/items",
        "http://[::ffff:127.0.0.1]/v1/items",
        "http://[64:ff9b::7f00:1]/v1/items",
    ] {
        let (status, body) = proxy_to(&broker, &ws, url).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{url}: {body}");
        assert_eq!(body["error"]["code"], "bad_request", "{url}: {body}");
        assert!(
            message(&body).contains("Blocked by SSRF protection"),
            "{url}: {body}"
        );
    }
}

/// `localhost` and anything under `.localhost` are refused by name, before
/// the resolver is asked at all — a resolver that answers `localhost` with
/// something public cannot get a request through.
#[tokio::test(flavor = "multi_thread")]
async fn proxy_refuses_localhost_names_by_name() {
    let (broker, ws) = guarded().await;

    for url in [
        "http://localhost:8080/v1/items",
        "http://LocalHost/v1/items",
        "http://localhost./v1/items",
        "http://api.localhost/v1/items",
    ] {
        let (status, body) = proxy_to(&broker, &ws, url).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{url}: {body}");
        assert!(message(&body).contains("localhost"), "{url}: {body}");
    }
}

/// A name the system resolver answers with a reserved address, so the
/// resolving branch of the guard runs for real. Linux `/etc/hosts` carries
/// these loopback aliases; the test names the file if neither is there
/// rather than quietly passing.
async fn name_resolving_to_a_reserved_address() -> &'static str {
    for name in ["ip6-localhost", "ip6-loopback"] {
        if let Ok(mut addrs) = tokio::net::lookup_host((name, 80u16)).await {
            if addrs.any(|a| a.ip().is_loopback()) {
                return name;
            }
        }
    }
    panic!("expected /etc/hosts to resolve ip6-localhost or ip6-loopback to the IPv6 loopback")
}

/// A hostname that is not spelled "localhost" but resolves to loopback is
/// refused on the resolved address, which is what stops a DNS-rebinding
/// target from getting through.
#[tokio::test(flavor = "multi_thread")]
async fn proxy_refuses_a_name_that_resolves_to_a_reserved_address() {
    let (broker, ws) = guarded().await;
    let name = name_resolving_to_a_reserved_address().await;

    let (status, body) = proxy_to(&broker, &ws, &format!("http://{name}/v1/items")).await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{name}: {body}");
    assert!(
        message(&body).contains("resolves to private/reserved address"),
        "{name}: {body}"
    );
}

/// A name the resolver cannot answer for is refused rather than attempted:
/// the guard fails closed.
#[tokio::test(flavor = "multi_thread")]
async fn proxy_refuses_a_name_that_does_not_resolve() {
    let (broker, ws) = guarded().await;

    let (status, body) = proxy_to(&broker, &ws, "http://no-such-host.invalid/v1/items").await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        message(&body).contains("Blocked by SSRF protection"),
        "{body}"
    );
}

/// A scheme the broker does not speak never becomes an outbound request.
#[tokio::test(flavor = "multi_thread")]
async fn proxy_refuses_non_http_schemes() {
    let (broker, ws) = guarded().await;

    for url in [
        "file:///etc/passwd",
        "gopher://example.com/",
        "ftp://ftp.example.com/x",
    ] {
        let (status, body) = proxy_to(&broker, &ws, url).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{url}: {body}");
    }
}

/// The contrast that makes the refusals above the guard and nothing else:
/// the identical loopback target, same unrestricted credential, on a broker
/// started with `--proxy-allow-loopback`, is forwarded.
#[tokio::test(flavor = "multi_thread")]
async fn the_same_loopback_target_is_forwarded_when_loopback_is_allowed() {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, &["credentials:vend"])
        .allow_loopback(true)
        .build()
        .await;
    let upstream = MockServer::start().await;
    mock_vend(&broker, CRED, "generic", SECRET, None).await;
    Mock::given(method("GET"))
        .and(path("/v1/items"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&upstream)
        .await;

    let target = format!("{}/v1/items", upstream.uri());
    let (allowed, body) = proxy_to(&broker, &ws, &target).await;
    assert_eq!(allowed, StatusCode::OK, "{body}");

    // The same URL, same unrestricted credential, guard on: refused, and
    // the upstream sees nothing.
    let (guarded_broker, guarded_ws) = guarded().await;
    let before = upstream.received_requests().await.unwrap().len();
    let (refused, body) = proxy_to(&guarded_broker, &guarded_ws, &target).await;
    assert_eq!(refused, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        upstream.received_requests().await.unwrap().len(),
        before,
        "a refused target must not be called"
    );
}

/// A credential fenced to exactly this host — scheme, host and port, no
/// wildcard in the host — is forwarded to a private address on a broker
/// with the guard on. The admin wrote where the credential goes; a service
/// on a tailnet or a LAN is exactly such a place, and needing to switch the
/// whole guard off to reach it was the bug.
#[tokio::test(flavor = "multi_thread")]
async fn a_credential_pinned_to_the_host_is_forwarded_to_a_private_address() {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, &["credentials:vend"])
        .allow_loopback(false)
        .build()
        .await;
    let upstream = MockServer::start().await;
    // `pattern_for` is `http://127.0.0.1:<port>/*`: one literal host.
    mock_vend(
        &broker,
        CRED,
        "bearer",
        SECRET,
        Some(&pattern_for(&upstream)),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/v1/items"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&upstream)
        .await;

    let target = format!("{}/v1/items", upstream.uri());
    let (status, body) = proxy_to(&broker, &ws, &target).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let received = upstream.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(
        received[0]
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok()),
        Some(format!("Bearer {SECRET}").as_str()),
        "the credential was injected on the way to the pinned host"
    );
}

/// A wildcard in the host pins nothing: `http://*/…` covers the loopback
/// alias, but it covers every other single-label host too, so the guard's
/// refusal stands.
#[tokio::test(flavor = "multi_thread")]
async fn a_wildcard_host_pattern_does_not_override_the_guard() {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, &["credentials:vend"])
        .allow_loopback(false)
        .build()
        .await;
    mock_vend(&broker, CRED, "bearer", SECRET, Some("http://*/v1/*")).await;
    let name = name_resolving_to_a_reserved_address().await;

    let (status, body) = proxy_to(&broker, &ws, &format!("http://{name}/v1/items")).await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        message(&body).contains("does not pin one host"),
        "the refusal says why the fence did not help: {body}"
    );
}

/// The refusal has to name its own escape hatches, and say where each is
/// read.
///
/// `Blocked by SSRF protection: target address is in a private or reserved
/// range` is a dead end. There are two ways out: an admin fences the
/// credential to this exact host, which the message spells out as a pattern
/// to copy; or the broker is restarted with `AGTCRDN_PROXY_ALLOW_LOOPBACK`,
/// a clap `env` argument on the broker (`crates/broker/src/config.rs`) read
/// once, at startup. The obvious guess — prefixing the `agentcordon proxy`
/// call with the flag — sets it on a process that never looks at it, and
/// the call is refused again (uat/artifacts/reviews/ONBOARDING-empirical.md F4).
#[tokio::test(flavor = "multi_thread")]
async fn the_refusal_names_the_pin_pattern_and_the_loopback_flag() {
    let (broker, ws) = guarded().await;

    let (status, body) = proxy_to(&broker, &ws, "http://127.0.0.1:18080/echo").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let msg = message(&body);

    assert!(
        msg.contains("http://127.0.0.1:18080/*"),
        "the pattern an admin would write to pin this host, ready to copy: {msg}"
    );
    assert!(
        msg.contains("has no allowed_url_pattern"),
        "say why the credential did not vouch for the target: {msg}"
    );
    assert!(
        msg.contains("AGTCRDN_PROXY_ALLOW_LOOPBACK=true agentcordon-broker"),
        "the flag belongs in front of the broker, at start: {msg}"
    );
    assert!(
        msg.contains("restart"),
        "the fix is to restart the broker, not to retry the command: {msg}"
    );
    assert!(
        msg.contains("startup"),
        "say that the broker reads the flag once, at startup: {msg}"
    );
    assert!(
        !msg.contains("AGTCRDN_PROXY_ALLOW_LOOPBACK=true agentcordon proxy"),
        "the CLI never reads the flag: {msg}"
    );
}
