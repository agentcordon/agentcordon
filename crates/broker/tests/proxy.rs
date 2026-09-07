//! `POST /proxy`: vend, inject, and forward to the upstream.

use axum::http::StatusCode;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::{
    mock_vend, mock_vend_data, pattern_for, vend_body, vend_body_with_metadata, vend_path,
    TestBroker, TestWorkspace,
};

const CRED: &str = "api-token";
const SECRET: &str = "tok-secret-value-1234567890";

/// A broker with one registered workspace and a mock upstream.
async fn setup() -> (TestBroker, TestWorkspace, MockServer) {
    let ws = TestWorkspace::generate();
    let broker = TestBroker::builder()
        .with_registered(&ws, &["credentials:vend"])
        .build()
        .await;
    let upstream = MockServer::start().await;
    (broker, ws, upstream)
}

async fn proxy(
    broker: &TestBroker,
    ws: &TestWorkspace,
    req: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    broker
        .send(ws.signed("POST", "/proxy", &req.to_string()))
        .await
}

fn get(url: String) -> serde_json::Value {
    serde_json::json!({ "method": "GET", "url": url, "credential": CRED })
}

/// The vend request tells the server where the credential is going, so the
/// server can bind the vend to that target.
#[tokio::test(flavor = "multi_thread")]
async fn vend_request_names_method_and_target_url() {
    let (broker, ws, upstream) = setup().await;
    let target = format!("{}/v1/items", upstream.uri());

    let data = vend_body(&broker, "bearer", SECRET, Some(&pattern_for(&upstream))).await;
    Mock::given(method("POST"))
        .and(path(vend_path(CRED)))
        .and(body_partial_json(serde_json::json!({
            "method": "GET",
            "target_url": target,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": data })))
        .expect(1)
        .mount(&broker.server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/items"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&upstream)
        .await;

    let (status, body) = proxy(&broker, &ws, get(target)).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["status_code"], 200);
}

// ---------------------------------------------------------------------------
// Target-bound vend: the broker checks the pattern again before injecting.
// ---------------------------------------------------------------------------

/// A URL inside the vended pattern is forwarded.
#[tokio::test(flavor = "multi_thread")]
async fn url_inside_allowed_pattern_is_forwarded() {
    let (broker, ws, upstream) = setup().await;
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
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;

    let (status, body) = proxy(&broker, &ws, get(format!("{}/v1/items", upstream.uri()))).await;

    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A pattern the server vended for does not admit this URL (a stale or
/// mismatched vend): refuse before anything reaches the upstream.
#[tokio::test(flavor = "multi_thread")]
async fn url_outside_allowed_pattern_is_forbidden() {
    let (broker, ws, upstream) = setup().await;
    mock_vend(
        &broker,
        CRED,
        "bearer",
        SECRET,
        Some("https://api.example.com/*"),
    )
    .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&upstream)
        .await;

    let (status, body) = proxy(&broker, &ws, get(format!("{}/v1/items", upstream.uri()))).await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    // Not `forbidden`: that reads as a Cedar decision and sends the user to
    // `/policies`, and this refusal is the credential's own URL pattern.
    assert_eq!(body["error"]["code"], "url_pattern_denied", "{body}");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("https://api.example.com/*"),
        "the message names the pattern: {message:?}"
    );
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

/// A non-generic credential vended without a pattern is refused: the broker
/// fails closed rather than inject an unbound secret.
#[tokio::test(flavor = "multi_thread")]
async fn missing_pattern_for_non_generic_credential_is_forbidden() {
    let (broker, ws, upstream) = setup().await;
    mock_vend(&broker, CRED, "bearer", SECRET, None).await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&upstream)
        .await;

    let (status, body) = proxy(&broker, &ws, get(format!("{}/v1/items", upstream.uri()))).await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "url_pattern_denied", "{body}");
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

/// The server's own URL-pattern refusal reaches the caller as the server
/// wrote it.
///
/// Every server 403 used to be flattened to
/// `{"code":"forbidden","message":"Access denied by server policy"}`, which
/// is exactly wrong for this one: the cause is the credential's
/// `allowed_url_pattern`, on a different screen from Cedar and with a
/// different fix. The code and the message come through; a Cedar denial is
/// still summarised (see `server_authority.rs`).
#[tokio::test(flavor = "multi_thread")]
async fn a_url_pattern_denial_from_the_server_is_relayed_verbatim() {
    let (broker, ws, upstream) = setup().await;
    let denial = "credential 'api-token' is fenced to the URL pattern \
                  https://api.example.com/*, which does not cover \
                  http://evil.example/steal.";
    Mock::given(method("POST"))
        .and(path(vend_path(CRED)))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": { "code": "url_pattern_denied", "message": denial }
        })))
        .mount(&broker.server)
        .await;

    let (status, body) = proxy(&broker, &ws, get(format!("{}/v1/items", upstream.uri()))).await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "url_pattern_denied", "{body}");
    assert_eq!(body["error"]["message"], denial, "{body}");
}

// ---------------------------------------------------------------------------
// Outbound client: what goes upstream and what comes back.
// ---------------------------------------------------------------------------

/// Values of one response header in the `[name, value]` list the broker
/// returns, in the order they arrived.
fn header_values(body: &serde_json::Value, name: &str) -> Vec<String> {
    body["data"]["headers"]
        .as_array()
        .unwrap_or_else(|| panic!("headers must be a list: {body}"))
        .iter()
        .filter(|pair| pair[0].as_str().unwrap().eq_ignore_ascii_case(name))
        .map(|pair| pair[1].as_str().unwrap().to_string())
        .collect()
}

/// A 3xx from the upstream is handed back to the CLI as-is. Following it
/// would send the injected credential wherever the upstream pointed.
#[tokio::test(flavor = "multi_thread")]
async fn upstream_redirect_is_returned_not_followed() {
    let (broker, ws, upstream) = setup().await;
    mock_vend(
        &broker,
        CRED,
        "bearer",
        SECRET,
        Some(&pattern_for(&upstream)),
    )
    .await;
    let location = format!("{}/moved", upstream.uri());
    Mock::given(method("GET"))
        .and(path("/start"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", location.as_str()))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/moved"))
        .respond_with(ResponseTemplate::new(200).set_body_string("followed"))
        .expect(0)
        .mount(&upstream)
        .await;

    let (status, body) = proxy(&broker, &ws, get(format!("{}/start", upstream.uri()))).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["status_code"], 302);
    assert_eq!(header_values(&body, "location"), vec![location]);
    let hits = upstream.received_requests().await.unwrap();
    assert!(
        hits.iter().all(|r| r.url.path() != "/moved"),
        "redirect target must not be requested"
    );
}

/// Hop-by-hop headers describe one connection, not the message; they are
/// dropped on the way out and on the way back.
#[tokio::test(flavor = "multi_thread")]
async fn hop_by_hop_headers_are_stripped_both_ways() {
    let (broker, ws, upstream) = setup().await;
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
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("keep-alive", "timeout=5")
                .insert_header("proxy-authenticate", "Basic")
                .insert_header("x-kept", "yes"),
        )
        .mount(&upstream)
        .await;

    let req = serde_json::json!({
        "method": "GET",
        "url": format!("{}/v1/items", upstream.uri()),
        "credential": CRED,
        "headers": {
            "Keep-Alive": "timeout=5",
            "Proxy-Authorization": "Basic abc",
            "TE": "trailers",
            "X-Kept": "yes",
        },
    });
    let (status, body) = proxy(&broker, &ws, req).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let sent = &upstream.received_requests().await.unwrap()[0].headers;
    assert!(sent.get("keep-alive").is_none());
    assert!(sent.get("proxy-authorization").is_none());
    assert!(sent.get("te").is_none());
    assert_eq!(sent.get("x-kept").unwrap(), "yes");
    assert!(header_values(&body, "keep-alive").is_empty());
    assert!(header_values(&body, "proxy-authenticate").is_empty());
    assert_eq!(header_values(&body, "x-kept"), vec!["yes"]);
}

/// Response headers come back as `[name, value]` pairs so repeated headers
/// (Set-Cookie, Link, ...) survive with their order.
#[tokio::test(flavor = "multi_thread")]
async fn repeated_response_headers_are_preserved_in_order() {
    let (broker, ws, upstream) = setup().await;
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
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("set-cookie", "a=1")
                .append_header("set-cookie", "b=2"),
        )
        .mount(&upstream)
        .await;

    let (status, body) = proxy(&broker, &ws, get(format!("{}/v1/items", upstream.uri()))).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(header_values(&body, "set-cookie"), vec!["a=1", "b=2"]);
}

/// The caller's body reaches the upstream byte for byte, under the caller's
/// Content-Type. Re-serialising JSON would reorder keys and drop whitespace,
/// which breaks signed or hashed payloads.
#[tokio::test(flavor = "multi_thread")]
async fn request_body_is_forwarded_verbatim() {
    let (broker, ws, upstream) = setup().await;
    mock_vend(
        &broker,
        CRED,
        "bearer",
        SECRET,
        Some(&pattern_for(&upstream)),
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/v1/items"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&upstream)
        .await;

    let raw_body = "{\"zeta\": 1,   \"alpha\":[1, 2]  }\n";
    let req = serde_json::json!({
        "method": "POST",
        "url": format!("{}/v1/items", upstream.uri()),
        "credential": CRED,
        "headers": { "Content-Type": "application/vnd.api+json" },
        "body": raw_body,
    });
    let (status, body) = proxy(&broker, &ws, req).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let sent = &upstream.received_requests().await.unwrap()[0];
    assert_eq!(sent.body, raw_body.as_bytes());
    assert_eq!(
        sent.headers.get("content-type").unwrap(),
        "application/vnd.api+json"
    );
}

/// `agentcordon proxy --body '{...}'` sends no Content-Type of its own; the
/// broker keeps labelling such a body as JSON so existing calls still work.
#[tokio::test(flavor = "multi_thread")]
async fn body_without_content_type_is_sent_as_json() {
    let (broker, ws, upstream) = setup().await;
    mock_vend(
        &broker,
        CRED,
        "bearer",
        SECRET,
        Some(&pattern_for(&upstream)),
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/v1/items"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&upstream)
        .await;

    let req = serde_json::json!({
        "method": "POST",
        "url": format!("{}/v1/items", upstream.uri()),
        "credential": CRED,
        "body": "{\"a\": 1}",
    });
    let (status, body) = proxy(&broker, &ws, req).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let sent = &upstream.received_requests().await.unwrap()[0];
    assert_eq!(sent.body, b"{\"a\": 1}");
    assert_eq!(
        sent.headers.get("content-type").unwrap(),
        "application/json"
    );
}

// ---------------------------------------------------------------------------
// Leak scanner: an upstream that echoes the secret does not reach the CLI.
// ---------------------------------------------------------------------------

/// Every injected value is redacted from the response body and from every
/// response header, in raw and encoded forms.
#[tokio::test(flavor = "multi_thread")]
async fn echoed_secret_is_redacted_from_body_and_headers() {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine;

    let (broker, ws, upstream) = setup().await;
    mock_vend(
        &broker,
        CRED,
        "bearer",
        SECRET,
        Some(&pattern_for(&upstream)),
    )
    .await;
    let echoed = serde_json::json!({
        "authorization": format!("Bearer {SECRET}"),
        "raw": SECRET,
        "b64": STANDARD.encode(SECRET),
        "b64url": URL_SAFE_NO_PAD.encode(format!("Bearer {SECRET}")),
        "pct": urlencoding::encode(&format!("Bearer {SECRET}")).into_owned(),
    });
    Mock::given(method("GET"))
        .and(path("/echo"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-echo", format!("Bearer {SECRET}").as_str())
                .insert_header("x-echo-b64", STANDARD.encode(SECRET).as_str())
                .set_body_json(echoed),
        )
        .mount(&upstream)
        .await;

    let (status, body) = proxy(&broker, &ws, get(format!("{}/echo", upstream.uri()))).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let data = &body["data"];
    assert_eq!(data["body"]["authorization"], "[REDACTED]");
    assert_eq!(data["body"]["raw"], "[REDACTED]");
    assert_eq!(data["body"]["b64"], "[REDACTED]");
    assert_eq!(data["body"]["b64url"], "[REDACTED]");
    assert_eq!(data["body"]["pct"], "[REDACTED]");
    assert_eq!(header_values(&body, "x-echo"), vec!["[REDACTED]"]);
    assert_eq!(header_values(&body, "x-echo-b64"), vec!["[REDACTED]"]);
    let text = body.to_string();
    assert!(!text.contains(SECRET), "raw secret leaked: {text}");
    assert!(
        !text.contains(&STANDARD.encode(SECRET)),
        "base64 secret leaked"
    );
}

/// An upstream body over the cap is refused as a bad gateway instead of
/// being buffered without bound.
#[tokio::test(flavor = "multi_thread")]
async fn oversized_upstream_body_is_bad_gateway() {
    let (broker, ws, upstream) = setup().await;
    mock_vend(
        &broker,
        CRED,
        "bearer",
        SECRET,
        Some(&pattern_for(&upstream)),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/big"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 10 * 1024 * 1024 + 1]))
        .mount(&upstream)
        .await;

    let (status, body) = proxy(&broker, &ws, get(format!("{}/big", upstream.uri()))).await;

    assert_eq!(status, StatusCode::BAD_GATEWAY, "{}", body["error"]);
    assert_eq!(body["error"]["code"], "bad_gateway");
}

/// A credential injected as a query parameter is redacted from the response
/// the same way a header credential is. The key never appears in a header,
/// so the scan has to know about what the transform put in the URL: an
/// upstream that echoes its own query string — in the body, or in a
/// `Location` it hands back — must not return the key to the agent.
#[tokio::test(flavor = "multi_thread")]
async fn injected_query_parameter_is_redacted_from_body_and_headers() {
    let (broker, ws, upstream) = setup().await;
    let data = vend_body_with_metadata(
        &broker,
        "api_key_query",
        SECRET,
        serde_json::json!({ "param_name": "api_key" }),
        Some(&pattern_for(&upstream)),
    )
    .await;
    mock_vend_data(&broker, CRED, data).await;

    let echoed_location = format!("{}/next?api_key={SECRET}", upstream.uri());
    Mock::given(method("GET"))
        .and(path("/echo"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("location", echoed_location.as_str())
                .set_body_json(serde_json::json!({
                    "you_sent": format!("/echo?api_key={SECRET}"),
                    "key": SECRET,
                })),
        )
        .mount(&upstream)
        .await;

    let (status, body) = proxy(&broker, &ws, get(format!("{}/echo", upstream.uri()))).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    // The key really did go upstream as a query parameter.
    let sent = &upstream.received_requests().await.unwrap()[0];
    assert_eq!(
        sent.url
            .query_pairs()
            .find(|(k, _)| k == "api_key")
            .unwrap()
            .1,
        SECRET
    );
    // ...and came back redacted, in the body and in the header.
    assert_eq!(body["data"]["body"]["key"], "[REDACTED]");
    assert_eq!(body["data"]["body"]["you_sent"], "/echo?api_key=[REDACTED]");
    assert_eq!(
        header_values(&body, "location"),
        vec![format!("{}/next?api_key=[REDACTED]", upstream.uri())]
    );
    let text = body.to_string();
    assert!(!text.contains(SECRET), "query credential leaked: {text}");
}

/// A generic credential is the one type that may be unbound.
#[tokio::test(flavor = "multi_thread")]
async fn missing_pattern_for_generic_credential_is_forwarded() {
    let (broker, ws, upstream) = setup().await;
    mock_vend(&broker, CRED, "generic", SECRET, None).await;
    Mock::given(method("GET"))
        .and(path("/v1/items"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;

    let (status, body) = proxy(&broker, &ws, get(format!("{}/v1/items", upstream.uri()))).await;

    assert_eq!(status, StatusCode::OK, "{body}");
}

// ---------------------------------------------------------------------------
// Leak scanner: only secret material is a needle.
// ---------------------------------------------------------------------------

/// A SigV4 signing run puts four values on the wire: the `Authorization`
/// header (secret — it is the signature), the session token when there is
/// one (secret), and `host` plus `x-amz-date` (not secret — the caller chose
/// the URL and the timestamp is public input to a signature the caller is
/// trying to debug).
///
/// Redacting the date was actively misleading: the same date reappears
/// inside `credential_scope`, which is part of the `Authorization` value the
/// upstream may quote back in an error, so a user saw one copy blanked and
/// one copy intact and concluded the clock was wrong. The credential's own
/// `secret_access_key`, meanwhile, never travels but is exactly what a
/// chatty upstream error page quotes, and it must not come back.
#[tokio::test(flavor = "multi_thread")]
async fn sigv4_response_keeps_the_date_and_host_but_loses_the_signature() {
    use wiremock::{Request as UpstreamRequest, Respond};

    const AWS_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    struct EchoSigning;
    impl Respond for EchoSigning {
        fn respond(&self, req: &UpstreamRequest) -> ResponseTemplate {
            let header = |name: &str| {
                req.headers
                    .get(name)
                    .map(|v| v.to_str().unwrap_or_default().to_string())
                    .unwrap_or_default()
            };
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "amz_date": header("x-amz-date"),
                "host": header("host"),
                "authorization": header("authorization"),
                // A verbose upstream that quotes the key it was given.
                "message": format!("no signer for key {AWS_SECRET_KEY}"),
            }))
        }
    }

    let (broker, ws, upstream) = setup().await;
    let credential = serde_json::json!({
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "secret_access_key": AWS_SECRET_KEY,
        "region": "us-east-1",
        "service": "execute-api",
    })
    .to_string();
    mock_vend(
        &broker,
        CRED,
        "aws",
        &credential,
        Some(&pattern_for(&upstream)),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/sign"))
        .respond_with(EchoSigning)
        .mount(&upstream)
        .await;

    let (status, body) = proxy(&broker, &ws, get(format!("{}/sign", upstream.uri()))).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let echoed = &body["data"]["body"];
    let amz_date = echoed["amz_date"].as_str().expect("amz_date echoed");
    assert!(
        amz_date.len() == 16 && amz_date.ends_with('Z'),
        "the SigV4 timestamp is not secret and must survive the scan: {body}"
    );
    assert_eq!(
        echoed["host"].as_str(),
        Some(
            upstream
                .uri()
                .trim_start_matches("http://")
                .trim_end_matches('/')
        ),
        "the host the caller chose is not secret: {body}"
    );
    assert_eq!(
        echoed["authorization"], "[REDACTED]",
        "the signature is secret: {body}"
    );
    let text = body.to_string();
    assert!(
        !text.contains(AWS_SECRET_KEY),
        "the credential's secret key must never come back: {text}"
    );
    assert!(
        echoed["message"]
            .as_str()
            .is_some_and(|m| m.contains("[REDACTED]")),
        "an echoed secret key is redacted, not dropped: {body}"
    );
}
