//! One error envelope, observed at the HTTP boundary.
//!
//! Every error a route returns is `{"error": {"code", "message"}}`, and a
//! list a caller may not read is a 403 in that shape, never an empty 200.
//! The OAuth endpoints are the one exception: RFC 6749 §5.2 fixes their
//! error body as `{"error", "error_description"}`, and they must not be
//! cached.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;

/// A viewer may not manage OIDC providers or OAuth provider clients. The
/// list routes say so with a 403 in the standard envelope, so a client
/// cannot mistake "forbidden" for "none configured".
#[tokio::test]
async fn forbidden_list_is_403_in_the_error_envelope() {
    let ctx = TestAppBuilder::new().build().await;
    create_test_user(&*ctx.store, "viewer", TEST_PASSWORD, UserRole::Viewer).await;
    let cookie = login_user_combined(&ctx.app, "viewer", TEST_PASSWORD).await;

    for path in ["/api/v1/oidc-providers", "/api/v1/oauth-provider-clients"] {
        let (status, body) =
            send_json(&ctx.app, Method::GET, path, None, Some(&cookie), None, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
        assert_eq!(body["error"]["code"], "forbidden", "{path}: {body}");
        assert!(
            body["error"]["message"].is_string(),
            "{path}: message is a string: {body}"
        );
        assert!(
            body.get("data").is_none(),
            "{path}: a refused list carries no data: {body}"
        );
    }
}

/// An admin still gets the list, as a `data` array.
#[tokio::test]
async fn permitted_list_is_200_with_data() {
    let ctx = TestAppBuilder::new().build().await;
    create_root_user(&*ctx.store, "root", TEST_PASSWORD).await;
    let cookie = login_user_combined(&ctx.app, "root", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/oidc-providers",
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["data"].is_array(), "{body}");
}

async fn post_form(
    app: &axum::Router,
    uri: &str,
    form: &str,
) -> (StatusCode, Value, Option<String>) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let cache_control = resp
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json, cache_control)
}

/// The token endpoint answers a bad grant with the RFC 6749 body: a flat
/// `error` string and an `error_description`, not the API envelope, and
/// tells caches to keep out.
#[tokio::test]
async fn oauth_token_error_has_the_rfc6749_shape() {
    let ctx = TestAppBuilder::new().build().await;

    let (status, body, cache_control) =
        post_form(&ctx.app, "/api/v1/oauth/token", "grant_type=bogus").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "unsupported_grant_type", "{body}");
    assert!(body["error_description"].is_string(), "{body}");
    assert!(
        body["error"].is_string(),
        "RFC shape: `error` is a string, not the API envelope object: {body}"
    );
    assert_eq!(cache_control.as_deref(), Some("no-store"));

    // A missing client on a known grant is `invalid_client`, 401.
    let (status, body, _) = post_form(
        &ctx.app,
        "/api/v1/oauth/token",
        "grant_type=client_credentials&client_id=nope&client_secret=nope",
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_client", "{body}");
}

/// The device-authorization endpoint uses the same RFC body.
#[tokio::test]
async fn oauth_device_code_error_has_the_rfc6749_shape() {
    let ctx = TestAppBuilder::new().build().await;

    let (status, body, cache_control) = post_form(
        &ctx.app,
        "/api/v1/oauth/device/code",
        "scope=credentials:discover",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_request", "{body}");
    assert!(body["error_description"].is_string(), "{body}");
    assert_eq!(cache_control.as_deref(), Some("no-store"));
}

/// Outside OAuth, an error is always the envelope.
#[tokio::test]
async fn api_error_is_the_envelope() {
    let ctx = TestAppBuilder::new().build().await;

    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/credentials",
        None,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["code"], "unauthorized", "{body}");
    assert!(body["error"]["message"].is_string(), "{body}");
}

/// A UI route answers a refused request with an HTML error page, not the
/// JSON envelope: the same `ApiError::Forbidden` that an API route renders
/// as `{"error": {...}}` reaches a browser as a page it can read.
#[tokio::test]
async fn forbidden_renders_json_on_the_api_and_html_on_a_ui_route() {
    let ctx = TestAppBuilder::new().build().await;
    create_test_user(&*ctx.store, "viewer", TEST_PASSWORD, UserRole::Viewer).await;
    let (session_cookie, csrf_token) = login_user(&ctx.app, "viewer", TEST_PASSWORD).await;
    let cookie = combined_cookie(&session_cookie, &csrf_token);
    // The activate form's token is derived from the session, not the cookie.
    let form_csrf = compute_consent_csrf(&session_cookie, &ctx.state.crypto.session_hash_key);

    // API sibling: JSON envelope.
    let (status, body) = send_json(
        &ctx.app,
        Method::POST,
        "/api/v1/oauth/device/approve",
        None,
        Some(&cookie),
        Some(&csrf_token),
        Some(serde_json::json!({ "user_code": "NOT-AREAL-CODE" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "forbidden", "{body}");

    // UI route: an HTML page carrying the same status.
    let (status, content_type, body) = post_form_html(
        &ctx.app,
        "/activate",
        &format!(
            "csrf_token={}&user_code=NOT-AREAL-CODE&decision=approve",
            urlencoding::encode(&form_csrf)
        ),
        &cookie,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        content_type
            .as_deref()
            .unwrap_or("")
            .starts_with("text/html"),
        "UI route answers with HTML, got {content_type:?}: {body}"
    );
    assert!(body.contains('<'), "an HTML body, not JSON: {body}");
}

/// A CSRF mismatch on a UI form is an HTML page too — the browser posted the
/// form, so it gets a page back, never a bare string or a JSON object.
#[tokio::test]
async fn ui_csrf_failure_is_an_html_page() {
    let ctx = TestAppBuilder::new().build().await;
    create_root_user(&*ctx.store, "root", TEST_PASSWORD).await;
    let (session_cookie, csrf_token) = login_user(&ctx.app, "root", TEST_PASSWORD).await;
    let cookie = combined_cookie(&session_cookie, &csrf_token);

    let (status, content_type, body) = post_form_html(
        &ctx.app,
        "/activate",
        "csrf_token=wrong&user_code=NOT-AREAL-CODE&decision=approve",
        &cookie,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        content_type
            .as_deref()
            .unwrap_or("")
            .starts_with("text/html"),
        "CSRF failure answers with HTML, got {content_type:?}: {body}"
    );
    assert!(body.contains('<'), "an HTML body: {body}");
}

/// An unrecognised decision value on a real pending activation is an HTML
/// page: the browser posted a form, so it gets a page back, not a bare
/// string.
#[tokio::test]
async fn ui_invalid_decision_is_an_html_page() {
    let ctx = TestAppBuilder::new().build().await;
    create_root_user(&*ctx.store, "root2", TEST_PASSWORD).await;
    let (session_cookie, csrf_token) = login_user(&ctx.app, "root2", TEST_PASSWORD).await;
    let cookie = combined_cookie(&session_cookie, &csrf_token);
    let form_csrf = compute_consent_csrf(&session_cookie, &ctx.state.crypto.session_hash_key);

    // A real pending device code, so the handler reaches the decision match.
    let (status, body, _) = post_form(
        &ctx.app,
        "/api/v1/oauth/device/code",
        "client_id=agentcordon-broker&scope=credentials:discover",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let user_code = body["user_code"].as_str().expect("user_code").to_string();

    let (status, content_type, body) = post_form_html(
        &ctx.app,
        "/activate",
        &format!(
            "csrf_token={}&user_code={}&decision=sideways",
            urlencoding::encode(&form_csrf),
            urlencoding::encode(&user_code)
        ),
        &cookie,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        content_type
            .as_deref()
            .unwrap_or("")
            .starts_with("text/html"),
        "invalid decision answers with HTML, got {content_type:?}: {body}"
    );
    assert!(body.contains('<'), "an HTML body: {body}");
}

/// POST a urlencoded form with a cookie; returns status, content-type, and
/// the raw body so the caller can tell HTML from JSON.
async fn post_form_html(
    app: &axum::Router,
    uri: &str,
    form: &str,
    cookie: &str,
) -> (StatusCode, Option<String>, String) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie)
        .body(Body::from(form.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        content_type,
        String::from_utf8_lossy(&bytes).to_string(),
    )
}
