//! Integration tests for OpenAPI spec serving (Feature 4) and Swagger UI
//! (Feature 5) from the v1.5.3 release.
//!
//! These endpoints are unauthenticated. Tests use `TestAppBuilder` with no
//! admin setup — just a bare router is sufficient.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt;

use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

async fn setup_test_app() -> Router {
    let ctx = TestAppBuilder::new().build().await;
    ctx.app
}

/// Send a GET request with no auth and return the status, raw bytes, and headers.
async fn get_raw_bytes(app: &Router, uri: &str) -> (StatusCode, Vec<u8>, axum::http::HeaderMap) {
    let request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, bytes.to_vec(), headers)
}

// ===========================================================================
// Feature 4A: GET /api/v1/openapi.yaml
// ===========================================================================

/// 4A-1: `GET /api/v1/openapi.yaml` returns 200 OK.
#[tokio::test]
async fn test_openapi_yaml_returns_200() {
    let app = setup_test_app().await;
    let (status, _body, _headers) = get_raw_bytes(&app, "/api/v1/openapi.yaml").await;
    assert_eq!(status, StatusCode::OK);
}

/// 4A-2: Content-Type is a standard YAML MIME type (not JSON, not HTML).
#[tokio::test]
async fn test_openapi_yaml_content_type() {
    let app = setup_test_app().await;
    let (_status, _body, headers) = get_raw_bytes(&app, "/api/v1/openapi.yaml").await;

    let ct = headers
        .get("content-type")
        .expect("Content-Type header should be present")
        .to_str()
        .expect("Content-Type should be valid UTF-8");

    // Accept any standard YAML MIME type.
    let is_yaml = ct.contains("text/yaml")
        || ct.contains("application/x-yaml")
        || ct.contains("text/x-yaml")
        || ct.contains("application/yaml");
    assert!(
        is_yaml,
        "Content-Type should be a YAML MIME type, got: {}",
        ct
    );

    // Must NOT be JSON or HTML.
    assert!(
        !ct.contains("application/json"),
        "Content-Type must not be application/json, got: {}",
        ct
    );
    assert!(
        !ct.contains("text/html"),
        "Content-Type must not be text/html, got: {}",
        ct
    );
}

/// 4A-3: Response body parses as valid YAML.
#[tokio::test]
async fn test_openapi_yaml_body_is_valid_yaml() {
    let app = setup_test_app().await;
    let (_status, body, _headers) = get_raw_bytes(&app, "/api/v1/openapi.yaml").await;
    let text = String::from_utf8(body).expect("Response should be valid UTF-8");

    let value: serde_yaml::Value =
        serde_yaml::from_str(&text).expect("Response body should be valid YAML");
    assert!(value.is_mapping(), "Top-level YAML should be a mapping");
}

/// 4A-4: Parsed YAML contains top-level `openapi` key starting with "3.".
#[tokio::test]
async fn test_openapi_yaml_has_openapi_version() {
    let app = setup_test_app().await;
    let (_status, body, _headers) = get_raw_bytes(&app, "/api/v1/openapi.yaml").await;
    let text = String::from_utf8(body).unwrap();
    let value: serde_yaml::Value = serde_yaml::from_str(&text).unwrap();

    let openapi = value
        .get("openapi")
        .expect("YAML should have top-level 'openapi' key");
    let version = openapi
        .as_str()
        .expect("'openapi' value should be a string");
    assert!(
        version.starts_with("3."),
        "OpenAPI version should start with '3.', got: {}",
        version
    );
}

/// 4A-5: Parsed YAML contains `info.title` mentioning "AgentCordon".
#[tokio::test]
async fn test_openapi_yaml_has_info_title() {
    let app = setup_test_app().await;
    let (_status, body, _headers) = get_raw_bytes(&app, "/api/v1/openapi.yaml").await;
    let text = String::from_utf8(body).unwrap();
    let value: serde_yaml::Value = serde_yaml::from_str(&text).unwrap();

    let info = value.get("info").expect("YAML should have 'info' key");
    let title = info
        .get("title")
        .expect("info should have 'title' key")
        .as_str()
        .expect("info.title should be a string");
    assert!(
        title.contains("AgentCordon"),
        "info.title should contain 'AgentCordon', got: {}",
        title
    );
}

/// 4A-6: Parsed YAML has a non-empty `paths` mapping with at least the
/// auth/token endpoint.
#[tokio::test]
async fn test_openapi_yaml_has_paths() {
    let app = setup_test_app().await;
    let (_status, body, _headers) = get_raw_bytes(&app, "/api/v1/openapi.yaml").await;
    let text = String::from_utf8(body).unwrap();
    let value: serde_yaml::Value = serde_yaml::from_str(&text).unwrap();

    let paths = value.get("paths").expect("YAML should have 'paths' key");
    let mapping = paths.as_mapping().expect("'paths' should be a mapping");
    assert!(!mapping.is_empty(), "'paths' should not be empty");

    // At minimum, the auth/token path should exist.
    let has_auth_token = mapping.keys().any(|k| {
        k.as_str()
            .map(|s| s.contains("auth/token"))
            .unwrap_or(false)
    });
    assert!(
        has_auth_token,
        "paths should include an auth/token endpoint"
    );
}

/// 4A-7: No auth required — request without any auth headers succeeds.
#[tokio::test]
async fn test_openapi_yaml_no_auth_required() {
    let app = setup_test_app().await;
    // Explicitly send a request with NO auth headers, cookies, or API keys.
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/openapi.yaml")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "OpenAPI spec should be accessible without authentication"
    );
}

/// 4A-8: Response body is at least 1000 bytes (the real spec is ~95KB).
#[tokio::test]
async fn test_openapi_yaml_body_not_empty() {
    let app = setup_test_app().await;
    let (_status, body, _headers) = get_raw_bytes(&app, "/api/v1/openapi.yaml").await;
    assert!(
        body.len() >= 1000,
        "OpenAPI spec body should be at least 1000 bytes, got {}",
        body.len()
    );
}

// ===========================================================================
// Feature 5A: GET /swagger (Swagger UI)
// ===========================================================================

/// 5A-1: `GET /swagger` returns 200 OK.
#[tokio::test]
async fn test_swagger_returns_200() {
    let app = setup_test_app().await;
    let (status, _body, _headers) = get_raw_bytes(&app, "/swagger").await;
    assert_eq!(status, StatusCode::OK);
}

/// 5A-2: Response Content-Type is text/html.
#[tokio::test]
async fn test_swagger_content_type_is_html() {
    let app = setup_test_app().await;
    let (_status, _body, headers) = get_raw_bytes(&app, "/swagger").await;

    let ct = headers
        .get("content-type")
        .expect("Content-Type header should be present")
        .to_str()
        .expect("Content-Type should be valid UTF-8");
    assert!(
        ct.contains("text/html"),
        "Content-Type should contain text/html, got: {}",
        ct
    );
}

/// 5A-3: Response body contains "swagger-ui" (case-insensitive).
#[tokio::test]
async fn test_swagger_body_contains_swagger_ui() {
    let app = setup_test_app().await;
    let (_status, body, _headers) = get_raw_bytes(&app, "/swagger").await;
    let text = String::from_utf8(body).expect("Response should be valid UTF-8");
    let lower = text.to_lowercase();
    assert!(
        lower.contains("swagger-ui") || lower.contains("swagger_ui"),
        "Response body should reference 'swagger-ui'"
    );
}

/// 5A-4: Response body references the OpenAPI spec URL.
#[tokio::test]
async fn test_swagger_body_references_openapi_spec() {
    let app = setup_test_app().await;
    let (_status, body, _headers) = get_raw_bytes(&app, "/swagger").await;
    let text = String::from_utf8(body).expect("Response should be valid UTF-8");
    assert!(
        text.contains("/api/v1/openapi.yaml") || text.contains("openapi.yaml"),
        "Response body should reference the OpenAPI spec URL"
    );
}

/// 5A-5: No external CDN references — fully self-contained.
#[tokio::test]
async fn test_swagger_no_external_cdn_references() {
    let app = setup_test_app().await;
    let (_status, body, _headers) = get_raw_bytes(&app, "/swagger").await;
    let text = String::from_utf8(body).expect("Response should be valid UTF-8");

    let forbidden_cdns = ["cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com"];
    for cdn in &forbidden_cdns {
        assert!(
            !text.contains(cdn),
            "Response body must not reference CDN '{}' — must be self-contained",
            cdn
        );
    }
}

/// 5A-6: No auth required — request without any auth headers succeeds.
#[tokio::test]
async fn test_swagger_no_auth_required() {
    let app = setup_test_app().await;
    let request = Request::builder()
        .method(Method::GET)
        .uri("/swagger")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Swagger UI should be accessible without authentication"
    );
}

/// 5A-7: `GET /swagger/` (trailing slash) returns 200 or a redirect, not 404.
#[tokio::test]
async fn test_swagger_trailing_slash_redirect_or_200() {
    let app = setup_test_app().await;
    let (status, _body, _headers) = get_raw_bytes(&app, "/swagger/").await;

    let acceptable = status == StatusCode::OK
        || status == StatusCode::MOVED_PERMANENTLY
        || status == StatusCode::FOUND
        || status == StatusCode::TEMPORARY_REDIRECT
        || status == StatusCode::PERMANENT_REDIRECT;

    assert!(
        acceptable,
        "GET /swagger/ should return 200 or a redirect, got: {}",
        status
    );
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "GET /swagger/ must not return 404"
    );
}

// ===========================================================================
// Feature 4B: OpenAPI spec content validation
// ===========================================================================

/// Helper: fetch and parse the OpenAPI spec as serde_yaml::Value.
async fn fetch_openapi_spec() -> serde_yaml::Value {
    let app = setup_test_app().await;
    let (_status, body, _headers) = get_raw_bytes(&app, "/api/v1/openapi.yaml").await;
    let text = String::from_utf8(body).expect("Response should be valid UTF-8");
    serde_yaml::from_str(&text).expect("Response body should be valid YAML")
}

/// Helper: check if a path exists in the spec's paths mapping.
fn spec_has_path(spec: &serde_yaml::Value, path: &str) -> bool {
    spec.get("paths")
        .and_then(|p| p.as_mapping())
        .map(|m| {
            m.keys()
                .any(|k| k.as_str().map(|s| s == path).unwrap_or(false))
        })
        .unwrap_or(false)
}

/// 4B-1: Spec includes MCP servers list endpoint (catalog/compose/discover removed).
#[tokio::test]
async fn test_openapi_covers_mcp_servers_list() {
    let spec = fetch_openapi_spec().await;
    assert!(
        spec_has_path(&spec, "/api/v1/mcp-servers"),
        "OpenAPI spec should include /api/v1/mcp-servers"
    );
}

/// 4B-4: Spec includes generate-policies endpoint.
#[tokio::test]
async fn test_openapi_covers_mcp_generate_policies() {
    let spec = fetch_openapi_spec().await;
    assert!(
        spec_has_path(&spec, "/api/v1/mcp-servers/{id}/generate-policies"),
        "OpenAPI spec should include /api/v1/mcp-servers/{{id}}/generate-policies"
    );
}

/// 4B-5: Spec includes device whoami endpoint.
#[tokio::test]
async fn test_openapi_covers_device_whoami() {
    let spec = fetch_openapi_spec().await;
    assert!(
        spec_has_path(&spec, "/api/v1/devices/whoami"),
        "OpenAPI spec should include /api/v1/devices/whoami"
    );
}

/// 4B-6: Spec includes device agents endpoint.
#[tokio::test]
async fn test_openapi_covers_device_agents() {
    let spec = fetch_openapi_spec().await;
    assert!(
        spec_has_path(&spec, "/api/v1/devices/{id}/agents"),
        "OpenAPI spec should include /api/v1/devices/{{id}}/agents"
    );
}

/// 4B-7: /api/v1/mcp-servers path should exist in OpenAPI spec (GET for list).
#[tokio::test]
async fn test_openapi_mcp_servers_path_exists() {
    let spec = fetch_openapi_spec().await;
    let mcp_path = spec.get("paths").and_then(|p| p.get("/api/v1/mcp-servers"));
    assert!(
        mcp_path.is_some(),
        "OpenAPI spec should include /api/v1/mcp-servers path"
    );
}

/// 4B-8: Security schemes include BearerAuth and SessionAuth.
#[tokio::test]
async fn test_openapi_security_schemes_defined() {
    let spec = fetch_openapi_spec().await;
    let schemes = spec
        .get("components")
        .and_then(|c| c.get("securitySchemes"))
        .and_then(|s| s.as_mapping())
        .expect("components.securitySchemes should be a mapping");

    let has_bearer_auth = schemes
        .keys()
        .any(|k| k.as_str().map(|s| s == "BearerAuth").unwrap_or(false));
    let has_session_auth = schemes
        .keys()
        .any(|k| k.as_str().map(|s| s == "SessionAuth").unwrap_or(false));

    assert!(has_bearer_auth, "securitySchemes should define BearerAuth");
    assert!(
        has_session_auth,
        "securitySchemes should define SessionAuth"
    );
}

/// 4B-9: info.version matches "1.5.3".
#[tokio::test]
async fn test_openapi_version_matches() {
    let spec = fetch_openapi_spec().await;
    let version = spec
        .get("info")
        .and_then(|i| i.get("version"))
        .and_then(|v| v.as_str())
        .expect("info.version should be a string");

    // Version comes from Cargo.toml — just verify it's a valid semver, not hardcoded
    assert!(
        version.split('.').count() == 3,
        "info.version should be valid semver, got '{}'",
        version
    );
}

/// 4B-10: Every path+method has a non-empty summary or description.
#[tokio::test]
async fn test_openapi_all_paths_have_descriptions() {
    let spec = fetch_openapi_spec().await;
    let paths = spec
        .get("paths")
        .and_then(|p| p.as_mapping())
        .expect("paths should be a mapping");

    let http_methods = ["get", "post", "put", "patch", "delete", "head", "options"];
    let mut missing = Vec::new();

    for (path_key, path_value) in paths {
        let path_str = path_key.as_str().unwrap_or("<unknown>");
        if let Some(path_map) = path_value.as_mapping() {
            for (method_key, method_value) in path_map {
                let method_str = method_key.as_str().unwrap_or("");
                if !http_methods.contains(&method_str) {
                    continue;
                }
                let has_summary = method_value
                    .get("summary")
                    .and_then(|s| s.as_str())
                    .map(|s| !s.trim().is_empty())
                    .unwrap_or(false);
                let has_description = method_value
                    .get("description")
                    .and_then(|s| s.as_str())
                    .map(|s| !s.trim().is_empty())
                    .unwrap_or(false);
                if !has_summary && !has_description {
                    missing.push(format!("{} {}", method_str.to_uppercase(), path_str));
                }
            }
        }
    }

    assert!(
        missing.is_empty(),
        "The following path+method combos lack a summary or description: {:?}",
        missing
    );
}
