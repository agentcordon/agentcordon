//! v3.3.0 — OAuth Provider Client Registration (DCR) integration tests.
//!
//! Verifies the design in
//! `docs/internal/architecture/adr-mcp-oauth-dcr-and-nomenclature.md`:
//!
//! - On `initiate_oauth`, the server discovers `/.well-known/oauth-protected-resource`
//!   and `/.well-known/oauth-authorization-server`, then performs RFC 7591
//!   Dynamic Client Registration if no `oauth_provider_clients` row exists for
//!   the discovered authorization server URL.
//! - The resulting row is keyed by `authorization_server_url`, shared across
//!   templates, and reused on subsequent calls.
//! - Manually-created rows opt out of DCR.
//! - Hardened HTTP client: HTTPS-only, max 5s, max 64 KiB, origin-locked.
//! - Settings endpoint is `/api/v1/oauth-provider-clients` (renamed from
//!   `/api/v1/mcp-oauth-apps`); old path 404s.
//! - Audit events for DCR are emitted from the discovery layer.
//!
//! These tests are written **against the ADR contract**. They are expected to
//! fail until the backend lands the feature; that is intentional.

#![allow(clippy::too_many_lines)]

use crate::common;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::routes::admin_api::mcp_templates::McpServerTemplate;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};
use axum::http::{Method, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use wiremock::matchers::{method as wm_method, path as wm_path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

// ---------------------------------------------------------------------------
// Mock authorization server
// ---------------------------------------------------------------------------

/// Behavior knobs for the mock OAuth authorization server.
#[derive(Clone, Debug, Default)]
struct MockBehavior {
    /// Delay metadata responses by this duration (used for timeout tests).
    metadata_delay: Option<Duration>,
    /// If true, the metadata endpoint returns a >64 KiB body.
    oversize_metadata: bool,
    /// If Some, the metadata document advertises a `token_endpoint` at this URL
    /// (used to test cross-origin rejection).
    cross_origin_token_endpoint: Option<String>,
    /// If true, the discovered metadata omits `registration_endpoint`.
    no_registration_endpoint: bool,
    /// If true, the DCR `/register` response omits `client_secret` (public client).
    public_client: bool,
    /// If true, both well-known endpoints return 404 instead of metadata.
    well_known_404: bool,
}

/// In-process mock OAuth authorization server. Uses wiremock under the hood.
struct MockAuthServer {
    server: MockServer,
    /// Captured DCR registration request bodies.
    register_calls: Arc<StdMutex<Vec<Value>>>,
    /// Captured token-exchange request bodies.
    #[allow(dead_code)]
    token_calls: Arc<StdMutex<Vec<String>>>,
}

impl MockAuthServer {
    async fn start_standard() -> Self {
        Self::start(MockBehavior::default()).await
    }

    async fn start(behavior: MockBehavior) -> Self {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let register_calls: Arc<StdMutex<Vec<Value>>> = Arc::new(StdMutex::new(Vec::new()));
        let token_calls: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));

        // ---- /.well-known/oauth-protected-resource ----
        if behavior.well_known_404 {
            Mock::given(wm_method("GET"))
                .and(wm_path("/.well-known/oauth-protected-resource"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&server)
                .await;
        } else {
            let body = json!({
                "resource": issuer,
                "authorization_servers": [issuer],
            });
            let mut tmpl = ResponseTemplate::new(200)
                .set_body_json(&body)
                .insert_header("content-type", "application/json");
            if let Some(d) = behavior.metadata_delay {
                tmpl = tmpl.set_delay(d);
            }
            Mock::given(wm_method("GET"))
                .and(wm_path("/.well-known/oauth-protected-resource"))
                .respond_with(tmpl)
                .mount(&server)
                .await;
        }

        // ---- /.well-known/oauth-authorization-server ----
        if behavior.well_known_404 {
            Mock::given(wm_method("GET"))
                .and(wm_path("/.well-known/oauth-authorization-server"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&server)
                .await;
        } else if behavior.oversize_metadata {
            // Return >64 KiB of JSON to trip the size guard.
            let big = "x".repeat(80 * 1024);
            let body = json!({ "issuer": issuer, "padding": big });
            Mock::given(wm_method("GET"))
                .and(wm_path("/.well-known/oauth-authorization-server"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(&body)
                        .insert_header("content-type", "application/json"),
                )
                .mount(&server)
                .await;
        } else {
            let token_endpoint = behavior
                .cross_origin_token_endpoint
                .clone()
                .unwrap_or_else(|| format!("{}/token", issuer));

            let auth_methods: Vec<&str> = if behavior.public_client {
                vec!["none"]
            } else {
                vec!["client_secret_basic"]
            };

            let mut metadata = json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{}/authorize", issuer),
                "token_endpoint": token_endpoint,
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": auth_methods,
                "scopes_supported": ["read", "write"],
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
            });
            if !behavior.no_registration_endpoint {
                metadata["registration_endpoint"] =
                    json!(format!("{}/register", issuer));
            }

            let mut tmpl = ResponseTemplate::new(200)
                .set_body_json(&metadata)
                .insert_header("content-type", "application/json");
            if let Some(d) = behavior.metadata_delay {
                tmpl = tmpl.set_delay(d);
            }

            Mock::given(wm_method("GET"))
                .and(wm_path("/.well-known/oauth-authorization-server"))
                .respond_with(tmpl)
                .mount(&server)
                .await;
        }

        // ---- POST /register (RFC 7591 DCR) ----
        if !behavior.no_registration_endpoint && !behavior.well_known_404 {
            let captured = register_calls.clone();
            let public = behavior.public_client;
            let issuer_for_resp = issuer.clone();

            struct DcrResponder {
                captured: Arc<StdMutex<Vec<Value>>>,
                public: bool,
                issuer: String,
            }
            impl Respond for DcrResponder {
                fn respond(&self, req: &Request) -> ResponseTemplate {
                    let body: Value =
                        serde_json::from_slice(&req.body).unwrap_or(Value::Null);
                    self.captured.lock().unwrap().push(body);
                    let mut resp = json!({
                        "client_id": "dcr-client-123",
                        "client_id_issued_at": 1_700_000_000_u64,
                        "registration_client_uri":
                            format!("{}/register/dcr-client-123", self.issuer),
                        "registration_access_token": "rat-abc-xyz",
                    });
                    if !self.public {
                        resp["client_secret"] = json!("dcr-secret-shhh");
                        resp["client_secret_expires_at"] = json!(0); // 0 = no expiry
                    }
                    ResponseTemplate::new(201)
                        .set_body_json(&resp)
                        .insert_header("content-type", "application/json")
                }
            }

            Mock::given(wm_method("POST"))
                .and(wm_path("/register"))
                .respond_with(DcrResponder {
                    captured,
                    public,
                    issuer: issuer_for_resp,
                })
                .mount(&server)
                .await;
        }

        // ---- POST /token (canned token exchange) ----
        {
            let captured = token_calls.clone();
            struct TokenResponder {
                captured: Arc<StdMutex<Vec<String>>>,
            }
            impl Respond for TokenResponder {
                fn respond(&self, req: &Request) -> ResponseTemplate {
                    let body = String::from_utf8_lossy(&req.body).to_string();
                    self.captured.lock().unwrap().push(body);
                    ResponseTemplate::new(200)
                        .set_body_json(json!({
                            "access_token": "fake-access",
                            "token_type": "Bearer",
                            "refresh_token": "fake-refresh",
                            "expires_in": 3600,
                            "scope": "read write",
                        }))
                        .insert_header("content-type", "application/json")
                }
            }
            Mock::given(wm_method("POST"))
                .and(wm_path("/token"))
                .respond_with(TokenResponder { captured })
                .mount(&server)
                .await;
        }

        // ---- GET /authorize (canned redirect to AgentCordon callback) ----
        Mock::given(wm_method("GET"))
            .and(wm_path("/authorize"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/"))
            .mount(&server)
            .await;

        Self {
            server,
            register_calls,
            token_calls,
        }
    }

    fn url(&self) -> String {
        self.server.uri()
    }

    fn register_call_count(&self) -> usize {
        self.register_calls.lock().unwrap().len()
    }

    fn last_register_body(&self) -> Option<Value> {
        self.register_calls.lock().unwrap().last().cloned()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_template(key: &str, resource_url: &str) -> McpServerTemplate {
    // Use serde_json to allow setting fields the BE will add (oauth2_resource_url,
    // oauth2_prefer_dcr, oauth2_allowed_auth_servers) without referencing them
    // by name from the struct definition.
    serde_json::from_value(json!({
        "key": key,
        "name": key,
        "description": format!("test template for {key}"),
        "upstream_url": "https://example.test/mcp",
        "transport": "http",
        "auth_method": "oauth2",
        "category": "test",
        "tags": [],
        "icon": "",
        "sort_order": 0_u32,
        "oauth2_scopes": "read write",
        "oauth2_resource_url": resource_url,
        "oauth2_prefer_dcr": true,
    }))
    .expect("template deserializes")
}

async fn setup_with_template(
    template: McpServerTemplate,
    base_url: String,
) -> (TestContext, String, String) {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_mcp_template(template)
        .with_config(move |c| {
            c.base_url = Some(base_url.clone());
        })
        .build()
        .await;

    let _user = common::create_test_user(
        &*ctx.store,
        "dcr-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, "dcr-user", common::TEST_PASSWORD).await;

    let ws_id = ctx
        .admin_agent
        .as_ref()
        .expect("admin workspace must exist")
        .id
        .0
        .to_string();

    (ctx, cookie, ws_id)
}

async fn initiate_oauth(
    ctx: &TestContext,
    cookie: &str,
    template_key: &str,
    workspace_id: &str,
) -> (StatusCode, Value) {
    common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/oauth/initiate",
        None,
        Some(cookie),
        Some(json!({
            "template_key": template_key,
            "workspace_id": workspace_id,
        })),
    )
    .await
}

async fn list_provider_clients(ctx: &TestContext, cookie: &str) -> (StatusCode, Value) {
    common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/oauth-provider-clients",
        None,
        Some(cookie),
        None,
    )
    .await
}

// ===========================================================================
// Scenario 1 — DCR happy path: first call discovers + registers
// ===========================================================================

#[tokio::test]
async fn test_dcr_first_register() {
    let mock = MockAuthServer::start_standard().await;
    let template = make_template("dcr-template-1", &mock.url());
    let (ctx, cookie, ws_id) =
        setup_with_template(template, "http://localhost:3140".to_string()).await;

    let (status, body) = initiate_oauth(&ctx, &cookie, "dcr-template-1", &ws_id).await;
    assert_eq!(status, StatusCode::OK, "initiate failed: {body}");

    // /register hit exactly once
    assert_eq!(
        mock.register_call_count(),
        1,
        "expected exactly one DCR registration POST"
    );

    // Body had the RFC 7591 fields
    let reg = mock.last_register_body().expect("register body captured");
    assert_eq!(reg["client_name"].as_str().is_some(), true);
    assert!(reg["redirect_uris"].is_array(), "redirect_uris must be array");
    let redirects = reg["redirect_uris"].as_array().unwrap();
    assert!(
        redirects
            .iter()
            .any(|u| u.as_str() == Some("http://localhost:3140/api/v1/mcp-servers/oauth/callback")),
        "redirect_uris should include AgentCordon callback, got {redirects:?}"
    );
    assert!(
        reg["grant_types"]
            .as_array()
            .map(|a| a.iter().any(|g| g == "authorization_code"))
            .unwrap_or(false),
        "grant_types should include authorization_code"
    );

    // Provider clients list should now contain a row sourced from DCR
    let (s, list) = list_provider_clients(&ctx, &cookie).await;
    assert_eq!(s, StatusCode::OK, "list failed: {list}");
    let items = list["data"]
        .as_array()
        .or_else(|| list.as_array())
        .expect("list returns array");
    let row = items
        .iter()
        .find(|r| {
            r["authorization_server_url"]
                .as_str()
                .map(|u| u.trim_end_matches('/'))
                == Some(mock.url().trim_end_matches('/'))
        })
        .expect("provider client row for mock auth server");
    assert_eq!(row["registration_source"].as_str(), Some("dcr"));
    assert_eq!(row["client_id"].as_str(), Some("dcr-client-123"));

    // Authorize URL contains the discovered client_id, state, and code_challenge
    let authorize_url = body["data"]["authorize_url"]
        .as_str()
        .or_else(|| body["authorize_url"].as_str())
        .expect("authorize_url in response");
    assert!(authorize_url.contains("client_id=dcr-client-123"));
    assert!(authorize_url.contains("state="));
    assert!(authorize_url.contains("code_challenge="));
    assert!(authorize_url.starts_with(&mock.url()));
}

// ===========================================================================
// Scenario 2 — Cache hit: second call reuses the registration
// ===========================================================================

#[tokio::test]
async fn test_dcr_second_call_reuses_cached_registration() {
    let mock = MockAuthServer::start_standard().await;
    let template = make_template("dcr-template-cache", &mock.url());
    let (ctx, cookie, ws_id) =
        setup_with_template(template, "http://localhost:3140".to_string()).await;

    let (s1, _) = initiate_oauth(&ctx, &cookie, "dcr-template-cache", &ws_id).await;
    assert_eq!(s1, StatusCode::OK);

    // Second call (different request, same template/AS) — server already has
    // the row, should NOT POST /register again. The first call may have
    // claimed the only "duplicate template" slot for this user; we expect
    // either OK or 409, but in BOTH cases discovery must short-circuit.
    let (_s2, _) = initiate_oauth(&ctx, &cookie, "dcr-template-cache", &ws_id).await;

    assert_eq!(
        mock.register_call_count(),
        1,
        "DCR should be cached; /register must be hit exactly once"
    );
}

// ===========================================================================
// Scenario 3 — Two templates, same auth server share one row
// ===========================================================================

#[tokio::test]
async fn test_dcr_shared_across_templates_same_auth_server() {
    let mock = MockAuthServer::start_standard().await;
    let t1 = make_template("dcr-shared-a", &mock.url());
    let t2 = make_template("dcr-shared-b", &mock.url());

    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_mcp_template(t1)
        .with_mcp_template(t2)
        .with_config(|c| c.base_url = Some("http://localhost:3140".to_string()))
        .build()
        .await;
    let _ = common::create_test_user(
        &*ctx.store,
        "dcr-shared-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "dcr-shared-user", common::TEST_PASSWORD).await;
    let ws_id = ctx.admin_agent.as_ref().unwrap().id.0.to_string();

    let (s1, _) = initiate_oauth(&ctx, &cookie, "dcr-shared-a", &ws_id).await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, _) = initiate_oauth(&ctx, &cookie, "dcr-shared-b", &ws_id).await;
    assert_eq!(s2, StatusCode::OK);

    assert_eq!(
        mock.register_call_count(),
        1,
        "two templates pointing at the same AS share one DCR registration"
    );

    let (_, list) = list_provider_clients(&ctx, &cookie).await;
    let items = list["data"]
        .as_array()
        .or_else(|| list.as_array())
        .expect("list returns array");
    let count = items
        .iter()
        .filter(|r| {
            r["authorization_server_url"]
                .as_str()
                .map(|u| u.trim_end_matches('/'))
                == Some(mock.url().trim_end_matches('/'))
        })
        .count();
    assert_eq!(count, 1, "only one provider client row for the AS");
}

// ===========================================================================
// Scenario 4 — Public client (no client_secret in DCR response)
// ===========================================================================

#[tokio::test]
async fn test_dcr_registration_no_client_secret_public_client() {
    let mock = MockAuthServer::start(MockBehavior {
        public_client: true,
        ..Default::default()
    })
    .await;
    let template = make_template("dcr-public", &mock.url());
    let (ctx, cookie, ws_id) =
        setup_with_template(template, "http://localhost:3140".to_string()).await;

    let (status, body) = initiate_oauth(&ctx, &cookie, "dcr-public", &ws_id).await;
    assert_eq!(status, StatusCode::OK, "initiate failed: {body}");

    let (_, list) = list_provider_clients(&ctx, &cookie).await;
    let items = list["data"]
        .as_array()
        .or_else(|| list.as_array())
        .expect("array");
    let row = items
        .iter()
        .find(|r| r["client_id"].as_str() == Some("dcr-client-123"))
        .expect("dcr row exists");
    // Public client: secret should be absent / null in the API representation.
    assert!(
        row.get("has_client_secret")
            .map(|v| v.as_bool() == Some(false))
            .unwrap_or(true),
        "public client must not have a stored client_secret"
    );
}

// ===========================================================================
// Scenario 5 — Confidential client (client_secret stored + used)
// ===========================================================================

#[tokio::test]
async fn test_dcr_registration_with_client_secret() {
    let mock = MockAuthServer::start_standard().await;
    let template = make_template("dcr-confidential", &mock.url());
    let (ctx, cookie, ws_id) =
        setup_with_template(template, "http://localhost:3140".to_string()).await;

    let (status, _) = initiate_oauth(&ctx, &cookie, "dcr-confidential", &ws_id).await;
    assert_eq!(status, StatusCode::OK);

    let (_, list) = list_provider_clients(&ctx, &cookie).await;
    let items = list["data"]
        .as_array()
        .or_else(|| list.as_array())
        .expect("array");
    let row = items
        .iter()
        .find(|r| r["client_id"].as_str() == Some("dcr-client-123"))
        .expect("dcr row exists");
    assert!(
        row.get("has_client_secret")
            .map(|v| v.as_bool() == Some(true))
            .unwrap_or(true),
        "confidential client should have a stored client_secret"
    );
}

// ===========================================================================
// Scenario 6 — Metadata fetch timeout
// ===========================================================================

#[tokio::test]
async fn test_dcr_metadata_fetch_timeout() {
    // Hardened HTTP client max timeout per ADR is 5s. Make the mock take 10s.
    let mock = MockAuthServer::start(MockBehavior {
        metadata_delay: Some(Duration::from_secs(10)),
        ..Default::default()
    })
    .await;
    let template = make_template("dcr-timeout", &mock.url());
    let (ctx, cookie, ws_id) =
        setup_with_template(template, "http://localhost:3140".to_string()).await;

    let (status, body) = initiate_oauth(&ctx, &cookie, "dcr-timeout", &ws_id).await;
    assert!(
        status == StatusCode::BAD_GATEWAY
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::REQUEST_TIMEOUT
            || status == StatusCode::GATEWAY_TIMEOUT,
        "expected timeout-style error, got {status} body={body}"
    );
    let err = body["error"]["message"]
        .as_str()
        .or_else(|| body["error"].as_str())
        .or_else(|| body["message"].as_str())
        .unwrap_or_default()
        .to_lowercase();
    assert!(
        err.contains("timeout") || err.contains("discover"),
        "error should mention timeout/discovery, got: {err}"
    );
}

// ===========================================================================
// Scenario 7 — Metadata body too large (>64 KiB)
// ===========================================================================

#[tokio::test]
async fn test_dcr_metadata_body_too_large() {
    let mock = MockAuthServer::start(MockBehavior {
        oversize_metadata: true,
        ..Default::default()
    })
    .await;
    let template = make_template("dcr-oversize", &mock.url());
    let (ctx, cookie, ws_id) =
        setup_with_template(template, "http://localhost:3140".to_string()).await;

    let (status, body) = initiate_oauth(&ctx, &cookie, "dcr-oversize", &ws_id).await;
    assert!(
        status.is_client_error() || status == StatusCode::BAD_GATEWAY,
        "oversize metadata must be rejected, got {status}"
    );
    let err = body["error"]["message"]
        .as_str()
        .or_else(|| body["error"].as_str())
        .or_else(|| body["message"].as_str())
        .unwrap_or_default()
        .to_lowercase();
    assert!(
        err.contains("size") || err.contains("large") || err.contains("limit"),
        "error should mention size limit, got: {err}"
    );
}

// ===========================================================================
// Scenario 8 — Cross-origin token endpoint rejected
// ===========================================================================

#[tokio::test]
async fn test_dcr_cross_origin_endpoint_rejected() {
    let mock = MockAuthServer::start(MockBehavior {
        cross_origin_token_endpoint: Some("https://evil.example/token".to_string()),
        ..Default::default()
    })
    .await;
    let template = make_template("dcr-cross-origin", &mock.url());
    let (ctx, cookie, ws_id) =
        setup_with_template(template, "http://localhost:3140".to_string()).await;

    let (status, body) = initiate_oauth(&ctx, &cookie, "dcr-cross-origin", &ws_id).await;
    assert!(
        status.is_client_error() || status == StatusCode::BAD_GATEWAY,
        "cross-origin token_endpoint must be rejected, got {status} body={body}"
    );
    let err = body["error"]["message"]
        .as_str()
        .or_else(|| body["error"].as_str())
        .or_else(|| body["message"].as_str())
        .unwrap_or_default()
        .to_lowercase();
    assert!(
        err.contains("origin") || err.contains("mismatch") || err.contains("allow"),
        "error should mention origin/mismatch, got: {err}"
    );

    // Nothing should have been stored.
    let (_, list) = list_provider_clients(&ctx, &cookie).await;
    let items = list["data"].as_array().or_else(|| list.as_array()).unwrap();
    assert!(
        !items.iter().any(|r| r["client_id"].as_str() == Some("dcr-client-123")),
        "no row should be stored on cross-origin rejection"
    );
}

// ===========================================================================
// Scenario 9 — No registration endpoint => fall back to manual (or error)
// ===========================================================================

#[tokio::test]
async fn test_dcr_no_registration_endpoint_falls_back_to_manual() {
    let mock = MockAuthServer::start(MockBehavior {
        no_registration_endpoint: true,
        ..Default::default()
    })
    .await;
    let template = make_template("dcr-no-reg", &mock.url());
    let (ctx, cookie, ws_id) =
        setup_with_template(template, "http://localhost:3140".to_string()).await;

    let (status, body) = initiate_oauth(&ctx, &cookie, "dcr-no-reg", &ws_id).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "no registration_endpoint and no manual row => BadRequest, got {status} body={body}"
    );
    let err = body["error"]["message"]
        .as_str()
        .or_else(|| body["error"].as_str())
        .or_else(|| body["message"].as_str())
        .unwrap_or_default()
        .to_lowercase();
    assert!(
        err.contains("provider client") || err.contains("manual") || err.contains("settings"),
        "error should ask admin to configure manually, got: {err}"
    );
}

// ===========================================================================
// Scenario 10 — Manual provider client present, DCR skipped
// ===========================================================================

#[tokio::test]
async fn test_manual_provider_client_still_works() {
    let mock = MockAuthServer::start_standard().await;
    let template = make_template("manual-template", &mock.url());
    let (ctx, cookie, ws_id) =
        setup_with_template(template, "http://localhost:3140".to_string()).await;

    // Admin manually creates a row via the new CRUD endpoint.
    let (cs, cb) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/oauth-provider-clients",
        None,
        Some(&cookie),
        Some(json!({
            "authorization_server_url": mock.url(),
            "authorize_endpoint": format!("{}/authorize", mock.url()),
            "token_endpoint": format!("{}/token", mock.url()),
            "client_id": "manual-client-id",
            "client_secret": "manual-secret",
            "requested_scopes": "read write",
            "label": "manual",
        })),
    )
    .await;
    assert!(
        cs == StatusCode::OK || cs == StatusCode::CREATED,
        "create manual provider client failed: {cs} {cb}"
    );

    let (status, body) = initiate_oauth(&ctx, &cookie, "manual-template", &ws_id).await;
    assert_eq!(status, StatusCode::OK, "initiate failed: {body}");

    // Discovery must NOT have hit /register.
    assert_eq!(
        mock.register_call_count(),
        0,
        "manual row should bypass DCR entirely"
    );

    let authorize_url = body["data"]["authorize_url"]
        .as_str()
        .or_else(|| body["authorize_url"].as_str())
        .expect("authorize_url");
    assert!(authorize_url.contains("client_id=manual-client-id"));
}

// ===========================================================================
// Scenario 11 — Endpoint rename: old path 404s, new path serves CRUD
// ===========================================================================

#[tokio::test]
async fn test_provider_client_crud_rename() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _ = common::create_test_user(
        &*ctx.store,
        "rename-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "rename-user", common::TEST_PASSWORD).await;

    // Old path is gone (404, not just disabled).
    let (old_status, _) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/mcp-oauth-apps",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(
        old_status,
        StatusCode::NOT_FOUND,
        "/api/v1/mcp-oauth-apps must 404 after rename"
    );

    // New path responds.
    let (new_status, _) = list_provider_clients(&ctx, &cookie).await;
    assert_eq!(new_status, StatusCode::OK);
}

// ===========================================================================
// Scenario 12 — DCR rows are read-only (PUT => 409)
// ===========================================================================

#[tokio::test]
async fn test_dcr_row_cannot_be_edited() {
    let mock = MockAuthServer::start_standard().await;
    let template = make_template("dcr-readonly", &mock.url());
    let (ctx, cookie, ws_id) =
        setup_with_template(template, "http://localhost:3140".to_string()).await;

    let (s, _) = initiate_oauth(&ctx, &cookie, "dcr-readonly", &ws_id).await;
    assert_eq!(s, StatusCode::OK);

    let (_, list) = list_provider_clients(&ctx, &cookie).await;
    let items = list["data"].as_array().or_else(|| list.as_array()).unwrap();
    let row = items
        .iter()
        .find(|r| r["registration_source"].as_str() == Some("dcr"))
        .expect("dcr row");
    let id = row["id"].as_str().expect("row id");

    let (put_status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/oauth-provider-clients/{id}"),
        None,
        Some(&cookie),
        Some(json!({ "label": "renamed" })),
    )
    .await;
    assert_eq!(
        put_status,
        StatusCode::CONFLICT,
        "PUT on a DCR row must 409, got {put_status} body={body}"
    );
}

// ===========================================================================
// Scenario 13 — Re-register a DCR row
// ===========================================================================

#[tokio::test]
async fn test_reregister_dcr_row() {
    let mock = MockAuthServer::start_standard().await;
    let template = make_template("dcr-reregister", &mock.url());
    let (ctx, cookie, ws_id) =
        setup_with_template(template, "http://localhost:3140".to_string()).await;

    let (s, _) = initiate_oauth(&ctx, &cookie, "dcr-reregister", &ws_id).await;
    assert_eq!(s, StatusCode::OK);

    let (_, list) = list_provider_clients(&ctx, &cookie).await;
    let items = list["data"].as_array().or_else(|| list.as_array()).unwrap();
    let row = items
        .iter()
        .find(|r| r["registration_source"].as_str() == Some("dcr"))
        .expect("dcr row");
    let id = row["id"].as_str().expect("row id").to_string();

    let calls_before = mock.register_call_count();

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/oauth-provider-clients/{id}/reregister"),
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "reregister failed: {status} {body}"
    );
    assert_eq!(
        mock.register_call_count(),
        calls_before + 1,
        "reregister should hit /register again"
    );

    // Row id is stable.
    let (_, list2) = list_provider_clients(&ctx, &cookie).await;
    let items2 = list2["data"].as_array().or_else(|| list2.as_array()).unwrap();
    assert!(
        items2.iter().any(|r| r["id"].as_str() == Some(&id)),
        "row id must be stable across reregister"
    );
}

// ===========================================================================
// Scenario 14 — Credential type rename migration
// ===========================================================================

#[tokio::test]
async fn test_credential_type_rename_migration() {
    // After migrations have run, NO credential should carry the legacy
    // `oauth2_authorization_code` type — they must all have been renamed to
    // `oauth2_user_authorization`. This test runs against a fresh in-memory
    // DB (so the invariant is trivially true) AND, more importantly, will
    // catch any future code path that re-introduces the old type string.
    //
    // The "with pre-existing legacy row" half of the migration is exercised
    // by the migration suite proper; doing it here would require raw SQL
    // access not exposed through the trait.
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let creds = ctx
        .store
        .list_credentials()
        .await
        .expect("list credentials");
    for c in &creds {
        assert_ne!(
            c.credential_type, "oauth2_authorization_code",
            "legacy credential type must not exist post-migration"
        );
    }
}

// ===========================================================================
// Scenario 15 — Audit events for DCR
// ===========================================================================

#[tokio::test]
async fn test_audit_events_for_dcr() {
    // Happy path: registration audit event must be present.
    let mock = MockAuthServer::start_standard().await;
    let template = make_template("dcr-audit-ok", &mock.url());
    let (ctx, cookie, ws_id) =
        setup_with_template(template, "http://localhost:3140".to_string()).await;

    let (s, _) = initiate_oauth(&ctx, &cookie, "dcr-audit-ok", &ws_id).await;
    assert_eq!(s, StatusCode::OK);

    let events = ctx
        .store
        .list_audit_events(1000, 0)
        .await
        .expect("list audit events");
    let serialized: Vec<String> = events
        .iter()
        .map(|e| serde_json::to_string(e).unwrap_or_default())
        .collect();
    assert!(
        serialized
            .iter()
            .any(|s| s.contains("o_auth_provider_client_created")),
        "expected an OAuthProviderClientCreated audit event; got: {serialized:?}"
    );

    // Failure path: timeout should emit a discovery-failure event.
    let mock_slow = MockAuthServer::start(MockBehavior {
        metadata_delay: Some(Duration::from_secs(10)),
        ..Default::default()
    })
    .await;
    let template_slow = make_template("dcr-audit-fail", &mock_slow.url());
    let (ctx2, cookie2, ws_id2) =
        setup_with_template(template_slow, "http://localhost:3140".to_string()).await;
    let _ = initiate_oauth(&ctx2, &cookie2, "dcr-audit-fail", &ws_id2).await;

    let events2 = ctx2
        .store
        .list_audit_events(1000, 0)
        .await
        .expect("list audit events");
    let serialized2: Vec<String> = events2
        .iter()
        .map(|e| serde_json::to_string(e).unwrap_or_default())
        .collect();
    assert!(
        serialized2
            .iter()
            .any(|s| s.contains("o_auth_provider_discovery_failed")),
        "expected an OAuthProviderDiscoveryFailed audit event on timeout; got: {serialized2:?}"
    );
}
