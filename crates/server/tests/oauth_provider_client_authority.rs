//! Who may manage an OAuth provider client, and what stands in the way of
//! deleting one.
//!
//! A provider client is AgentCordon's own registration at an upstream
//! authorization server — one row per origin, shared by every MCP server at
//! that origin, holding a `client_id` and (usually) a `client_secret`. It was
//! guarded by `manage_mcp_servers` on `System`, which every operator holds, so
//! any operator could rewrite or delete the registration every other tenant's
//! MCP servers authenticate with.
//!
//! Creating, updating, deleting and re-registering now need
//! `manage_oauth_provider_clients`, which the default policy grants to enabled
//! admins only. Listing stays on `manage_mcp_servers` so an operator can still
//! see which client an origin uses — without its secret. Dynamic Client
//! Registration during an install is not one of these operations: the server
//! creates that row on the operator's behalf while the operator holds only
//! `manage_mcp_servers`.
//!
//! Deletion is refused while anything depends on the row. Update is not: a
//! rotated provider secret has to get in somehow, and the audit row says how
//! much was standing behind it when it changed.

use axum::http::{Method, StatusCode};
use serde_json::{json, Value};
use uuid::Uuid;
use wiremock::matchers::{method as wm_method, path as wm_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::mcp::{McpAuthMethod, McpServer, McpServerId, McpTransport};
use agent_cordon_core::domain::oauth_provider_client::{
    OAuthProviderClient, OAuthProviderClientId, RegistrationSource,
};
use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::storage::AuditFilter;
use agent_cordon_server::templates::McpServerTemplate;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

use crate::common::{create_test_user, login_user_combined, send_json_auto_csrf, TEST_PASSWORD};

const CLIENT_SECRET: &str = "PROVIDER-CLIENT-SECRET-do-not-leak";
const ROTATED_SECRET: &str = "PROVIDER-CLIENT-SECRET-rotated";

// ---------------------------------------------------------------------------
// Seeding
// ---------------------------------------------------------------------------

/// A manually configured provider client for `as_url`, with a sealed secret.
async fn seed_provider_client(ctx: &TestContext, as_url: &str) -> OAuthProviderClientId {
    let id = OAuthProviderClientId(Uuid::new_v4());
    let (encrypted, nonce) = ctx
        .encryptor
        .encrypt(CLIENT_SECRET.as_bytes(), id.0.to_string().as_bytes())
        .expect("encrypt client secret");
    let now = chrono::Utc::now();
    ctx.store
        .create_oauth_provider_client(&OAuthProviderClient {
            id: id.clone(),
            authorization_server_url: as_url.to_string(),
            issuer: None,
            authorize_endpoint: format!("{as_url}/authorize"),
            token_endpoint: format!("{as_url}/token"),
            registration_endpoint: None,
            code_challenge_methods_supported: vec![],
            token_endpoint_auth_methods_supported: vec![],
            scopes_supported: vec![],
            client_id: "provider-client-id".to_string(),
            encrypted_client_secret: Some(encrypted),
            nonce: Some(nonce),
            requested_scopes: String::new(),
            registration_source: RegistrationSource::Manual,
            client_id_issued_at: None,
            client_secret_expires_at: None,
            registration_access_token_encrypted: None,
            registration_access_token_nonce: None,
            registration_client_uri: None,
            label: "seeded provider".to_string(),
            enabled: true,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("create provider client");
    id
}

/// An `oauth2_user_authorization` credential provisioned against `as_url`.
async fn seed_credential(ctx: &TestContext, name: &str, as_url: &str) -> CredentialId {
    seed_credential_with_metadata(
        ctx,
        name,
        json!({
            "oauth2_token_url": format!("{as_url}/token"),
            "oauth2_client_id": "provider-client-id",
            "authorization_server_url": as_url,
        }),
    )
    .await
}

/// The same, with the metadata written out by hand — used for rows that
/// predate `authorization_server_url` being recorded at provisioning.
async fn seed_credential_with_metadata(
    ctx: &TestContext,
    name: &str,
    metadata: Value,
) -> CredentialId {
    let cred_id = CredentialId(Uuid::new_v4());
    let (ciphertext, nonce) = ctx
        .encryptor
        .encrypt(b"REFRESH-TOKEN", cred_id.0.to_string().as_bytes())
        .expect("encrypt secret");
    let now = chrono::Utc::now();
    ctx.store
        .store_credential(&StoredCredential {
            id: cred_id.clone(),
            name: name.to_string(),
            service: "upstream".to_string(),
            encrypted_value: ciphertext,
            nonce,
            scopes: vec![],
            metadata,
            created_by: None,
            created_by_user: None,
            created_at: now,
            updated_at: now,
            allowed_url_pattern: None,
            expires_at: None,
            transform_script: None,
            transform_name: Some("bearer".to_string()),
            vault_id: agent_cordon_core::domain::vault::DEFAULT_VAULT_ID.to_string(),
            vault_name: "default".to_string(),
            credential_type: "oauth2_user_authorization".to_string(),
            tags: vec![],
            description: None,
            target_identity: None,
            key_version: 1,
        })
        .await
        .expect("store credential");
    cred_id
}

/// An OAuth2 MCP server that authenticates with `cred`.
async fn seed_mcp_server(ctx: &TestContext, name: &str, cred: &CredentialId) {
    let now = chrono::Utc::now();
    let server = McpServer {
        id: McpServerId(Uuid::new_v4()),
        workspace_id: None,
        name: name.to_string(),
        upstream_url: "https://mcp.example.com/thing".to_string(),
        transport: McpTransport::Http,
        allowed_tools: None,
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials: Some(vec![cred.clone()]),
        auth_method: McpAuthMethod::OAuth2,
        template_key: None,
        discovered_tools: None,
        created_by_user: None,
    };
    ctx.store.create_mcp_server(&server).await.expect("create");
}

/// One admin and one operator, both signed in.
async fn admin_and_operator(ctx: &TestContext) -> (String, String) {
    create_test_user(&*ctx.store, "opc-admin", TEST_PASSWORD, UserRole::Admin).await;
    create_test_user(
        &*ctx.store,
        "opc-operator",
        TEST_PASSWORD,
        UserRole::Operator,
    )
    .await;
    let admin = login_user_combined(&ctx.app, "opc-admin", TEST_PASSWORD).await;
    let operator = login_user_combined(&ctx.app, "opc-operator", TEST_PASSWORD).await;
    (admin, operator)
}

fn create_body(as_url: &str) -> Value {
    json!({
        "label": "manual client",
        "authorization_server_url": as_url,
        "authorize_endpoint": format!("{as_url}/authorize"),
        "token_endpoint": format!("{as_url}/token"),
        "client_id": "manual-client-id",
        "client_secret": CLIENT_SECRET,
    })
}

// ---------------------------------------------------------------------------
// Slice 1 — the new action gates create, update, delete and re-register
// ---------------------------------------------------------------------------

/// Creating a provider client is an admin operation. An operator holds
/// `manage_mcp_servers`, which is no longer enough.
#[tokio::test]
async fn an_operator_cannot_create_a_provider_client() {
    let ctx = TestAppBuilder::new().build().await;
    let (admin, operator) = admin_and_operator(&ctx).await;

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/oauth-provider-clients",
        None,
        Some(&operator),
        Some(create_body("https://as.operator.test")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an operator may not create a provider client: {body}"
    );
    assert_eq!(body["error"]["code"], "forbidden", "{body}");

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/oauth-provider-clients",
        None,
        Some(&admin),
        Some(create_body("https://as.admin.test")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "an admin may create one: {body}");
}

/// Update, delete and re-register are the same operation from the policy's
/// point of view: they rewrite the registration every MCP server at the origin
/// authenticates with.
#[tokio::test]
async fn an_operator_cannot_update_delete_or_reregister_a_provider_client() {
    let ctx = TestAppBuilder::new().build().await;
    let (admin, operator) = admin_and_operator(&ctx).await;
    let id = seed_provider_client(&ctx, "https://as.example.test").await;
    let path = format!("/api/v1/oauth-provider-clients/{}", id.0);

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &path,
        None,
        Some(&operator),
        Some(json!({ "label": "hijacked" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "operator update: {body}");

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("{path}/reregister"),
        None,
        Some(&operator),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "operator reregister: {body}");

    let (status, body) =
        send_json_auto_csrf(&ctx.app, Method::DELETE, &path, None, Some(&operator), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "operator delete: {body}");

    // The row is untouched, and an admin can still edit it.
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &path,
        None,
        Some(&admin),
        Some(json!({ "label": "renamed by admin" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "admin update: {body}");
    assert_eq!(body["data"]["label"], "renamed by admin", "{body}");
}

/// An operator still needs to see which client an origin uses, so listing
/// stays on `manage_mcp_servers` — and the listing never carries the secret.
#[tokio::test]
async fn an_operator_lists_provider_clients_and_the_listing_omits_the_secret() {
    let ctx = TestAppBuilder::new().build().await;
    let (_admin, operator) = admin_and_operator(&ctx).await;
    let id = seed_provider_client(&ctx, "https://as.example.test").await;

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/oauth-provider-clients",
        None,
        Some(&operator),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "operator list: {body}");

    let rows = body["data"].as_array().expect("data array");
    let row = rows
        .iter()
        .find(|r| r["id"].as_str() == Some(&id.0.to_string()))
        .unwrap_or_else(|| panic!("seeded client in listing: {body}"));
    assert_eq!(row["authorization_server_url"], "https://as.example.test");
    assert_eq!(row["client_id"], "provider-client-id");

    let serialized = body.to_string();
    assert!(
        !serialized.contains(CLIENT_SECRET),
        "the listing must not carry the client secret: {serialized}"
    );
    for leaked in [
        "client_secret",
        "encrypted_client_secret",
        "nonce",
        "registration_access_token",
    ] {
        assert!(
            row.get(leaked).is_none(),
            "the listing must not carry `{leaked}`: {row}"
        );
    }

    // The single-client read is the same shape.
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/oauth-provider-clients/{}", id.0),
        None,
        Some(&operator),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "operator read: {body}");
    assert!(
        !body.to_string().contains(CLIENT_SECRET),
        "the single-client read must not carry the client secret: {body}"
    );
}

// ---------------------------------------------------------------------------
// Slice 2 — DCR during an install is not gated on the new action
// ---------------------------------------------------------------------------

/// A mock authorization server that advertises RFC 7591 registration.
async fn mock_authorization_server() -> MockServer {
    let server = MockServer::start().await;
    let issuer = server.uri();

    Mock::given(wm_method("GET"))
        .and(wm_path("/.well-known/oauth-protected-resource"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "resource": issuer,
                    "authorization_servers": [issuer],
                }))
                .insert_header("content-type", "application/json"),
        )
        .mount(&server)
        .await;

    Mock::given(wm_method("GET"))
        .and(wm_path("/.well-known/oauth-authorization-server"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "issuer": issuer,
                    "authorization_endpoint": format!("{issuer}/authorize"),
                    "token_endpoint": format!("{issuer}/token"),
                    "registration_endpoint": format!("{issuer}/register"),
                    "code_challenge_methods_supported": ["S256"],
                    "scopes_supported": ["read", "write"],
                }))
                .insert_header("content-type", "application/json"),
        )
        .mount(&server)
        .await;

    Mock::given(wm_method("POST"))
        .and(wm_path("/register"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({
                    "client_id": "dcr-client-for-operator",
                    "client_secret": "dcr-secret",
                    "client_id_issued_at": 1_700_000_000,
                }))
                .insert_header("content-type", "application/json"),
        )
        .mount(&server)
        .await;

    server
}

fn oauth_template(key: &str, resource_url: &str) -> McpServerTemplate {
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

/// Installing an OAuth2 MCP server registers AgentCordon at the provider on
/// the operator's behalf. That is the server acting, not the operator managing
/// provider clients, so it must keep working for a principal who holds only
/// `manage_mcp_servers`.
#[tokio::test]
async fn an_operator_install_registers_a_dcr_client_without_the_manage_action() {
    let mock = mock_authorization_server().await;
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_mcp_template(oauth_template("dcr-for-operator", &mock.uri()))
        .with_config(|c| {
            c.base_url = Some("http://localhost:3140".to_string());
        })
        .build()
        .await;
    let (_admin, operator) = admin_and_operator(&ctx).await;
    let ws_id = ctx
        .admin_agent
        .as_ref()
        .expect("admin workspace")
        .id
        .0
        .to_string();

    // The operator is refused the management action ...
    let (status, _) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/oauth-provider-clients",
        None,
        Some(&operator),
        Some(create_body("https://as.blocked.test")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // ... and the install still registers a client for them.
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/mcp-servers/oauth/initiate",
        None,
        Some(&operator),
        Some(json!({ "template_key": "dcr-for-operator", "workspace_id": ws_id })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "operator install: {body}");

    let rows = ctx
        .store
        .list_oauth_provider_clients()
        .await
        .expect("list provider clients");
    let row = rows
        .iter()
        .find(|r| {
            r.authorization_server_url.trim_end_matches('/') == mock.uri().trim_end_matches('/')
        })
        .expect("a provider client row for the mock authorization server");
    assert_eq!(row.registration_source, RegistrationSource::Dcr);
    assert_eq!(row.client_id, "dcr-client-for-operator");
}

// ---------------------------------------------------------------------------
// Slice 3 — deletion is refused while dependents exist; update is not
// ---------------------------------------------------------------------------

async fn seed_with_dependents(ctx: &TestContext, as_url: &str) -> OAuthProviderClientId {
    let id = seed_provider_client(ctx, as_url).await;
    let a = seed_credential(ctx, "notion-oauth-a", as_url).await;
    let b = seed_credential(ctx, "notion-oauth-b", as_url).await;
    seed_mcp_server(ctx, "notion", &a).await;
    seed_mcp_server(ctx, "notion-two", &b).await;
    // A credential at a different origin is not a dependent.
    let other = seed_credential(ctx, "other-oauth", "https://other.example.test").await;
    seed_mcp_server(ctx, "other", &other).await;
    id
}

/// Deleting the client would leave every credential and MCP server at that
/// origin unable to refresh. The 409 says how many of each are standing behind
/// it.
#[tokio::test]
async fn deleting_a_provider_client_with_dependents_is_refused_with_409() {
    let ctx = TestAppBuilder::new().build().await;
    let (admin, _operator) = admin_and_operator(&ctx).await;
    let id = seed_with_dependents(&ctx, "https://as.example.test").await;

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/oauth-provider-clients/{}", id.0),
        None,
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "admin delete: {body}");
    assert_eq!(body["error"]["code"], "conflict", "{body}");

    let message = body["error"]["message"].as_str().expect("message");
    assert!(
        message.contains('2'),
        "the refusal names the 2 dependent credentials: {message}"
    );
    assert!(
        message.to_lowercase().contains("credential"),
        "the refusal names credentials: {message}"
    );
    assert!(
        message.to_lowercase().contains("mcp server"),
        "the refusal names MCP servers: {message}"
    );

    assert!(
        ctx.store
            .get_oauth_provider_client(&id)
            .await
            .expect("get")
            .is_some(),
        "the client is still there"
    );
}

/// With nothing depending on it, the client goes.
#[tokio::test]
async fn deleting_a_provider_client_with_no_dependents_succeeds() {
    let ctx = TestAppBuilder::new().build().await;
    let (admin, _operator) = admin_and_operator(&ctx).await;
    let id = seed_provider_client(&ctx, "https://as.lonely.test").await;

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/oauth-provider-clients/{}", id.0),
        None,
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "admin delete: {body}");
    assert!(
        ctx.store
            .get_oauth_provider_client(&id)
            .await
            .expect("get")
            .is_none(),
        "the client is gone"
    );
}

/// A rotated provider secret arrives through update, so update stays allowed
/// even with dependents. The audit row records what changed and how much was
/// depending on the row when it did — never the secret itself.
#[tokio::test]
async fn updating_a_provider_client_audits_the_dependent_counts_and_changed_fields() {
    let ctx = TestAppBuilder::new().build().await;
    let (admin, _operator) = admin_and_operator(&ctx).await;
    let id = seed_with_dependents(&ctx, "https://as.example.test").await;

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/oauth-provider-clients/{}", id.0),
        None,
        Some(&admin),
        Some(json!({ "label": "rotated", "client_secret": ROTATED_SECRET })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "admin update with dependents: {body}"
    );

    let events: Vec<Value> = ctx
        .store
        .list_audit_events_filtered(&AuditFilter {
            limit: 500,
            ..Default::default()
        })
        .await
        .expect("audit list")
        .into_iter()
        .map(|e| serde_json::to_value(e).expect("serialize"))
        .collect();

    let event = events
        .iter()
        .find(|e| {
            e["resource_type"] == "oauth_provider_client"
                && e["resource_id"] == id.0.to_string()
                && e["action"] == "update"
        })
        .unwrap_or_else(|| panic!("an update audit row for the client: {events:#?}"));

    // The builder's `details` land on the row as `metadata`.
    let details = &event["metadata"];
    assert_eq!(
        details["dependent_credentials"], 2,
        "the audit row names the dependent credential count: {event}"
    );
    assert_eq!(
        details["dependent_mcp_servers"], 2,
        "the audit row names the dependent MCP server count: {event}"
    );
    let changed = details["changed_fields"]
        .as_array()
        .unwrap_or_else(|| panic!("changed_fields array: {event}"));
    let changed: Vec<&str> = changed.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        changed.contains(&"label"),
        "changed_fields names the label: {changed:?}"
    );
    assert!(
        changed.contains(&"client_secret"),
        "changed_fields names the secret rotation: {changed:?}"
    );

    let serialized = serde_json::to_string(&events).expect("serialize events");
    assert!(
        !serialized.contains(ROTATED_SECRET),
        "no audit row carries the new secret value"
    );
    assert!(
        !serialized.contains(CLIENT_SECRET),
        "no audit row carries the old secret value"
    );
}

/// A credential written before provisioning recorded the authorization server
/// still blocks the delete: it is placed by the origin of the token endpoint
/// it uses.
#[tokio::test]
async fn a_legacy_credential_without_a_recorded_authorization_server_still_blocks_delete() {
    let ctx = TestAppBuilder::new().build().await;
    let (admin, _operator) = admin_and_operator(&ctx).await;
    let id = seed_provider_client(&ctx, "https://as.example.test").await;
    seed_credential_with_metadata(
        &ctx,
        "legacy-oauth",
        json!({
            "oauth2_token_url": "https://as.example.test/token",
            "oauth2_client_id": "provider-client-id",
        }),
    )
    .await;

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/oauth-provider-clients/{}", id.0),
        None,
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "admin delete: {body}");
    let message = body["error"]["message"].as_str().expect("message");
    assert!(
        message.contains("1 OAuth2 credential"),
        "the one legacy credential is counted: {message}"
    );
}
