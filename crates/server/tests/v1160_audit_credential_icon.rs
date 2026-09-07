//! Integration tests — issue #35: audit log credential-icon row hint.
//!
//! Verifies that the audit page derives an icon hint (`icon == "credential"`)
//! for credential lifecycle events fetched from `GET /api/v1/audit`, so the
//! unexpanded row can show a credential glyph alongside the credential name
//! and workspace the API returns.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_core::storage::Store;
use agent_cordon_server::test_helpers::TestAppBuilder;
use uuid::Uuid;

use crate::common;

async fn seed_credential_vended_event(store: &(dyn Store + Send + Sync)) {
    let event = AuditEvent::builder(AuditEventType::CredentialVended)
        .action("vend_credential")
        .resource("credential", "cred-xyz")
        .workspace_actor(&WorkspaceId(Uuid::new_v4()), "ws-alpha")
        .details(json!({ "credential_name": "github-token" }))
        .decision(AuditDecision::Permit, None)
        .build();
    store
        .append_audit_event(&event)
        .await
        .expect("seed credential vended event");
}

async fn get_page(app: &axum::Router, uri: &str, cookie: &str) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    (status, body)
}

#[tokio::test]
async fn audit_page_template_renders_credential_icon_svg() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = common::create_test_user(
        &*ctx.store,
        "icon-admin-2",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, "icon-admin-2", common::TEST_PASSWORD).await;

    let (status, body) = get_page(&ctx.app, "/audit", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("audit-evt-icon-credential"),
        "audit page template should render a credential icon marker so the unexpanded row shows a glyph for credential events"
    );
    assert!(
        body.contains("ev.icon === 'credential'"),
        "the credential icon should be conditionally shown via ev.icon"
    );
}

#[tokio::test]
async fn audit_page_derives_credential_icon_hint_from_api_events() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = common::create_test_user(
        &*ctx.store,
        "icon-admin",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, "icon-admin", common::TEST_PASSWORD).await;

    seed_credential_vended_event(&*ctx.store).await;

    // The page is a shell: no event data, only the rule that maps the API's
    // `credential_*` event types to the credential glyph.
    let (status, body) = get_page(&ctx.app, "/audit", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("/^credential_/.test(ev.event_type || '') ? 'credential' : ''"),
        "audit page derives the icon hint from the API event type"
    );
    assert!(
        !body.contains("github-token") && !body.contains("ws-alpha"),
        "audit page must not embed event data; it comes from the API"
    );

    // The API returns what the row shows: the event type, the credential
    // name, and the workspace name.
    let (status, api) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/audit?limit=50",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let row = api["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["metadata"]["credential_name"] == "github-token")
        .unwrap_or_else(|| panic!("the seeded event is listed: {api}"));
    assert_eq!(row["event_type"], "credential_vended");
    assert_eq!(row["workspace_name"], "ws-alpha");
}
