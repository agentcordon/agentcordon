//! Integration tests — issue #35: audit log credential-icon row hint.
//!
//! Verifies that credential lifecycle events render an icon hint
//! (`icon == "credential"`) in the audit page's embedded events array,
//! so the unexpanded row can show a credential glyph alongside the
//! credential name and workspace.

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
async fn audit_page_emits_credential_icon_hint_for_vending_row() {
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

    let (status, body) = get_page(&ctx.app, "/audit", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("\"icon\":\"credential\""),
        "audit page should embed icon hint for credential events; body did not contain it"
    );
    assert!(
        body.contains("github-token"),
        "audit page should embed the credential name"
    );
    assert!(
        body.contains("ws-alpha"),
        "audit page should embed the workspace name"
    );
}
