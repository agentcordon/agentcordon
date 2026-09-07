//! Audit export: the CSV, syslog, and JSONL exporters must show a caller
//! exactly what the audit list shows them, in a form that is safe to open.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use crate::common::*;
use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::user::{User, UserRole};
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

async fn get_text(app: &axum::Router, uri: &str, cookie: &str) -> (StatusCode, String) {
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Record an audit event as if `actor` had performed `action` on `resource_id`.
async fn record(ctx: &TestContext, actor: &User, action: &str, resource_id: &str) {
    let event = AuditEvent::builder(AuditEventType::CredentialCreated)
        .action(action)
        .user_actor(actor)
        .resource("credential", resource_id)
        .correlation_id("test-corr")
        .decision(AuditDecision::Permit, Some("test"))
        .build();
    ctx.store.append_audit_event(&event).await.expect("append");
}

/// The list endpoint scopes a non-admin to their own events. The CSV export
/// must apply the same scope: a viewer's export contains their own actions
/// and nothing done by other users.
#[tokio::test]
async fn viewer_csv_export_contains_only_their_own_events() {
    let ctx = TestAppBuilder::new().build().await;
    let root = create_root_user(&*ctx.store, "export-root", TEST_PASSWORD).await;
    let viewer = create_user_in_db(
        &*ctx.store,
        "export-viewer",
        TEST_PASSWORD,
        UserRole::Viewer,
        false,
        true,
    )
    .await;
    record(&ctx, &root, "root-did-this", "cred-of-root").await;
    record(&ctx, &viewer, "viewer-did-this", "cred-of-viewer").await;

    let cookie = login_user_combined(&ctx.app, "export-viewer", TEST_PASSWORD).await;
    let (status, csv) = get_text(&ctx.app, "/api/v1/audit/export", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert!(csv.contains("viewer-did-this"), "own event present:\n{csv}");
    assert!(
        !csv.contains("root-did-this"),
        "another user's event must not be exported:\n{csv}"
    );
}

/// The audit list passes `limit` straight to the query. A page size has a
/// ceiling so one request cannot pull the whole table.
#[tokio::test]
async fn audit_list_page_size_is_capped() {
    let ctx = TestAppBuilder::new().build().await;
    let root = create_root_user(&*ctx.store, "cap-root", TEST_PASSWORD).await;
    for i in 0..520 {
        record(&ctx, &root, "bulk", &format!("cred-{i}")).await;
    }
    let cookie = login_user_combined(&ctx.app, "cap-root", TEST_PASSWORD).await;

    let (status, body) = send_json(
        &ctx.app,
        axum::http::Method::GET,
        "/api/v1/audit?limit=100000",
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let rows = body["data"].as_array().expect("rows").len();
    assert!(rows <= 500, "a page is at most 500 rows, got {rows}");
    assert!(rows >= 500, "and the cap is 500, not lower: got {rows}");
}

/// A value that starts with a formula character would execute when the CSV
/// is opened in a spreadsheet. Such cells are prefixed so they read as text.
#[tokio::test]
async fn csv_export_neutralises_formula_cells() {
    let ctx = TestAppBuilder::new().build().await;
    let root = create_root_user(&*ctx.store, "formula-root", TEST_PASSWORD).await;
    record(
        &ctx,
        &root,
        "create",
        "=HYPERLINK(\"http://evil.example\",\"click\")",
    )
    .await;

    let cookie = login_user_combined(&ctx.app, "formula-root", TEST_PASSWORD).await;
    let (status, csv) = get_text(&ctx.app, "/api/v1/audit/export", &cookie).await;

    assert_eq!(status, StatusCode::OK);
    let row = csv
        .lines()
        .find(|l| l.contains("HYPERLINK"))
        .expect("the event is exported");
    assert!(
        !row.contains(",=HYPERLINK") && !row.contains(",\"=HYPERLINK"),
        "a cell must not begin with '=':\n{row}"
    );
    assert!(
        row.contains("'=HYPERLINK"),
        "the formula cell is prefixed with an apostrophe:\n{row}"
    );
}
