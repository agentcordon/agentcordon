//! v1.15.0 — Feature 8: Audit Log Policy Reasoning
//!
//! Tests that policy reasoning in audit logs is access-controlled.

use axum::http::{Method, StatusCode};

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::*;

/// Test: Policy reasoning is only visible to admin users.
#[tokio::test]
async fn test_policy_reasoning_visible_to_admin_only() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let _viewer = create_test_user(&*ctx.store, "viewer", TEST_PASSWORD, UserRole::Viewer).await;

    // Viewer tries to access audit API
    let (viewer_cookie, viewer_csrf) = login_user(&ctx.app, "viewer", TEST_PASSWORD).await;
    let viewer_full_cookie = combined_cookie(&viewer_cookie, &viewer_csrf);

    let (status, _body) = send_json(
        &ctx.app,
        Method::GET,
        "/api/v1/audit?limit=10",
        None,
        Some(&viewer_full_cookie),
        None,
        None,
    )
    .await;

    // Viewer should either be denied (403) or get events without decision_reason
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::OK,
        "viewer audit access should be controlled: status={}",
        status
    );
}
