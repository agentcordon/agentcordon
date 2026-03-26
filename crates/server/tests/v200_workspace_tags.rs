//! v2.0 — Workspace tag management tests.
//!
//! Tests the POST /api/v1/workspaces/{id}/tags and
//! DELETE /api/v1/workspaces/{id}/tags/{tag} endpoints.
//! These require user (admin) auth, not workspace JWT auth.

use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

use agent_cordon_core::domain::user::UserRole;

use crate::common::*;
use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn admin_session(ctx: &agent_cordon_server::test_helpers::TestContext) -> (String, String) {
    create_user_in_db(
        &*ctx.store,
        "tag-admin",
        TEST_PASSWORD,
        UserRole::Admin,
        true,
        true,
    )
    .await;
    login_user(&ctx.app, "tag-admin", TEST_PASSWORD).await
}

// ===========================================================================
// 1. Admin adds a tag to a workspace
// ===========================================================================

#[tokio::test]
async fn test_add_tag_to_workspace() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (session_cookie, csrf_token) = admin_session(&ctx).await;
    let ws = ctx.admin_agent.as_ref().unwrap();
    let ws_id = ws.id.0;

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/workspaces/{}/tags", ws_id),
        None,
        Some(&combined_cookie(&session_cookie, &csrf_token)),
        Some(json!({"tag": "production"})),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "add tag: {}", body);
    let tags = &body["data"]["tags"];
    assert!(tags.is_array(), "response should have tags array");
    let tag_list: Vec<String> = tags
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    assert!(
        tag_list.contains(&"production".to_string()),
        "tags should contain 'production': {:?}",
        tag_list
    );
}

// ===========================================================================
// 2. Remove tag from workspace
// ===========================================================================

#[tokio::test]
async fn test_remove_tag_from_workspace() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (session_cookie, csrf_token) = admin_session(&ctx).await;
    let ws = ctx.admin_agent.as_ref().unwrap();
    let ws_id = ws.id.0;
    let cookie = combined_cookie(&session_cookie, &csrf_token);

    // Add tag first
    let (status, _body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/workspaces/{}/tags", ws_id),
        None,
        Some(&cookie),
        Some(json!({"tag": "to-remove"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "add tag should succeed");

    // Remove tag
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/workspaces/{}/tags/to-remove", ws_id),
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "remove tag: {}", body);
    let tags = &body["data"]["tags"];
    let tag_list: Vec<String> = tags
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    assert!(
        !tag_list.contains(&"to-remove".to_string()),
        "tag should be removed: {:?}",
        tag_list
    );
}

// ===========================================================================
// 3. Duplicate tag is idempotent
// ===========================================================================

#[tokio::test]
async fn test_add_duplicate_tag_idempotent() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (session_cookie, csrf_token) = admin_session(&ctx).await;
    let ws = ctx.admin_agent.as_ref().unwrap();
    let ws_id = ws.id.0;
    let cookie = combined_cookie(&session_cookie, &csrf_token);

    // Add same tag twice
    for _ in 0..2 {
        let (status, _body) = send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            &format!("/api/v1/workspaces/{}/tags", ws_id),
            None,
            Some(&cookie),
            Some(json!({"tag": "duplicate"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    // Verify tag appears only once
    let ws_updated = ctx
        .store
        .get_workspace(&ws.id)
        .await
        .expect("get workspace")
        .expect("workspace exists");
    let count = ws_updated
        .tags
        .iter()
        .filter(|t| t.as_str() == "duplicate")
        .count();
    assert_eq!(
        count, 1,
        "duplicate tag should appear exactly once, found {}",
        count
    );
}

// ===========================================================================
// 4. Empty tag string -> 400
// ===========================================================================

#[tokio::test]
async fn test_add_tag_empty_string_returns_400() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (session_cookie, csrf_token) = admin_session(&ctx).await;
    let ws = ctx.admin_agent.as_ref().unwrap();
    let ws_id = ws.id.0;

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/workspaces/{}/tags", ws_id),
        None,
        Some(&combined_cookie(&session_cookie, &csrf_token)),
        Some(json!({"tag": ""})),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "empty tag should be rejected: {}",
        body
    );
}

// ===========================================================================
// 5. Non-admin (viewer) cannot tag workspace -> 403
// ===========================================================================

#[tokio::test]
async fn test_non_admin_cannot_tag_workspace() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // Create a viewer user
    create_user_in_db(
        &*ctx.store,
        "viewer-user",
        TEST_PASSWORD,
        UserRole::Viewer,
        false,
        true,
    )
    .await;
    let (session_cookie, csrf_token) = login_user(&ctx.app, "viewer-user", TEST_PASSWORD).await;

    let ws = ctx.admin_agent.as_ref().unwrap();
    let ws_id = ws.id.0;

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/workspaces/{}/tags", ws_id),
        None,
        Some(&combined_cookie(&session_cookie, &csrf_token)),
        Some(json!({"tag": "unauthorized-tag"})),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer should not be able to add tags: {}",
        body
    );
}

// ===========================================================================
// 6. Tag nonexistent workspace -> 404
// ===========================================================================

#[tokio::test]
async fn test_tag_nonexistent_workspace_returns_404() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let (session_cookie, csrf_token) = admin_session(&ctx).await;
    let fake_id = Uuid::new_v4();

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/workspaces/{}/tags", fake_id),
        None,
        Some(&combined_cookie(&session_cookie, &csrf_token)),
        Some(json!({"tag": "ghost-tag"})),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "nonexistent workspace: {}",
        body
    );
}
