//! Integration tests — v1.9.1 Feature 3: SQLite Connection Pool.
//!
//! Verifies that the store supports concurrent read operations without
//! serializing them, and that write-read consistency is preserved.

use crate::common;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;
use axum::http::{Method, StatusCode};
use std::time::Duration;

// ===========================================================================
// 3A. Happy Path
// ===========================================================================

/// Spawn 10 concurrent read operations. All should complete without
/// serializing behind a single connection.
#[tokio::test]
async fn test_concurrent_reads_complete() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // Pre-create some agents to read
    for i in 0..10 {
        common::create_agent_in_db(
            &*ctx.store,
            &format!("pool-agent-{}", i),
            vec!["test"],
            true,
            None,
        )
        .await;
    }

    let _user = common::create_test_user(
        &*ctx.store,
        "pool-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, "pool-user", common::TEST_PASSWORD).await;

    let start = std::time::Instant::now();

    // Spawn 10 concurrent GET /api/v1/agents
    let mut handles = Vec::new();
    for _ in 0..10 {
        let app = ctx.app.clone();
        let cookie = cookie.clone();
        handles.push(tokio::spawn(async move {
            let (status, body) = common::send_json(
                &app,
                Method::GET,
                "/api/v1/workspaces",
                None,
                Some(&cookie),
                None,
                None,
            )
            .await;
            (status, body)
        }));
    }

    let timeout = Duration::from_secs(10);
    for handle in handles {
        let (status, _) = tokio::time::timeout(timeout, handle)
            .await
            .expect("concurrent read should complete within timeout")
            .expect("task should not panic");
        assert_eq!(status, StatusCode::OK, "concurrent read should succeed");
    }

    let elapsed = start.elapsed();
    // With a pool, 10 reads should complete much faster than sequentially
    assert!(
        elapsed < Duration::from_secs(10),
        "10 concurrent reads should complete within 10s (took {:?})",
        elapsed,
    );
}

#[tokio::test]
async fn test_write_then_read_consistent() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "wr-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, "wr-user", common::TEST_PASSWORD).await;

    // Write: create a credential
    let (create_status, create_body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "name": "pool-test-cred",
            "service": "test-service",
            "credential_type": "generic",
            "secret_value": "test-secret-value"
        })),
    )
    .await;
    assert!(
        create_status == StatusCode::CREATED || create_status == StatusCode::OK,
        "credential creation should succeed: {:?}",
        create_body,
    );

    let cred_id = create_body["data"]["id"]
        .as_str()
        .expect("credential should have id");

    // Read: get the credential back
    let (get_status, get_body) = common::send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{}", cred_id),
        None,
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(get_status, StatusCode::OK);
    assert_eq!(
        get_body["data"]["name"].as_str(),
        Some("pool-test-cred"),
        "read-after-write should return consistent data",
    );
}

#[tokio::test]
async fn test_concurrent_reads_during_write() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "rw-conc-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, "rw-conc-user", common::TEST_PASSWORD).await;

    // Start a write (create agent) and simultaneously issue reads
    let write_app = ctx.app.clone();
    let write_cookie = cookie.clone();
    let write_handle = tokio::spawn(async move {
        let (status, _) = common::send_json_auto_csrf(
            &write_app,
            Method::POST,
            "/api/v1/credentials",
            None,
            Some(&write_cookie),
            Some(serde_json::json!({
                "name": "concurrent-write-cred",
                "service": "test",
                "credential_type": "generic",
                "secret_value": "secret"
            })),
        )
        .await;
        status
    });

    let mut read_handles = Vec::new();
    for _ in 0..5 {
        let app = ctx.app.clone();
        let cookie = cookie.clone();
        read_handles.push(tokio::spawn(async move {
            let (status, _) = common::send_json(
                &app,
                Method::GET,
                "/api/v1/workspaces",
                None,
                Some(&cookie),
                None,
                None,
            )
            .await;
            status
        }));
    }

    let timeout = Duration::from_secs(10);

    let write_status = tokio::time::timeout(timeout, write_handle)
        .await
        .expect("write should complete within timeout")
        .expect("write task should not panic");
    assert!(
        write_status == StatusCode::CREATED || write_status == StatusCode::OK,
        "write should succeed",
    );

    for handle in read_handles {
        let read_status = tokio::time::timeout(timeout, handle)
            .await
            .expect("read should complete within timeout")
            .expect("read task should not panic");
        assert_eq!(
            read_status,
            StatusCode::OK,
            "concurrent read should succeed during write"
        );
    }
}

// ===========================================================================
// 3B. Retry/Idempotency
// ===========================================================================

#[tokio::test]
async fn test_same_query_concurrent_returns_same_result() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    // Create some agents
    for i in 0..3 {
        common::create_agent_in_db(
            &*ctx.store,
            &format!("same-query-agent-{}", i),
            vec!["test"],
            true,
            None,
        )
        .await;
    }

    let _user = common::create_test_user(
        &*ctx.store,
        "same-query-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "same-query-user", common::TEST_PASSWORD).await;

    // Issue the same query 5 times concurrently
    let mut handles = Vec::new();
    for _ in 0..5 {
        let app = ctx.app.clone();
        let cookie = cookie.clone();
        handles.push(tokio::spawn(async move {
            let (status, body) = common::send_json(
                &app,
                Method::GET,
                "/api/v1/workspaces",
                None,
                Some(&cookie),
                None,
                None,
            )
            .await;
            (status, body)
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        let (status, body) = handle.await.expect("task should not panic");
        assert_eq!(status, StatusCode::OK);
        results.push(body);
    }

    // All results should have the same agent count
    let first_count = results[0]["data"].as_array().map(|a| a.len());
    for (i, result) in results.iter().enumerate() {
        let count = result["data"].as_array().map(|a| a.len());
        assert_eq!(
            count, first_count,
            "concurrent query {} returned different count than first",
            i,
        );
    }
}

// ===========================================================================
// 3D. Cross-Feature
// ===========================================================================

#[tokio::test]
async fn test_login_and_list_agents_concurrent() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _user = common::create_test_user(
        &*ctx.store,
        "cross-feature-user",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "cross-feature-user", common::TEST_PASSWORD).await;

    // Login (Argon2 + DB) concurrent with listing agents (DB read)
    let login_app = ctx.app.clone();
    let login_handle = tokio::spawn(async move {
        let (status, _) = common::send_json(
            &login_app,
            Method::POST,
            "/api/v1/auth/login",
            None,
            None,
            None,
            Some(serde_json::json!({
                "username": "cross-feature-user",
                "password": common::TEST_PASSWORD,
            })),
        )
        .await;
        status
    });

    let list_app = ctx.app.clone();
    let list_cookie = cookie.clone();
    let list_handle = tokio::spawn(async move {
        let (status, _) = common::send_json(
            &list_app,
            Method::GET,
            "/api/v1/workspaces",
            None,
            Some(&list_cookie),
            None,
            None,
        )
        .await;
        status
    });

    let timeout = Duration::from_secs(10);

    let login_status = tokio::time::timeout(timeout, login_handle)
        .await
        .expect("login should complete")
        .expect("login task ok");
    let list_status = tokio::time::timeout(timeout, list_handle)
        .await
        .expect("list should complete")
        .expect("list task ok");

    assert_eq!(
        login_status,
        StatusCode::OK,
        "concurrent login should succeed"
    );
    assert_eq!(
        list_status,
        StatusCode::OK,
        "concurrent list should succeed"
    );
}
