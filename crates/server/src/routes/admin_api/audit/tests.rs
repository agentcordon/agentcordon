use super::export::{sd_escape, syslog_priority};
use super::*;
use axum::body::Body;
use axum::http::{self, Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use agent_cordon_core::crypto::password::hash_password;
use agent_cordon_core::domain::audit::{AuditDecision, AuditEventType};
use agent_cordon_core::domain::user::{User, UserId, UserRole};
use agent_cordon_core::storage::Store;

use crate::test_helpers::TestAppBuilder;

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

async fn create_root_user(store: &dyn Store, username: &str) -> User {
    let password_hash = hash_password("test-pass-123!").expect("hash");
    let now = chrono::Utc::now();
    let user = User {
        id: UserId(Uuid::new_v4()),
        username: username.to_string(),
        display_name: Some(format!("Test {}", username)),
        password_hash,
        role: UserRole::Admin,
        is_root: true,
        enabled: true,
        created_at: now,
        updated_at: now,
    };
    store.create_user(&user).await.expect("create user");
    user
}

async fn login_user(app: &axum::Router, username: &str) -> String {
    let body = serde_json::json!({
        "username": username,
        "password": "test-pass-123!"
    });
    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/api/v1/auth/login")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let mut cookie_parts = Vec::new();
    for (name, value) in resp.headers() {
        if name == "set-cookie" {
            if let Some(nv) = value.to_str().ok().and_then(|v| v.split(';').next()) {
                cookie_parts.push(nv.trim().to_string());
            }
        }
    }
    cookie_parts.join("; ")
}

async fn send_get(
    app: &axum::Router,
    uri: &str,
    cookie: Option<&str>,
) -> (StatusCode, String, Vec<(String, String)>) {
    let mut builder = Request::builder().method(http::Method::GET).uri(uri);
    if let Some(c) = cookie {
        builder = builder.header(http::header::COOKIE, c);
    }
    let req = builder.body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&bytes).to_string();
    (status, body, headers)
}

async fn insert_test_audit_event(
    store: &dyn Store,
    event_type: AuditEventType,
    action: &str,
    resource_type: &str,
    resource_id: Option<&str>,
    decision: AuditDecision,
) -> AuditEvent {
    let event = AuditEvent {
        id: Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        correlation_id: Uuid::new_v4().to_string(),
        event_type,
        workspace_id: None,
        workspace_name: Some("test-agent".to_string()),
        user_id: Some("user-1".to_string()),
        user_name: Some("Test User".to_string()),
        action: action.to_string(),
        resource_type: resource_type.to_string(),
        resource_id: resource_id.map(|s| s.to_string()),
        decision,
        decision_reason: Some("test reason".to_string()),
        metadata: serde_json::json!({"key": "value"}),
    };
    store
        .append_audit_event(&event)
        .await
        .expect("append audit event");
    event
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

/// Basic CSV export: create events, export, verify CSV format and headers.
#[tokio::test]
async fn test_audit_csv_export_basic() {
    let ctx = TestAppBuilder::new().build().await;
    let _user = create_root_user(ctx.store.as_ref(), "admin").await;
    let cookie = login_user(&ctx.app, "admin").await;

    // Insert a few audit events
    insert_test_audit_event(
        ctx.store.as_ref(),
        AuditEventType::WorkspaceCreated,
        "create_agent",
        "agent",
        Some("agent-1"),
        AuditDecision::Permit,
    )
    .await;

    insert_test_audit_event(
        ctx.store.as_ref(),
        AuditEventType::CredentialCreated,
        "create_credential",
        "credential",
        Some("cred-1"),
        AuditDecision::Forbid,
    )
    .await;

    // Export CSV
    let (status, body, headers) = send_get(&ctx.app, "/api/v1/audit/export", Some(&cookie)).await;

    assert_eq!(status, StatusCode::OK, "export should succeed: {}", body);

    // Check Content-Type header
    let content_type = headers
        .iter()
        .find(|(k, _)| k == "content-type")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert_eq!(content_type, "text/csv");

    // Check Content-Disposition header
    let content_disp = headers
        .iter()
        .find(|(k, _)| k == "content-disposition")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert!(
        content_disp.starts_with("attachment; filename=\"audit-export-"),
        "Content-Disposition should set filename: got {}",
        content_disp
    );
    assert!(
        content_disp.ends_with(".csv\""),
        "filename should end with .csv: got {}",
        content_disp
    );

    // Verify CSV structure
    let lines: Vec<&str> = body.lines().collect();
    assert!(
        lines.len() >= 3,
        "should have header + at least 2 data rows, got {} lines",
        lines.len()
    );

    // Header row
    assert_eq!(
            lines[0],
            "timestamp,correlation_id,event_type,user_id,user_name,workspace_id,workspace_name,action,resource_type,resource_id,decision,decision_reason,metadata"
        );

    // Data rows should contain expected values
    let all_data = lines[1..].join("\n");
    assert!(
        all_data.contains("workspace_created"),
        "should contain agent_created event type"
    );
    assert!(
        all_data.contains("credential_created"),
        "should contain credential_created event type"
    );
    assert!(
        all_data.contains("create_agent"),
        "should contain create_agent action"
    );
    assert!(
        all_data.contains("create_credential"),
        "should contain create_credential action"
    );
    assert!(
        all_data.contains("permit"),
        "should contain permit decision"
    );
    assert!(
        all_data.contains("forbid"),
        "should contain forbid decision"
    );

    // Verify each data row has the right number of columns (13)
    for (i, line) in lines[1..].iter().enumerate() {
        if line.starts_with('#') {
            continue; // skip comment rows
        }
        let col_count = count_csv_columns(line);
        assert_eq!(
            col_count,
            13,
            "row {} should have 13 columns, got {}",
            i + 1,
            col_count
        );
    }
}

/// CSV export with resource_type filter works correctly.
#[tokio::test]
async fn test_audit_csv_export_with_filters() {
    let ctx = TestAppBuilder::new().build().await;
    let _user = create_root_user(ctx.store.as_ref(), "admin").await;
    let cookie = login_user(&ctx.app, "admin").await;

    // Insert events with different resource types
    insert_test_audit_event(
        ctx.store.as_ref(),
        AuditEventType::WorkspaceCreated,
        "create_agent",
        "agent",
        Some("agent-1"),
        AuditDecision::Permit,
    )
    .await;

    insert_test_audit_event(
        ctx.store.as_ref(),
        AuditEventType::CredentialCreated,
        "create_credential",
        "credential",
        Some("cred-1"),
        AuditDecision::Permit,
    )
    .await;

    insert_test_audit_event(
        ctx.store.as_ref(),
        AuditEventType::CredentialDeleted,
        "delete_credential",
        "credential",
        Some("cred-2"),
        AuditDecision::Forbid,
    )
    .await;

    // Export with resource_type=credential filter
    let (status, body, _headers) = send_get(
        &ctx.app,
        "/api/v1/audit/export?resource_type=credential",
        Some(&cookie),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "filtered export should succeed");

    let lines: Vec<&str> = body.lines().collect();
    assert!(
        lines.len() >= 3,
        "should have header + 2 credential rows, got {} lines",
        lines.len()
    );

    // Should NOT contain agent events
    let data = lines[1..].join("\n");
    assert!(
        !data.contains("workspace_created"),
        "filtered export should not include agent events"
    );
    assert!(
        data.contains("credential_created"),
        "filtered export should include credential events"
    );
    assert!(
        data.contains("credential_deleted"),
        "filtered export should include credential_deleted events"
    );
}

/// Unauthenticated request to CSV export returns 401.
#[tokio::test]
async fn test_audit_csv_export_requires_auth() {
    let ctx = TestAppBuilder::new().build().await;

    // No auth cookie or bearer token
    let (status, _body, _headers) = send_get(&ctx.app, "/api/v1/audit/export", None).await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "unauthenticated export should fail with 401 or 403, got {}",
        status
    );
}

/// CSV escaping: fields with commas, quotes, and newlines are properly escaped.
#[tokio::test]
async fn test_audit_csv_export_escaping() {
    let ctx = TestAppBuilder::new().build().await;
    let _user = create_root_user(ctx.store.as_ref(), "admin").await;
    let cookie = login_user(&ctx.app, "admin").await;

    // Insert event with tricky metadata containing commas and quotes
    let event = AuditEvent {
        id: Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        correlation_id: Uuid::new_v4().to_string(),
        event_type: AuditEventType::PolicyEvaluated,
        workspace_id: None,
        workspace_name: Some("agent, with \"commas\"".to_string()),
        user_id: None,
        user_name: None,
        action: "evaluate".to_string(),
        resource_type: "policy".to_string(),
        resource_id: None,
        decision: AuditDecision::Permit,
        decision_reason: Some("policy says \"yes\", proceed".to_string()),
        metadata: serde_json::json!({"note": "has, comma"}),
    };
    ctx.store.append_audit_event(&event).await.expect("append");

    let (status, body, _headers) = send_get(&ctx.app, "/api/v1/audit/export", Some(&cookie)).await;

    assert_eq!(status, StatusCode::OK);

    let lines: Vec<&str> = body.lines().collect();
    let data_lines: Vec<&str> = lines[1..]
        .iter()
        .filter(|l| !l.starts_with('#'))
        .copied()
        .collect();
    assert!(!data_lines.is_empty(), "should have at least one data row");

    let csv_body = data_lines.join("\n");
    assert!(
        csv_body.contains("\"agent, with \"\"commas\"\"\""),
        "workspace_name with commas and quotes should be properly escaped in: {}",
        csv_body
    );
    assert!(
        csv_body.contains("\"policy says \"\"yes\"\", proceed\""),
        "decision_reason with commas and quotes should be properly escaped in: {}",
        csv_body
    );
}

/// Helper: count CSV columns handling quoted fields.
fn count_csv_columns(line: &str) -> usize {
    let mut count = 1;
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if in_quotes {
                    if chars.peek() == Some(&'"') {
                        chars.next();
                    } else {
                        in_quotes = false;
                    }
                } else {
                    in_quotes = true;
                }
            }
            ',' if !in_quotes => {
                count += 1;
            }
            _ => {}
        }
    }
    count
}

// -----------------------------------------------------------------------
// Syslog Export Tests
// -----------------------------------------------------------------------

/// Basic syslog export: create events, export, verify RFC 5424 format.
#[tokio::test]
async fn test_audit_syslog_export_basic() {
    let ctx = TestAppBuilder::new().build().await;
    let _user = create_root_user(ctx.store.as_ref(), "admin").await;
    let cookie = login_user(&ctx.app, "admin").await;

    // Note: login itself creates audit events (user_login_success).
    // We filter by resource_type=agent to isolate our test events.

    insert_test_audit_event(
        ctx.store.as_ref(),
        AuditEventType::WorkspaceCreated,
        "create_agent",
        "agent",
        Some("agent-1"),
        AuditDecision::Permit,
    )
    .await;

    insert_test_audit_event(
        ctx.store.as_ref(),
        AuditEventType::CredentialAccessDenied,
        "access_credential",
        "credential",
        Some("cred-1"),
        AuditDecision::Forbid,
    )
    .await;

    // Export only agent events to avoid login audit noise
    let (status, body, headers) = send_get(
        &ctx.app,
        "/api/v1/audit/export/syslog?resource_type=agent",
        Some(&cookie),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "syslog export should succeed: {}",
        body
    );

    // Check Content-Type
    let content_type = headers
        .iter()
        .find(|(k, _)| k == "content-type")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert_eq!(content_type, "text/plain; charset=utf-8");

    // Check Content-Disposition
    let content_disp = headers
        .iter()
        .find(|(k, _)| k == "content-disposition")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert!(
        content_disp.contains(".log\""),
        "filename should end with .log: got {}",
        content_disp
    );

    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "should have 1 agent syslog line, got {}",
        lines.len()
    );

    // Allow -> priority 134 (local0.info)
    assert!(
        lines[0].starts_with("<134>1 "),
        "Allow event should have priority 134: {}",
        lines[0]
    );
    assert!(
        lines[0].contains("AgentCordon"),
        "should contain app name: {}",
        lines[0]
    );
    assert!(
        lines[0].contains("event_type=\"workspace_created\""),
        "should contain event_type in structured data: {}",
        lines[0]
    );
    assert!(
        lines[0].contains("decision=\"permit\""),
        "should contain decision in structured data: {}",
        lines[0]
    );
    assert!(
        lines[0].contains("action=\"create_agent\""),
        "should contain action in structured data: {}",
        lines[0]
    );

    // Also export credential events to verify Deny priority
    let (status, body, _) = send_get(
        &ctx.app,
        "/api/v1/audit/export/syslog?resource_type=credential",
        Some(&cookie),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 1, "should have 1 credential syslog line");
    assert!(
        lines[0].starts_with("<131>1 "),
        "Deny event should have priority 131: {}",
        lines[0]
    );
    assert!(
        lines[0].contains("decision=\"forbid\""),
        "should contain forbid decision: {}",
        lines[0]
    );
}

/// Syslog export with resource_type filter.
#[tokio::test]
async fn test_audit_syslog_export_with_filters() {
    let ctx = TestAppBuilder::new().build().await;
    let _user = create_root_user(ctx.store.as_ref(), "admin").await;
    let cookie = login_user(&ctx.app, "admin").await;

    insert_test_audit_event(
        ctx.store.as_ref(),
        AuditEventType::WorkspaceCreated,
        "create_agent",
        "agent",
        Some("agent-1"),
        AuditDecision::Permit,
    )
    .await;

    insert_test_audit_event(
        ctx.store.as_ref(),
        AuditEventType::CredentialCreated,
        "create_credential",
        "credential",
        Some("cred-1"),
        AuditDecision::Permit,
    )
    .await;

    let (status, body, _headers) = send_get(
        &ctx.app,
        "/api/v1/audit/export/syslog?resource_type=credential",
        Some(&cookie),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "filtered syslog export should succeed"
    );

    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "should have 1 credential event, got {}",
        lines.len()
    );
    assert!(
        lines[0].contains("resource_type=\"credential\""),
        "should contain credential resource_type: {}",
        lines[0]
    );
}

/// Syslog export requires authentication.
#[tokio::test]
async fn test_audit_syslog_export_requires_auth() {
    let ctx = TestAppBuilder::new().build().await;

    let (status, _body, _headers) = send_get(&ctx.app, "/api/v1/audit/export/syslog", None).await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "unauthenticated syslog export should fail with 401 or 403, got {}",
        status
    );
}

/// Syslog structured data escaping: values with quotes and brackets.
#[tokio::test]
async fn test_audit_syslog_sd_escaping() {
    let ctx = TestAppBuilder::new().build().await;
    let _user = create_root_user(ctx.store.as_ref(), "admin").await;
    let cookie = login_user(&ctx.app, "admin").await;

    let event = AuditEvent {
        id: Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        correlation_id: Uuid::new_v4().to_string(),
        event_type: AuditEventType::PolicyEvaluated,
        workspace_id: None,
        workspace_name: Some("test-agent".to_string()),
        user_id: Some("user\"with]quotes".to_string()),
        user_name: Some("Test User".to_string()),
        action: "eval\\action".to_string(),
        resource_type: "policy".to_string(),
        resource_id: Some("pol-1".to_string()),
        decision: AuditDecision::Permit,
        decision_reason: Some("allowed".to_string()),
        metadata: serde_json::json!({}),
    };
    ctx.store.append_audit_event(&event).await.expect("append");

    let (status, body, _headers) =
        send_get(&ctx.app, "/api/v1/audit/export/syslog", Some(&cookie)).await;

    assert_eq!(status, StatusCode::OK);

    let lines: Vec<&str> = body.lines().collect();
    assert!(!lines.is_empty(), "should have at least one syslog line");

    // Find the line containing our test event (other lines may be policy
    // evaluation audit events emitted by the auditing engine).
    let line = lines
        .iter()
        .find(|l| l.contains("eval\\\\action"))
        .unwrap_or_else(|| panic!("could not find test event in syslog output: {:?}", lines));

    // Verify SD-PARAM escaping: " -> \", ] -> \], \ -> \\
    assert!(
        line.contains("user=\"user\\\"with\\]quotes\""),
        "user_id with special chars should be SD-escaped: {}",
        line
    );
    assert!(
        line.contains("action=\"eval\\\\action\""),
        "action with backslash should be SD-escaped: {}",
        line
    );
}

// -----------------------------------------------------------------------
// JSON Lines Export Tests
// -----------------------------------------------------------------------

/// Basic JSONL export: create events, export, verify NDJSON format.
#[tokio::test]
async fn test_audit_jsonl_export_basic() {
    let ctx = TestAppBuilder::new().build().await;
    let _user = create_root_user(ctx.store.as_ref(), "admin").await;
    let cookie = login_user(&ctx.app, "admin").await;

    // Note: login creates audit events. We filter by resource_type to isolate test data.

    insert_test_audit_event(
        ctx.store.as_ref(),
        AuditEventType::WorkspaceCreated,
        "create_agent",
        "agent",
        Some("agent-1"),
        AuditDecision::Permit,
    )
    .await;

    insert_test_audit_event(
        ctx.store.as_ref(),
        AuditEventType::CredentialCreated,
        "create_credential",
        "credential",
        Some("cred-1"),
        AuditDecision::Forbid,
    )
    .await;

    // Export only agent events first
    let (status, body, headers) = send_get(
        &ctx.app,
        "/api/v1/audit/export/jsonl?resource_type=agent",
        Some(&cookie),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "jsonl export should succeed: {}",
        body
    );

    // Check Content-Type is NDJSON
    let content_type = headers
        .iter()
        .find(|(k, _)| k == "content-type")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert_eq!(content_type, "application/x-ndjson");

    // Check Content-Disposition
    let content_disp = headers
        .iter()
        .find(|(k, _)| k == "content-disposition")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert!(
        content_disp.contains(".jsonl\""),
        "filename should end with .jsonl: got {}",
        content_disp
    );

    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "should have 1 agent JSON line, got {}",
        lines.len()
    );

    // Each line should be valid JSON with expected fields
    for (i, line) in lines.iter().enumerate() {
        let parsed: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("line {} should be valid JSON: {} -- {}", i, e, line));

        assert!(parsed.get("id").is_some(), "line {} should have id", i);
        assert!(
            parsed.get("timestamp").is_some(),
            "line {} should have timestamp",
            i
        );
        assert!(
            parsed.get("correlation_id").is_some(),
            "line {} should have correlation_id",
            i
        );
        assert!(
            parsed.get("event_type").is_some(),
            "line {} should have event_type",
            i
        );
        assert!(
            parsed.get("action").is_some(),
            "line {} should have action",
            i
        );
        assert!(
            parsed.get("resource_type").is_some(),
            "line {} should have resource_type",
            i
        );
        assert!(
            parsed.get("decision").is_some(),
            "line {} should have decision",
            i
        );
    }

    // Verify specific content
    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first["event_type"], "workspace_created");
    assert_eq!(first["action"], "create_agent");
    assert_eq!(first["decision"], "permit");

    // Export credential events
    let (status, body, _) = send_get(
        &ctx.app,
        "/api/v1/audit/export/jsonl?resource_type=credential",
        Some(&cookie),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 1, "should have 1 credential JSON line");

    let cred_event: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(cred_event["event_type"], "credential_created");
    assert_eq!(cred_event["action"], "create_credential");
    assert_eq!(cred_event["decision"], "forbid");
}

/// JSONL export with resource_type filter.
#[tokio::test]
async fn test_audit_jsonl_export_with_filters() {
    let ctx = TestAppBuilder::new().build().await;
    let _user = create_root_user(ctx.store.as_ref(), "admin").await;
    let cookie = login_user(&ctx.app, "admin").await;

    insert_test_audit_event(
        ctx.store.as_ref(),
        AuditEventType::WorkspaceCreated,
        "create_agent",
        "agent",
        Some("agent-1"),
        AuditDecision::Permit,
    )
    .await;

    insert_test_audit_event(
        ctx.store.as_ref(),
        AuditEventType::CredentialCreated,
        "create_credential",
        "credential",
        Some("cred-1"),
        AuditDecision::Permit,
    )
    .await;

    let (status, body, _headers) = send_get(
        &ctx.app,
        "/api/v1/audit/export/jsonl?resource_type=agent",
        Some(&cookie),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "filtered jsonl export should succeed"
    );

    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "should have 1 agent event, got {}",
        lines.len()
    );

    let parsed: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(parsed["resource_type"], "agent");
}

/// JSONL export requires authentication.
#[tokio::test]
async fn test_audit_jsonl_export_requires_auth() {
    let ctx = TestAppBuilder::new().build().await;

    let (status, _body, _headers) = send_get(&ctx.app, "/api/v1/audit/export/jsonl", None).await;

    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "unauthenticated jsonl export should fail with 401 or 403, got {}",
        status
    );
}

/// JSONL export returns empty body when filter matches no events.
#[tokio::test]
async fn test_audit_jsonl_export_empty() {
    let ctx = TestAppBuilder::new().build().await;
    let _user = create_root_user(ctx.store.as_ref(), "admin").await;
    let cookie = login_user(&ctx.app, "admin").await;

    // Filter by a resource_type that has no events
    let (status, body, headers) = send_get(
        &ctx.app,
        "/api/v1/audit/export/jsonl?resource_type=nonexistent",
        Some(&cookie),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "empty jsonl export should succeed");

    let content_type = headers
        .iter()
        .find(|(k, _)| k == "content-type")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert_eq!(content_type, "application/x-ndjson");

    assert!(
        body.is_empty(),
        "empty export should have empty body, got: {}",
        body
    );
}

/// Syslog export returns empty body when filter matches no events.
#[tokio::test]
async fn test_audit_syslog_export_empty() {
    let ctx = TestAppBuilder::new().build().await;
    let _user = create_root_user(ctx.store.as_ref(), "admin").await;
    let cookie = login_user(&ctx.app, "admin").await;

    // Filter by a resource_type that has no events
    let (status, body, headers) = send_get(
        &ctx.app,
        "/api/v1/audit/export/syslog?resource_type=nonexistent",
        Some(&cookie),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "empty syslog export should succeed");

    let content_type = headers
        .iter()
        .find(|(k, _)| k == "content-type")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert_eq!(content_type, "text/plain; charset=utf-8");

    assert!(
        body.is_empty(),
        "empty export should have empty body, got: {}",
        body
    );
}

// -----------------------------------------------------------------------
// Unit tests for helper functions
// -----------------------------------------------------------------------

#[test]
fn test_syslog_priority_mapping() {
    assert_eq!(syslog_priority(&AuditDecision::Permit), 134);
    assert_eq!(syslog_priority(&AuditDecision::Forbid), 131);
    assert_eq!(syslog_priority(&AuditDecision::Error), 131);
    assert_eq!(syslog_priority(&AuditDecision::NotApplicable), 134);
}

#[test]
fn test_sd_escape() {
    assert_eq!(sd_escape("simple"), "simple");
    assert_eq!(sd_escape(r#"has"quote"#), r#"has\"quote"#);
    assert_eq!(sd_escape("has]bracket"), r"has\]bracket");
    assert_eq!(sd_escape(r"has\backslash"), r"has\\backslash");
    assert_eq!(sd_escape(r#"all"three]\chars"#), r#"all\"three\]\\chars"#);
}
