use axum::http::{Method, StatusCode};
use serde_json::{json, Value};

use agent_cordon_core::domain::credential::CredentialId;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

use crate::common::{
    create_root_user, create_test_user, ctx_agent_jwt, login_user_combined, send_json,
    send_json_auto_csrf, TEST_PASSWORD,
};

/// Create a credential through the admin API and let the workspace vend it.
///
/// Both steps are the real routes: `POST /api/v1/credentials` seals and
/// stores the secret exactly as production does, and
/// `POST /api/v1/credentials/{id}/permissions` writes the Cedar grant and
/// reloads the engine. A fixture that wrote the credential row and the grant
/// policy straight into the store could disagree with either.
async fn credential_with_pattern(
    ctx: &TestContext,
    name: &str,
    pattern: Option<&str>,
) -> CredentialId {
    create_root_user(&*ctx.store, "vend-root", TEST_PASSWORD).await;
    let cookie = login_user_combined(&ctx.app, "vend-root", TEST_PASSWORD).await;

    let mut body = json!({
        "name": name,
        "service": "github",
        "secret_value": "s3cret",
        "transform_name": "bearer",
    });
    if let Some(p) = pattern {
        body["allowed_url_pattern"] = json!(p);
    }
    let (status, resp) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create credential: {resp}");
    let cred_id = CredentialId(
        resp["data"]["id"]
            .as_str()
            .expect("credential id")
            .parse()
            .expect("uuid"),
    );
    assert_eq!(
        resp["data"]["allowed_url_pattern"],
        pattern.map(Value::from).unwrap_or(Value::Null),
        "the create route stored the pattern it was given: {resp}"
    );

    let ws = ctx.agents.get("ws").expect("agent");
    let (status, resp) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{}/permissions", cred_id.0),
        None,
        Some(&cookie),
        Some(json!({ "workspace_id": ws.id.0.to_string(), "permission": "delegated_use" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "grant delegated_use: {resp}");
    cred_id
}

async fn vend(
    ctx: &TestContext,
    jwt: &str,
    name: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    send_json(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/vend-device/{name}"),
        Some(jwt),
        None,
        None,
        body,
    )
    .await
}

fn target(method: &str, url: &str) -> Value {
    json!({ "method": method, "target_url": url })
}

#[tokio::test]
async fn vend_refuses_a_target_outside_the_credential_pattern() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws", &[])
        .build()
        .await;
    credential_with_pattern(&ctx, "gh", Some("https://api.github.com/*")).await;
    let jwt = ctx_agent_jwt(&ctx, "ws").await;

    let (status, body) = vend(
        &ctx,
        &jwt,
        "gh",
        Some(target("GET", "https://evil.example/steal")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (status, body) = vend(
        &ctx,
        &jwt,
        "gh",
        Some(target("GET", "https://api.github.com/repos/x")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["data"]["allowed_url_pattern"],
        "https://api.github.com/*"
    );
}

#[tokio::test]
async fn vend_of_a_pattern_bound_credential_requires_a_target() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws", &[])
        .build()
        .await;
    credential_with_pattern(&ctx, "gh", Some("https://api.github.com/*")).await;
    let jwt = ctx_agent_jwt(&ctx, "ws").await;

    let (status, body) = vend(&ctx, &jwt, "gh", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "no target: {body}");

    let (status, body) = vend(&ctx, &jwt, "gh", Some(json!({}))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "empty body: {body}");
}

#[tokio::test]
async fn vend_without_a_pattern_needs_no_target() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws", &[])
        .build()
        .await;
    credential_with_pattern(&ctx, "open", None).await;
    let jwt = ctx_agent_jwt(&ctx, "ws").await;

    let (status, body) = vend(&ctx, &jwt, "open", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["data"]["allowed_url_pattern"].is_null());
}

/// The pattern is matched structurally: scheme, host, and port as parsed
/// values, host globs at label boundaries, glob on the path only. A
/// textual glob let `https://*.github.com/*` match a URL whose query
/// string merely contained `.github.com/`.
#[tokio::test]
async fn vend_pattern_matching_is_structural() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws", &[])
        .build()
        .await;
    credential_with_pattern(&ctx, "gh", Some("https://*.github.com/*")).await;
    let jwt = ctx_agent_jwt(&ctx, "ws").await;

    let bad = [
        "https://attacker.example/?u=.github.com/",
        "https://api.github.com.attacker.example/repos",
        "http://api.github.com/repos",
        "https://api.github.com:8443/repos",
        "https://github.com/repos",
    ];
    for url in bad {
        let (status, body) = vend(&ctx, &jwt, "gh", Some(target("GET", url))).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{url} must be refused: {body}"
        );
    }
    let (status, body) = vend(
        &ctx,
        &jwt,
        "gh",
        Some(target("GET", "https://api.github.com/repos?per_page=1")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Read the audit list as an admin user.
async fn audit_events(ctx: &TestContext, cookie: &str, event_type: &str) -> Vec<Value> {
    let (status, body) = send_json(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/audit?event_type={event_type}&limit=100"),
        None,
        Some(cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "audit list: {body}");
    body["data"].as_array().expect("audit array").clone()
}

async fn audit_admin_cookie(ctx: &TestContext) -> String {
    create_test_user(
        &*ctx.store,
        "audit-admin",
        TEST_PASSWORD,
        agent_cordon_core::domain::user::UserRole::Admin,
    )
    .await;
    login_user_combined(&ctx.app, "audit-admin", TEST_PASSWORD).await
}

/// A vend refused by `allowed_url_pattern` is audited. The Cedar path
/// self-audits its own denials; this check returned before ever reaching
/// it, so a URL-pattern refusal left no trace at all.
#[tokio::test]
async fn vend_denied_by_pattern_writes_an_audit_event() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws", &[])
        .build()
        .await;
    let cred_id = credential_with_pattern(&ctx, "gh", Some("https://api.github.com/*")).await;
    let jwt = ctx_agent_jwt(&ctx, "ws").await;
    let ws_id = ctx.agents.get("ws").expect("agent").id.0.to_string();
    let cookie = audit_admin_cookie(&ctx).await;

    let (status, body) = vend(
        &ctx,
        &jwt,
        "gh",
        Some(target("GET", "https://evil.example/steal")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let events = audit_events(&ctx, &cookie, "credential_vend_denied").await;
    let denial = events
        .iter()
        .find(|e| e["resource_id"] == cred_id.0.to_string())
        .unwrap_or_else(|| panic!("a credential_vend_denied row for the credential: {events:?}"));

    assert_eq!(denial["decision"], "forbid", "{denial}");
    assert_eq!(denial["workspace_id"], ws_id, "{denial}");
    assert_eq!(denial["resource_type"], "credential", "{denial}");
    assert_eq!(
        denial["metadata"]["target_url"], "https://evil.example/steal",
        "the denial names the target it refused: {denial}"
    );
    assert_eq!(
        denial["metadata"]["allowed_url_pattern"], "https://api.github.com/*",
        "the denial names the pattern it checked against: {denial}"
    );
    assert_eq!(denial["metadata"]["credential_name"], "gh", "{denial}");

    assert!(
        audit_events(&ctx, &cookie, "credential_vended")
            .await
            .is_empty(),
        "a refused vend must not write a CredentialVended row"
    );
}

/// A pattern-bound credential vended with no target at all is refused and
/// audited too, naming the pattern but no target.
#[tokio::test]
async fn vend_without_a_target_writes_an_audit_event() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws", &[])
        .build()
        .await;
    let cred_id = credential_with_pattern(&ctx, "gh", Some("https://api.github.com/*")).await;
    let jwt = ctx_agent_jwt(&ctx, "ws").await;
    let cookie = audit_admin_cookie(&ctx).await;

    let (status, body) = vend(&ctx, &jwt, "gh", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let events = audit_events(&ctx, &cookie, "credential_vend_denied").await;
    let denial = events
        .iter()
        .find(|e| e["resource_id"] == cred_id.0.to_string())
        .unwrap_or_else(|| panic!("a credential_vend_denied row: {events:?}"));
    assert!(
        denial["metadata"]["target_url"].is_null(),
        "no target was named: {denial}"
    );
    assert_eq!(
        denial["metadata"]["allowed_url_pattern"], "https://api.github.com/*",
        "{denial}"
    );
}

/// A URL-pattern refusal names itself.
///
/// It used to come back as `{"code":"forbidden","message":"target is outside
/// ..."}`, which the broker flattened to "Access denied by server policy" —
/// sending the user to Cedar and `/policies` when the cause was the
/// credential's own `allowed_url_pattern`, a different screen and a different
/// concept. The code has to distinguish the two, and the message has to name
/// the pattern and the target so the reader can see the mismatch.
///
/// The other side of the distinction — a real Cedar denial still answering
/// `forbidden` / "access denied by policy" — is pinned in
/// `vault_ownership.rs`.
#[tokio::test]
async fn vend_denied_by_pattern_reports_a_url_pattern_code() {
    let ctx = TestAppBuilder::new()
        .with_admin()
        .with_agent("ws", &[])
        .build()
        .await;
    credential_with_pattern(&ctx, "gh", Some("https://api.github.com/*")).await;
    let jwt = ctx_agent_jwt(&ctx, "ws").await;

    let (status, body) = vend(
        &ctx,
        &jwt,
        "gh",
        Some(target("GET", "https://evil.example/steal")),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        body["error"]["code"], "url_pattern_denied",
        "a pattern miss is not a policy denial: {body}"
    );
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("https://api.github.com/*"),
        "the message must name the pattern: {message:?}"
    );
    assert!(
        message.contains("https://evil.example/steal"),
        "the message must name the target: {message:?}"
    );
}
