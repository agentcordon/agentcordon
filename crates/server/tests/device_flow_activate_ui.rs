//! Regression tests for the UI `/activate` POST handler.
//!
//! Round-2 beta testers found that the browser-side approve path at
//! `POST /activate` flipped the device_code row to `approved` but skipped
//! provisioning the workspace record + OAuth client that the API approve
//! endpoint performs. The CLI then polled `/oauth/token` forever because
//! `state.store.get_workspace_by_name(...)` returned `None`, producing
//! `invalid_grant`.
//!
//! These tests lock in that `POST /activate` + `/oauth/token` tokenize
//! end-to-end so the same regression cannot slip back in.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use agent_cordon_core::domain::audit::AuditDecision;
use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::oauth2::eff_wordlist::normalize_user_code;
use agent_cordon_core::oauth2::types::DeviceCodeStatus;
use agent_cordon_core::storage::AuditFilter;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::{
    combined_cookie, compute_consent_csrf, create_user_in_db, login_user, TEST_PASSWORD,
};

const BOOTSTRAP_CLIENT_ID: &str = "agentcordon-broker";
const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
// 64-char lowercase hex — matches `validate_new_workspace_params`.
const TEST_PK_HASH: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

/// POST `application/x-www-form-urlencoded`, no extra headers.
async fn post_form(app: &Router, uri: &str, body: &str) -> (StatusCode, Value, Option<String>) {
    post_form_with_cookie(app, uri, body, None).await
}

/// POST form with an optional Cookie header. Returns the Location header when set.
async fn post_form_with_cookie(
    app: &Router,
    uri: &str,
    body: &str,
    cookie: Option<&str>,
) -> (StatusCode, Value, Option<String>) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(c) = cookie {
        builder = builder.header(header::COOKIE, c);
    }
    let req = builder.body(Body::from(body.to_string())).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json, location)
}

/// Regression: the UI approve path at `POST /activate` must provision the
/// workspace record + OAuth client so the subsequent `/oauth/token` exchange
/// succeeds. Before this fix, the row was flipped to approved but the
/// workspace lookup by name returned `None`, producing `invalid_grant`
/// forever.
#[tokio::test]
async fn ui_activate_approve_provisions_workspace_and_tokenizes() {
    let ctx = TestAppBuilder::new().build().await;
    let state = ctx.state.clone();

    // Operator (the approving user). Default Cedar policy permits operators
    // to `manage_workspaces` + `create_workspace` resources.
    create_user_in_db(
        &*ctx.store,
        "approver",
        TEST_PASSWORD,
        UserRole::Operator,
        false,
        true,
    )
    .await;
    let (session_cookie, _csrf) = login_user(&ctx.app, "approver", TEST_PASSWORD).await;

    // 1. Issue a device_code with workspace_name_prefill + pk_hash_prefill
    //    (mirrors what `agentcordon-broker` POSTs on `agentcordon register`).
    let workspace_name = "ui-activate-regression-ws";
    let issue_body = format!(
        "client_id={BOOTSTRAP_CLIENT_ID}&scope=credentials:discover&\
         workspace_name={workspace_name}&public_key_hash={TEST_PK_HASH}"
    );
    let (s, body, _) = post_form(&ctx.app, "/api/v1/oauth/device/code", &issue_body).await;
    assert_eq!(s, StatusCode::OK, "device_code issue: {body}");
    let device_code = body["device_code"].as_str().expect("device_code").to_string();
    let user_code = body["user_code"].as_str().expect("user_code").to_string();

    // 2. Approve via the UI POST /activate path (what the browser does
    //    when the user clicks Approve on `/activate?user_code=XXX`).
    let csrf = compute_consent_csrf(&session_cookie, &state.session_hash_key);
    let activate_body = format!(
        "csrf_token={}&user_code={}&decision=approve",
        urlencoding::encode(&csrf),
        urlencoding::encode(&user_code),
    );
    let (s, _, location) =
        post_form_with_cookie(&ctx.app, "/activate", &activate_body, Some(&session_cookie)).await;
    assert_eq!(
        s,
        StatusCode::SEE_OTHER,
        "UI approve should 303 to /activate/success (Location={location:?})"
    );
    assert_eq!(
        location.as_deref(),
        Some("/activate/success"),
        "UI approve should redirect to success"
    );

    // 3. The workspace row must now exist and be bound to the pk_hash — this
    //    is the invariant the old code violated.
    let ws = ctx
        .store
        .get_workspace_by_name(workspace_name)
        .await
        .expect("workspace lookup");
    let ws = ws.expect(
        "workspace row must exist after UI approve — \
         provision_workspace_for_approved_device_code must have run",
    );
    assert_eq!(
        ws.pk_hash.as_deref(),
        Some(TEST_PK_HASH),
        "workspace pk_hash must match the device_code's pk_hash_prefill"
    );

    // 4. OAuth client bound to the same pk_hash must exist so `/oauth/token`
    //    can look it up after issuing the access_token.
    let client = ctx
        .store
        .get_oauth_client_by_public_key_hash(TEST_PK_HASH)
        .await
        .expect("client lookup");
    assert!(
        client.is_some(),
        "OAuth client bound to pk_hash must exist after UI approve"
    );

    // 5. Token exchange must succeed — the round-2 P0 symptom was
    //    `400 invalid_grant` forever at this step.
    let token_body = format!(
        "grant_type={DEVICE_GRANT_TYPE}&client_id={BOOTSTRAP_CLIENT_ID}&device_code={device_code}"
    );
    let (s, body, _) = post_form(&ctx.app, "/api/v1/oauth/token", &token_body).await;
    assert_eq!(
        s,
        StatusCode::OK,
        "token exchange after UI approve must succeed, got {body}"
    );
    assert!(
        body.get("access_token").and_then(Value::as_str).is_some(),
        "token response must include access_token, got {body}"
    );
}

/// Control test: the API approve path (`POST /api/v1/oauth/device/approve`)
/// must continue to provision the workspace. Before the refactor this path
/// had the provisioning inline; after the refactor it delegates to the
/// shared `provision_workspace_for_approved_device_code` helper. This test
/// guards against a regression in the shared helper.
#[tokio::test]
async fn api_approve_provisions_workspace_and_tokenizes() {
    let ctx = TestAppBuilder::new().build().await;

    // Operator user — default Cedar policy grants `manage_workspaces`.
    create_user_in_db(
        &*ctx.store,
        "op",
        TEST_PASSWORD,
        UserRole::Operator,
        false,
        true,
    )
    .await;
    let (session_cookie, csrf_token) = login_user(&ctx.app, "op", TEST_PASSWORD).await;
    // Browser requests present both `agtcrdn_session` and `agtcrdn_csrf` in
    // the Cookie header; the server validates that the `x-csrf-token`
    // header equals the cookie's csrf value.
    let cookie_header = combined_cookie(&session_cookie, &csrf_token);

    // Issue with workspace_name_prefill + pk_hash_prefill
    let workspace_name = "api-approve-regression-ws";
    let issue_body = format!(
        "client_id={BOOTSTRAP_CLIENT_ID}&scope=credentials:discover&\
         workspace_name={workspace_name}&public_key_hash={TEST_PK_HASH}"
    );
    let (s, body, _) = post_form(&ctx.app, "/api/v1/oauth/device/code", &issue_body).await;
    assert_eq!(s, StatusCode::OK, "device_code issue: {body}");
    let device_code = body["device_code"].as_str().unwrap().to_string();
    let user_code = body["user_code"].as_str().unwrap().to_string();

    // Approve via API — caller MUST supply public_key_hash.
    let approve_body = serde_json::json!({
        "user_code": user_code,
        "public_key_hash": TEST_PK_HASH,
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/oauth/device/approve")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, &cookie_header)
        .header("x-csrf-token", &csrf_token)
        .body(Body::from(serde_json::to_vec(&approve_body).unwrap()))
        .unwrap();
    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    assert_eq!(status, StatusCode::OK, "API approve: {body}");

    // Workspace must exist bound to the pk_hash.
    let ws = ctx
        .store
        .get_workspace_by_name(workspace_name)
        .await
        .expect("workspace lookup")
        .expect("workspace row must exist after API approve");
    assert_eq!(ws.pk_hash.as_deref(), Some(TEST_PK_HASH));

    // Token exchange succeeds.
    let token_body = format!(
        "grant_type={DEVICE_GRANT_TYPE}&client_id={BOOTSTRAP_CLIENT_ID}&device_code={device_code}"
    );
    let (s, body, _) = post_form(&ctx.app, "/api/v1/oauth/token", &token_body).await;
    assert_eq!(s, StatusCode::OK, "token exchange: {body}");
    assert!(body.get("access_token").and_then(Value::as_str).is_some());
}

// ---------------------------------------------------------------------------
// Cedar `manage_workspaces` gate on POST /activate
// ---------------------------------------------------------------------------
//
// The browser-side approve/deny handler used to have no policy check — only
// session + CSRF validation — so any authenticated user (including a
// `Viewer`, or any operator the admin has specifically denied
// `manage_workspaces` for) could approve a pending device code from the UI
// and — on first registration of a prefilled workspace_name — become the
// `owner_id` of the resulting workspace row. These tests lock in that the
// Cedar gate now rejects those principals at the same point as the API
// sibling `/api/v1/oauth/device/approve`.

/// Issue a device_code with prefilled workspace_name + pk_hash and return
/// `(device_code, user_code)`. Does not require authentication — the
/// bootstrap broker client is the principal.
async fn issue_prefilled_device_code(app: &Router, workspace_name: &str) -> (String, String) {
    let issue_body = format!(
        "client_id={BOOTSTRAP_CLIENT_ID}&scope=credentials:discover&\
         workspace_name={workspace_name}&public_key_hash={TEST_PK_HASH}"
    );
    let (s, body, _) = post_form(app, "/api/v1/oauth/device/code", &issue_body).await;
    assert_eq!(s, StatusCode::OK, "device_code issue: {body}");
    (
        body["device_code"].as_str().unwrap().to_string(),
        body["user_code"].as_str().unwrap().to_string(),
    )
}

/// Count `PolicyEvaluated` / `Forbid` audit rows for the given action.
/// Used to assert the Cedar gate emitted a deny event. The SQLite audit
/// backend serializes event_type as snake_case strings.
async fn count_policy_forbid_evals(
    ctx: &agent_cordon_server::test_helpers::TestContext,
    action: &str,
) -> usize {
    let filter = AuditFilter {
        limit: 200,
        offset: 0,
        event_type: Some("policy_evaluated".to_string()),
        action: Some(action.to_string()),
        ..Default::default()
    };
    let events = ctx
        .store
        .list_audit_events_filtered(&filter)
        .await
        .expect("list audit events");
    events
        .into_iter()
        .filter(|e| matches!(e.decision, AuditDecision::Forbid))
        .count()
}

/// A `Viewer` must NOT be able to approve a pending device_code from the UI.
/// The default Cedar policy set does not grant `manage_workspaces` to
/// viewers, so the gate added on POST /activate should reject the request
/// and leave the row in `Pending`. A `PolicyEvaluated` audit event with
/// decision=Forbid is expected.
#[tokio::test]
async fn ui_activate_approve_denied_for_viewer() {
    let ctx = TestAppBuilder::new().build().await;
    let state = ctx.state.clone();

    create_user_in_db(
        &*ctx.store,
        "viewer_user",
        TEST_PASSWORD,
        UserRole::Viewer,
        false,
        true,
    )
    .await;
    let (session_cookie, _) = login_user(&ctx.app, "viewer_user", TEST_PASSWORD).await;

    let workspace_name = "ui-activate-viewer-approve-ws";
    let (_device_code, user_code) = issue_prefilled_device_code(&ctx.app, workspace_name).await;

    let forbid_before = count_policy_forbid_evals(&ctx, "manage_workspaces").await;

    let csrf = compute_consent_csrf(&session_cookie, &state.session_hash_key);
    let activate_body = format!(
        "csrf_token={}&user_code={}&decision=approve",
        urlencoding::encode(&csrf),
        urlencoding::encode(&user_code),
    );
    let (status, _, location) =
        post_form_with_cookie(&ctx.app, "/activate", &activate_body, Some(&session_cookie)).await;

    // The handler re-renders the activate page with an error message rather
    // than redirecting. Either way, the critical invariant is: NOT a 303 to
    // /activate/success.
    assert_ne!(
        location.as_deref(),
        Some("/activate/success"),
        "viewer must not be redirected to /activate/success (status={status})"
    );
    assert_ne!(
        status,
        StatusCode::SEE_OTHER,
        "viewer approve must not 303-redirect"
    );

    // The device_code row must still be Pending — approve did NOT succeed.
    let normalized = normalize_user_code(&user_code);
    let row = ctx
        .store
        .get_device_code_by_user_code(&normalized)
        .await
        .expect("device code lookup")
        .expect("device code row must exist");
    assert_eq!(
        row.status,
        DeviceCodeStatus::Pending,
        "viewer approve must leave the row Pending, got {:?}",
        row.status
    );

    // The workspace row must NOT have been provisioned.
    let ws = ctx
        .store
        .get_workspace_by_name(workspace_name)
        .await
        .expect("workspace lookup");
    assert!(
        ws.is_none(),
        "workspace must not have been provisioned by a denied approve"
    );

    // A new `PolicyEvaluated` Forbid audit event for manage_workspaces must
    // have been emitted by the AuditingPolicyEngine.
    let forbid_after = count_policy_forbid_evals(&ctx, "manage_workspaces").await;
    assert!(
        forbid_after > forbid_before,
        "expected a new PolicyEvaluated/Forbid audit event for manage_workspaces \
         (before={forbid_before}, after={forbid_after})"
    );
}

/// A `Viewer` must NOT be able to deny a pending device_code from the UI
/// either — otherwise a viewer could cancel another operator's enrollment.
/// The row must remain `Pending` after the request.
#[tokio::test]
async fn ui_activate_deny_denied_for_viewer() {
    let ctx = TestAppBuilder::new().build().await;
    let state = ctx.state.clone();

    create_user_in_db(
        &*ctx.store,
        "viewer_deny",
        TEST_PASSWORD,
        UserRole::Viewer,
        false,
        true,
    )
    .await;
    let (session_cookie, _) = login_user(&ctx.app, "viewer_deny", TEST_PASSWORD).await;

    let workspace_name = "ui-activate-viewer-deny-ws";
    let (_device_code, user_code) = issue_prefilled_device_code(&ctx.app, workspace_name).await;

    let forbid_before = count_policy_forbid_evals(&ctx, "manage_workspaces").await;

    let csrf = compute_consent_csrf(&session_cookie, &state.session_hash_key);
    let activate_body = format!(
        "csrf_token={}&user_code={}&decision=deny",
        urlencoding::encode(&csrf),
        urlencoding::encode(&user_code),
    );
    let (status, _, location) =
        post_form_with_cookie(&ctx.app, "/activate", &activate_body, Some(&session_cookie)).await;

    // Not a 303 to /activate/denied — the policy gate fires BEFORE the deny
    // path and re-renders the form with an error.
    assert_ne!(
        location.as_deref(),
        Some("/activate/denied"),
        "viewer must not be redirected to /activate/denied (status={status})"
    );
    assert_ne!(
        status,
        StatusCode::SEE_OTHER,
        "viewer deny must not 303-redirect to /activate/denied"
    );

    // Critical: the row must STILL be Pending — a viewer must not be able to
    // flip it to Denied and cancel the operator's enrollment.
    let normalized = normalize_user_code(&user_code);
    let row = ctx
        .store
        .get_device_code_by_user_code(&normalized)
        .await
        .expect("device code lookup")
        .expect("device code row must exist");
    assert_eq!(
        row.status,
        DeviceCodeStatus::Pending,
        "viewer deny must leave the row Pending (not flipped to Denied), got {:?}",
        row.status
    );

    // Policy gate emitted a Forbid audit event.
    let forbid_after = count_policy_forbid_evals(&ctx, "manage_workspaces").await;
    assert!(
        forbid_after > forbid_before,
        "expected a new PolicyEvaluated/Forbid audit event for manage_workspaces \
         (before={forbid_before}, after={forbid_after})"
    );
}

// ---------------------------------------------------------------------------
// F5 regression: unauth redirect preserves path + query string
// ---------------------------------------------------------------------------
//
// When a user on their laptop pastes a cross-context `verification_uri_complete`
// URL like `/activate?user_code=foo-bar-baz-qux`, the `page_auth` middleware
// redirects them to `/login?next=...`. Before this fix, the middleware only
// preserved the path and dropped the query string, so after login they'd land
// on bare `/activate` with no prefilled user_code — forcing them to copy the
// code from their terminal a second time. This test locks in that the query
// string is preserved.

/// Hit `GET /activate?user_code=...` with no session cookie. The redirect
/// `Location` header must carry the URL-encoded path AND query string.
#[tokio::test]
async fn unauth_activate_redirect_preserves_user_code_query() {
    let ctx = TestAppBuilder::new().build().await;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/activate?user_code=foo-bar-baz-qux")
        .body(Body::empty())
        .unwrap();
    let resp = ctx.app.clone().oneshot(req).await.unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "unauth /activate must 303 to /login"
    );
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("Location header on unauth /activate redirect");

    // `urlencoding::encode("/activate?user_code=foo-bar-baz-qux")` →
    // `%2Factivate%3Fuser_code%3Dfoo-bar-baz-qux`. The exact bytes matter
    // because the client-side JS reads `next` via URLSearchParams and
    // navigates there verbatim.
    assert_eq!(
        location, "/login?next=%2Factivate%3Fuser_code%3Dfoo-bar-baz-qux",
        "redirect must preserve both path and query string in `next`"
    );
}

/// Control: hitting a bare authenticated page (no query string) still produces
/// a well-formed redirect. Guards against a regression where `path_and_query`
/// somehow adds a stray `?` when no query is present.
#[tokio::test]
async fn unauth_dashboard_redirect_has_no_trailing_question_mark() {
    let ctx = TestAppBuilder::new().build().await;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/dashboard")
        .body(Body::empty())
        .unwrap();
    let resp = ctx.app.clone().oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("Location header");
    assert_eq!(location, "/login?next=%2Fdashboard");
}

// ---------------------------------------------------------------------------
// F6 regression: GET /activate displays the workspace name before approve
// ---------------------------------------------------------------------------
//
// The browser consent page must show the workspace being authorized so the
// user can visually confirm which terminal session they're approving — a
// user with two pending device codes on two different hosts otherwise
// cannot tell them apart from the UI alone.

/// Authenticated GET `/activate?user_code=X` must render the workspace
/// name from the device_code row in the response body.
#[tokio::test]
async fn ui_activate_get_renders_workspace_name() {
    let ctx = TestAppBuilder::new().build().await;

    create_user_in_db(
        &*ctx.store,
        "approver_view",
        TEST_PASSWORD,
        UserRole::Operator,
        false,
        true,
    )
    .await;
    let (session_cookie, _) = login_user(&ctx.app, "approver_view", TEST_PASSWORD).await;

    // Issue a pending device code with a distinctive workspace_name_prefill.
    let workspace_name = "beta-laptop-ws";
    let (_device_code, user_code) = issue_prefilled_device_code(&ctx.app, workspace_name).await;

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/activate?user_code={}", urlencoding::encode(&user_code)))
        .header(header::COOKIE, &session_cookie)
        .body(Body::empty())
        .unwrap();
    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "GET /activate should render");

    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(bytes.to_vec()).expect("utf-8 html");

    assert!(
        html.contains(workspace_name),
        "activate page must display the workspace name `{workspace_name}` so the \
         user can visually verify which workspace they're approving. \
         HTML did not contain that substring."
    );
    // Askama escapes by default — confirm we rendered inside <strong>, not
    // as a raw `{{ ws }}` template placeholder or as a `|safe` unescaped
    // block (which would be an XSS vector).
    assert!(
        html.contains("<strong>beta-laptop-ws</strong>"),
        "workspace name should be rendered inside <strong> via Askama's \
         default-escaping, not as a template placeholder or unescaped."
    );
}

/// Control: GET `/activate` with no `user_code` query param must NOT display
/// a workspace line at all (there's no device_code row to look up yet).
#[tokio::test]
async fn ui_activate_get_omits_workspace_name_when_no_user_code() {
    let ctx = TestAppBuilder::new().build().await;

    create_user_in_db(
        &*ctx.store,
        "bare_view",
        TEST_PASSWORD,
        UserRole::Operator,
        false,
        true,
    )
    .await;
    let (session_cookie, _) = login_user(&ctx.app, "bare_view", TEST_PASSWORD).await;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/activate")
        .header(header::COOKIE, &session_cookie)
        .body(Body::empty())
        .unwrap();
    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(bytes.to_vec()).expect("utf-8 html");

    // Bare /activate should fall through to the generic "Enter the code…"
    // copy, not render "You are authorizing <strong>…</strong>".
    assert!(
        !html.contains("You are authorizing"),
        "bare /activate (no user_code) must not render the workspace-authorization \
         line because there's no device_code row to look up"
    );
}
