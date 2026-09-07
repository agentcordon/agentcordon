//! Guards for the admin-UI review findings B1, B2, M1, M2 and M9.
//!
//! Every one of these is a server-side refusal that the review found missing:
//! the UI could drive the install into a state it then described wrongly. The
//! tests are at the HTTP boundary — `TestAppBuilder` over in-memory SQLite,
//! driven with `tower::ServiceExt::oneshot` — because the refusal has to hold
//! for `curl` as well as for the page.
//!
//! - B1: the last enabled Cedar policy cannot be deleted or disabled, and the
//!   seeded `default` policy cannot be deleted at all. The policies page must
//!   not claim a built-in default is in force when nothing is enabled.
//! - B2: the login page's SSO button must name the route that actually starts
//!   the OIDC flow.
//! - M1: credential and vault names are unique per owner.
//! - M2: `allowed_url_pattern` is validated on create and update, not only on
//!   vend.
//! - M9: a Cedar validation failure carries the validator's messages.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

use crate::common;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn admin_session() -> (TestContext, String) {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    common::create_test_user(
        &*ctx.store,
        "guard-admin",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, "guard-admin", common::TEST_PASSWORD).await;
    (ctx, cookie)
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

/// The id of the policy the test app seeds, which is the shipped `default`.
async fn seeded_default_policy_id(ctx: &TestContext) -> String {
    let policies = ctx.store.list_policies().await.expect("list policies");
    policies
        .into_iter()
        .find(|p| p.name == "default")
        .expect("the test app seeds a policy named 'default'")
        .id
        .0
        .to_string()
}

/// Create an enabled Cedar policy through the admin API; returns its id.
async fn create_policy(app: &axum::Router, cookie: &str, name: &str) -> String {
    let (status, body) = common::send_json_auto_csrf(
        app,
        Method::POST,
        "/api/v1/policies",
        None,
        Some(cookie),
        Some(json!({
            "name": name,
            "cedar_policy": "permit(principal, action, resource);",
            "enabled": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create policy {name}: {body}");
    body["data"]["id"].as_str().expect("policy id").to_string()
}

fn error_message(body: &Value) -> String {
    body["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

// ===========================================================================
// B1 — the last enabled policy
// ===========================================================================

/// The seeded `default` policy is the whole authorization model on a fresh
/// install. Deleting it is never a recoverable mistake: the seed only re-runs
/// at boot, so the console would be left denying every non-root caller.
#[tokio::test]
async fn deleting_the_seeded_default_policy_is_refused() {
    let (ctx, cookie) = admin_session().await;
    let default_id = seeded_default_policy_id(&ctx).await;

    // Another enabled policy exists, so this is not the "last enabled" case:
    // the built-in default is refused on its own account.
    create_policy(&ctx.app, &cookie, "an-extra-policy").await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/policies/{default_id}"),
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    let msg = error_message(&body);
    assert!(
        msg.contains("default"),
        "the refusal must name the built-in default policy: {msg}"
    );

    // And it is still there.
    let policies = ctx.store.list_policies().await.expect("list policies");
    assert!(
        policies.iter().any(|p| p.name == "default"),
        "the default policy must survive a refused delete"
    );
}

/// A custom policy that happens to be the only enabled one cannot be deleted
/// either: the install would answer 403 to every operator, viewer and
/// workspace, and only root would still work.
#[tokio::test]
async fn deleting_the_last_enabled_policy_is_refused() {
    let (ctx, cookie) = admin_session().await;
    let default_id = seeded_default_policy_id(&ctx).await;
    let custom_id = create_policy(&ctx.app, &cookie, "the-only-one").await;

    // Disable the seeded default — allowed, because `the-only-one` is enabled.
    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/policies/{default_id}"),
        None,
        Some(&cookie),
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "disabling default while another policy is enabled must be allowed: {body}"
    );

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/policies/{custom_id}"),
        None,
        Some(&cookie),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    let msg = error_message(&body);
    for word in ["operator", "viewer", "workspace"] {
        assert!(
            msg.contains(word),
            "the refusal must say who would be refused (missing {word:?}): {msg}"
        );
    }
}

/// The per-grant rows the permissions UI writes are not policies in this
/// sense: each permits one workspace one action on one credential, and none of
/// them lets a person reach a page. An install carrying a hundred of them and
/// no authored policy is as locked out as an empty one, so they must not count
/// towards "another policy is enabled".
#[tokio::test]
async fn grant_policies_do_not_count_as_the_other_enabled_policy() {
    let (ctx, cookie) = admin_session().await;
    let default_id = seeded_default_policy_id(&ctx).await;

    // The shape the permissions UI writes: `grant:<cred>:<workspace>:<action>`.
    ctx.state
        .services
        .policies
        .ensure_grant(
            format!(
                "grant:{}:{}:read",
                uuid::Uuid::new_v4(),
                uuid::Uuid::new_v4()
            ),
            "permit(principal, action, resource);".to_string(),
            "a generated grant".to_string(),
        )
        .await
        .expect("store grant policy");

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/policies/{default_id}"),
        None,
        Some(&cookie),
        Some(json!({ "enabled": false })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a generated grant is not the other enabled policy: {body}"
    );
}

/// Disabling is the same lockout by another route, so it is refused the same
/// way.
#[tokio::test]
async fn disabling_the_last_enabled_policy_is_refused() {
    let (ctx, cookie) = admin_session().await;
    let default_id = seeded_default_policy_id(&ctx).await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/policies/{default_id}"),
        None,
        Some(&cookie),
        Some(json!({ "enabled": false })),
    )
    .await;

    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    let msg = error_message(&body);
    for word in ["operator", "viewer", "workspace"] {
        assert!(
            msg.contains(word),
            "the refusal must say who would be refused (missing {word:?}): {msg}"
        );
    }

    let policies = ctx.store.list_policies().await.expect("list policies");
    let default = policies.iter().find(|p| p.name == "default").unwrap();
    assert!(default.enabled, "the policy must still be enabled");
}

/// The default policy is still editable — only its removal is refused.
#[tokio::test]
async fn the_default_policy_can_still_be_edited() {
    let (ctx, cookie) = admin_session().await;
    let default_id = seeded_default_policy_id(&ctx).await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/policies/{default_id}"),
        None,
        Some(&cookie),
        Some(json!({ "description": "edited by the test" })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["data"]["description"], "edited by the test");
}

/// The empty state told the reader a built-in default was in force. Nothing of
/// the sort exists: with no enabled policy the engine loads an empty set and
/// only the root bypass survives.
#[tokio::test]
async fn the_policies_page_does_not_claim_a_built_in_default_applies() {
    let (ctx, cookie) = admin_session().await;
    let (status, body) = get_page(&ctx.app, "/security", &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert!(
        !body.contains("Using the built-in default policy"),
        "the empty state must not claim a built-in default is in force"
    );
    assert!(
        body.contains("Nothing is permitted except the root user"),
        "the empty state must say what no enabled policy means"
    );
    assert!(
        body.contains("/security/new"),
        "the empty state must link to New Policy"
    );
}

// ===========================================================================
// B2 — the login page's SSO button
// ===========================================================================

/// The button pointed at `/api/v1/oidc/auth/<id>`, which is not a route. The
/// real one is `/api/v1/auth/oidc/authorize?provider=<id>`.
#[tokio::test]
async fn the_login_page_sso_button_names_the_oidc_authorize_route() {
    let ctx = TestAppBuilder::new().build().await;
    let (status, body) = get_page(&ctx.app, "/login", "").await;
    assert_eq!(status, StatusCode::OK);

    assert!(
        !body.contains("/api/v1/oidc/auth/"),
        "the login page must not link to the 404 route /api/v1/oidc/auth/<id>"
    );
    assert!(
        body.contains("/api/v1/auth/oidc/authorize?provider="),
        "the login page must start SSO at /api/v1/auth/oidc/authorize"
    );
}

// ===========================================================================
// M9 — Cedar validation detail
// ===========================================================================

/// "Policy validation failed" on its own tells the author nothing. The
/// validator's own messages travel in the error body.
#[tokio::test]
async fn a_cedar_validation_failure_carries_the_validator_messages() {
    let (ctx, cookie) = admin_session().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies",
        None,
        Some(&cookie),
        Some(json!({
            "name": "broken",
            "cedar_policy": "permit(principal, action, resource)",
        })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let errors = body["error"]["details"]["errors"]
        .as_array()
        .unwrap_or_else(|| panic!("no validator errors in the body: {body}"));
    assert!(
        !errors.is_empty(),
        "no validator errors in the body: {body}"
    );
    assert!(
        errors
            .iter()
            .any(|e| !e["message"].as_str().unwrap_or_default().is_empty()),
        "every validator error was blank: {body}"
    );
}

/// The same detail reaches an update, not only a create.
#[tokio::test]
async fn a_cedar_validation_failure_on_update_carries_the_validator_messages() {
    let (ctx, cookie) = admin_session().await;
    let id = create_policy(&ctx.app, &cookie, "editable").await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/policies/{id}"),
        None,
        Some(&cookie),
        Some(json!({ "cedar_policy": "permit(principal, action, resource)" })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let errors = body["error"]["details"]["errors"]
        .as_array()
        .unwrap_or_else(|| panic!("no validator errors in the body: {body}"));
    assert!(
        !errors.is_empty(),
        "no validator errors in the body: {body}"
    );
}

// ===========================================================================
// M1 — duplicate names
// ===========================================================================

async fn create_credential(
    app: &axum::Router,
    cookie: &str,
    name: &str,
) -> (StatusCode, serde_json::Value) {
    common::send_json_auto_csrf(
        app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(cookie),
        Some(json!({
            "name": name,
            "service": "example",
            "secret_value": "s3cret",
        })),
    )
    .await
}

#[tokio::test]
async fn a_second_credential_with_the_same_name_is_refused_for_the_same_owner() {
    let (ctx, cookie) = admin_session().await;

    let (status, body) = create_credential(&ctx.app, &cookie, "review-generic").await;
    assert_eq!(status, StatusCode::OK, "first create: {body}");

    let (status, body) = create_credential(&ctx.app, &cookie, "review-generic").await;
    assert_eq!(status, StatusCode::CONFLICT, "second create: {body}");
    let msg = error_message(&body);
    assert!(
        msg.contains("review-generic"),
        "the refusal must name the existing credential: {msg}"
    );
}

#[tokio::test]
async fn renaming_a_credential_onto_another_of_the_same_owner_is_refused() {
    let (ctx, cookie) = admin_session().await;

    let (status, body) = create_credential(&ctx.app, &cookie, "cred-a").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body_b) = create_credential(&ctx.app, &cookie, "cred-b").await;
    assert_eq!(status, StatusCode::OK, "{body_b}");
    let id_b = body_b["data"]["id"].as_str().unwrap().to_string();

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/credentials/{id_b}"),
        None,
        Some(&cookie),
        Some(json!({ "name": "cred-a" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "rename: {body}");
    assert!(error_message(&body).contains("cred-a"));
}

/// Two owners keep their own namespaces: the 409 must not leak the existence
/// of someone else's credential (migration 011).
#[tokio::test]
async fn two_owners_may_each_hold_a_credential_of_the_same_name() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    common::create_test_user(&*ctx.store, "alice", common::TEST_PASSWORD, UserRole::Admin).await;
    common::create_test_user(&*ctx.store, "bob", common::TEST_PASSWORD, UserRole::Admin).await;
    let alice = common::login_user_combined(&ctx.app, "alice", common::TEST_PASSWORD).await;
    let bob = common::login_user_combined(&ctx.app, "bob", common::TEST_PASSWORD).await;

    let (status, body) = create_credential(&ctx.app, &alice, "shared-api-key").await;
    assert_eq!(status, StatusCode::OK, "alice: {body}");
    let (status, body) = create_credential(&ctx.app, &bob, "shared-api-key").await;
    assert_eq!(status, StatusCode::OK, "bob: {body}");
}

#[tokio::test]
async fn a_second_vault_with_the_same_name_is_refused_for_the_same_owner() {
    let (ctx, cookie) = admin_session().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/vaults",
        None,
        Some(&cookie),
        Some(json!({ "name": "operator-vault" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "first vault: {body}");

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/vaults",
        None,
        Some(&cookie),
        Some(json!({ "name": "operator-vault" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "second vault: {body}");
    assert!(
        error_message(&body).contains("operator-vault"),
        "the refusal must name the existing vault: {body}"
    );
}

#[tokio::test]
async fn renaming_a_vault_onto_another_of_the_same_owner_is_refused() {
    let (ctx, cookie) = admin_session().await;

    for name in ["vault-a", "vault-b"] {
        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/vaults",
            None,
            Some(&cookie),
            Some(json!({ "name": name })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "create {name}: {body}");
        if name == "vault-b" {
            let id = body["data"]["id"].as_str().unwrap().to_string();
            let (status, body) = common::send_json_auto_csrf(
                &ctx.app,
                Method::PATCH,
                &format!("/api/v1/vaults/{id}"),
                None,
                Some(&cookie),
                Some(json!({ "name": "vault-a" })),
            )
            .await;
            assert_eq!(status, StatusCode::CONFLICT, "rename: {body}");
            assert!(error_message(&body).contains("vault-a"));
        }
    }
}

/// Two owners keep their own vault namespaces too.
#[tokio::test]
async fn two_owners_may_each_hold_a_vault_of_the_same_name() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    common::create_test_user(&*ctx.store, "alice", common::TEST_PASSWORD, UserRole::Admin).await;
    common::create_test_user(&*ctx.store, "bob", common::TEST_PASSWORD, UserRole::Admin).await;
    let alice = common::login_user_combined(&ctx.app, "alice", common::TEST_PASSWORD).await;
    let bob = common::login_user_combined(&ctx.app, "bob", common::TEST_PASSWORD).await;

    for cookie in [&alice, &bob] {
        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/vaults",
            None,
            Some(cookie),
            Some(json!({ "name": "shared-label" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
}

// ===========================================================================
// M2 — allowed_url_pattern
// ===========================================================================

#[tokio::test]
async fn a_credential_cannot_be_created_with_an_unparseable_url_pattern() {
    let (ctx, cookie) = admin_session().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(json!({
            "name": "review-bad-pattern",
            "service": "example",
            "secret_value": "s3cret",
            "allowed_url_pattern": "not a url",
        })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let msg = error_message(&body);
    assert!(
        msg.contains("allowed_url_pattern"),
        "the refusal must name the field: {msg}"
    );
}

#[tokio::test]
async fn a_url_pattern_must_carry_a_host_and_an_http_scheme() {
    let (ctx, cookie) = admin_session().await;

    for pattern in ["ftp://example.com/*", "https:///*", "api.github.com/*"] {
        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/credentials",
            None,
            Some(&cookie),
            Some(json!({
                "name": format!("bad-{}", pattern.len()),
                "service": "example",
                "secret_value": "s3cret",
                "allowed_url_pattern": pattern,
            })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "pattern {pattern:?} should be refused: {body}"
        );
    }
}

/// A `*` in the host stands for exactly one DNS label, so a partial-label
/// wildcard would never match anything the matcher accepts.
#[tokio::test]
async fn a_partial_host_wildcard_is_refused() {
    let (ctx, cookie) = admin_session().await;

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(json!({
            "name": "partial-wildcard",
            "service": "example",
            "secret_value": "s3cret",
            "allowed_url_pattern": "https://api-*.github.com/*",
        })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
}

#[tokio::test]
async fn the_documented_url_patterns_are_accepted() {
    let (ctx, cookie) = admin_session().await;

    for (i, pattern) in [
        "https://api.github.com/*",
        "https://*.amazonaws.com/*",
        "https://**.amazonaws.com/*",
    ]
    .iter()
    .enumerate()
    {
        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/credentials",
            None,
            Some(&cookie),
            Some(json!({
                "name": format!("good-pattern-{i}"),
                "service": "example",
                "secret_value": "s3cret",
                "allowed_url_pattern": pattern,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "pattern {pattern:?}: {body}");
    }
}

#[tokio::test]
async fn a_credential_cannot_be_updated_to_an_unparseable_url_pattern() {
    let (ctx, cookie) = admin_session().await;
    let (status, body) = create_credential(&ctx.app, &cookie, "updatable").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id = body["data"]["id"].as_str().unwrap().to_string();

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/credentials/{id}"),
        None,
        Some(&cookie),
        Some(json!({ "allowed_url_pattern": "not a url" })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert!(error_message(&body).contains("allowed_url_pattern"));
}

/// The empty string is how the form clears the restriction; it must stay a
/// legal update.
#[tokio::test]
async fn an_empty_url_pattern_still_clears_the_restriction() {
    let (ctx, cookie) = admin_session().await;
    let (status, body) = create_credential(&ctx.app, &cookie, "clearable").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id = body["data"]["id"].as_str().unwrap().to_string();

    let (status, body) = common::send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/credentials/{id}"),
        None,
        Some(&cookie),
        Some(json!({ "allowed_url_pattern": "" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
}
