//! `PUT /api/v1/credentials/{id}` validates the fields it writes.
//!
//! The update route used to copy `vault`, `transform_name`, and
//! `transform_script` straight from the body: a credential could be moved
//! into another user's vault, a transform name nobody implements was
//! accepted, and a script that does not parse only failed at first proxy
//! use. Create shared the last two gaps.
//!
//! A vault is named by id on the wire, so these tests create the vault
//! first and move the credential into that id.

use axum::http::{Method, StatusCode};
use axum::Router;
use serde_json::{json, Value};

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::domain::vault::DEFAULT_VAULT_ID;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common::{combined_cookie, create_user_in_db, login_user, send_json, TEST_PASSWORD};

async fn app_with_operator(
    app: &Router,
    store: &dyn agent_cordon_core::storage::Store,
    name: &str,
) -> (String, String) {
    create_user_in_db(store, name, TEST_PASSWORD, UserRole::Operator, false, true).await;
    let (session, csrf) = login_user(app, name, TEST_PASSWORD).await;
    (combined_cookie(&session, &csrf), csrf)
}

async fn create_credential(
    app: &Router,
    cookie: &str,
    csrf: &str,
    body: Value,
) -> (StatusCode, Value) {
    send_json(
        app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(cookie),
        Some(csrf),
        Some(body),
    )
    .await
}

async fn create_credential_ok(
    app: &Router,
    cookie: &str,
    csrf: &str,
    name: &str,
    vault_id: Option<&str>,
) -> String {
    let mut payload = json!({ "name": name, "service": "svc", "secret_value": "s3cret" });
    if let Some(v) = vault_id {
        payload["vault_id"] = json!(v);
    }
    let (status, body) = create_credential(app, cookie, csrf, payload).await;
    assert_eq!(status, StatusCode::OK, "create {name}: {body}");
    body["data"]["id"].as_str().expect("id").to_string()
}

/// A vault owned by the caller. Returns its id.
async fn create_vault(app: &Router, cookie: &str, csrf: &str, name: &str) -> String {
    let (status, body) = send_json(
        app,
        Method::POST,
        "/api/v1/vaults",
        None,
        Some(cookie),
        Some(csrf),
        Some(json!({ "name": name })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create vault {name}: {body}");
    body["data"]["id"].as_str().expect("id").to_string()
}

async fn update(
    app: &Router,
    cookie: &str,
    csrf: &str,
    id: &str,
    body: Value,
) -> (StatusCode, Value) {
    send_json(
        app,
        Method::PUT,
        &format!("/api/v1/credentials/{id}"),
        None,
        Some(cookie),
        Some(csrf),
        Some(body),
    )
    .await
}

async fn get_vault(app: &Router, cookie: &str, id: &str) -> String {
    let (status, body) = send_json(
        app,
        Method::GET,
        &format!("/api/v1/credentials/{id}"),
        None,
        Some(cookie),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "get: {body}");
    body["data"]["vault_id"]
        .as_str()
        .expect("vault_id")
        .to_string()
}

#[tokio::test]
async fn moving_a_credential_into_a_vault_you_do_not_own_is_refused() {
    let ctx = TestAppBuilder::new().build().await;
    let (alice_cookie, alice_csrf) = app_with_operator(&ctx.app, &*ctx.store, "alice").await;
    let (bob_cookie, bob_csrf) = app_with_operator(&ctx.app, &*ctx.store, "bob").await;

    let alice_vault = create_vault(&ctx.app, &alice_cookie, &alice_csrf, "alice-vault").await;
    create_credential_ok(
        &ctx.app,
        &alice_cookie,
        &alice_csrf,
        "alice-cred",
        Some(&alice_vault),
    )
    .await;
    let bob_cred = create_credential_ok(&ctx.app, &bob_cookie, &bob_csrf, "bob-cred", None).await;

    let (status, body) = update(
        &ctx.app,
        &bob_cookie,
        &bob_csrf,
        &bob_cred,
        json!({ "vault_id": alice_vault }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        get_vault(&ctx.app, &bob_cookie, &bob_cred).await,
        DEFAULT_VAULT_ID
    );
}

#[tokio::test]
async fn moving_a_credential_into_a_vault_you_own_is_allowed() {
    let ctx = TestAppBuilder::new().build().await;
    let (bob_cookie, bob_csrf) = app_with_operator(&ctx.app, &*ctx.store, "bob").await;

    let bob_vault = create_vault(&ctx.app, &bob_cookie, &bob_csrf, "bob-vault").await;
    let bob_cred = create_credential_ok(&ctx.app, &bob_cookie, &bob_csrf, "bob-cred", None).await;

    let (status, body) = update(
        &ctx.app,
        &bob_cookie,
        &bob_csrf,
        &bob_cred,
        json!({ "vault_id": bob_vault }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(get_vault(&ctx.app, &bob_cookie, &bob_cred).await, bob_vault);

    // A second vault of the caller's own is just as reachable — the id is what
    // identifies it, and the name is only a label (one this owner has not used
    // already: names are unique per owner). Moving back to the shared default
    // always works.
    let another = create_vault(&ctx.app, &bob_cookie, &bob_csrf, "bob-vault-two").await;
    let (status, body) = update(
        &ctx.app,
        &bob_cookie,
        &bob_csrf,
        &bob_cred,
        json!({ "vault_id": another }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(get_vault(&ctx.app, &bob_cookie, &bob_cred).await, another);

    let (status, body) = update(
        &ctx.app,
        &bob_cookie,
        &bob_csrf,
        &bob_cred,
        json!({ "vault_id": DEFAULT_VAULT_ID }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        get_vault(&ctx.app, &bob_cookie, &bob_cred).await,
        DEFAULT_VAULT_ID
    );
}

/// A vault id nobody has is a 404, not a silent new vault: naming a vault
/// no longer creates one.
#[tokio::test]
async fn moving_a_credential_into_a_vault_that_does_not_exist_is_not_found() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = app_with_operator(&ctx.app, &*ctx.store, "bob").await;
    let cred = create_credential_ok(&ctx.app, &cookie, &csrf, "cred", None).await;

    let (status, body) = update(
        &ctx.app,
        &cookie,
        &csrf,
        &cred,
        json!({ "vault_id": uuid::Uuid::new_v4().to_string() }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn unknown_transform_name_is_refused() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = app_with_operator(&ctx.app, &*ctx.store, "op").await;
    let cred = create_credential_ok(&ctx.app, &cookie, &csrf, "cred", None).await;

    let (status, body) = update(
        &ctx.app,
        &cookie,
        &csrf,
        &cred,
        json!({ "transform_name": "rot13" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let (status, body) = update(
        &ctx.app,
        &cookie,
        &csrf,
        &cred,
        json!({ "transform_name": "bearer" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["transform_name"], "bearer");

    let (status, body) = create_credential(
        &ctx.app,
        &cookie,
        &csrf,
        json!({ "name": "c2", "service": "svc", "secret_value": "s", "transform_name": "rot13" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn transform_script_that_does_not_parse_is_refused() {
    let ctx = TestAppBuilder::new().build().await;
    let (cookie, csrf) = app_with_operator(&ctx.app, &*ctx.store, "op").await;
    let cred = create_credential_ok(&ctx.app, &cookie, &csrf, "cred", None).await;

    let broken = "let x = ;";
    let (status, body) = update(
        &ctx.app,
        &cookie,
        &csrf,
        &cred,
        json!({ "transform_script": broken }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let (status, body) = create_credential(
        &ctx.app,
        &cookie,
        &csrf,
        json!({ "name": "c2", "service": "svc", "secret_value": "s", "transform_script": broken }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let fine = "\"Bearer \" + secret";
    let (status, body) = update(
        &ctx.app,
        &cookie,
        &csrf,
        &cred,
        json!({ "transform_script": fine }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}
