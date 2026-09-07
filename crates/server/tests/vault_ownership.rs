//! A vault is a row with an owner, and the owner decides.
//!
//! Two things follow from that, and both are here. *Placement*: a credential
//! goes in the caller's own vault or in the shared default, never in someone
//! else's, because joining a vault is how you would otherwise reach — or pass
//! on — another user's secrets. *Sharing*: granting is the owner's act at any
//! role, while `manage_vaults`, which the default policy grants to admins, is
//! an audit power on top — it reads any share list and revokes any share, and
//! it never grants one.
//!
//! Every route names a vault by id. A display name identifies nothing: two
//! users may each own a vault called `team`, and so may one user.

use axum::http::{Method, StatusCode};
use serde_json::{json, Value};

use agent_cordon_core::domain::user::{User, UserRole};
use agent_cordon_core::domain::vault::DEFAULT_VAULT_ID;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

use crate::common::{
    create_root_user, create_test_user, login_user_combined, send_json_auto_csrf, TEST_PASSWORD,
};

/// Create a credential, optionally naming a vault by id. Returns the raw
/// response.
async fn create_credential(
    ctx: &TestContext,
    cookie: &str,
    name: &str,
    vault_id: Option<&str>,
) -> (StatusCode, Value) {
    let mut body = json!({ "name": name, "service": "svc", "secret_value": "s3cret" });
    if let Some(v) = vault_id {
        body["vault_id"] = json!(v);
    }
    send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(cookie),
        Some(body),
    )
    .await
}

/// Create a vault owned by whoever the cookie belongs to. Returns its id.
async fn create_vault(ctx: &TestContext, cookie: &str, name: &str) -> String {
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/vaults",
        None,
        Some(cookie),
        Some(json!({ "name": name })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create vault {name}: {body}");
    body["data"]["id"].as_str().expect("vault id").to_string()
}

struct Cast {
    bob: User,
    carol: User,
    alice_cookie: String,
    bob_cookie: String,
    root_cookie: String,
}

/// Three admins and root. Admins hold `manage_vaults`; only ownership of the
/// vault separates them.
async fn cast(ctx: &TestContext) -> Cast {
    create_test_user(&*ctx.store, "vault-alice", TEST_PASSWORD, UserRole::Admin).await;
    let bob = create_test_user(&*ctx.store, "vault-bob", TEST_PASSWORD, UserRole::Admin).await;
    let carol = create_test_user(&*ctx.store, "vault-carol", TEST_PASSWORD, UserRole::Admin).await;
    create_root_user(&*ctx.store, "vault-root", TEST_PASSWORD).await;
    Cast {
        bob,
        carol,
        alice_cookie: login_user_combined(&ctx.app, "vault-alice", TEST_PASSWORD).await,
        bob_cookie: login_user_combined(&ctx.app, "vault-bob", TEST_PASSWORD).await,
        root_cookie: login_user_combined(&ctx.app, "vault-root", TEST_PASSWORD).await,
    }
}

/// Placement rules, in one pass: naming no vault lands in the shared
/// default; the default takes anyone's credential; your own vault takes
/// more; a vault someone else owns is refused; root places anywhere; and a
/// vault id nobody has is a 404 rather than a vault quietly created.
#[tokio::test]
async fn credential_placement_follows_vault_ownership() {
    let ctx = TestAppBuilder::new().build().await;
    let c = cast(&ctx).await;

    // Omitting the vault lands in the system default.
    let (status, body) = create_credential(&ctx, &c.alice_cookie, "a-implicit", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["vault_id"], DEFAULT_VAULT_ID, "{body}");
    assert_eq!(body["data"]["vault_name"], "default", "{body}");

    // The default is shared: naming it explicitly works for anyone.
    let (status, body) =
        create_credential(&ctx, &c.bob_cookie, "b-default", Some(DEFAULT_VAULT_ID)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "bob may use the default vault: {body}"
    );

    let alice_vault = create_vault(&ctx, &c.alice_cookie, "alice-vault").await;

    // Alice owns it, so she may put credentials in it.
    let (status, body) =
        create_credential(&ctx, &c.alice_cookie, "a-first", Some(&alice_vault)).await;
    assert_eq!(status, StatusCode::OK, "Alice's own vault: {body}");
    assert_eq!(body["data"]["vault_id"], alice_vault, "{body}");
    assert_eq!(body["data"]["vault_name"], "alice-vault", "{body}");

    // Bob does not. Joining would put his credential where Alice decides who
    // sees it — and would once have let him share hers onward.
    let (status, body) =
        create_credential(&ctx, &c.bob_cookie, "b-intruder", Some(&alice_vault)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "Bob must not join Alice's vault: {body}"
    );

    // Root places anywhere.
    let (status, body) =
        create_credential(&ctx, &c.root_cookie, "root-anywhere", Some(&alice_vault)).await;
    assert_eq!(status, StatusCode::OK, "root may place anywhere: {body}");

    // A vault id nobody has does not create one.
    let (status, body) = create_credential(
        &ctx,
        &c.alice_cookie,
        "a-nowhere",
        Some(&uuid::Uuid::new_v4().to_string()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "naming a vault does not create it: {body}"
    );
}

/// The same gate on update: a credential cannot be *moved* into a vault its
/// owner does not own. Without this, the create-time check is a formality —
/// put it in the default, then move it.
#[tokio::test]
async fn a_credential_cannot_be_moved_into_someone_elses_vault() {
    let ctx = TestAppBuilder::new().build().await;
    let c = cast(&ctx).await;
    let alice_vault = create_vault(&ctx, &c.alice_cookie, "alice-vault").await;

    let (status, body) = create_credential(&ctx, &c.bob_cookie, "b-own", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let bob_cred = body["data"]["id"].as_str().unwrap().to_string();

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::PUT,
        &format!("/api/v1/credentials/{bob_cred}"),
        None,
        Some(&c.bob_cookie),
        Some(json!({ "vault_id": alice_vault })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "Bob must not move his credential into Alice's vault: {body}"
    );
}

async fn share_list_response(ctx: &TestContext, cookie: &str, vault: &str) -> (StatusCode, Value) {
    send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/vaults/{vault}/shares"),
        None,
        Some(cookie),
        None,
    )
    .await
}

async fn shares(ctx: &TestContext, cookie: &str, vault: &str) -> Vec<Value> {
    let (status, body) = share_list_response(ctx, cookie, vault).await;
    assert_eq!(status, StatusCode::OK, "list shares: {body}");
    body["data"].as_array().expect("share array").clone()
}

/// Granting is the owner's alone; revoking is the owner's *and* an admin's.
///
/// `manage_vaults` exists so someone can cut off a share they did not make.
/// It deliberately does not run the other way: an admin who could grant one
/// could hand any user's credentials to anybody.
#[tokio::test]
async fn manage_vaults_revokes_a_share_but_never_grants_one() {
    let ctx = TestAppBuilder::new().build().await;
    let c = cast(&ctx).await;
    let carol_id = c.carol.id.0.to_string();
    let alice_vault = create_vault(&ctx, &c.alice_cookie, "alice-vault").await;

    // Bob is an admin — he clears `manage_vaults` — but owns nothing here,
    // so he cannot hand Alice's vault to himself or to anyone else.
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/vaults/{alice_vault}/shares"),
        None,
        Some(&c.bob_cookie),
        Some(json!({ "user_id": c.bob.id.0.to_string(), "permission": "read" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "manage_vaults must not grant a share on someone else's vault: {body}"
    );

    // The owner grants one.
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/vaults/{alice_vault}/shares"),
        None,
        Some(&c.alice_cookie),
        Some(json!({ "user_id": carol_id, "permission": "read" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Alice shares her own vault: {body}");
    assert_eq!(body["data"]["vault_id"], alice_vault, "{body}");
    assert_eq!(body["data"]["permission_level"], "read", "{body}");

    // And an admin revokes it, which is what the grant is for.
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/vaults/{alice_vault}/shares/{carol_id}"),
        None,
        Some(&c.bob_cookie),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "manage_vaults revokes a share it did not make: {body}"
    );
    assert!(shares(&ctx, &c.alice_cookie, &alice_vault).await.is_empty());
}

/// Sharing needs no role, only ownership: an operator who owns a vault
/// shares it, and a user who owns nothing in it is refused whatever role
/// they hold.
#[tokio::test]
async fn sharing_is_the_owners_act_at_any_role() {
    let ctx = TestAppBuilder::new().build().await;
    let operator = create_test_user(
        &*ctx.store,
        "vault-operator",
        TEST_PASSWORD,
        UserRole::Operator,
    )
    .await;
    let viewer =
        create_test_user(&*ctx.store, "vault-viewer", TEST_PASSWORD, UserRole::Viewer).await;
    let operator_cookie = login_user_combined(&ctx.app, "vault-operator", TEST_PASSWORD).await;
    let viewer_cookie = login_user_combined(&ctx.app, "vault-viewer", TEST_PASSWORD).await;

    let vault = create_vault(&ctx, &operator_cookie, "operator-vault").await;

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/vaults/{vault}/shares"),
        None,
        Some(&operator_cookie),
        Some(json!({ "user_id": viewer.id.0.to_string() })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an operator shares the vault they own: {body}"
    );
    assert_eq!(
        body["data"]["permission_level"], "read",
        "read is the default: {body}"
    );

    // The recipient is not thereby a sharer.
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/vaults/{vault}/shares"),
        None,
        Some(&viewer_cookie),
        Some(json!({ "user_id": operator.id.0.to_string() })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a share does not carry the right to re-share: {body}"
    );
}

/// Only `read` exists. `write` and `admin` were accepted and stored, and
/// nothing anywhere consulted them: a promise the system did not keep.
#[tokio::test]
async fn write_and_admin_shares_are_refused() {
    let ctx = TestAppBuilder::new().build().await;
    let c = cast(&ctx).await;
    let vault = create_vault(&ctx, &c.alice_cookie, "alice-vault").await;

    for level in ["write", "admin", "superadmin"] {
        let (status, body) = send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            &format!("/api/v1/vaults/{vault}/shares"),
            None,
            Some(&c.alice_cookie),
            Some(json!({ "user_id": c.carol.id.0.to_string(), "permission": level })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "permission '{level}' must be refused: {body}"
        );
    }
}

/// The share list names the users who hold another user's credentials, so
/// reading it is gated per-vault the way sharing is. A signed-in user who
/// owns nothing in the vault — a viewer here, so the read is the only thing
/// under test — is refused. The vault's owner reads it, and so does an
/// admin, who holds `manage_vaults` over every vault, and root.
#[tokio::test]
async fn the_share_list_is_refused_to_a_stranger() {
    let ctx = TestAppBuilder::new().build().await;
    let c = cast(&ctx).await;
    create_test_user(&*ctx.store, "vault-viewer", TEST_PASSWORD, UserRole::Viewer).await;
    let viewer_cookie = login_user_combined(&ctx.app, "vault-viewer", TEST_PASSWORD).await;

    let alice_vault = create_vault(&ctx, &c.alice_cookie, "alice-vault").await;
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/vaults/{alice_vault}/shares"),
        None,
        Some(&c.alice_cookie),
        Some(json!({ "user_id": c.carol.id.0.to_string(), "permission": "read" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Alice shares her own vault: {body}");

    // A signed-in stranger must not learn who holds Alice's credentials.
    let (status, body) = share_list_response(&ctx, &viewer_cookie, &alice_vault).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a stranger must not read Alice's share list: {body}"
    );

    // The owner, an admin who owns nothing here, and root all read it.
    for (who, cookie) in [
        ("owner", &c.alice_cookie),
        ("admin", &c.bob_cookie),
        ("root", &c.root_cookie),
    ] {
        let (status, body) = share_list_response(&ctx, cookie, &alice_vault).await;
        assert_eq!(status, StatusCode::OK, "{who} reads the share list: {body}");
        assert_eq!(
            body["data"].as_array().expect("share array").len(),
            1,
            "{who} sees the one share: {body}"
        );
    }
}

async fn vault_credentials(ctx: &TestContext, cookie: &str, vault: &str) -> Vec<Value> {
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/vaults/{vault}/credentials"),
        None,
        Some(cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list vault credentials: {body}");
    body["data"].as_array().expect("credential array").clone()
}

/// `GET /vaults/{id}/credentials` does not refuse a stranger — it answers
/// with what that stranger may see, which is nothing. That is why the
/// route-authorization sweep classifies this read as not owner-scoped: the
/// filtering, not a 403, is the security property, so it is asserted here.
#[tokio::test]
async fn vault_contents_are_scoped_to_the_owner() {
    let ctx = TestAppBuilder::new().build().await;
    let c = cast(&ctx).await;
    let bob_id = c.bob.id.0.to_string();
    let alice_vault = create_vault(&ctx, &c.alice_cookie, "alice-vault").await;

    let (status, body) =
        create_credential(&ctx, &c.alice_cookie, "a-secret", Some(&alice_vault)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    assert_eq!(
        vault_credentials(&ctx, &c.alice_cookie, &alice_vault)
            .await
            .len(),
        1,
        "Alice sees her own credential"
    );
    assert!(
        vault_credentials(&ctx, &c.bob_cookie, &alice_vault)
            .await
            .is_empty(),
        "Bob sees nothing in a vault that is not shared with him"
    );

    // Sharing is what makes it visible.
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/vaults/{alice_vault}/shares"),
        None,
        Some(&c.alice_cookie),
        Some(json!({ "user_id": bob_id, "permission": "read" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Alice shares with Bob: {body}");

    assert_eq!(
        vault_credentials(&ctx, &c.bob_cookie, &alice_vault)
            .await
            .len(),
        1,
        "the share is what makes Alice's credential visible to Bob"
    );
}

/// What a read share buys the recipient: the vault's credentials show up in
/// their credential list and their detail reads, and the vault itself
/// appears in their vault list naming who shared it. It buys nothing else —
/// the secret stays sealed.
///
/// The recipient here is a viewer, whose Cedar grants reach none of Alice's
/// credentials, so the share is the only thing that could be letting them
/// through.
#[tokio::test]
async fn a_read_share_makes_the_vaults_credentials_visible_and_nothing_more() {
    let ctx = TestAppBuilder::new().build().await;
    let c = cast(&ctx).await;
    let viewer =
        create_test_user(&*ctx.store, "vault-viewer", TEST_PASSWORD, UserRole::Viewer).await;
    let viewer_cookie = login_user_combined(&ctx.app, "vault-viewer", TEST_PASSWORD).await;

    let alice_vault = create_vault(&ctx, &c.alice_cookie, "alice-vault").await;
    let (status, body) =
        create_credential(&ctx, &c.alice_cookie, "a-secret", Some(&alice_vault)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let cred_id = body["data"]["id"].as_str().unwrap().to_string();

    let list = |cookie: String| {
        let app = ctx.app.clone();
        async move {
            let (status, body) = send_json_auto_csrf(
                &app,
                Method::GET,
                "/api/v1/credentials",
                None,
                Some(&cookie),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "list credentials: {body}");
            body["data"]
                .as_array()
                .expect("credential array")
                .iter()
                .filter_map(|c| c["name"].as_str().map(str::to_string))
                .collect::<Vec<_>>()
        }
    };

    assert!(
        !list(viewer_cookie.clone())
            .await
            .contains(&"a-secret".to_string()),
        "before the share the viewer sees nothing of Alice's"
    );
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{cred_id}"),
        None,
        Some(&viewer_cookie),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "detail is refused too: {body}"
    );

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/vaults/{alice_vault}/shares"),
        None,
        Some(&c.alice_cookie),
        Some(json!({ "user_id": viewer.id.0.to_string(), "permission": "read" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Alice shares with the viewer: {body}"
    );

    assert!(
        list(viewer_cookie.clone())
            .await
            .contains(&"a-secret".to_string()),
        "the share puts Alice's credential in the viewer's list"
    );
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{cred_id}"),
        None,
        Some(&viewer_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "and in their detail read: {body}");
    assert_eq!(body["data"]["vault_name"], "alice-vault", "{body}");

    // The vault shows in their list, naming who shared it.
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/vaults",
        None,
        Some(&viewer_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list vaults: {body}");
    let shared = body["data"]
        .as_array()
        .expect("vault array")
        .iter()
        .find(|v| v["id"] == alice_vault.as_str())
        .unwrap_or_else(|| panic!("the shared vault is listed: {body}"))
        .clone();
    assert_eq!(shared["shared_by"], "vault-alice", "{shared}");
    assert_eq!(shared["permission"], "read", "{shared}");

    // The secret itself stays sealed.
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/credentials/{cred_id}/reveal"),
        None,
        Some(&viewer_cookie),
        Some(json!({})),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a read share does not reveal the secret: {body}"
    );
    assert!(body.get("data").is_none(), "no secret comes back: {body}");
}

/// `reveal` answered 404 to a caller who had just read the same credential
/// through a share, which reads as "it is gone" rather than "you may not"
/// (uat/artifacts/fresh-user-native.md Finding 7, docker F-13). 404 is right
/// for a caller who cannot see the credential at all — that is the
/// non-enumeration rule — and wrong for one who can: they get the same 403,
/// with the same policy message, that edit and delete already answer.
#[tokio::test]
async fn reveal_answers_403_to_a_caller_who_can_already_see_the_credential() {
    let ctx = TestAppBuilder::new().build().await;
    let c = cast(&ctx).await;
    let viewer =
        create_test_user(&*ctx.store, "vault-viewer", TEST_PASSWORD, UserRole::Viewer).await;
    let viewer_cookie = login_user_combined(&ctx.app, "vault-viewer", TEST_PASSWORD).await;

    let alice_vault = create_vault(&ctx, &c.alice_cookie, "alice-vault").await;
    let (status, body) =
        create_credential(&ctx, &c.alice_cookie, "a-secret", Some(&alice_vault)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let cred_id = body["data"]["id"].as_str().unwrap().to_string();

    let reveal = |cookie: String, cred_id: String| {
        let app = ctx.app.clone();
        async move {
            send_json_auto_csrf(
                &app,
                Method::POST,
                &format!("/api/v1/credentials/{cred_id}/reveal"),
                None,
                Some(&cookie),
                Some(json!({})),
            )
            .await
        }
    };

    // Before the share the viewer cannot see the credential at all: 404, so
    // the answer never confirms that the id exists.
    let (status, body) = reveal(viewer_cookie.clone(), cred_id.clone()).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a stranger learns nothing from reveal: {body}"
    );

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/vaults/{alice_vault}/shares"),
        None,
        Some(&c.alice_cookie),
        Some(json!({ "user_id": viewer.id.0.to_string(), "permission": "read" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Alice shares the vault: {body}");

    // The same caller can now GET the credential.
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/credentials/{cred_id}"),
        None,
        Some(&viewer_cookie),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the share makes it readable: {body}"
    );

    // So reveal must say "not allowed", not "not there".
    let (status, body) = reveal(viewer_cookie.clone(), cred_id.clone()).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read-share recipient is refused, not told the credential is gone: {body}"
    );
    assert_eq!(body["error"]["code"], "forbidden", "{body}");
    assert_eq!(
        body["error"]["message"], "access denied by policy",
        "the same sentence edit and delete answer: {body}"
    );
    assert!(body.get("data").is_none(), "no secret comes back: {body}");

    // The owner still reveals it.
    let (status, body) = reveal(c.alice_cookie.clone(), cred_id.clone()).await;
    assert_eq!(status, StatusCode::OK, "the owner reveals: {body}");
    assert_eq!(body["data"]["secret_value"], "s3cret", "{body}");
}

/// The credential list and detail must say how the caller reaches each row,
/// because the page decides from it whether to offer Reveal / Edit / Delete /
/// Grant. A read-share recipient was shown all four and the server refused
/// every one (uat/artifacts/fresh-user-native.md Finding 7).
#[tokio::test]
async fn a_shared_read_credential_reports_its_access_in_list_and_detail() {
    let ctx = TestAppBuilder::new().build().await;
    let c = cast(&ctx).await;
    let viewer =
        create_test_user(&*ctx.store, "vault-viewer", TEST_PASSWORD, UserRole::Viewer).await;
    let viewer_cookie = login_user_combined(&ctx.app, "vault-viewer", TEST_PASSWORD).await;

    let alice_vault = create_vault(&ctx, &c.alice_cookie, "alice-vault").await;
    let (status, body) =
        create_credential(&ctx, &c.alice_cookie, "a-secret", Some(&alice_vault)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let cred_id = body["data"]["id"].as_str().unwrap().to_string();

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/vaults/{alice_vault}/shares"),
        None,
        Some(&c.alice_cookie),
        Some(json!({ "user_id": viewer.id.0.to_string(), "permission": "read" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "Alice shares the vault: {body}");

    let detail = |cookie: String, cred_id: String| {
        let app = ctx.app.clone();
        async move {
            let (status, body) = send_json_auto_csrf(
                &app,
                Method::GET,
                &format!("/api/v1/credentials/{cred_id}"),
                None,
                Some(&cookie),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "detail: {body}");
            body["data"].clone()
        }
    };
    let listed = |cookie: String| {
        let app = ctx.app.clone();
        async move {
            let (status, body) = send_json_auto_csrf(
                &app,
                Method::GET,
                "/api/v1/credentials",
                None,
                Some(&cookie),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "list: {body}");
            body["data"]
                .as_array()
                .expect("credential array")
                .iter()
                .find(|c| c["name"] == "a-secret")
                .unwrap_or_else(|| panic!("a-secret is listed: {body}"))
                .clone()
        }
    };

    for row in [
        listed(viewer_cookie.clone()).await,
        detail(viewer_cookie.clone(), cred_id.clone()).await,
    ] {
        assert_eq!(
            row["access"], "shared_read",
            "the viewer reaches this only through the share: {row}"
        );
    }

    for row in [
        listed(c.alice_cookie.clone()).await,
        detail(c.alice_cookie.clone(), cred_id.clone()).await,
    ] {
        assert_eq!(row["access"], "full", "the owner has full access: {row}");
    }
}

/// The system default vault is shared infrastructure. It has no owner to
/// rename, share or delete it, and every principal writes to it, so all
/// three are refused outright.
#[tokio::test]
async fn the_default_vault_cannot_be_renamed_shared_or_deleted() {
    let ctx = TestAppBuilder::new().build().await;
    let c = cast(&ctx).await;

    for (what, method, body) in [
        (
            "renamed",
            Method::PATCH,
            Some(json!({ "name": "not-default" })),
        ),
        ("deleted", Method::DELETE, None),
    ] {
        let (status, resp) = send_json_auto_csrf(
            &ctx.app,
            method,
            &format!("/api/v1/vaults/{DEFAULT_VAULT_ID}"),
            None,
            Some(&c.root_cookie),
            body,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "the default vault must not be {what}, even by root: {resp}"
        );
    }

    let (status, resp) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        &format!("/api/v1/vaults/{DEFAULT_VAULT_ID}/shares"),
        None,
        Some(&c.root_cookie),
        Some(json!({ "user_id": c.carol.id.0.to_string() })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the default vault is already everyone's; sharing it is meaningless: {resp}"
    );
}

/// Renaming and deleting belong to the owner. A vault that still holds
/// credentials is a conflict rather than a cascade: deleting it would take
/// the credentials with it, which is never what "remove this grouping"
/// meant.
#[tokio::test]
async fn a_vault_is_renamed_by_its_owner_and_deleted_only_when_empty() {
    let ctx = TestAppBuilder::new().build().await;
    let c = cast(&ctx).await;
    let vault = create_vault(&ctx, &c.alice_cookie, "alice-vault").await;

    // A non-owner admin cannot rename it, whatever `manage_vaults` says.
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::PATCH,
        &format!("/api/v1/vaults/{vault}"),
        None,
        Some(&c.bob_cookie),
        Some(json!({ "name": "bobs-now" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::PATCH,
        &format!("/api/v1/vaults/{vault}"),
        None,
        Some(&c.alice_cookie),
        Some(json!({ "name": "alice-renamed" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the owner renames: {body}");
    assert_eq!(body["data"]["name"], "alice-renamed", "{body}");
    assert_eq!(body["data"]["id"], vault, "renaming keeps the id: {body}");

    let (status, body) = create_credential(&ctx, &c.alice_cookie, "a-held", Some(&vault)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let cred_id = body["data"]["id"].as_str().unwrap().to_string();

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/vaults/{vault}"),
        None,
        Some(&c.alice_cookie),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a vault that still holds a credential is not deleted: {body}"
    );

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/credentials/{cred_id}"),
        None,
        Some(&c.alice_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::DELETE,
        &format!("/api/v1/vaults/{vault}"),
        None,
        Some(&c.alice_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "an empty vault is deleted: {body}");

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        &format!("/api/v1/vaults/{vault}/shares"),
        None,
        Some(&c.alice_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "and is gone: {body}");
}

/// A name is a label, not an identity — but it is the only label the vault
/// picker shows, so two of *one owner's* vaults may not share one (UI review
/// M1). Across owners the name is free, and the ids keep the vaults apart.
#[tokio::test]
async fn two_owners_may_each_hold_a_vault_named_team() {
    let ctx = TestAppBuilder::new().build().await;
    let c = cast(&ctx).await;

    let first = create_vault(&ctx, &c.alice_cookie, "team").await;
    let second = create_vault(&ctx, &c.bob_cookie, "team").await;
    assert_ne!(first, second);

    let (status, body) = create_credential(&ctx, &c.alice_cookie, "in-first", Some(&first)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["vault_id"], first, "{body}");

    assert_eq!(
        vault_credentials(&ctx, &c.bob_cookie, &second).await.len(),
        0,
        "the same name is not the same vault"
    );
}

/// One owner is refused a second vault of the same name, with the name in the
/// message.
#[tokio::test]
async fn one_owner_may_not_hold_two_vaults_of_the_same_name() {
    let ctx = TestAppBuilder::new().build().await;
    let c = cast(&ctx).await;

    create_vault(&ctx, &c.alice_cookie, "team").await;

    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/vaults",
        None,
        Some(&c.alice_cookie),
        Some(json!({ "name": "team" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("team"),
        "the refusal names the existing vault: {body}"
    );
}
