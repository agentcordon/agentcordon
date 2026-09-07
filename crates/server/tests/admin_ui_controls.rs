//! Admin UI controls: the operations an operator is documented to perform must
//! be reachable from a page, not only from a hand-crafted API call.
//!
//! These are HTTP-seam tests over the rendered page shell — they assert that a
//! control and its confirmation copy are in the HTML the page ships, not that
//! the JavaScript behaves. Behaviour is covered by the Playwright scenarios in
//! `uat/playwright/tests`.
//!
//! One test here is a static guard over the template sources rather than the
//! HTTP boundary: Alpine 3 runs a component's own `init()` automatically, so an
//! element carrying both `x-data="component()"` and `x-init="init()"` runs it
//! twice. That is invisible to the HTTP seam and only shows up in a browser, so
//! the templates are checked directly.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use std::path::{Path, PathBuf};

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};
use tower::ServiceExt;

use crate::common;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn admin_session() -> (TestContext, String) {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    common::create_test_user(
        &*ctx.store,
        "ctl-admin",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, "ctl-admin", common::TEST_PASSWORD).await;
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

fn assert_contains(body: &str, uri: &str, needle: &str, why: &str) {
    assert!(
        body.contains(needle),
        "{uri}: {why} — expected the page HTML to contain {needle:?}"
    );
}

// ---------------------------------------------------------------------------
// Alpine double-init guard
// ---------------------------------------------------------------------------

fn html_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read templates dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            html_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "html") {
            out.push(path);
        }
    }
}

/// The text of the element that carries `x-init` at `at`: back to the opening
/// `<` and forward to the next `<` (attribute values in these templates never
/// contain a raw `<`).
fn element_around(src: &str, at: usize) -> &str {
    let start = src[..at].rfind('<').map(|i| i + 1).unwrap_or(0);
    let end = src[at..].find('<').map(|i| at + i).unwrap_or(src.len());
    &src[start..end]
}

/// Alpine 3 calls a data object's own `init()` and evaluates `x-init`, so an
/// element with both runs it twice. The audit page's `init()` was not
/// idempotent — it called `toggleEvent(id)`, so a deep link opened the row and
/// then closed it again (uat/artifacts/reviews/REPORT.md D1).
#[test]
fn no_template_pairs_a_component_x_data_with_x_init_init() {
    let templates = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates");
    let mut files = Vec::new();
    html_files(&templates, &mut files);
    assert!(!files.is_empty(), "no templates found under {templates:?}");

    let mut offenders = Vec::new();
    for file in &files {
        let src = std::fs::read_to_string(file).expect("read template");
        let mut from = 0;
        while let Some(rel) = src[from..].find(r#"x-init="init()"#) {
            let at = from + rel;
            let element = element_around(&src, at);
            if element.contains("x-data=\"") {
                let line = src[..at].matches('\n').count() + 1;
                offenders.push(format!("{}:{line}", file.display()));
            }
            from = at + 1;
        }
    }

    assert!(
        offenders.is_empty(),
        "Alpine runs a component's init() itself; these elements also carry \
         x-init=\"init()\" and so run it twice:\n  {}",
        offenders.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// D3 — workspace revocation
// ---------------------------------------------------------------------------

/// `POST /api/v1/workspaces/{id}/revoke` is the only way to reach the documented
/// `Revoked` state, and the workspace detail surfaces offered only Disable and
/// Delete (uat/artifacts/reviews/REPORT.md D3). Both surfaces must offer the control, and must say
/// — before the operator commits — that it is final and that registering a new
/// identity is the way back.
///
/// There is one: `/workspaces/{id}` is the workspace's page. Revoke lives in
/// the header's `⋯` overflow with Delete, so the assertion is about the
/// control and its copy, not about it being a top-level button.
#[tokio::test]
async fn workspace_detail_offers_a_revoke_control_that_explains_it_is_final() {
    let (ctx, cookie) = admin_session().await;
    let (ws, _) = common::create_agent_in_db(&*ctx.store, "ctl-ws", vec![], true, None).await;

    for uri in workspace_detail_surfaces(&ws.id.0.to_string()) {
        let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{uri}");

        assert_contains(
            &body,
            &uri,
            r#"id="ws-revoke-btn""#,
            "the page has a Revoke control",
        );
        assert_contains(
            &body,
            &uri,
            r#"id="ws-revoke-confirm""#,
            "revoking asks for confirmation first",
        );
        assert_contains(&body, &uri, "/revoke", "the control calls the revoke API");

        let lower = body.to_lowercase();
        assert!(
            lower.contains("final"),
            "{uri}: the confirmation says revocation is final"
        );
        assert!(
            lower.contains("register"),
            "{uri}: the confirmation says registering a new identity is the way back"
        );
        assert!(
            body.contains("'revoked'"),
            "{uri}: the page reflects the revoked status"
        );
        assert!(
            body.contains("isRevoked()"),
            "{uri}: Enable is disabled once the workspace is revoked"
        );
    }
}

// ---------------------------------------------------------------------------
// D4 — master-key re-seal
// ---------------------------------------------------------------------------

/// `docs/master-key.md` step 4 tells an admin to call
/// `POST /api/v1/admin/rotate-key`, and no page offered it (uat/artifacts/reviews/REPORT.md D4).
#[tokio::test]
async fn settings_offers_a_master_key_reseal_control_for_admins() {
    let (ctx, cookie) = admin_session().await;

    let (status, body) = get_page(&ctx.app, "/settings", &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        "/settings",
        r#"id="reseal-btn""#,
        "settings has a re-seal control",
    );
    assert_contains(
        &body,
        "/settings",
        r#"id="reseal-confirm""#,
        "re-sealing asks for confirmation first",
    );
    assert_contains(
        &body,
        "/settings",
        "/api/v1/admin/rotate-key",
        "the control calls the rotate-key API",
    );
    assert_contains(
        &body,
        "/settings",
        "re_encrypted_count",
        "the page shows the report's counts",
    );
    assert_contains(
        &body,
        "/settings",
        "resealErrors",
        "the page shows the report's errors",
    );
}

/// The re-seal control is admin-only, like every other Administration control
/// on the page. Only the markup is gated — the page's one script is the same
/// for everyone — and the endpoint refuses a non-admin regardless.
#[tokio::test]
async fn settings_hides_the_reseal_control_from_a_non_admin() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    common::create_test_user(
        &*ctx.store,
        "ctl-viewer",
        common::TEST_PASSWORD,
        UserRole::Viewer,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, "ctl-viewer", common::TEST_PASSWORD).await;

    let (status, body) = get_page(&ctx.app, "/settings", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains(r#"id="reseal-btn""#),
        "/settings: a viewer is not offered the re-seal control"
    );
    assert!(
        !body.contains(r#"id="reseal-confirm""#),
        "/settings: a viewer is not offered the re-seal confirmation"
    );
}

// ---------------------------------------------------------------------------
// D12 — the API-key credential types the API accepts
// ---------------------------------------------------------------------------

/// `api_key_header` and `api_key_query` are creatable through
/// `POST /api/v1/credentials`, each needing the metadata the broker names the
/// header (or the query parameter) with. The New Credential form offered three
/// types and no way to supply that metadata, so both were API-only.
#[tokio::test]
async fn new_credential_form_offers_the_api_key_types_and_their_metadata() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/credentials/new";

    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    for value in ["api_key_header", "api_key_query"] {
        assert_contains(
            &body,
            uri,
            &format!(r#"value="{value}""#),
            "the type select offers the type",
        );
    }
    assert_contains(
        &body,
        uri,
        r#"id="cred-header-name""#,
        "api_key_header asks for the header name",
    );
    assert_contains(
        &body,
        uri,
        r#"id="cred-param-name""#,
        "api_key_query asks for the query parameter name",
    );
    // Each field is shown only for the type that needs it.
    assert_contains(
        &body,
        uri,
        "form.credentialType === 'api_key_header'",
        "the header-name field is bound to its type",
    );
    assert_contains(
        &body,
        uri,
        "form.credentialType === 'api_key_query'",
        "the param-name field is bound to its type",
    );
    // They are submitted where validate_credential_metadata looks for them.
    assert_contains(
        &body,
        uri,
        "body.metadata.header_name",
        "the header name is sent as metadata.header_name",
    );
    assert_contains(
        &body,
        uri,
        "body.metadata.param_name",
        "the param name is sent as metadata.param_name",
    );
    // And the list page renders the new types with a name, not a raw string.
    for label in ["api_key_header:", "api_key_query:"] {
        assert_contains(&body, uri, label, "credTypeLabel names the type");
    }
}

/// An empty header (or parameter) name is refused before the request is made,
/// with the message the API would have answered — so the form never hands the
/// user a different sentence than `curl` would get.
#[tokio::test]
async fn new_credential_form_rejects_an_empty_api_key_name_with_the_api_message() {
    let (ctx, cookie) = admin_session().await;

    // What the API says when the metadata is missing.
    let (status, api) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "name": "ctl-api-key",
            "service": "svc",
            "secret_value": "sk-1",
            "credential_type": "api_key_header",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{api}");
    let api_message = api["error"]["message"].as_str().unwrap_or_default();
    assert_eq!(
        api_message, "credential_type 'api_key_header' requires a non-empty metadata.header_name",
        "the API message this form must match: {api}"
    );

    // The page builds the same sentence client-side.
    let (status, body) = get_page(&ctx.app, "/credentials/new", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    for fragment in ["credential_type '", "' requires a non-empty metadata."] {
        assert_contains(
            &body,
            "/credentials/new",
            fragment,
            "the form refuses an empty name with the API's wording",
        );
    }
    // The two halves the page splices the type and the key between are exactly
    // the two the API's message is made of.
    assert!(
        api_message.starts_with("credential_type '")
            && api_message.contains("' requires a non-empty metadata."),
        "the API message changed shape; the form's copy must follow: {api_message}"
    );
}

/// Every credential type the New Credential form offers must have a
/// `_blank_<credential_type>` system template behind it.
///
/// The Blank path renders its inputs from that template's `fields` (see
/// `selectedTemplateFields` in `pages/credentials/new.html`): with no such
/// template the type select still offers the type, but the form renders **no
/// secret field at all** and the type cannot be created through the UI. This
/// guard walks `KNOWN_CREDENTIAL_TYPES`, keeps the ones the select offers, and
/// requires a blank template with a required secret field for each — so
/// offering a new type without shipping its blank template fails here rather
/// than in a browser.
#[tokio::test]
async fn every_offered_credential_type_has_a_blank_template_with_a_secret_field() {
    let (ctx, cookie) = admin_session().await;

    let (status, page) = get_page(&ctx.app, "/credentials/new", &cookie).await;
    assert_eq!(status, StatusCode::OK);

    let (status, templates) = common::send_json_auto_csrf(
        &ctx.app,
        Method::GET,
        "/api/v1/credential-templates",
        None,
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list templates: {templates}");
    let templates = templates["data"].as_array().expect("data array").clone();

    let mut checked = 0;
    for credential_type in agent_cordon_server::services::credentials::KNOWN_CREDENTIAL_TYPES {
        // Types the form does not offer (e.g. `oauth2_user_authorization`, which
        // only the delegated-OAuth flow creates) need no blank template.
        if !page.contains(&format!(r#"<option value="{credential_type}""#)) {
            continue;
        }
        checked += 1;
        let key = format!("_blank_{credential_type}");
        let tpl = templates
            .iter()
            .find(|t| t["key"].as_str() == Some(key.as_str()))
            .unwrap_or_else(|| {
                panic!(
                    "/credentials/new offers credential_type '{credential_type}' but the catalog \
                     has no '{key}' template, so the form renders no fields for it"
                )
            });
        let fields = tpl["fields"].as_array().unwrap_or_else(|| {
            panic!("'{key}' must declare fields");
        });
        assert!(
            fields.iter().any(|f| f["secret"].as_bool().unwrap_or(false)
                && f["required"].as_bool().unwrap_or(false)),
            "'{key}' must declare a required secret field, or the admin has nowhere to type \
             the secret; got: {fields:?}"
        );
    }
    assert!(
        checked >= 5,
        "the type select should still offer the documented types; only {checked} matched"
    );
}

/// The marketplace install modal says where the key it is asking for will be
/// sent. A template naming `api_key_header` is provisioned as that header, and
/// an admin pasting a key into the form should not have to read the JSON to
/// find out which of the two forms the server will see.
#[tokio::test]
async fn install_modal_says_where_a_templates_api_key_is_sent() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/mcp-servers/marketplace";

    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        uri,
        r#"id="install-secret-placement""#,
        "the secret field says where the key goes",
    );
    assert_contains(
        &body,
        uri,
        "t.api_key_header",
        "the hint reads the template's header placement",
    );
    assert_contains(
        &body,
        uri,
        "t.api_key_query",
        "the hint reads the template's query placement",
    );
    assert_contains(
        &body,
        uri,
        "Authorization: Bearer",
        "and names the bearer default for a template with no placement",
    );
}

/// The docs tell a reader to click **Install**. The modal called the button
/// "Add to workspace" for a template the user is already connected to, and
/// "Install" otherwise, so neither a reader following the text nor a UI
/// automation found the control the docs name. Only the OAuth flow keeps its
/// own label, which the docs also describe ("click **Connect**").
#[tokio::test]
async fn install_modal_confirm_button_says_install_for_every_non_oauth_template() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/mcp-servers/marketplace";

    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert!(
        !body.contains("Add to workspace"),
        "the confirm button must not have a third name: {uri}"
    );
    assert_contains(
        &body,
        uri,
        "'Connect with ' + selectedTemplate.name",
        "an OAuth template still says what it is connecting to",
    );
    assert_contains(
        &body,
        uri,
        ": 'Install'",
        "every other template says Install, the word the docs use",
    );
}

/// A server whose install-time probe failed has no tools and, until this
/// control, no way back except delete and reinstall. The install modal names
/// the control it points at, so the two strings have to agree.
#[tokio::test]
async fn mcp_server_detail_offers_a_rediscover_tools_control() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/mcp-servers/00000000-0000-0000-0000-000000000001";

    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        uri,
        "Rediscover tools",
        "the detail page offers the retry the docs and the install modal name",
    );
    assert_contains(
        &body,
        uri,
        "/discover-tools",
        "and it posts to the rediscovery route",
    );
}

/// The install modal reports a discovery failure instead of redirecting on
/// to a list page that shows a server with no tools and no explanation.
#[tokio::test]
async fn install_modal_reports_a_tool_discovery_failure() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/mcp-servers/marketplace";

    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        uri,
        "tool_discovery_error",
        "the modal reads the field the install response carries",
    );
    assert_contains(&body, uri, "tool discovery failed", "and says so in words");
    assert_contains(
        &body,
        uri,
        "Rediscover tools",
        "pointing at the control that fixes it",
    );
}

// ---------------------------------------------------------------------------
// OAuth provider clients — listing for operators, controls for admins
// ---------------------------------------------------------------------------

/// An OAuth provider client is AgentCordon's registration at an upstream
/// authorization server, shared by every MCP server at that origin. Changing
/// one needs `manage_oauth_provider_clients` (admins only), but an operator
/// still has to see which client an origin uses, so the listing stays and only
/// the controls that write go.
///
/// Markup only — the page's one script is the same for everyone, and the API
/// refuses a non-admin regardless.
#[tokio::test]
async fn settings_shows_provider_clients_to_an_operator_without_the_write_controls() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    common::create_test_user(
        &*ctx.store,
        "ctl-operator",
        common::TEST_PASSWORD,
        UserRole::Operator,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, "ctl-operator", common::TEST_PASSWORD).await;

    let (status, body) = get_page(&ctx.app, "/settings", &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        "/settings",
        r#"id="opc-clients-table""#,
        "an operator still sees which client each origin uses",
    );
    for control in [
        r#"id="opc-add-btn""#,
        r#"id="opc-new-client-form""#,
        r#"id="opc-delete-modal""#,
        "opc-delete",
        "opc-reregister",
        "opc-toggle",
    ] {
        assert!(
            !body.contains(control),
            "/settings: an operator is not offered {control:?} — provider-client writes are \
             admin-only"
        );
    }
}

/// The counterpart: an admin gets every control, so the test above cannot pass
/// by the section having been dropped from the page.
#[tokio::test]
async fn settings_offers_provider_client_controls_to_an_admin() {
    let (ctx, cookie) = admin_session().await;

    let (status, body) = get_page(&ctx.app, "/settings", &cookie).await;
    assert_eq!(status, StatusCode::OK);

    for control in [
        r#"id="opc-clients-table""#,
        r#"id="opc-add-btn""#,
        r#"id="opc-new-client-form""#,
        r#"id="opc-delete-modal""#,
        "opc-delete",
        "opc-reregister",
        "opc-toggle",
    ] {
        assert_contains(
            &body,
            "/settings",
            control,
            "an admin manages provider clients from the page",
        );
    }
}

/// An operator holds `manage_mcp_servers`, which is what
/// `GET /api/v1/oauth-provider-clients` asks for, and the section is rendered
/// for them — but the page fetched the list only when the caller was an admin,
/// so an operator got the markup with nothing in it and still could not see
/// which client an origin uses. Whoever is shown the section must be the one
/// the page loads it for.
#[tokio::test]
async fn settings_loads_the_provider_client_listing_for_whoever_is_shown_it() {
    for (role, username, expected) in [
        (UserRole::Admin, "ctl-mcp-admin", "canManageMcp: true"),
        (UserRole::Operator, "ctl-mcp-operator", "canManageMcp: true"),
        (UserRole::Viewer, "ctl-mcp-viewer", "canManageMcp: false"),
    ] {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        common::create_test_user(&*ctx.store, username, common::TEST_PASSWORD, role).await;
        let cookie = common::login_user_combined(&ctx.app, username, common::TEST_PASSWORD).await;

        let (status, body) = get_page(&ctx.app, "/settings", &cookie).await;
        assert_eq!(status, StatusCode::OK);

        assert_contains(
            &body,
            "/settings",
            expected,
            "the page knows whether this caller may read provider clients",
        );
        assert_contains(
            &body,
            "/settings",
            "if (this.canManageMcp)",
            "and loads the listing on that, not on being an admin",
        );
    }
}

/// Deleting a provider client that anything still authenticates with answers
/// `409`, naming the dependent credentials and MCP servers. The page fired the
/// request, ignored the answer and toasted "OAuth provider client deleted"
/// either way, so an admin was told the row was gone while it was still there.
/// The refusal has to reach the page that asked for it, in the server's own
/// words.
#[tokio::test]
async fn settings_shows_the_reason_a_provider_client_delete_was_refused() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/settings";

    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        uri,
        r#"id="opc-delete-error""#,
        "the delete modal has somewhere to put the refusal",
    );
    assert_contains(
        &body,
        uri,
        "opcDeleteError",
        "and state the refusal is read from",
    );
    assert_contains(
        &body,
        uri,
        "deleteOAuthProviderResp.ok",
        "the handler branches on the answer instead of assuming success",
    );
}

// ---------------------------------------------------------------------------
// Vaults — a vault is a row with an id, so every surface names it by id
// ---------------------------------------------------------------------------

/// A viewer session, for the read-only half of the vault assertions.
async fn viewer_session() -> (TestContext, String) {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    common::create_test_user(
        &*ctx.store,
        "ctl-vault-viewer",
        common::TEST_PASSWORD,
        UserRole::Viewer,
    )
    .await;
    let cookie =
        common::login_user_combined(&ctx.app, "ctl-vault-viewer", common::TEST_PASSWORD).await;
    (ctx, cookie)
}

/// `POST /api/v1/credentials` takes `vault_id`, not a vault name, and a vault
/// the caller does not own is refused. The form therefore cannot ask for a
/// free-text name: it offers the vaults the caller may actually write to,
/// showing each vault's display name and submitting its id.
#[tokio::test]
async fn new_credential_form_picks_a_vault_by_id_from_the_vault_list() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/credentials/new";

    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        uri,
        r#"id="cred-vault""#,
        "the form has a vault control",
    );
    assert_contains(
        &body,
        uri,
        "'/api/v1/vaults'",
        "the vault control is populated from the vault list API",
    );
    assert_contains(
        &body,
        uri,
        "body.vault_id",
        "the form submits the vault's id, not its name",
    );
    assert!(
        !body.contains("body.vault ="),
        "{uri}: the old name-keyed `vault` field is gone"
    );
    // Only the vaults this caller may place a credential in: their own, plus
    // the system default. A `manage_vaults` holder is listed every vault on
    // the install, and placing into someone else's is a 403.
    assert_contains(
        &body,
        uri,
        "ownVaults",
        "the select is narrowed to the vaults the caller may write to",
    );
    assert_contains(
        &body,
        uri,
        "is_default",
        "the system default is always offered",
    );
    assert_contains(
        &body,
        uri,
        "owner_user_id",
        "and the caller's own vaults are matched by owner",
    );
}

/// Creating the vault is part of storing the first credential in it — the form
/// offers a "New vault" control that posts to the vault API and selects what it
/// gets back, so an operator never has to leave the page to make a grouping.
#[tokio::test]
async fn new_credential_form_creates_a_vault_inline_and_selects_it() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/credentials/new";

    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    for marker in [
        r#"id="cred-vault-new-btn""#,
        r#"id="cred-vault-new-name""#,
        r#"id="cred-vault-new-create""#,
    ] {
        assert_contains(&body, uri, marker, "the form creates a vault inline");
    }
    assert_contains(
        &body,
        uri,
        "createVault()",
        "the inline control calls the create action",
    );
    assert_contains(
        &body,
        uri,
        "this.form.vaultId =",
        "and the new vault becomes the selected one",
    );
}

/// The credential's vault is shown by name and changed by id, on both detail
/// surfaces: the split-view pane and the standalone `/view` page.
#[tokio::test]
async fn credential_detail_shows_the_vault_name_and_moves_by_vault_id() {
    let (ctx, cookie) = admin_session().await;
    let (status, created) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(&cookie),
        Some(serde_json::json!({
            "name": "ctl-vault-cred",
            "service": "svc",
            "secret_value": "sk-1",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create credential: {created}");
    let id = created["data"]["id"].as_str().expect("credential id");

    for uri in credential_detail_surfaces(id) {
        let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{uri}");

        assert_contains(
            &body,
            &uri,
            "credential.vault_name",
            "the vault is shown by its display name",
        );
        assert_contains(
            &body,
            &uri,
            r#"id="cred-vault-select""#,
            "editing offers a vault select",
        );
        assert_contains(
            &body,
            &uri,
            "editForm.vaultId",
            "the select is bound to the vault id",
        );
        assert_contains(
            &body,
            &uri,
            "body.vault_id",
            "moving the credential sends vault_id",
        );
        assert_contains(
            &body,
            &uri,
            "'/api/v1/vaults'",
            "the options come from the vault list API",
        );
    }
}

/// The credentials list shows each credential's vault and filters by it. The
/// filter is over the vault the row names, so two vaults sharing a display
/// name stay distinguishable — the option value is the id.
#[tokio::test]
async fn credentials_list_shows_and_filters_by_vault() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/credentials";

    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        uri,
        r#"id="cred-vault-filter""#,
        "the list has a vault filter",
    );
    assert_contains(
        &body,
        uri,
        "vaultFilter",
        "the filter has state the list reads",
    );
    assert_contains(
        &body,
        uri,
        "cred.vault_name",
        "each row names the vault it is in",
    );
    assert_contains(
        &body,
        uri,
        "c.vault_id",
        "and the filter matches on the vault's id, not its name",
    );
    // The row is a table row now, and it still carries the vault it is in so
    // the filtered list can be read off the DOM.
    assert_contains(
        &body,
        uri,
        r#":data-vault-id="cred.vault_id""#,
        "the table row names the vault it belongs to",
    );
}

/// The Vaults section: the caller's own vaults, each renamable, shareable and
/// deletable, plus the vaults shared with them marked with who shared them.
#[tokio::test]
async fn settings_offers_a_vaults_section_with_rename_share_and_delete() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/settings";

    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    for marker in [
        r#"id="vaults-section""#,
        r#"id="vaults-table""#,
        // The name cell becomes an input while renaming, so the row is
        // addressed by the vault's id, not by the name shown in it.
        r#":data-vault-id="v.id""#,
        r#"id="vault-new-name""#,
        r#"id="vault-create-btn""#,
        "vault-rename-btn",
        "vault-rename-input",
        "vault-delete-btn",
        r#"id="vault-delete-modal""#,
        r#"id="vault-delete-confirm""#,
        "vault-share-btn",
        "vault-share-user",
        "vault-share-submit",
        "vault-share-revoke",
    ] {
        assert_contains(&body, uri, marker, "the Vaults section offers the control");
    }

    // The routes each control drives, by id.
    assert_contains(
        &body,
        uri,
        "'/api/v1/vaults'",
        "the section lists and creates vaults",
    );
    assert_contains(
        &body,
        uri,
        "'/api/v1/vaults/' + ",
        "and renames, deletes and shares by id",
    );
    assert_contains(
        &body,
        uri,
        "/shares",
        "shares are a sub-resource of a vault",
    );

    // Only `read` is a share level the authorization model keeps; the API
    // answers 400 for `write` and `admin`, so the control never offers them.
    assert_contains(
        &body,
        uri,
        "permission: 'read'",
        "a share grants read and nothing else",
    );
    for refused in [r#"value="write""#, r#"value="admin""#] {
        assert!(
            !body.contains(refused),
            "{uri}: the share control must not offer {refused:?} — the API refuses it"
        );
    }

    // A vault shared with the caller says who shared it.
    assert_contains(
        &body,
        uri,
        "Shared by",
        "a vault shared with the caller is marked as such",
    );
    assert_contains(&body, uri, "v.shared_by", "and names who shared it");
}

/// The system default vault is shared infrastructure: it has no owner, and the
/// API refuses to rename, share or delete it. The page must not offer controls
/// that can only produce a 403, and deleting a vault that still holds
/// credentials must be refused before the request, with the reason.
#[tokio::test]
async fn settings_withholds_owner_controls_from_the_default_vault_and_guards_delete() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/settings";

    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    for guard in ["canRename(", "canShare(", "canDelete("] {
        assert_contains(
            &body,
            uri,
            guard,
            "each owner control is gated on the vault it is for",
        );
    }
    assert_contains(
        &body,
        uri,
        "!v.is_default",
        "the default vault is offered no owner control",
    );
    assert_contains(
        &body,
        uri,
        "credentialCount(",
        "delete knows whether the vault still holds credentials",
    );
    // The tooltip on the disabled control says why, in the API's own terms.
    assert_contains(
        &body,
        uri,
        "move or delete them first",
        "the disabled Delete says what to do instead",
    );
}

/// `manage_vaults` — which the default policy grants admins — reads any
/// vault's share list and revokes a share, but never grants one: handing out
/// another user's credentials is the owner's act alone. The page must mirror
/// that, or an admin gets a control that always 403s.
#[tokio::test]
async fn settings_lets_an_admin_revoke_any_share_but_never_grant_one() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/settings";

    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        uri,
        "canManageShares(",
        "an admin reads the share list of a vault they do not own",
    );
    assert_contains(
        &body,
        uri,
        "isAdmin",
        "and the page knows the caller holds manage_vaults",
    );
    // Sharing is gated on ownership, not on being an admin.
    assert_contains(
        &body,
        uri,
        "isOwner(",
        "the share control is gated on owning the vault",
    );
}

/// A viewer sees the vaults shared with them and their credentials, and
/// nothing that writes: a viewer holds no `create` on System, so offering a
/// "New vault" form would only ever produce a 403.
#[tokio::test]
async fn settings_shows_a_viewer_the_vaults_section_without_the_create_control() {
    let (ctx, cookie) = viewer_session().await;
    let uri = "/settings";

    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        uri,
        r#"id="vaults-table""#,
        "a viewer still sees the vaults shared with them",
    );
    for control in [r#"id="vault-new-name""#, r#"id="vault-create-btn""#] {
        assert!(
            !body.contains(control),
            "/settings: a viewer is not offered {control:?} — creating a vault needs `create`"
        );
    }
}

// ---------------------------------------------------------------------------
// F-18 — every asset the page shell references must be served
// ---------------------------------------------------------------------------

/// Every absolute URL `base.html` names in a `src`/`href` is fetched by the
/// browser on every admin page, so a missing one is a 404 in the console of
/// every page while the page itself renders fine
/// (uat/artifacts/fresh-user-docker.md F-18).
#[tokio::test]
async fn every_asset_the_page_shell_references_is_served() {
    let ctx = TestAppBuilder::new().with_admin().build().await;

    let shell = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("templates")
            .join("base.html"),
    )
    .expect("read base.html");

    let mut refs: Vec<String> = Vec::new();
    for attr in ["src=\"", "href=\""] {
        let mut from = 0;
        while let Some(rel) = shell[from..].find(attr) {
            let start = from + rel + attr.len();
            let end = start + shell[start..].find('"').expect("closing quote");
            let url = &shell[start..end];
            if url.starts_with('/') && url.contains('.') {
                refs.push(url.to_string());
            }
            from = end;
        }
    }
    // An asset a shell asset loads in turn.
    refs.push("/data/service-logos.json".to_string());
    // A browser with no `<link rel="icon">` it can use asks for this by itself.
    refs.push("/favicon.ico".to_string());
    // The shared icon sprite. `base.html` does not reference it — a `<use>` in
    // a page does, from phase 3 on — but it is embedded from the same
    // `static/` tree and a missing sprite fails silently as blank buttons.
    refs.push("/icons.svg".to_string());
    assert!(
        refs.iter().any(|r| r.ends_with(".css")),
        "expected to find the stylesheet in base.html"
    );

    for url in &refs {
        let resp = ctx
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(url.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "{url}: referenced from every admin page but not served"
        );
    }
}

// ---------------------------------------------------------------------------
// Read-share recipients, credential type names, transforms
// ---------------------------------------------------------------------------

/// The one surface that renders a credential's controls. The split pane is
/// gone: `/credentials/{id}` is a full page around the pane partial, and
/// `/credentials/{id}/view` redirects to it.
fn credential_detail_surfaces(id: &str) -> [String; 1] {
    [format!("/credentials/{id}")]
}

/// A read share makes a vault's credentials visible and grants nothing else.
/// The detail surfaces offered Reveal Secret, Edit, Delete and Grant
/// Permissions to a recipient anyway, and the server refused every one with
/// nothing shown on the page (uat/artifacts/fresh-user-native.md Finding 7).
/// The controls must be gated on the `access` the read reports.
#[tokio::test]
async fn credential_detail_hides_the_controls_a_read_share_refuses() {
    let (ctx, cookie) = admin_session().await;
    let id = uuid::Uuid::new_v4().to_string();

    for uri in credential_detail_surfaces(&id) {
        let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{uri}");

        assert_contains(
            &body,
            &uri,
            "credential.access === 'shared_read'",
            "the page reads the access the API reports",
        );
        assert_contains(
            &body,
            &uri,
            r#"id="cred-shared-read-notice""#,
            "and says so, rather than leaving the recipient to click and fail",
        );
        assert_contains(
            &body,
            &uri,
            r#"x-if="!editing && !isSharedRead()""#,
            "Edit and Delete are withheld from a read-share recipient",
        );
        assert_contains(
            &body,
            &uri,
            r#"x-show="!revealedSecret && !isSharedRead()""#,
            "Reveal Secret is withheld from a read-share recipient",
        );
        assert_contains(
            &body,
            &uri,
            r#"class="detail-card grant-card" x-show="!isSharedRead()""#,
            "Grant Permissions is withheld from a read-share recipient",
        );

        // A refusal the page did not predict must still be shown.
        assert_contains(
            &body,
            &uri,
            "reportError(resp",
            "a failed fetch surfaces the server's message instead of failing into the console",
        );
    }
}

/// A viewer holds no `create` on System, so the credential form answers 403
/// however they reach it. The list must not offer the button.
#[tokio::test]
async fn the_credential_list_offers_a_viewer_no_add_control() {
    let (ctx, cookie) = viewer_session().await;
    let uri = "/credentials";

    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("Add Credential"),
        "/credentials: a viewer is not offered Add Credential — storing one needs `create`"
    );

    // An admin still is.
    let (ctx, cookie) = admin_session().await;
    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_contains(&body, uri, "Add Credential", "an admin may store one");
}

/// `credential_type` has one name in the docs, the CLI and the API, and the
/// UI used three other vocabularies for it — `generic` was labelled "API Key"
/// directly above the two types that really are API keys
/// (uat/artifacts/fresh-user-docker.md F-7). Every surface names the type.
#[tokio::test]
async fn the_credential_type_picker_uses_the_documented_type_names() {
    let (ctx, cookie) = admin_session().await;

    let (status, body) = get_page(&ctx.app, "/credentials/new", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    for option in [
        "generic — bearer token or any secret",
        "api_key_header — custom header",
        "api_key_query — query parameter",
        "aws — SigV4",
        "oauth2_client_credentials — application",
    ] {
        assert_contains(
            &body,
            "/credentials/new",
            option,
            "the type picker names the type the docs name",
        );
    }
    // The sixth type is minted by the OAuth2 MCP install, and the form says so.
    assert_contains(
        &body,
        "/credentials/new",
        "oauth2_user_authorization",
        "the picker accounts for the sixth type rather than pretending to five",
    );
    for invented in [
        ">API Key<",
        ">API Key (custom header)<",
        ">AWS Credentials<",
        ">OAuth2 Client Credentials<",
    ] {
        assert!(
            !body.contains(invented),
            "/credentials/new: the picker still offers the invented label {invented:?}"
        );
    }

    // The pill and the list read the same name, with the gloss beside it.
    let (_, shell) = get_page(&ctx.app, "/credentials", &cookie).await;
    for gloss in [
        "generic: 'bearer token or any secret'",
        "api_key_header: 'custom header'",
        "api_key_query: 'query parameter'",
        "aws: 'SigV4'",
        "oauth2_client_credentials: 'application'",
        "oauth2_user_authorization: 'delegated'",
    ] {
        assert_contains(
            &shell,
            "/credentials",
            gloss,
            "the shared label table glosses each documented type",
        );
    }
    assert!(
        !shell.contains("generic: 'API Key'"),
        "/credentials: credTypeLabel still renames `generic` to \"API Key\""
    );
}

/// `transform_name` is documented but had no field on either credential form,
/// so the one shape that needs it — a `generic` credential injected as HTTP
/// Basic — could not be made from the admin UI at all
/// (uat/artifacts/fresh-user-native.md Finding 5). Only `generic` gets the
/// choice: every other type's injection follows from the type.
#[tokio::test]
async fn the_credential_forms_offer_a_transform_for_the_generic_type() {
    let (ctx, cookie) = admin_session().await;

    let (status, body) = get_page(&ctx.app, "/credentials/new", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_contains(
        &body,
        "/credentials/new",
        r#"id="cred-transform""#,
        "the New Credential form has a Transform select",
    );
    assert_contains(
        &body,
        "/credentials/new",
        "form.credentialType === 'generic'",
        "and offers it for `generic` only",
    );
    assert_contains(
        &body,
        "/credentials/new",
        "body.transform_name = this.form.transformName",
        "and submits it as transform_name",
    );

    let id = uuid::Uuid::new_v4().to_string();
    for uri in credential_detail_surfaces(&id) {
        let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert!(
            body.contains(r#"id="cred-transform-select""#)
                || body.contains(r#"id="cred-pane-transform-select""#),
            "{uri}: the Edit form has a Transform select"
        );
        assert_contains(
            &body,
            &uri,
            "body.transform_name = this.editForm.transformName",
            "and the edit submits it as transform_name",
        );
        assert_contains(
            &body,
            &uri,
            "isGeneric()",
            "gated on the type that has a choice to make",
        );
    }

    // Custom header and query placement come from the type, not a transform.
    for uri in ["/credentials/new".to_string(), format!("/credentials/{id}")] {
        let (_, body) = get_page(&ctx.app, &uri, &cookie).await;
        assert!(
            body.contains("is not a transform"),
            "{uri}: the form says custom header / query parameter come from the type"
        );
    }
}

/// Every value the Transform select offers must be one the API the form posts
/// to accepts, or the control is a 400 generator. `aws-sigv4` is not offered:
/// the `aws` type implies it.
#[tokio::test]
async fn every_transform_the_form_offers_is_accepted_by_the_api() {
    let (ctx, cookie) = admin_session().await;

    for (i, transform) in ["bearer", "basic-auth", "identity"].iter().enumerate() {
        let (status, body) = common::send_json_auto_csrf(
            &ctx.app,
            Method::POST,
            "/api/v1/credentials",
            None,
            Some(&cookie),
            Some(serde_json::json!({
                "name": format!("ctl-transform-{i}"),
                "service": "svc",
                "secret_value": "s3cret",
                "credential_type": "generic",
                "transform_name": transform,
            })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the form offers transform_name {transform:?}: {body}"
        );
        assert_eq!(body["data"]["transform_name"], *transform, "{body}");
    }
}

// ---------------------------------------------------------------------------
// Shared UI primitives — `AC.*` (uat/artifacts/reviews/UI-REVIEW findings A1, A2, B2, B3, M6,
// M7, M8, M13)
//
// The admin UI grew by copy-and-paste: four confirmation patterns (a partial,
// twelve inline modals, native `confirm()`/`prompt()`/`alert()`), 21 hand-rolled
// copies of `reportApiError`, and mutating fetches that never look at the
// response. These tests are the guard rails for the one set of primitives that
// replaces them, and they read the template sources directly because none of
// this is visible at the HTTP seam.
// ---------------------------------------------------------------------------

fn templates_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates")
}

fn static_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static")
}

fn all_templates() -> Vec<(PathBuf, String)> {
    let mut files = Vec::new();
    html_files(&templates_dir(), &mut files);
    assert!(!files.is_empty(), "no templates found");
    files.sort();
    files
        .into_iter()
        .map(|p| {
            let src = std::fs::read_to_string(&p).expect("read template");
            (p, src)
        })
        .collect()
}

fn rel(path: &Path) -> String {
    path.strip_prefix(templates_dir())
        .unwrap_or(path)
        .display()
        .to_string()
}

fn ac_js() -> String {
    std::fs::read_to_string(static_dir().join("js/ac.js"))
        .expect("static/js/ac.js — the shared UI primitives module must exist")
}

fn vault_css() -> String {
    std::fs::read_to_string(static_dir().join("css/vault.css")).expect("read vault.css")
}

/// One module defines every shared primitive, and `base.html` loads it on every
/// page (including the standalone activate/consent/login shells, which override
/// `{% block body %}` but not `{% block head %}`).
#[test]
fn base_html_loads_the_shared_ac_primitives_module() {
    let base = std::fs::read_to_string(templates_dir().join("base.html")).expect("read base.html");
    assert!(
        base.contains("/js/ac.js"),
        "base.html must load /js/ac.js so every page has AC.confirm / AC.fetch / AC.reportError"
    );

    let src = ac_js();
    for needed in [
        "AC.confirm",
        "AC.modal",
        "AC.fetch",
        "AC.reportError",
        "AC.toast",
    ] {
        assert!(src.contains(needed), "static/js/ac.js must define {needed}");
    }
    assert!(
        src.contains("window.reportApiError"),
        "the old global name reportApiError must stay as an alias of AC.reportError"
    );
}

/// A1/M7: one dialog component, focus-managed. The markup lives in `base.html`
/// so every page has it; the behaviour lives in `ac.js`.
#[test]
fn the_shared_confirm_dialog_is_focus_managed() {
    let base = std::fs::read_to_string(templates_dir().join("base.html")).expect("read base.html");
    assert!(
        base.contains(r#"id="ac-confirm""#),
        "base.html must render the one shared confirm dialog"
    );
    for attr in [
        r#"role="dialog""#,
        r#"aria-modal="true""#,
        "aria-labelledby",
    ] {
        assert!(
            base.contains(attr),
            "the shared confirm dialog must carry {attr}"
        );
    }
    assert!(
        base.contains(r#"id="ac-confirm-cancel""#),
        "initial focus goes to Cancel, so it must be addressable"
    );

    let src = ac_js();
    for behaviour in ["inert", "Escape", "Tab", "restore"] {
        assert!(
            src.contains(behaviour),
            "ac.js must implement modal {behaviour} handling"
        );
    }
}

/// B2: the four confirmation patterns collapse into `AC.confirm`. Native
/// dialogs are modal to the whole browser, unstyleable and untestable.
#[test]
fn no_template_uses_a_native_confirm_prompt_or_alert() {
    let mut offenders = Vec::new();
    for (path, src) in all_templates() {
        for (i, line) in src.lines().enumerate() {
            let hit = ["confirm(", "prompt(", "alert("].iter().any(|native| {
                line.match_indices(native).any(|(at, _)| {
                    // `AC.confirm(`, `this.confirm(`, `confirmDelete(` etc. are
                    // ours; a native call is preceded by nothing or by `window.`.
                    let before = &line[..at];
                    if before.ends_with("window.") {
                        return true;
                    }
                    let ident_char = before
                        .chars()
                        .next_back()
                        .is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '$' || c == '.');
                    !ident_char
                })
            });
            if hit {
                offenders.push(format!("{}:{}: {}", rel(&path), i + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "native confirm()/prompt()/alert() must be AC.confirm / a form field / a toast:\n  {}",
        offenders.join("\n  ")
    );
}

/// `partials/delete_modal.html` was one of four confirmation shapes and the
/// only one that said "Confirm Delete" while the inline copies named the thing.
#[test]
fn the_delete_modal_partial_is_retired() {
    assert!(
        !templates_dir().join("partials/delete_modal.html").exists(),
        "partials/delete_modal.html must be replaced by AC.confirm"
    );
    let mut users = Vec::new();
    for (path, src) in all_templates() {
        if src.contains("partials/delete_modal.html") {
            users.push(rel(&path));
        }
    }
    assert!(
        users.is_empty(),
        "still including the retired partial: {users:?}"
    );
}

/// M6/M8/B3: every mutating call goes through `AC.fetch`, which adds the CSRF
/// header and turns a 401 into a redirect to `/login?next=…`. A raw `fetch`
/// with `method: 'POST'` is a call that fails silently when the session dies.
#[test]
fn every_mutating_fetch_goes_through_ac_fetch() {
    let mut offenders = Vec::new();
    for (path, src) in all_templates() {
        for verb in ["'POST'", "'PUT'", "'DELETE'", "'PATCH'"] {
            for (at, _) in src.match_indices(verb) {
                // Only a `method:` option, not a string in a comment or a label.
                let before = &src[at.saturating_sub(40)..at];
                if !before.contains("method") {
                    continue;
                }
                let Some(fetch_at) = src[..at].rfind("fetch(") else {
                    continue;
                };
                if src[..fetch_at].ends_with("AC.") {
                    continue;
                }
                let line = src[..fetch_at].matches('\n').count() + 1;
                offenders.push(format!("{}:{line}", rel(&path)));
            }
        }
    }
    offenders.sort();
    offenders.dedup();
    assert!(
        offenders.is_empty(),
        "these mutating fetches bypass AC.fetch (no CSRF header, no 401 redirect):\n  {}",
        offenders.join("\n  ")
    );
}

/// A2/M13: toasts are dispatched through one helper, so "never toast an empty
/// string" and "errors are assertive and persistent" are decided in one place.
#[test]
fn no_template_dispatches_a_toast_event_by_hand() {
    let mut offenders = Vec::new();
    for (path, src) in all_templates() {
        if rel(&path) == "partials/toast.html" {
            continue;
        }
        for (i, line) in src.lines().enumerate() {
            if line.contains("CustomEvent('toast'") || line.contains("CustomEvent(\"toast\"") {
                offenders.push(format!("{}:{}", rel(&path), i + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "dispatch toasts with showToast()/AC.toast(), which refuses an empty message:\n  {}",
        offenders.join("\n  ")
    );
}

/// A2: an error toast must be announced assertively, stay until dismissed, and
/// carry a close button; a success stays polite and auto-dismisses.
#[test]
fn error_toasts_are_assertive_persistent_and_dismissable() {
    let src = std::fs::read_to_string(templates_dir().join("partials/toast.html"))
        .expect("read toast partial");
    assert!(
        src.contains("'alert'") && src.contains("'status'"),
        "the toast role must be alert for errors and status for successes"
    );
    assert!(
        src.contains("toast-close"),
        "every toast needs a close button"
    );
    assert!(
        src.contains("mouseenter") && src.contains("focusin"),
        "the auto-dismiss timer must pause on hover and focus"
    );
    assert!(
        !src.contains("'Something happened'"),
        "an empty toast message is refused, not padded with filler (M13)"
    );
}

/// M13: the helper itself refuses a blank message.
#[test]
fn the_toast_helper_refuses_an_empty_message() {
    let src = ac_js();
    let at = src
        .find("AC.toast = function")
        .expect("ac.js defines AC.toast");
    let window = &src[at..(at + 400).min(src.len())];
    assert!(
        window.contains("if (!message"),
        "AC.toast must return early on an empty message (M13); saw:\n{window}"
    );
}

/// M6: a 401 in the middle of a page action is a dead session, and the page
/// must say so on the login page rather than doing nothing.
#[test]
fn ac_fetch_redirects_to_login_with_a_session_expired_message() {
    let src = ac_js();
    assert!(src.contains("401"), "AC.fetch must notice a 401");
    assert!(
        src.contains("/login?next="),
        "AC.fetch must send the user to /login?next=<current>"
    );
    assert!(
        src.to_lowercase().contains("session expired"),
        "the login page must say why it asked for a password again"
    );
}

/// M8: a non-OK response never produces a success toast.
#[test]
fn ac_report_error_is_the_only_way_a_failed_response_is_announced() {
    let src = ac_js();
    assert!(
        src.contains("AC.reportError = async function"),
        "ac.js must define AC.reportError(resp, fallback)"
    );
    assert!(src.contains("'error'"), "AC.reportError toasts type error");
}

// ---------------------------------------------------------------------------
// Global layout — mobile drawer, table scrolling, sticky header (B3, B4, M5,
// A16)
// ---------------------------------------------------------------------------

/// B3: the mobile menu was a strip of unlabelled icons drawn over the heading.
#[test]
fn the_mobile_nav_is_a_labelled_drawer_with_a_backdrop() {
    let nav =
        std::fs::read_to_string(templates_dir().join("partials/nav.html")).expect("read nav.html");
    assert!(
        nav.contains("nav-drawer-backdrop"),
        "the open drawer needs a backdrop that closes it"
    );
    assert!(
        nav.contains("keydown.escape"),
        "Escape must close the drawer"
    );
    assert!(
        nav.contains("nav-drawer-close"),
        "the drawer needs a visible close control"
    );

    let css = vault_css();
    assert!(
        css.contains(".nav-drawer-backdrop"),
        "vault.css must style the drawer backdrop"
    );
    // The 480px rule hid every nav label, which is what made the drawer
    // unreadable in the review screenshots.
    assert!(
        !css.contains(".top-bar-nav .nav-link span:not(.nav-icon)"),
        "the drawer's links must keep their labels on narrow viewports"
    );
}

/// B4/M5: a `.tbl` on a phone clipped to one- and two-character columns,
/// because a `display: block` table shrink-wraps its anonymous table box and
/// leaves `overflow-x` nothing to scroll. The fix is a wrapper — and there are
/// forty-odd tables across the pages and the AJAX detail partials, so the
/// wrapper is added once, in `ac.js`, both for markup already on the page and
/// for markup that arrives later.
#[test]
fn every_table_scrolls_horizontally_instead_of_clipping() {
    let css = vault_css();
    let at = css
        .find(".tbl-scroll {")
        .expect("vault.css must define .tbl-scroll");
    assert!(
        css[at..].contains("overflow-x: auto"),
        ".tbl-scroll must scroll horizontally on a narrow viewport"
    );

    let js = ac_js();
    assert!(
        js.contains("table.tbl") && js.contains("'tbl-scroll'"),
        "ac.js must wrap every table.tbl in a .tbl-scroll container"
    );
    assert!(
        js.contains("MutationObserver"),
        "a table that arrives in an AJAX detail pane must be wrapped too"
    );

    // The old mobile rules turned the table itself into the scroll box, which
    // is the shape that clipped.
    assert!(
        !css.contains("    .tbl {\n        display: block;"),
        "the table must stay a table; the wrapper is what scrolls"
    );
}

/// A16: `.tbl th` sticks to `top: 0`, which is under the 56 px top bar.
#[test]
fn the_sticky_table_header_offsets_below_the_top_bar() {
    let css = vault_css();
    assert!(
        css.contains("--topbar-h"),
        "the 56 px top bar height must be a token, not a magic number"
    );
    let at = css.find(".tbl th {").expect(".tbl th rule");
    let rule = &css[at..at + 600];
    assert!(
        rule.contains("var(--topbar-h)"),
        "the sticky header must clear the top bar; saw:\n{rule}"
    );
}

/// C3: `.btn-approve` / `.btn-deny` are used by the device-activation pages but
/// were defined only in `consent.html`'s inline stylesheet, so the two buttons
/// of the RFC 8628 flow rendered as bare text.
#[test]
fn the_activation_buttons_are_styled_from_the_shared_stylesheet() {
    let css = vault_css();
    assert!(
        css.contains(".btn-approve") && css.contains(".btn-deny"),
        "vault.css must define .btn-approve and .btn-deny"
    );
    let consent =
        std::fs::read_to_string(templates_dir().join("consent.html")).expect("read consent.html");
    assert!(
        !consent.contains(".btn-approve {"),
        "consent.html must not keep a private copy of the rule"
    );
}

/// C3: sixteen classes the templates use render as nothing.
#[test]
fn vault_css_defines_every_class_the_templates_use() {
    let css = vault_css();
    let missing: Vec<&str> = [
        ".pill-sm",
        ".text-sm",
        ".text-lg",
        ".text-right",
        ".form-input-sm",
        ".alert",
        ".alert-warning",
        ".form-hint-warn",
        ".form-help",
        ".btn-icon",
        ".btn-icon-xs",
        ".pill-danger",
        ".pill-muted",
        ".close-btn",
        ".md-row-vault",
        ".audit-detail-td",
        ".audit-evt-icon-credential",
        ".tester-input-field",
        ".tester-result-summary",
    ]
    .into_iter()
    .filter(|c| {
        !css.contains(&format!("{c} "))
            && !css.contains(&format!("{c},"))
            && !css.contains(&format!("{c}{{"))
            && !css.contains(&format!("{c}:"))
    })
    .collect();
    assert!(
        missing.is_empty(),
        "used in templates but defined nowhere, so they render as nothing: {missing:?}"
    );
}

/// A6/C4: the policy pages fall back to a Tailwind palette because these tokens
/// are referenced but never defined.
#[test]
fn the_contrast_tokens_the_pages_reference_are_defined() {
    let css = vault_css();
    for token in ["--color-warn", "--color-link", "--bg-hover", "--faint"] {
        assert!(
            css.contains(&format!("{token}:")),
            "{token} is referenced by the pages with a hard-coded fallback; define it"
        );
    }
    // A6: the warn pill was 3.19:1 and the link colour 4.11:1.
    assert!(
        !css.contains("--warn: #b5850a"),
        "--warn must be darkened to pass 4.5:1 on --warn-bg"
    );
    assert!(
        css.contains("--ink-muted"),
        "opacity-muted text down to 2.5:1 must be replaced by a token colour"
    );
}

/// A6: `.btn-warning` is white on amber — 1.53:1 in dark mode.
#[test]
fn the_warning_button_label_is_legible_in_dark_mode() {
    let css = vault_css();
    let at = css.find(".btn-warning {").expect(".btn-warning rule");
    let rule = &css[at..at + 200];
    assert!(
        !rule.contains("color: #fff"),
        "a white label on amber fails AA in both themes; use an ink label:\n{rule}"
    );
}

/// M5: the New Credential form measured 401 px in a 390 px viewport.
#[test]
fn the_new_credential_form_fits_a_narrow_viewport() {
    let css = vault_css();
    let at = css
        .find(".template-grid")
        .expect(".template-grid must be constrained in vault.css");
    let rule = &css[at..(at + 400).min(css.len())];
    assert!(
        rule.contains("minmax("),
        "the grid must use minmax() so cards shrink instead of overflowing:\n{rule}"
    );
}

// ---------------------------------------------------------------------------
// Design review phase 1 — tokens and global components
// (uat/artifacts/reviews/DESIGN-REVIEW.md §3.2–§3.10)
//
// Phase 1 changes no template but `base.html`'s one preload line, so every
// assertion below reads `static/css/vault.css` as text and asserts the shape
// of the global rules. A per-page rule that contradicts one of these is
// phase 2's and phase 3's problem; a *global* one is this file's.
// ---------------------------------------------------------------------------

fn base_html() -> String {
    std::fs::read_to_string(templates_dir().join("base.html")).expect("read base.html")
}

/// The body of the first rule whose selector text matches `selector`.
/// `selector` must include the opening brace (`".card {"`) so `.card` does not
/// match `.card-title`.
fn css_rule<'a>(css: &'a str, selector: &str) -> &'a str {
    let at = css
        .find(selector)
        .unwrap_or_else(|| panic!("vault.css defines no `{selector}` rule"));
    let open = at + css[at..].find('{').expect("rule body");
    let close = open + css[open..].find('}').expect("rule end");
    &css[open + 1..close]
}

/// §3.2, the largest change in the review and invisible in a CSS diff: `--font`
/// named Inter and nothing ever loaded it, so every screenshot in the live
/// review was the OS fallback. Ship the face or stop naming it.
#[test]
fn the_ui_font_the_tokens_name_is_actually_shipped_and_loaded() {
    let css = vault_css();

    assert!(
        css.contains("@font-face"),
        "vault.css declares a UI face in --font and loads nothing; add an @font-face"
    );
    let face = css_rule(&css, "@font-face {");
    assert!(
        face.contains("InterVariable"),
        "the @font-face must name the family --font asks for:\n{face}"
    );
    assert!(
        face.contains("/fonts/InterVariable.woff2"),
        "the face must be self-hosted from static/fonts (no third-party font host — the CSP \
         allows none):\n{face}"
    );
    assert!(
        face.contains("font-display: swap"),
        "a blocking swap period leaves the page blank; use font-display: swap:\n{face}"
    );

    let token = css_rule(&css, ":root {");
    let font_line = token
        .lines()
        .find(|l| l.trim_start().starts_with("--font:"))
        .expect("--font token");
    assert!(
        font_line.contains("InterVariable"),
        "--font must name the face that is loaded first: {font_line}"
    );
    assert!(
        font_line.contains("ui-sans-serif") || font_line.contains("system-ui"),
        "the fallback stack must be explicit rather than trailing off into `sans-serif`: \
         {font_line}"
    );

    assert!(
        static_dir().join("fonts/InterVariable.woff2").exists(),
        "static/fonts/InterVariable.woff2 must ship with the binary (rust_embed serves \
         static/)"
    );
    assert!(
        static_dir().join("fonts/LICENSE").exists(),
        "the OFL text and the version the font came from must travel with the file"
    );

    let shell = base_html();
    assert!(
        shell.contains("rel=\"preload\"")
            && shell.contains("as=\"font\"")
            && shell.contains("/fonts/InterVariable.woff2"),
        "base.html must preload the face; discovering it through the stylesheet costs a \
         second round trip and a flash of fallback text"
    );
    assert!(
        shell.contains("crossorigin"),
        "a font preload without `crossorigin` is fetched twice"
    );
}

/// §3.2: numerals in tables, counts and timestamps must be tabular, or a column
/// of ids and dates fails to line up.
#[test]
fn the_numerals_that_line_up_in_a_column_are_tabular() {
    let css = vault_css();
    for selector in [".tbl {", ".dash-card-count {", ".timestamp {"] {
        let rule = css_rule(&css, selector);
        assert!(
            rule.contains("tabular-nums") || rule.contains("\"tnum\""),
            "{selector} shows numerals in a column and must set tabular figures:\n{rule}"
        );
    }
}

/// §3.2: the seven-step scale exists as tokens and the pages ignore it (22 px
/// titles, 18 px card headings, 11 px pills). Enforce it once, on the global
/// selectors, so a page that writes a bare `<h1>` lands on the scale.
#[test]
fn the_type_scale_is_enforced_by_the_global_selectors() {
    let css = vault_css();

    for (selector, token) in [
        // Page title: 24/600.
        ("h1,", "--text-2xl"),
        (".page-title,", "--text-2xl"),
        (".content-header h2 {", "--text-2xl"),
        // Card and detail title: 16/600.
        (".card-title {", "--text-lg"),
        (".detail-header h3 {", "--text-lg"),
        (".dash-section-title {", "--text-lg"),
        // Meta and table headers: 13/500.
        (".meta {", "--text-sm"),
        (".tbl th {", "--text-sm"),
        // Pills: 12. 11 px is below the floor the review sets.
        (".pill {", "--text-xs"),
    ] {
        let rule = css_rule(&css, selector);
        assert!(
            rule.contains(&format!("var({token})")),
            "{selector} must take its size from {token}, not a literal:\n{rule}"
        );
    }

    // Weights: 400, 500, 600. Nothing heavier.
    for heavy in ["font-weight: 700", "font-weight: 800", "font-weight: bold"] {
        assert!(
            !css.contains(heavy),
            "vault.css still uses `{heavy}`; the scale allows 400/500/600 only"
        );
    }

    // Two line heights, and both are tokens so a page cannot invent a third.
    assert!(
        css.contains("--leading-body: 1.5") && css.contains("--leading-heading: 1.25"),
        "text you read is 1.5 and text you scan is 1.25; both are tokens"
    );
    let body = css_rule(&css, "\nbody {");
    assert!(
        body.contains("line-height: 1.5"),
        "body line-height is 1.5, not 1.6:\n{body}"
    );
    let headings = css_rule(&css, "h1,");
    assert!(
        headings.contains("var(--leading-heading)"),
        "headings scan at 1.25:\n{headings}"
    );
}

/// §3.3: `--sp-1 … --sp-12` are defined and referenced by nothing. The global
/// components are where the rhythm has to start.
#[test]
fn the_global_components_space_on_the_four_pixel_scale() {
    let css = vault_css();

    for (selector, why) in [
        (".card {", "card padding 24 → 20"),
        (".btn {", "button padding 8/16 → 8/12"),
        (".form-input {", "input padding 8/12"),
        (".form-group {", "form group 22 → 16"),
        (".tbl td {", "cell padding 10/12"),
        (".detail-row {", "detail row 12 → 8"),
        (".pill {", "pill padding 2/8"),
    ] {
        let rule = css_rule(&css, selector);
        assert!(
            rule.contains("var(--sp-"),
            "{selector} ({why}) still hard-codes its spacing:\n{rule}"
        );
    }

    // Control heights are tokens: 32 in a toolbar or a table row, 36 in a form.
    assert!(
        css.contains("--control-h: 32px") && css.contains("--control-h-lg: 36px"),
        "the two control heights must be tokens, not repeated literals"
    );
    let btn = css_rule(&css, ".btn {");
    assert!(
        btn.contains("var(--control-h)"),
        "the default button is the 32 px toolbar control:\n{btn}"
    );

    // A table row is 40 px, not 44.
    let td = css_rule(&css, ".tbl td {");
    assert!(
        !td.contains("height: 44px"),
        "table rows tighten from 44 to 40:\n{td}"
    );
    assert!(
        td.contains("var(--row-h)"),
        "the row height is a token so the density change happens in one place:\n{td}"
    );
    assert!(css.contains("--row-h: 40px"), "--row-h is 40px");
}

/// §3.4: a card carried a border *and* a shadow, `.detail-card` a shadow and no
/// border, the login card neither. One rule: resting surfaces are bordered,
/// floating ones are shadowed.
#[test]
fn resting_surfaces_are_bordered_and_only_floating_ones_are_shadowed() {
    let css = vault_css();

    for selector in [".card {", ".detail-card {", ".dash-card {"] {
        let rule = css_rule(&css, selector);
        assert!(
            rule.contains("border: 1px solid var(--line)"),
            "{selector} is a resting surface: 1px --line border:\n{rule}"
        );
        assert!(
            !rule.contains("box-shadow"),
            "{selector} is a resting surface and must not float:\n{rule}"
        );
    }

    for selector in [".modal {", ".modal-card {", ".toast {"] {
        let rule = css_rule(&css, selector);
        assert!(
            rule.contains("box-shadow"),
            "{selector} floats above the page and keeps its shadow:\n{rule}"
        );
    }

    // A linked tile changes its border on hover, nothing else.
    let hover = css_rule(&css, "a.dash-card-link:hover {");
    assert!(
        !hover.contains("box-shadow") && !hover.contains("transform"),
        "a hovered tile moves its border colour and nothing else:\n{hover}"
    );

    // Rules between rows, never a zebra.
    assert!(
        !css.contains("nth-child(odd)") && !css.contains("nth-child(even)"),
        "tables are ruled, not striped"
    );

    // The active nav tab is an underline; the wash behind it was a second
    // signal saying the same thing.
    let active = css_rule(&css, ".nav-link.nav-active {");
    assert!(
        !active.contains("background: var(--accent-glow)"),
        "the underline is the active signal; drop the wash:\n{active}"
    );
}

/// §3.5: five radius tokens plus three legacy aliases, and templates mixing
/// `--r-sm` with `--radius-sm` for the same corner. Four tokens: 4/6/8/12.
#[test]
fn the_radius_tokens_collapse_to_four() {
    let css = vault_css();
    for (token, value) in [
        ("--radius-xs", "4px"),
        ("--radius-sm", "6px"),
        ("--radius-md", "8px"),
        ("--radius-lg", "12px"),
    ] {
        assert!(
            css.contains(&format!("{token}: {value}")),
            "{token} must be {value}"
        );
    }
    assert!(
        !css.contains("--radius-pill"),
        "nothing in the product is a capsule; the toggle switch keeps its own literal"
    );
    for legacy in ["var(--r)", "var(--r-sm)", "var(--radius)"] {
        assert!(
            !css.contains(legacy),
            "vault.css still reaches for the legacy alias `{legacy}`; map it to one of the \
             four canonical tokens (the alias itself stays defined only until the two inline \
             styles left in dashboard.html and login.html go in phase 3)"
        );
    }
}

/// §3.6: outside the nav and the dashboard tiles the UI draws its icons with
/// text glyphs, which render in whatever the fallback font has and sit at the
/// wrong baseline. One sprite, added now, used in phase 3.
#[test]
fn the_icon_sprite_ships_with_a_utility_class() {
    let sprite = std::fs::read_to_string(static_dir().join("icons.svg"))
        .expect("static/icons.svg — the shared Lucide sprite");

    for name in [
        "search",
        "plus",
        "pencil",
        "trash",
        "more-horizontal",
        "copy",
        "eye",
        "eye-off",
        "refresh-cw",
        "external-link",
        "check",
        "x",
        "chevron-down",
        "chevron-right",
        "chevron-up",
        "arrow-left",
        "arrow-up",
        "arrow-down",
        "shield",
        "key",
        "users",
        "server",
        "file-text",
        "settings",
        "log-out",
        "sun",
        "moon",
        "alert-triangle",
        "info",
    ] {
        assert!(
            sprite.contains(&format!("id=\"{name}\"")),
            "the sprite is missing the `{name}` symbol the review lists"
        );
    }
    assert!(
        static_dir().join("icons.LICENSE").exists(),
        "the icon set's licence and version must travel with the sprite"
    );

    let css = vault_css();
    let icon = css_rule(&css, ".icon {");
    assert!(
        icon.contains("currentColor"),
        "an icon takes the colour of the control it sits in:\n{icon}"
    );
    assert!(
        css.contains(".icon-lg"),
        "the nav draws at 20 px; give the size a class rather than an inline style"
    );
}

/// §3.8: colour means state; a category is grey. Auth mode is not a status, and
/// amber on OAuth read as a warning on every marketplace card.
#[test]
fn a_category_pill_is_grey_and_only_a_status_pill_carries_colour() {
    let css = vault_css();

    for token in [
        "--state-ok",
        "--state-warn",
        "--state-bad",
        "--state-neutral",
    ] {
        assert!(
            css.contains(&format!("{token}:")),
            "{token} must name what a pill means, so a page picks a meaning not a colour"
        );
    }

    let at = css
        .find(".pill-neutral,")
        .expect("vault.css must define .pill-neutral and alias the category pills to it");
    let block = &css[at..at + css[at..].find('}').expect("rule end")];
    assert!(
        block.contains("var(--state-neutral)"),
        "the neutral pill is the one grey every category shares:\n{block}"
    );
    for alias in [".pill-type", ".pill-scope", ".pill-info", ".pill-muted"] {
        assert!(
            block.contains(alias),
            "{alias} is a category, so it renders as the neutral pill:\n{block}"
        );
    }

    // The three status pills keep their colour.
    for (selector, token) in [
        (".pill-ok {", "--state-ok"),
        (".pill-warn {", "--state-warn"),
        (".pill-bad {", "--state-bad"),
    ] {
        let rule = css_rule(&css, selector);
        assert!(
            rule.contains(&format!("var({token})")),
            "{selector} is a state and takes {token}:\n{rule}"
        );
    }

    // `--info` survives for informational banners only.
    assert!(
        css.contains("--info:"),
        "--info stays defined; the informational banners use it"
    );
}

/// §3.9: the dark palette is zinc (blue-grey) under a light palette that is
/// warm (yellow-grey), so a dark page reads as a different product.
#[test]
fn the_dark_surfaces_are_warm_like_the_light_ones() {
    let css = vault_css();
    let dark = css_rule(&css, "[data-theme=\"dark\"] {");

    for (token, value) in [
        ("--wash", "#161514"),
        ("--surface", "#1f1e1c"),
        ("--line", "#2e2c29"),
        ("--ink", "#ece9e4"),
        ("--ink-soft", "#b3ada4"),
        ("--secondary-hover-bg", "#2a2825"),
    ] {
        assert!(
            dark.contains(&format!("{token}: {value}")),
            "dark {token} must warm to {value}:\n{dark}"
        );
    }
    // The accent is the one thing that does not move.
    assert!(
        dark.contains("--accent: #e8743a"),
        "the dark accent stays:\n{dark}"
    );
    for zinc in ["#18181b", "#27272a", "#3f3f46", "#e4e4e7", "#a1a1aa"] {
        assert!(
            !dark.contains(zinc),
            "dark palette still carries the zinc value {zinc}"
        );
    }
}

/// §3.9 again, but arithmetic rather than a value match: the retuned dark
/// palette must still clear AA on the surfaces it is painted on, and each state
/// colour must clear it on its own 10 % tint, which is what a pill is.
#[test]
fn every_dark_text_token_still_clears_aa_on_its_surface() {
    fn channel(hex: &str, at: usize) -> f64 {
        f64::from(u8::from_str_radix(&hex[at..at + 2], 16).expect("hex pair")) / 255.0
    }
    fn linear(c: f64) -> f64 {
        if c <= 0.04045 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    }
    fn luminance(hex: &str) -> f64 {
        let h = hex.trim_start_matches('#');
        0.2126 * linear(channel(h, 0))
            + 0.7152 * linear(channel(h, 2))
            + 0.0722 * linear(channel(h, 4))
    }
    fn ratio(a: &str, b: &str) -> f64 {
        let (x, y) = (luminance(a), luminance(b));
        let (hi, lo) = if x > y { (x, y) } else { (y, x) };
        (hi + 0.05) / (lo + 0.05)
    }
    /// A 10 % tint of `fg` over `bg` — what a `.pill-ok` background is.
    fn tint(fg: &str, bg: &str) -> String {
        let (f, b) = (fg.trim_start_matches('#'), bg.trim_start_matches('#'));
        let mut out = String::from("#");
        for i in 0..3 {
            let at = i * 2;
            let v = channel(f, at) * 0.10 + channel(b, at) * 0.90;
            out.push_str(&format!("{:02x}", (v * 255.0).round() as u8));
        }
        out
    }

    let css = vault_css();
    let dark = css_rule(&css, "[data-theme=\"dark\"] {").to_string();
    let value = |token: &str| -> String {
        let at = dark
            .find(&format!("{token}: "))
            .unwrap_or_else(|| panic!("the dark palette defines no {token}"));
        let from = at + token.len() + 2;
        let to = from + dark[from..].find(';').expect("declaration end");
        dark[from..to].trim().to_string()
    };

    let surface = value("--surface");
    let wash = value("--wash");

    for token in ["--ink", "--ink-soft", "--ink-faint", "--ink-muted"] {
        let colour = value(token);
        for (name, bg) in [("--surface", &surface), ("--wash", &wash)] {
            let r = ratio(&colour, bg);
            assert!(
                r >= 4.5,
                "dark {token} ({colour}) is {r:.2}:1 on {name} ({bg}) — AA body text needs 4.5"
            );
        }
    }

    for token in ["--safe", "--warn", "--danger", "--info", "--accent"] {
        let colour = value(token);
        let bg = tint(&colour, &surface);
        let r = ratio(&colour, &bg);
        assert!(
            r >= 4.5,
            "dark {token} ({colour}) is {r:.2}:1 as pill text on its own 10 % tint ({bg})"
        );
    }
}

/// §3.10: content must not move on arrival, a hover must not move a control,
/// and everything must stop for a reader who asked for less motion.
#[test]
fn motion_is_capped_and_reduced_motion_is_honoured() {
    let css = vault_css();

    assert!(
        !css.contains("mdDetailFadeIn"),
        "the detail pane's fade-and-rise is what the review screenshots caught mid-way; \
         content should not move on arrival"
    );
    // A row tag is a label now, not a button; nothing under the pointer moves.
    assert!(
        !css.contains(".md-row-tag-btn"),
        "the row tag stopped being a second filter button (uat/artifacts/reviews/DESIGN-REVIEW.md 1.4)"
    );
    let modal_in = css_rule(&css, "@keyframes modalFadeIn {");
    assert!(
        !modal_in.contains("transform"),
        "the modal fades; it does not rise:\n{modal_in}"
    );

    // Every transition is 150 ms or less.
    for (n, line) in css.lines().enumerate() {
        let Some(at) = line.find("transition") else {
            continue;
        };
        for token in line[at..].split([',', ' ', ';']) {
            let ms = if let Some(v) = token.strip_suffix("ms") {
                v.parse::<f64>().ok()
            } else if let Some(v) = token.strip_suffix('s') {
                v.parse::<f64>().ok().map(|s| s * 1000.0)
            } else {
                None
            };
            if let Some(ms) = ms {
                assert!(
                    ms <= 150.0,
                    "vault.css:{}: a {ms} ms transition — the cap is 150 ms\n{line}",
                    n + 1
                );
            }
        }
    }

    let reduced = css_rule(&css, "@media (prefers-reduced-motion: reduce) {");
    assert!(
        reduced.contains("animation-duration: 0.01ms !important")
            && reduced.contains("transition-duration: 0.01ms !important"),
        "one global rule must stop animation and transition for a reader who asked:\n{reduced}"
    );
}

// ---------------------------------------------------------------------------
// M14 — disabling a workspace is destructive and must be confirmed
// ---------------------------------------------------------------------------

/// Revoke has a full warning modal; Disable flipped the status on one click and
/// every agent lost access with no toast.
#[tokio::test]
async fn disabling_a_workspace_asks_for_confirmation_first() {
    let (ctx, cookie) = admin_session().await;
    let (ws, _) =
        common::create_agent_in_db(&*ctx.store, "ctl-disable-ws", vec![], true, None).await;

    for uri in workspace_detail_surfaces(&ws.id.0.to_string()) {
        let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert!(
            body.contains("AC.confirm"),
            "{uri}: Disable must confirm before agents lose access (M14)"
        );
        let lower = body.to_lowercase();
        assert!(
            lower.contains("lose access") || lower.contains("stop working"),
            "{uri}: the confirmation must say what stops working"
        );
    }
}

// ---------------------------------------------------------------------------
// Dashboard, audit and history — one vocabulary, one query, one reload
// (uat/artifacts/reviews/UI-REVIEW-live.md M11 and m1, uat/artifacts/reviews/UI-REVIEW-static.md J3)
// ---------------------------------------------------------------------------

/// The wire name of an audit event type: what `GET /api/v1/audit?event_type=`
/// matches on, and the only string a page may ask for.
fn wire_name(t: agent_cordon_core::domain::audit::AuditEventType) -> String {
    serde_json::to_value(t)
        .expect("event type serializes")
        .as_str()
        .expect("event type is a string")
        .to_string()
}

/// The dashboard's "Recent MCP Activity" widget asked for `mcp_tool_call` and
/// `mcp_tool_denied`. `McpServerService::record_tool_called` writes
/// `mcp_tool_called` and `record_tool_call_denied` writes
/// `mcp_tool_call_denied`, so the widget matched nothing and said "No MCP
/// activity yet" while the workspace History tab listed the same calls
/// (uat/artifacts/reviews/UI-REVIEW-live.md M11). The page must name the strings the server
/// writes.
#[tokio::test]
async fn the_dashboard_asks_for_the_mcp_event_types_the_server_writes() {
    use agent_cordon_core::domain::audit::AuditEventType;
    let (ctx, cookie) = admin_session().await;

    let (status, body) = get_page(&ctx.app, "/dashboard", &cookie).await;
    assert_eq!(status, StatusCode::OK);

    for t in [
        AuditEventType::McpToolCalled,
        AuditEventType::McpToolCallDenied,
    ] {
        let name = wire_name(t);
        assert!(
            body.contains(&format!("'{name}'")),
            "/dashboard: the MCP activity widget must query {name:?}, the event type the \
             MCP service writes"
        );
    }

    assert!(
        !body.contains("'mcp_tool_denied'"),
        "/dashboard: `mcp_tool_denied` is written by nothing; querying it is what made the \
         widget claim there was no MCP activity"
    );
}

/// Every table that shows an audit event names its type the same way. The
/// Dashboard and Audit pages ran `eventTypeLabel`; the four History tabs
/// printed the raw `mcp_tool_called` / `credential_secret_rotated`
/// (uat/artifacts/reviews/UI-REVIEW-live.md m1).
#[test]
fn every_surface_that_shows_an_event_type_labels_it() {
    let templates = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates");
    let mut files = Vec::new();
    html_files(&templates, &mut files);

    let mut offenders = Vec::new();
    for file in &files {
        let src = std::fs::read_to_string(file).expect("read template");
        for (i, line) in src.lines().enumerate() {
            for raw in [
                r#"x-text="ev.event_type""#,
                r#"x-text="evt.event_type""#,
                r#"x-text="event && event.event_type""#,
                r#"x-text="evt.action || evt.event_type""#,
            ] {
                if line.contains(raw) {
                    offenders.push(format!("{}:{}", file.display(), i + 1));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "an event type shown to a reader goes through eventTypeLabel(); these print the raw \
         wire name:\n  {}",
        offenders.join("\n  ")
    );
}

/// The same event named a different principal on two pages: the Dashboard read
/// `user_name || workspace_name`, the Audit page `workspace_name || user_name`
/// (uat/artifacts/reviews/UI-REVIEW-static.md B4). One helper decides.
#[test]
fn one_helper_names_the_principal_of_an_audit_event() {
    let templates = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates");
    let mut files = Vec::new();
    html_files(&templates, &mut files);

    let mut offenders = Vec::new();
    for file in &files {
        // base.html is where the one helper is defined.
        if file.file_name().is_some_and(|n| n == "base.html") {
            continue;
        }
        let src = std::fs::read_to_string(file).expect("read template");
        for (i, line) in src.lines().enumerate() {
            if line.contains("workspace_name") && line.contains("user_name") && line.contains("||")
            {
                offenders.push(format!("{}:{}  {}", file.display(), i + 1, line.trim()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "an audit event's principal comes from eventPrincipal() in base.html, not from an \
         inline precedence that differs per page:\n  {}",
        offenders.join("\n  ")
    );

    let base = std::fs::read_to_string(templates.join("base.html")).expect("read base.html");
    assert!(
        base.contains("function eventPrincipal("),
        "base.html defines the one helper the pages call"
    );
}

/// One `ac:audit_event` re-ran `refresh()`, which is one stats fetch plus four
/// audit fetches — five requests per audit row on a busy broker
/// (uat/artifacts/reviews/UI-REVIEW-static.md J3). SSE-driven reloads coalesce, and the
/// listeners are registered once.
#[test]
fn the_dashboard_coalesces_sse_driven_reloads() {
    let dashboard =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates/pages/dashboard.html");
    let src = std::fs::read_to_string(&dashboard).expect("read dashboard.html");

    assert!(
        !src.contains("=> this.refresh()"),
        "dashboard.html: an SSE listener must not call refresh() directly — a burst of audit \
         events then costs five fetches each"
    );
    assert!(
        src.contains("scheduleRefresh"),
        "dashboard.html: SSE events go through a coalescing scheduleRefresh()"
    );
    assert!(
        src.contains("_sseBound"),
        "dashboard.html: the SSE listeners are registered once per page, not once per init()"
    );
}

// ---------------------------------------------------------------------------
// Dead front-end code
// (uat/artifacts/reviews/UI-REVIEW-static.md C1, C2, J8, T2, T6)
// ---------------------------------------------------------------------------

/// Every file under `templates/` and `static/`, for the "nothing references
/// this any more" guards below. Alpine's own minified bundle is skipped: it is
/// vendored, not ours, and its identifiers are not our vocabulary.
fn front_end_sources() -> Vec<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    for dir in [root.join("templates"), root.join("static")] {
        let mut stack = vec![dir];
        while let Some(d) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue;
            };
            for entry in entries {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.file_name().is_some_and(|n| n != "alpine.min.js") {
                    out.push(path);
                }
            }
        }
    }
    out
}

/// Assert `needle` appears in no template, stylesheet or script of ours.
fn assert_unreferenced(needle: &str, why: &str) {
    let mut hits = Vec::new();
    for file in front_end_sources() {
        let Ok(src) = std::fs::read_to_string(&file) else {
            continue;
        };
        for (i, line) in src.lines().enumerate() {
            if line.contains(needle) {
                hits.push(format!("{}:{}", file.display(), i + 1));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "{needle:?} is gone: {why}. Still referenced at:\n  {}",
        hits.join("\n  ")
    );
}

/// `partials/audit_detail_pane.html` (and its route), `partials/pagination.html`
/// and `partials/csrf_meta.html` were dead: the audit page expands rows inline
/// and calls the API itself, nothing includes the pager, and the CSRF meta tag
/// was emitted on every page for no reader — `getCsrfToken` reads the cookie
/// (uat/artifacts/reviews/UI-REVIEW-static.md T1, T6, J8).
#[test]
fn the_dead_partials_are_deleted_and_nothing_includes_them() {
    let partials = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates/partials");
    for dead in [
        "audit_detail_pane.html",
        "pagination.html",
        "csrf_meta.html",
    ] {
        assert!(
            !partials.join(dead).exists(),
            "partials/{dead} is dead and must be deleted"
        );
        assert_unreferenced(dead, "the partial is deleted");
    }
    assert_unreferenced(
        r#"name="csrf-token""#,
        "no script reads the meta tag; getCsrfToken() reads the double-submit cookie",
    );
}

/// The slide-in panel in `base.html` shipped on every admin page — a
/// component, its markup and ~250 lines of CSS — and nothing has dispatched
/// `slide-panel-open` since #31. It also `x-html`s fetched HTML into the page,
/// which is the one place API-shaped markup could land unescaped
/// (uat/artifacts/reviews/UI-REVIEW-static.md T2).
#[test]
fn the_dead_slide_panel_is_deleted_everywhere() {
    for needle in [
        "slidePanel",
        "slide-panel",
        "slide-in-panel",
        "panel-header",
        "panel-body",
        "panel-section",
        "panel-grant-",
        "panel-tools-list",
    ] {
        assert_unreferenced(
            needle,
            "the slide panel is deleted (uat/artifacts/reviews/UI-REVIEW-static.md T2)",
        );
    }
}

/// Helpers that no markup and no other script calls. Each was found by
/// reading every template (uat/artifacts/reviews/UI-REVIEW-static.md J8); each is deleted with
/// the state it wrote.
#[test]
fn the_dead_javascript_helpers_are_deleted() {
    for (needle, why) in [
        (
            "setTypeFilter",
            "audit.html: no control calls it; the filter pills use toggleTypeFilter",
        ),
        (
            "typeFilterSingle",
            "audit.html: written by the All pill, read by nothing",
        ),
        (
            "templateMatches(",
            "credentials/new.html: the picker calls templateMatchesTpl(tpl)",
        ),
        ("useTemplate", "policies/new.html: no control calls it"),
        (
            "copyToClipboard",
            "workspaces/list.html: defined, never called",
        ),
        (
            "detailHtml",
            "the split-pane list pages write it and never read it",
        ),
        (
            "mcpLogoUrl",
            "mcp_servers/list.html: service-icons.js resolves a logo by exact key, not by \
             substring — \"Squarespace\" was getting the Square logo",
        ),
        (
            "mcpLogoDarkClass",
            "mcp_servers/list.html: service-icons.js exposes logoDarkClass",
        ),
    ] {
        assert_unreferenced(needle, why);
    }
}

/// `vault.css` defined the dark palette twice — once under `[data-theme=dark]`
/// and again, verbatim, under `prefers-color-scheme` — and the copies had
/// already drifted: the second applied the `.pill-scope` inset highlight to
/// `:root:not([data-theme])`, i.e. to every light-mode reader who had never
/// chosen a theme (uat/artifacts/reviews/UI-REVIEW-static.md C2).
#[test]
fn the_dark_palette_is_defined_once() {
    let css = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static/css/vault.css"),
    )
    .expect("read vault.css");

    let media_blocks = css.matches("@media (prefers-color-scheme").count();
    assert_eq!(
        media_blocks, 0,
        "vault.css still carries {media_blocks} prefers-color-scheme block(s). The theme is \
         resolved before first paint in base.html and stamped on `data-theme`, so the dark \
         palette is written once under [data-theme=\"dark\"] and needs no second copy."
    );

    assert!(
        !css.contains(":root:not([data-theme]) .pill-scope {"),
        "vault.css: the .pill-scope dark highlight was applied to every reader without a \
         stored theme, light mode included"
    );

    // The page shell must actually do the resolving the stylesheet now assumes.
    let base = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates/base.html"),
    )
    .expect("read base.html");
    assert!(
        base.contains("prefers-color-scheme: dark"),
        "base.html resolves the OS preference itself, before first paint"
    );
    assert!(
        base.contains("setAttribute('data-theme'"),
        "base.html stamps the resolved theme so [data-theme=\"dark\"] can be the one selector"
    );
}

/// The class selectors `vault.css` defined with no user in any template or
/// script (uat/artifacts/reviews/UI-REVIEW-static.md C1). Deleting a rule is safe exactly when
/// nothing names its class, so the guard is the same either way: the selector
/// is gone from the stylesheet and the class is used nowhere.
#[test]
fn the_dead_css_classes_are_deleted() {
    let css = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static/css/vault.css"),
    )
    .expect("read vault.css");

    let dead = [
        "detail-list",
        "slide-panel-footer",
        "try-it-",
        "workspace-tree",
        "workspace-group",
        "agent-list-item",
        "pe-highlight",
        "pe-token",
        "status-dot",
        "status-enabled",
        "tbl-compact",
        "device-group-table",
        "form-row",
        "pill-count",
        "detail-section-chevron",
        "install-cmd",
        "empty-icon",
        "user-role-pill",
        "policy-tester-grid",
        "gap-2",
        "mt-4",
    ];

    let mut still_there = Vec::new();
    for class in dead {
        if css.contains(&format!(".{class}")) {
            still_there.push(class);
        }
    }
    assert!(
        still_there.is_empty(),
        "vault.css still defines dead class selectors (nothing in templates or static/ uses \
         them): {still_there:?}"
    );

    // `.perm-form-batch`/`.perm-form-row` are live; the bare `.perm-form` is not.
    assert!(
        !css.contains(".perm-form select"),
        "vault.css: `.perm-form` has no user — only `.perm-form-batch` and `.perm-form-row` do"
    );

    for dangling in [
        ".device-group-table th:first-child,",
        ".tbl-compact th,",
        ".pe-highlight,",
    ] {
        assert!(
            !css.contains(dangling),
            "vault.css: {dangling:?} is a dangling selector — its rule body belongs to the \
             block that follows, which now inherits a stray selector"
        );
    }
}

// ---------------------------------------------------------------------------
// MCP list — a viewer is not offered a control the API refuses
// (uat/artifacts/reviews/UI-REVIEW-live.md M3)
// ---------------------------------------------------------------------------

/// Installing an MCP server needs `create` on System, which a viewer does not
/// hold, so the marketplace's Install cards and the empty state's invitation
/// to browse it are a 403 waiting to happen. A viewer is told why the list is
/// empty instead.
#[tokio::test]
async fn the_mcp_list_offers_a_viewer_no_install_control() {
    let (ctx, cookie) = viewer_session().await;
    let uri = "/mcp-servers";

    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("/mcp-servers/marketplace"),
        "/mcp-servers: a viewer is not sent to the marketplace — installing needs `create`"
    );
    assert!(
        !body.contains("Browse the marketplace"),
        "/mcp-servers: a viewer's empty state must not invite them to install"
    );

    // And the marketplace page itself offers them no card to press.
    let (status, body) = get_page(&ctx.app, "/mcp-servers/marketplace", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("marketplace-card"),
        "/mcp-servers/marketplace: a viewer is offered no template to install"
    );

    // An admin still is: the list sends them to the marketplace, and the
    // marketplace shows them the cards.
    let (ctx, cookie) = admin_session().await;
    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_contains(
        &body,
        uri,
        r#"href="/mcp-servers/marketplace""#,
        "an admin may install one",
    );
    let (status, body) = get_page(&ctx.app, "/mcp-servers/marketplace", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_contains(
        &body,
        "/mcp-servers/marketplace",
        r#"id="marketplace""#,
        "and the cards are there to press",
    );
}

// ---------------------------------------------------------------------------
// Generated agent files — the registration page and the CLI agree
// (uat/artifacts/reviews/UI-REVIEW-static.md B9)
// ---------------------------------------------------------------------------

/// `init.rs` has a test asserting `init` must *not* create `.mcp.json`, and
/// the installed skill tells the agent there is none and not to make one. The
/// registration page told the operator the opposite twice.
#[tokio::test]
async fn the_registration_page_does_not_claim_init_writes_mcp_json() {
    let (ctx, cookie) = admin_session().await;

    let (status, body) = get_page(&ctx.app, "/register", &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert!(
        !body.contains(".mcp.json"),
        "/register: `agentcordon init` does not write .mcp.json — MCP servers are reached \
         through the broker"
    );
    assert!(
        !body.contains("MCP gateway config"),
        "/register: there is no MCP gateway config file for init to install"
    );
}

/// The page names the files `init` actually writes. It named `AGENTS.md` and
/// `CLAUDE.md`, which `init` stopped writing in 0.4.1 (ADR-0013): an operator
/// following the page would have looked for two files that were never created
/// and missed the one that was.
#[tokio::test]
async fn the_registration_page_describes_the_skill_init_installs() {
    let (ctx, cookie) = admin_session().await;

    let (status, body) = get_page(&ctx.app, "/register", &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert!(
        body.contains(".agents/skills/agentcordon/SKILL.md"),
        "/register: name the skill `init` writes"
    );
    assert!(
        body.contains(".claude/skills/") && body.contains(".kiro/skills/"),
        "/register: name the two runtimes that read a different skill directory"
    );
    assert!(
        body.contains("--agent"),
        "/register: say how to skip the question in a script"
    );
    for gone in ["AGENTS.md", "CLAUDE.md"] {
        assert!(
            !body.contains(gone),
            "/register: `init` does not write {gone} (ADR-0013)"
        );
    }
}

// ---------------------------------------------------------------------------
// B1/T1 — one detail surface per entity
//
// `pages/credentials/detail.html` and `partials/credential_detail_pane.html`
// were two copies of the same 900 lines, and they had drifted: the pane showed
// and saved Description and Target Identity while the page dropped both, the
// page reported a 403 and the pane rendered nothing, the page's Restore modal
// closed on Escape and the pane's did not, and the two contradicted each other
// about who may grant a credential to a workspace. Each of those is a test
// below, and both surfaces answer them because there is now one template.
// ---------------------------------------------------------------------------

/// The source of a template, for the assertions that are about the file rather
/// than about one rendered page.
fn template_source(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("templates")
        .join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The one surface that renders a workspace's detail: `/workspaces/{id}`, a
/// full page around the pane partial.
fn workspace_detail_surfaces(id: &str) -> [String; 1] {
    [format!("/workspaces/{id}")]
}

async fn a_workspace(ctx: &TestContext, name: &str) -> String {
    let (ws, _) = common::create_agent_in_db(&*ctx.store, name, vec![], true, None).await;
    ws.id.0.to_string()
}

async fn a_credential(ctx: &TestContext, cookie: &str, name: &str) -> String {
    let (status, created) = common::send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(cookie),
        Some(serde_json::json!({
            "name": name,
            "service": "svc",
            "secret_value": "sk-1",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create credential: {created}");
    created["data"]["id"].as_str().expect("id").to_string()
}

/// The standalone detail page includes the pane rather than carrying a second
/// copy of it, so there is one component to fix when either is wrong.
#[test]
fn each_detail_page_includes_the_pane_partial_instead_of_copying_it() {
    for (page, partial, component) in [
        (
            "pages/credentials/detail.html",
            "partials/credential_detail_pane.html",
            "credentialDetailPage()",
        ),
        (
            "pages/workspaces/detail.html",
            "partials/workspace_detail_pane.html",
            "workspaceDetailPage()",
        ),
    ] {
        let src = template_source(page);
        assert!(
            src.contains(&format!(r#"{{% include "{partial}" %}}"#)),
            "{page}: must include {partial} rather than copy it"
        );
        assert!(
            !src.contains(component),
            "{page}: the duplicated `{component}` component is gone; the pane's is the only one"
        );
        // A page that still carried the copy would be longer than the shell it
        // should now be.
        assert!(
            src.lines().count() < 40,
            "{page}: a shell around the pane is a few lines, not {}",
            src.lines().count()
        );
    }
}

/// Drift 1: the pane showed Description and Target Identity and sent both on
/// save; the page showed neither, so editing a credential from the standalone
/// page silently dropped them. The pane's behaviour is the one that survives.
#[tokio::test]
async fn every_credential_detail_surface_shows_and_saves_description_and_target_identity() {
    let (ctx, cookie) = admin_session().await;
    let id = a_credential(&ctx, &cookie, "ctl-desc-cred").await;

    for uri in credential_detail_surfaces(&id) {
        let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_contains(
            &body,
            &uri,
            "editForm.description",
            "Description is editable",
        );
        assert_contains(
            &body,
            &uri,
            "editForm.targetIdentity",
            "Target Identity is editable",
        );
        assert_contains(
            &body,
            &uri,
            "description: this.editForm.description || null",
            "and the save sends the description instead of dropping it",
        );
        assert_contains(
            &body,
            &uri,
            "target_identity: this.editForm.targetIdentity || null",
            "and the target identity too",
        );
    }
}

/// Drift 2: blanking the URL restriction sent `""` from the page and `null`
/// from the pane. `null` is the one that clears the column.
#[tokio::test]
async fn blanking_the_url_restriction_clears_it_on_every_surface() {
    let (ctx, cookie) = admin_session().await;
    let id = a_credential(&ctx, &cookie, "ctl-pattern-cred").await;

    for uri in credential_detail_surfaces(&id) {
        let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_contains(
            &body,
            &uri,
            "allowed_url_pattern: this.editForm.allowedUrlPattern || null",
            "an emptied pattern is sent as null, which clears it",
        );
    }
}

/// Drift 3: Escape closed the Restore modal on the page and not in the pane.
#[tokio::test]
async fn the_restore_secret_modal_closes_on_escape_on_every_surface() {
    let (ctx, cookie) = admin_session().await;
    let id = a_credential(&ctx, &cookie, "ctl-restore-cred").await;

    for uri in credential_detail_surfaces(&id) {
        let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_contains(
            &body,
            &uri,
            "restoreModal && (restoreModal = false)",
            "Escape closes the Restore modal",
        );
    }
}

/// Drift 4: the two surfaces contradicted each other about who may grant a
/// credential to a workspace. `PolicyService::load_and_authorize_permissions`
/// accepts `manage_permissions` *or* the credential's owner, so the sentence
/// that names both is the true one.
#[tokio::test]
async fn a_refused_grant_names_the_owner_as_well_as_an_admin() {
    let (ctx, cookie) = admin_session().await;
    let id = a_credential(&ctx, &cookie, "ctl-grant-cred").await;

    for uri in credential_detail_surfaces(&id) {
        let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_contains(
            &body,
            &uri,
            "you must be the credential owner or an admin to manage permissions",
            "the refusal names both the owner and an admin",
        );
        assert!(
            !body.contains("requires admin privileges"),
            "{uri}: the owner may grant too — the admin-only sentence is wrong"
        );
    }
}

/// Drift 5: the page used the shared delete-modal partial, which carries
/// `role="dialog"` and a label; the panes had hand-rolled copies with neither
/// — three shapes for one question. Every surface now asks it through
/// `AC.confirm`, which is the focus-managed dialog in `base.html`.
#[tokio::test]
async fn every_delete_confirmation_is_the_one_shared_dialog() {
    let (ctx, cookie) = admin_session().await;
    let cred = a_credential(&ctx, &cookie, "ctl-del-dialog-cred").await;
    let ws = a_workspace(&ctx, "ctl-del-dialog-ws").await;

    let mut uris: Vec<String> = credential_detail_surfaces(&cred).to_vec();
    uris.extend(workspace_detail_surfaces(&ws));

    for uri in uris {
        let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_contains(
            &body,
            &uri,
            "AC.confirm({",
            "deleting asks through the one focus-managed dialog",
        );
        assert!(
            !body.contains(r#"x-show="deleteModal""#),
            "{uri}: the hand-rolled delete overlay is gone — AC.confirm is the only one"
        );
    }
}

/// Drift 6: the pane had a History tab; `/workspaces/{id}/view` did not, so a
/// phone could not see a workspace's events at all.
#[tokio::test]
async fn every_workspace_detail_surface_offers_the_history_tab() {
    let (ctx, cookie) = admin_session().await;
    let ws = a_workspace(&ctx, "ctl-history-ws").await;

    for uri in workspace_detail_surfaces(&ws) {
        let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_contains(&body, &uri, "loadHistory()", "the History tab loads events");
        assert_contains(
            &body,
            &uri,
            "activeTab === 'history'",
            "and has a panel of its own",
        );
    }
}

/// Drift 7: the page called `$refs.editTagInput.focus()` unguarded, which
/// throws while the tag editor is closed.
#[tokio::test]
async fn the_workspace_tag_editor_guards_its_focus_call() {
    let (ctx, cookie) = admin_session().await;
    let ws = a_workspace(&ctx, "ctl-tagfocus-ws").await;

    for uri in workspace_detail_surfaces(&ws) {
        let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_contains(
            &body,
            &uri,
            "$refs.editTagInput && $refs.editTagInput.focus()",
            "focusing the tag input is guarded on the ref existing",
        );
    }
}

// ---------------------------------------------------------------------------
// M3 — a refusal is not an empty state
// ---------------------------------------------------------------------------

/// A 403 on a detail fetch used to render nothing at all in the pane and an
/// "Access Denied" card with a "Back to Credentials" button on the page. Say
/// what happened, and offer no action the caller cannot take.
#[tokio::test]
async fn a_forbidden_detail_says_so_without_a_call_to_action() {
    let (ctx, cookie) = admin_session().await;
    let cred = a_credential(&ctx, &cookie, "ctl-403-cred").await;
    let ws = a_workspace(&ctx, "ctl-403-ws").await;

    for (uri, sentence) in credential_detail_surfaces(&cred)
        .into_iter()
        .map(|u| (u, "You do not have permission to view this credential."))
        .chain(
            workspace_detail_surfaces(&ws)
                .into_iter()
                .map(|u| (u, "You do not have permission to view this workspace.")),
        )
    {
        let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_contains(&body, &uri, "accessDenied", "a 403 has a state of its own");
        assert_contains(&body, &uri, sentence, "and a sentence that names it");
        assert!(
            !body.contains("Access Denied"),
            "{uri}: say what the caller may not do, not a two-word status"
        );
    }
}

/// The same for a list: a viewer whose `/api/v1/workspaces` answers 403 was
/// shown "No workspaces yet" and pointed at the registration flow.
#[tokio::test]
async fn a_forbidden_list_says_so_without_a_call_to_action() {
    let (ctx, cookie) = admin_session().await;

    for (uri, sentence) in [
        (
            "/credentials",
            "You do not have permission to view credentials.",
        ),
        (
            "/workspaces",
            "You do not have permission to view workspaces.",
        ),
    ] {
        let (status, body) = get_page(&ctx.app, uri, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_contains(
            &body,
            uri,
            "listForbidden",
            "a refused list has a state of its own, separate from an empty one",
        );
        assert_contains(&body, uri, sentence, "and says so");
    }
}

/// A viewer holds no `create` on System, so registering a workspace is a 403
/// for them however they reach it — the credentials list already withholds Add
/// Credential and the workspaces list must withhold Register Workspace.
#[tokio::test]
async fn the_workspace_list_offers_a_viewer_no_register_control() {
    let (ctx, cookie) = viewer_session().await;
    let (status, body) = get_page(&ctx.app, "/workspaces", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("Register Workspace"),
        "/workspaces: a viewer is not offered Register Workspace"
    );

    let (ctx, cookie) = admin_session().await;
    let (status, body) = get_page(&ctx.app, "/workspaces", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_contains(
        &body,
        "/workspaces",
        "Register Workspace",
        "an admin still is",
    );
}

/// A viewer cannot update or delete a credential or a workspace, so the detail
/// surfaces do not offer Edit, Delete, Revoke or Grant to one.
#[tokio::test]
async fn a_viewer_is_offered_no_write_control_on_a_detail_surface() {
    let (ctx, admin) = admin_session().await;
    common::create_test_user(
        &*ctx.store,
        "ctl-detail-viewer",
        common::TEST_PASSWORD,
        UserRole::Viewer,
    )
    .await;
    let viewer =
        common::login_user_combined(&ctx.app, "ctl-detail-viewer", common::TEST_PASSWORD).await;

    let cred = a_credential(&ctx, &admin, "ctl-viewer-cred").await;
    let ws = a_workspace(&ctx, "ctl-viewer-ws").await;

    let mut uris: Vec<String> = credential_detail_surfaces(&cred).to_vec();
    uris.extend(workspace_detail_surfaces(&ws));

    for uri in uris {
        let (status, body) = get_page(&ctx.app, &uri, &viewer).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        for control in ["Grant Permission", "Revoke</button>", ">Delete</button>"] {
            assert!(
                !body.contains(control),
                "{uri}: a viewer holds no write action — {control:?} must not be offered"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// M4/J1/J2 — the canonical deep link on a narrow viewport
// ---------------------------------------------------------------------------

/// One URL per credential and per workspace. The list is a table of links to
/// `/{entity}/{id}`; there is no pane to select into, so the `_isMobile`
/// branch that decided whether a deep link could be read (J1) has nothing
/// left to decide and is gone, along with the AJAX fragment loader (J2).
#[tokio::test]
async fn a_list_row_links_to_the_entity_page_instead_of_a_pane() {
    let (ctx, cookie) = admin_session().await;

    for (uri, path) in [
        ("/credentials", "/credentials/"),
        ("/workspaces", "/workspaces/"),
    ] {
        let (status, body) = get_page(&ctx.app, uri, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{uri}");

        assert!(
            !body.contains("_isMobile"),
            "{uri}: the mobile deep-link branch has nothing left to decide"
        );
        assert!(
            !body.contains("detail-partial"),
            "{uri}: the list no longer fetches a detail fragment"
        );
        assert!(
            !body.contains("md-split"),
            "{uri}: the split pane is retired in favour of a table and a page"
        );
        assert_contains(
            &body,
            uri,
            &format!(r#":href="'{path}' + "#),
            "each row is a link to the entity's own page",
        );
    }
}

/// `Alpine.destroyTree` calls a component's `destroy()`. The panes register
/// window listeners in `init()`, so they must take them off again there.
#[tokio::test]
async fn a_detail_pane_removes_its_window_listeners_when_destroyed() {
    let (ctx, cookie) = admin_session().await;
    let cred = a_credential(&ctx, &cookie, "ctl-destroy-cred").await;
    let ws = a_workspace(&ctx, "ctl-destroy-ws").await;

    let mut uris: Vec<String> = credential_detail_surfaces(&cred).to_vec();
    uris.extend(workspace_detail_surfaces(&ws));

    for uri in uris {
        let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_contains(
            &body,
            &uri,
            "destroy()",
            "the pane has a teardown Alpine can call",
        );
        assert_contains(
            &body,
            &uri,
            "window.removeEventListener",
            "and it takes its window listeners off again",
        );
    }
}

// ---------------------------------------------------------------------------
// S2 (static review) — the revealed secret must not outlive the reveal
// ---------------------------------------------------------------------------

/// The revealed secret stayed in Alpine state — and its 30 s interval kept
/// ticking — when the operator entered edit mode, switched tab or selected
/// another credential. One teardown, called from all three.
#[tokio::test]
async fn the_revealed_secret_is_cleared_when_the_pane_leaves_the_reveal() {
    let (ctx, cookie) = admin_session().await;
    let id = a_credential(&ctx, &cookie, "ctl-reveal-cred").await;

    for uri in credential_detail_surfaces(&id) {
        let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_contains(
            &body,
            &uri,
            "clearRevealedSecret()",
            "there is one teardown for the revealed secret",
        );
        // Entering edit mode, changing tab and being destroyed all call it.
        for caller in ["startEdit()", "selectTab(", "destroy()"] {
            assert_contains(
                &body,
                &uri,
                caller,
                "the reveal is torn down on every way out of it",
            );
        }
        assert!(
            body.matches("clearRevealedSecret()").count() >= 4,
            "{uri}: the teardown is defined and called from edit, tab change and destroy"
        );
    }
}

// ---------------------------------------------------------------------------
// M10 — a rotation row names its date and its actor
// ---------------------------------------------------------------------------

/// The Secret Rotations table read `entry.rotated_at` and `entry.changed_by`,
/// which the API has never sent: the row showed "-" for both while the audit
/// table under it carried the timestamp. The response's own field names are
/// `changed_at` and (now) `changed_by_name`.
#[tokio::test]
async fn a_rotation_row_names_the_date_and_the_actor() {
    let (ctx, cookie) = admin_session().await;
    let id = a_credential(&ctx, &cookie, "ctl-rotation-cred").await;

    for uri in credential_detail_surfaces(&id) {
        let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_contains(
            &body,
            &uri,
            "entry.changed_at",
            "the row reads the date the API sends",
        );
        assert_contains(
            &body,
            &uri,
            "entry.changed_by_name",
            "and the actor the API sends",
        );
        assert!(
            !body.contains("entry.rotated_at"),
            "{uri}: `rotated_at` is not a field of the history response"
        );
        // Restoring names the entry by id, which is what the route takes.
        assert_contains(
            &body,
            &uri,
            "'/secret-history/' + this.restoreEntry.id + '/restore'",
            "restore addresses the history row the way the route does",
        );
    }
}

// ---------------------------------------------------------------------------
// M12 — User Management is not read-only
// ---------------------------------------------------------------------------

/// Settings listed users with a Role and an Enabled column and no way to change
/// either, and no way to reset a password, although `PUT /api/v1/users/{id}`
/// and `POST /api/v1/users/{id}/change-password` have always taken both.
#[tokio::test]
async fn settings_offers_an_admin_the_user_controls_the_api_supports() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/settings";
    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        uri,
        "saveUserRole(u",
        "a user's role can be changed from the row",
    );
    assert_contains(
        &body,
        uri,
        "toggleUserEnabled(u",
        "a user can be disabled and enabled again",
    );
    assert_contains(
        &body,
        uri,
        "openResetPassword(u",
        "and an admin can reset another user's password",
    );
    assert_contains(
        &body,
        uri,
        "/change-password",
        "the reset calls the route that enforces the flow",
    );
    // Root's role and enabled flag are the server's to refuse; do not offer
    // them, and never offer to disable the account you are signed in as.
    assert_contains(
        &body,
        uri,
        "canEditUser(u)",
        "the row's controls follow what the server will accept",
    );
}

/// A viewer never sees the section at all — `manage_users` is an admin action —
/// so nothing about it leaks into their page.
#[tokio::test]
async fn settings_offers_a_viewer_no_user_controls() {
    let (ctx, cookie) = viewer_session().await;
    let (status, body) = get_page(&ctx.app, "/settings", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("User Management"),
        "/settings: user management belongs to `manage_users`, which a viewer does not hold"
    );
    assert!(
        !body.contains(">Add User<"),
        "/settings: and a viewer is not invited to create one"
    );
}

// ---------------------------------------------------------------------------
// A3/A9/A10 — every control on these pages has a name and reports its state
// ---------------------------------------------------------------------------

/// Ten inline-edit inputs and five tag editors carried a placeholder and no
/// accessible name, so a screen reader announced "edit text" on the credential
/// name, service, secret and URL-pattern fields. The name is the label the
/// sighted reader sees: each `.detail-label` carries an id and its field points
/// at it with `aria-labelledby`, so the two cannot say different things. An
/// `aria-label` is for the controls with no visible label of their own.
#[test]
fn every_input_on_the_detail_panes_has_an_accessible_name() {
    for rel in [
        "partials/credential_detail_pane.html",
        "partials/workspace_detail_pane.html",
    ] {
        let src = template_source(rel);
        let mut unnamed = Vec::new();
        let mut dangling = Vec::new();
        for tag in ["<input", "<select", "<textarea"] {
            let mut from = 0;
            while let Some(rel_at) = src[from..].find(tag) {
                let at = from + rel_at;
                let end = at + src[at..].find('>').expect("closing bracket");
                let element = &src[at..end];
                from = end;
                let line = src[..at].matches('\n').count() + 1;
                // A checkbox inside its own `<label>` is named by that label.
                if element.contains(r#"type="checkbox""#) {
                    continue;
                }
                if let Some(rest) = element.split("aria-labelledby=\"").nth(1) {
                    let id = rest.split('"').next().unwrap_or("");
                    // The id must belong to an element this template renders.
                    if !src.contains(&format!(r#"id="{id}""#)) {
                        dangling.push(format!("{rel}:{line} names #{id}, which nothing defines"));
                    }
                } else if !element.contains("aria-label=") {
                    unnamed.push(format!("{rel}:{line} {}", element.replace('\n', " ")));
                }
            }
        }
        assert!(
            unnamed.is_empty(),
            "these inputs have no accessible name (A3):\n{}",
            unnamed.join("\n")
        );
        assert!(
            dangling.is_empty(),
            "these inputs are labelled by an id that does not exist (A3):\n{}",
            dangling.join("\n")
        );
    }
}

/// A3/A10: the tag editors on these pages name their input and remove a chip
/// with a button, not a 14 px `<span>`.
#[test]
fn every_tag_editor_on_these_pages_is_labelled_and_removable_by_button() {
    for rel in [
        "partials/credential_detail_pane.html",
        "partials/workspace_detail_pane.html",
        "pages/credentials/new.html",
    ] {
        let src = template_source(rel);
        assert!(
            src.contains(r#"aria-label="Add tag""#),
            "{rel}: the tag input needs a name of its own — it has no visible label"
        );
        assert!(
            !src.contains(r#"<span class="chip-remove""#),
            "{rel}: removing a tag is a button with a label, not a span"
        );
        assert!(
            src.contains(r#":aria-label="'Remove tag ' + tag""#),
            "{rel}: and the button says which tag it removes"
        );
    }
}

/// Grant and Deny are a two-state toggle drawn with buttons; a toggle reports
/// which of the two is on.
#[tokio::test]
async fn the_grant_and_deny_toggle_reports_which_is_pressed() {
    let (ctx, cookie) = admin_session().await;
    let id = a_credential(&ctx, &cookie, "ctl-toggle-cred").await;

    for uri in credential_detail_surfaces(&id) {
        let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        // The value is the string, not the boolean: Alpine removes an
        // attribute bound to `false`, which drops "not chosen" instead of
        // saying it. Grant/Deny is a segmented control now, so the attribute
        // is `aria-checked` (uat/artifacts/reviews/DESIGN-REVIEW.md §1.6); the string rule is
        // the same, and `partials/mcp_permissions_tab.html` set it.
        assert_contains(
            &body,
            &uri,
            r#":aria-checked="grantMode === 'grant' ? 'true' : 'false'""#,
            "Grant says whether it is the selected mode",
        );
        assert_contains(
            &body,
            &uri,
            r#":aria-checked="grantMode === 'deny' ? 'true' : 'false'""#,
            "and so does Deny",
        );

        // The glyph controls say what they do.
        assert_contains(
            &body,
            &uri,
            "'Revoke ' + permLabel(perm.permission)",
            "the permissions table's ✕ names the permission and the workspace",
        );
        assert_contains(
            &body,
            &uri,
            r#"<span class="sr-only" x-text="rsopLabel(entry.decision)"></span>"#,
            "the Effective Access decision is a word as well as a tick or a cross",
        );
    }

    // The MCP server's Access tab shows the same matrix and owes the same word.
    let uri = "/mcp-servers/00000000-0000-0000-0000-0000000000ff";
    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_contains(
        &body,
        uri,
        r#"<span class="sr-only" x-text="rsopLabel(entry.decision)"></span>"#,
        "the Effective Access decision is a word here too",
    );
}

/// The tag-filter pills on the two list pages are toggles, and a toggle reports
/// which state it is in — as a string, for the reason above.
#[tokio::test]
async fn the_tag_filter_pills_report_whether_they_are_on() {
    let (ctx, cookie) = admin_session().await;

    for uri in ["/credentials", "/workspaces"] {
        let (status, body) = get_page(&ctx.app, uri, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_contains(
            &body,
            uri,
            r#":aria-pressed="tagFilter.includes(tag) ? 'true' : 'false'""#,
            "a tag filter says whether it is applied",
        );
    }
}

// ---------------------------------------------------------------------------
// UI review B1 / M1 / M2 / M9: the markers a refusal needs on the page
// ---------------------------------------------------------------------------

/// The policies list must mark the policy that cannot be disabled, and say why
/// on the control itself rather than letting the click fail (UI review B1).
#[tokio::test]
async fn the_policies_list_marks_the_last_enabled_policy_and_disables_its_toggle() {
    let (ctx, cookie) = admin_session().await;
    let (status, body) = get_page(&ctx.app, "/security", &cookie).await;
    assert_eq!(status, StatusCode::OK);

    // The list still marks the state; the control that acts on it lives on the
    // detail page now (uat/artifacts/reviews/DESIGN-REVIEW.md §1.10).
    assert_contains(
        &body,
        "/security",
        ">last enabled policy<",
        "the row carries a pill naming the state",
    );
    assert_contains(
        &body,
        "/security",
        r#":title="lockoutReason(policy)""#,
        "and the pill carries the reason as its title",
    );
    assert!(
        body.contains("every operator, viewer and workspace is refused"),
        "/security: the reason must name who would be refused"
    );

    let id = seeded_policy_id(&ctx).await;
    let uri = format!("/security/{id}");
    let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_contains(
        &body,
        &uri,
        r#":disabled="isLastEnabled""#,
        "the Disable control is disabled for the last enabled policy",
    );
    assert_contains(
        &body,
        &uri,
        r#":title="isLastEnabled ? lockoutReason : null""#,
        "and carries the reason as its title",
    );
}

/// Disabling a policy is confirmed with the consequence, not "are you sure?".
#[tokio::test]
async fn disabling_a_policy_is_confirmed_with_its_consequence() {
    let (ctx, cookie) = admin_session().await;
    let id = seeded_policy_id(&ctx).await;
    let uri = format!("/security/{id}");
    let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        &uri,
        r#"@click="askToggle()""#,
        "the toggle asks before it acts",
    );
    assert!(
        body.contains("takes it out of the evaluated policy set immediately"),
        "{uri}: the dialog must say what disabling does"
    );
}

/// The policy detail page marks the same state and refuses Delete outright for
/// the seeded default.
#[tokio::test]
async fn the_policy_detail_page_says_why_delete_is_refused() {
    let (ctx, cookie) = admin_session().await;
    let policies = ctx.store.list_policies().await.expect("list policies");
    let id = policies
        .iter()
        .find(|p| p.name == "default")
        .expect("the test app seeds a 'default' policy")
        .id
        .0
        .to_string();

    let uri = format!("/security/{id}");
    let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        &uri,
        r#":disabled="!!deleteRefusal""#,
        "Delete is disabled when the API would refuse it",
    );
    assert_contains(
        &body,
        &uri,
        r#":title="deleteRefusal || null""#,
        "and carries the reason as its title",
    );
    assert_contains(
        &body,
        &uri,
        ">last enabled policy<",
        "the last-enabled state is marked",
    );
    assert!(
        body.contains("is the built-in default policy and cannot be deleted"),
        "{uri}: the built-in default's refusal must be spelled out"
    );
    assert!(
        body.contains("stops being permitted the moment it is deleted"),
        "{uri}: the delete dialog must name the consequence, not just 'cannot be undone'"
    );
}

/// The Cedar validator's messages are rendered under the editor on both the
/// create form and the detail page's editor (UI review M9).
#[tokio::test]
async fn both_policy_editors_render_the_cedar_validator_messages() {
    let (ctx, cookie) = admin_session().await;
    let policies = ctx.store.list_policies().await.expect("list policies");
    let id = policies.first().expect("a seeded policy").id.0.to_string();

    for uri in ["/security/new".to_string(), format!("/security/{id}")] {
        let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_contains(
            &body,
            &uri,
            r#"id="policy-cedar-errors""#,
            "the editor has somewhere to put the validator's messages",
        );
        assert_contains(
            &body,
            &uri,
            "err.error.details.errors",
            "and reads them off the 400 body",
        );
        assert_contains(
            &body,
            &uri,
            r#"x-text="err.message""#,
            "rendering each message",
        );
    }
}

/// A duplicate name is a 409 the form must show next to the Name field, not
/// only in a toast that has gone by the time the reader looks back (M1).
#[tokio::test]
async fn the_new_credential_form_shows_a_duplicate_name_next_to_the_field() {
    let (ctx, cookie) = admin_session().await;
    let (status, body) = get_page(&ctx.app, "/credentials/new", &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        "/credentials/new",
        r#"id="cred-name-error""#,
        "the Name field has an inline error slot",
    );
    assert_contains(
        &body,
        "/credentials/new",
        r#"x-text="fieldErrors.name""#,
        "which renders the server's message",
    );
    assert_contains(
        &body,
        "/credentials/new",
        "placeFieldError(resp.status, message)",
        "and the submit handler routes the refusal to it",
    );
}

/// The Vaults section does the same for a duplicate vault name.
#[tokio::test]
async fn the_vaults_section_shows_a_duplicate_name_next_to_the_field() {
    let (ctx, cookie) = admin_session().await;
    let (status, body) = get_page(&ctx.app, "/settings", &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        "/settings",
        r#"id="vault-new-name-error""#,
        "the new-vault field has an inline error slot",
    );
    assert_contains(
        &body,
        "/settings",
        r#"x-text="vaultNameError""#,
        "which renders the server's message",
    );
    assert_contains(
        &body,
        "/settings",
        r#"x-text="renameVaultError""#,
        "and so does the rename field",
    );
}

/// The URL-pattern field states the grammar the server enforces and has
/// somewhere to put the 400 (UI review M2).
#[tokio::test]
async fn the_url_pattern_field_documents_its_grammar_and_shows_the_refusal() {
    let (ctx, cookie) = admin_session().await;
    let (status, body) = get_page(&ctx.app, "/credentials/new", &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        "/credentials/new",
        r#"id="cred-url-pattern-error""#,
        "the pattern field has an inline error slot",
    );
    assert_contains(
        &body,
        "/credentials/new",
        r#"x-text="fieldErrors.allowedUrlPattern""#,
        "which renders the server's message",
    );
    assert!(
        body.contains("stands for exactly one"),
        "/credentials/new: the help text must state what a host wildcard means"
    );
    assert!(
        body.contains("https://*.example.com/*"),
        "/credentials/new: the help text must show a pattern that works"
    );
}

/// The login page's SSO button is a link to the route that starts the flow,
/// not to the 404 it used to name (UI review B2).
#[tokio::test]
async fn the_login_page_sso_button_is_a_link_to_the_authorize_route() {
    let ctx = TestAppBuilder::new().build().await;
    let (status, body) = get_page(&ctx.app, "/login", "").await;
    assert_eq!(status, StatusCode::OK);

    assert!(
        !body.contains("/api/v1/oidc/auth/"),
        "/login: the 404 route must be gone"
    );
    assert_contains(
        &body,
        "/login",
        r#":href="ssoStartUrl(provider.id)""#,
        "the SSO control is a link with a real destination",
    );
}

/// A18/A3: the policy pages' unnamed controls. A placeholder is not a label
/// and a glyph is not a name, so search, filter and every icon-only control on
/// these pages carries an accessible name.
#[tokio::test]
async fn the_policy_pages_name_their_search_filter_and_icon_controls() {
    let (ctx, cookie) = admin_session().await;
    let policies = ctx.store.list_policies().await.expect("list policies");
    let id = policies.first().expect("a seeded policy").id.0.to_string();

    let (status, list) = get_page(&ctx.app, "/security", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_contains(
        &list,
        "/security",
        r#"aria-label="Search policies""#,
        "the policy search names itself",
    );
    assert_contains(
        &list,
        "/security",
        r#"aria-label="Filter policies by type""#,
        "and so does the type filter",
    );

    let detail_uri = format!("/security/{id}");
    let (status, detail) = get_page(&ctx.app, &detail_uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);
    for needle in [
        "'Move statement ' + (idx + 1) + ' up'",
        "'Move statement ' + (idx + 1) + ' down'",
        "'Remove statement ' + (idx + 1)",
        "'Effect of statement ' + (idx + 1)",
    ] {
        assert_contains(
            &detail,
            &detail_uri,
            needle,
            "each statement control names the statement it acts on",
        );
    }

    let (status, new_page) = get_page(&ctx.app, "/security/new", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_contains(
        &new_page,
        "/security/new",
        r#"aria-label="Close template preview""#,
        "the preview's × says what it closes",
    );

    let (status, tester) = get_page(&ctx.app, "/security/tester", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_contains(
        &tester,
        "/security/tester",
        ">Clear all scenarios<",
        "the scenario menu names what it clears instead of showing a bare ×",
    );
}

/// A sortable column is a control and an ordering: the clickable part is a
/// real button, and the header cell reports the order with `aria-sort`. A
/// `<th>` carrying an `@click` is neither reachable by keyboard nor announced.
#[tokio::test]
async fn the_sortable_policy_columns_are_buttons_that_report_their_order() {
    let (ctx, cookie) = admin_session().await;
    let (status, body) = get_page(&ctx.app, "/security", &cookie).await;
    assert_eq!(status, StatusCode::OK);

    for column in ["name", "enabled", "updated"] {
        assert_contains(
            &body,
            "/security",
            &format!(r#":aria-sort="ariaSort('{column}')""#),
            "the header cell reports which way the table is ordered",
        );
        assert_contains(
            &body,
            "/security",
            &format!(r#"class="policy-sort-btn" @click="sort('{column}')""#),
            "and the control that changes it is a button",
        );
    }

    assert!(
        !body.contains(r#"<th class="policy-col-sortable" @click="#),
        "/security: a <th> with an @click is not a control"
    );
}

// ---------------------------------------------------------------------------
// Phase 2 — one placement grammar (uat/artifacts/reviews/DESIGN-REVIEW.md §2.1)
// ---------------------------------------------------------------------------

/// Every page header reads the same way: the primary action at the right end,
/// secondary actions beside it, and everything destructive behind a `⋯`
/// overflow. Delete used to sit 8 px from Edit on every detail surface in the
/// product; the shared confirm protects it, and now placement does too.
#[test]
fn every_destructive_action_sits_behind_a_header_overflow_menu() {
    for (file, buttons) in [
        (
            "partials/credential_detail_pane.html",
            vec![r#"data-testid="credential-delete""#],
        ),
        (
            "partials/workspace_detail_pane.html",
            vec![r#"id="ws-revoke-btn""#, r#"data-testid="workspace-delete""#],
        ),
        (
            "pages/mcp_servers/detail.html",
            vec![r#"data-testid="mcp-delete""#],
        ),
        (
            "pages/policies/detail.html",
            vec![r#"data-testid="policy-delete""#],
        ),
        ("pages/settings.html", vec![r#"class="vault-delete-btn"#]),
    ] {
        let src = template_source(file);
        assert!(
            src.contains("acOverflowMenu()"),
            "{file}: the destructive actions belong in the shared overflow menu"
        );
        assert!(
            src.contains(r#"aria-haspopup="menu""#),
            "{file}: the overflow trigger announces the menu it opens"
        );
        for needle in buttons {
            let at = src
                .find(needle)
                .unwrap_or_else(|| panic!("{file}: expected to find {needle}"));
            let element = element_around(&src, at);
            assert!(
                element.contains(r#"role="menuitem""#),
                "{file}: {needle} must be an item of the overflow menu, not a header button; \
                 saw:\n{element}"
            );
        }
    }
}

/// One overflow menu, defined once. It is a labelled button that says it opens
/// a menu, it reports whether the menu is open, and while it is open the menu
/// holds the keyboard the way every other dialog in the product does — the
/// `AC.modal` handle, which traps Tab, answers Escape and gives focus back to
/// the trigger.
#[test]
fn the_overflow_menu_is_one_keyboard_operable_component() {
    let base = template_source("base.html");
    let at = base
        .find("function acOverflowMenu()")
        .expect("base.html defines the one overflow-menu component");
    let body = &base[at..(at + 1400).min(base.len())];
    for needle in ["AC.modal(", "onEscape", "release()"] {
        assert!(
            body.contains(needle),
            "acOverflowMenu must reuse the shared focus handling ({needle}):\n{body}"
        );
    }

    for file in [
        "partials/credential_detail_pane.html",
        "partials/workspace_detail_pane.html",
        "pages/mcp_servers/detail.html",
        "pages/policies/detail.html",
        "pages/settings.html",
        "partials/nav.html",
    ] {
        let src = template_source(file);
        assert!(
            src.contains(r#":aria-expanded="open"#),
            "{file}: the trigger reports whether its menu is open"
        );
        assert!(
            src.contains(r#"role="menu""#),
            "{file}: the items are a menu"
        );
    }
}

// ---------------------------------------------------------------------------
// Phase 2 — the user menu (uat/artifacts/reviews/DESIGN-REVIEW.md §1.1)
// ---------------------------------------------------------------------------

/// The theme toggle is set once and never touched again, and Sign Out is a
/// once-a-day control; both cost a slot in the top bar of every page. They
/// move into a menu under the signed-in user's name, which is what the name
/// was already doing sitting there — and the mobile drawer mirrors it, because
/// the top bar's right-hand group is hidden on a phone.
#[test]
fn the_user_menu_holds_the_identity_the_theme_and_sign_out() {
    let nav = template_source("partials/nav.html");

    let at = nav
        .find(r#"class="user-menu""#)
        .expect("nav.html: the username is the trigger of a user menu");
    let menu = &nav[at..];
    for needle in [
        "user-menu-role",
        "$store.theme.toggle()",
        r#"class="nav-link nav-drawer-extra sign-out"#,
    ] {
        assert!(
            nav.contains(needle),
            "nav.html: the user menu and the drawer carry {needle}"
        );
    }
    assert!(
        menu.contains("signOut()"),
        "nav.html: Sign Out is an item of the user menu"
    );
    // The UAT helper signs out through `button.sign-out`; the drawer's copy
    // and the menu's copy both answer to it.
    assert!(
        nav.matches("sign-out").count() >= 2,
        "nav.html: the drawer mirrors the menu's Sign Out"
    );
    // The theme toggle no longer occupies a slot of its own in the bar.
    assert!(
        !nav.contains(r#"<button class="theme-toggle""#),
        "nav.html: the theme toggle moved into the user menu"
    );
}

// ---------------------------------------------------------------------------
// Phase 2 — Settings keeps one page and gains a rail (§2.4)
// ---------------------------------------------------------------------------

/// Settings is seven cards under five uppercase bands with no sub-navigation:
/// re-seal and the provider clients are below the fold on every visit. One
/// page with a sticky rail of section links fixes that without splitting the
/// template — and therefore without splitting the nine `settings_*` tests.
#[tokio::test]
async fn settings_offers_a_sticky_rail_of_section_links() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/settings";
    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        uri,
        r#"class="settings-rail""#,
        "the page has a section rail",
    );
    for (anchor, section) in [
        ("#account-section", r#"id="account-section""#),
        ("#vaults-section", r#"id="vaults-section""#),
        ("#users-section", r#"id="users-section""#),
        ("#sso-section", r#"id="sso-section""#),
        ("#master-key-section", r#"id="master-key-section""#),
        ("#oauth-clients-section", r#"id="oauth-clients-section""#),
    ] {
        assert_contains(
            &body,
            uri,
            &format!(r#"href="{anchor}""#),
            "the rail links to the section",
        );
        assert_contains(&body, uri, section, "and the section is there to link to");
    }
    // The version string lives at the foot of the rail.
    assert_contains(
        &body,
        uri,
        r#"class="settings-rail-version""#,
        "the rail carries the version",
    );

    let css = vault_css();
    assert!(
        css.contains(".settings-rail"),
        "vault.css must style the settings rail"
    );
}

// ---------------------------------------------------------------------------
// Phase 2 — the audit filter bar (§2.6)
// ---------------------------------------------------------------------------

/// Seventeen event types wrap the pill row to two lines and reflow on every
/// load. The type filter becomes a dropdown; the three decision values stay
/// pills, because three is a segmented control and seventeen is a menu.
#[tokio::test]
async fn the_audit_type_filter_is_a_dropdown_and_the_decisions_stay_pills() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/audit";
    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        uri,
        r#"id="audit-type-filter""#,
        "the event-type filter is one control",
    );
    assert_contains(
        &body,
        uri,
        r#"aria-label="Event type""#,
        "and it is named for a screen reader",
    );
    assert_contains(
        &body,
        uri,
        "<option value=\"\">All event types</option>",
        "its first option is the unfiltered list",
    );
    assert!(
        !body.contains("typeFilter.includes(t)"),
        "/audit: the type pills are replaced by the dropdown"
    );

    // The decision filter keeps its pills, and keeps reporting its state.
    for label in [">All decisions<", ">Permit<", ">Forbid<"] {
        assert_contains(&body, uri, label, "the decision pills stay");
    }
    assert_contains(
        &body,
        uri,
        "audit-filter-pill",
        "and they are still the pill control the UAT drives",
    );
}

// ---------------------------------------------------------------------------
// Phase 2 — the dashboard's first run (§2.2)
// ---------------------------------------------------------------------------

/// The Register Workspace card is the only orange element on the dashboard of
/// every instance forever. It is a first-run instruction, so it belongs to the
/// first run: a checklist of the three things a new instance needs, each
/// ticking itself off from the counts the stats API already serves.
#[tokio::test]
async fn the_dashboard_shows_a_first_run_checklist_instead_of_a_permanent_cta() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/dashboard";
    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        uri,
        r#"class="dash-checklist""#,
        "a first run gets a checklist",
    );
    for (step, href) in [
        ("Store a credential", "/credentials/new"),
        ("Register a workspace", "/register"),
        ("Install an MCP server", "/mcp-servers/marketplace"),
    ] {
        assert_contains(&body, uri, step, "the checklist names the step");
        assert_contains(
            &body,
            uri,
            &format!(r#"href="{href}""#),
            "and links to the page that does it",
        );
    }
    assert_contains(
        &body,
        uri,
        "stats.credentials_total > 0",
        "a step ticks itself off from the counts the stats API serves",
    );
    // The card is shown only while there is no workspace at all.
    let at = body
        .find(r#"class="dash-cta-card""#)
        .expect("/dashboard: the CTA card is still there for a first run");
    let element = element_around(&body, at);
    assert!(
        element.contains("isFirstRun"),
        "/dashboard: the CTA card is shown only on a first run; saw:\n{element}"
    );

    let css = vault_css();
    assert!(
        css.contains(".dash-checklist"),
        "vault.css must style the checklist"
    );
}

// ---------------------------------------------------------------------------
// Phase 2 — the marketplace is a page (§2.5)
// ---------------------------------------------------------------------------

/// Two `content-header`s, two searches and two fetches of the same list on one
/// page was the cost of gluing the marketplace to the bottom of the installed
/// list. It gets its own page; the list gets the primary action it never had.
#[tokio::test]
async fn the_mcp_list_offers_add_server_and_the_marketplace_is_its_own_page() {
    let (ctx, cookie) = admin_session().await;

    let uri = "/mcp-servers";
    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_contains(
        &body,
        uri,
        r#"href="/mcp-servers/marketplace" class="btn btn-primary""#,
        "the list's primary action opens the marketplace",
    );
    assert_contains(&body, uri, ">Add server<", "and says what it does");
    assert!(
        !body.contains("marketplace-card"),
        "{uri}: the template grid moved to its own page"
    );

    let uri = "/mcp-servers/marketplace";
    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_contains(&body, uri, "marketplace-card", "the cards are here");
    assert_contains(
        &body,
        uri,
        r#"id="install-modal-title""#,
        "and so is the install modal, unchanged",
    );
    assert_eq!(
        body.matches(r#"class="search-input""#).count(),
        1,
        "{uri}: the two searches merged into one"
    );
}

// ===========================================================================
// Phase 3 — per-page composition (uat/artifacts/reviews/DESIGN-REVIEW.md §1.18, §2, §3.11)
// ===========================================================================

async fn seeded_policy_id(ctx: &TestContext) -> String {
    let policies = ctx.store.list_policies().await.expect("list policies");
    policies
        .iter()
        .find(|p| p.name == "default")
        .expect("the test app seeds a 'default' policy")
        .id
        .0
        .to_string()
}

// ---------------------------------------------------------------------------
// Policies list (§1.10)
// ---------------------------------------------------------------------------

/// Three controls on the policies list existed because the API had a route for
/// them, not because an operator needed them: a "Hide grant policies" checkbox
/// next to a select that already has "Grants Only", an Enabled pill whose only
/// behaviour was to swallow a click, and a row Enable/Disable button that the
/// detail page hides behind Edit. The select absorbs the checkbox, the pill
/// goes back to being a pill, and the toggle moves to the detail header.
#[tokio::test]
async fn the_policies_list_drops_the_grant_checkbox_the_pill_click_and_the_row_toggle() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/security";
    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert!(
        !body.contains("hideGrants"),
        "{uri}: the 'Hide grant policies' checkbox is the select's job"
    );
    assert!(
        !body.contains("Hide grant policies"),
        "{uri}: and its label goes with it"
    );
    // The select carries both outcomes the checkbox used to.
    for option in [
        ">All except grants<",
        ">Grants only<",
        ">System only<",
        ">Custom only<",
    ] {
        assert_contains(
            &body,
            uri,
            option,
            "the one filter select names every outcome",
        );
    }

    assert!(
        !body.contains(r#"@click.stop x-text="policy.enabled"#),
        "{uri}: the Enabled pill is a pill, not a click sink"
    );
    assert!(
        !body.contains("policy-toggle-btn"),
        "{uri}: Enable/Disable moved to the policy detail header"
    );
    assert!(
        !body.contains("askToggle("),
        "{uri}: and so did the dialog that confirms it"
    );

    // Row click and name link were two ways to the same URL; one link is left.
    assert!(
        !body.contains("window.location.href = '/security/' + policy.id"),
        "{uri}: the row is a link, not a link inside a click handler"
    );
    assert_contains(
        &body,
        uri,
        r#"class="cred-name row-link""#,
        "the name is the row's one link",
    );

    // The tester banner is a header button, not 72px of card above the table.
    assert!(
        !body.contains("policy-tester-cta"),
        "{uri}: the Policy Tester banner is a header button now"
    );
    assert_contains(
        &body,
        uri,
        r#"href="/security/tester" class="btn btn-secondary""#,
        "the tester is a secondary header action",
    );
    assert_contains(&body, uri, ">Open tester<", "and says what it opens");
}

// ---------------------------------------------------------------------------
// Policy detail (§1.11)
// ---------------------------------------------------------------------------

/// Enable/Disable is a secondary button in a detail header on workspaces and
/// MCP servers, a row button on the policies list, and an edit-mode checkbox on
/// the policy detail — three affordances for one piece of state. The detail
/// header wins everywhere.
#[tokio::test]
async fn the_policy_detail_header_carries_disable_and_enable() {
    let (ctx, cookie) = admin_session().await;
    let id = seeded_policy_id(&ctx).await;
    let uri = format!("/security/{id}");
    let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        &uri,
        r#"data-testid="policy-toggle""#,
        "the header carries the Disable/Enable button",
    );
    let at = body
        .find(r#"data-testid="policy-toggle""#)
        .expect("the toggle is on the page");
    let element = element_around(&body, at);
    assert!(
        element.contains("btn-secondary"),
        "{uri}: Enable is not the page's primary action; saw:\n{element}"
    );
    assert!(
        !body.contains(r#"x-model="editForm.enabled""#),
        "{uri}: the state is not behind Edit → checkbox → Save any more"
    );
    // The lockout guard and its dialog come with it.
    assert_contains(
        &body,
        &uri,
        "lockoutReason",
        "the last-enabled policy still explains why it cannot be disabled",
    );
    assert!(
        body.contains("takes it out of the evaluated policy set immediately"),
        "{uri}: the dialog must say what disabling does"
    );
}

/// Two icons on every statement card is 48 icons on the seeded policy. They
/// stay reachable — hover, and focus, so the keyboard still finds them — but
/// they are not drawn over the whole page at rest.
#[test]
fn the_per_statement_icons_are_revealed_on_hover_or_focus() {
    let css = vault_css();
    let rule = css_rule(&css, ".cedar-stmt-header-actions");
    assert!(
        rule.contains("opacity: 0"),
        "vault.css: the per-statement icons rest invisible; saw:\n{rule}"
    );
    for selector in [
        ".cedar-stmt-card:hover .cedar-stmt-header-actions",
        ".cedar-stmt-header-actions:focus-within",
    ] {
        assert!(
            css.contains(selector),
            "vault.css: {selector} must bring the per-statement icons back"
        );
    }
}

// ---------------------------------------------------------------------------
// One policy tester (§1.11, §1.12)
// ---------------------------------------------------------------------------

/// Two testers with disjoint vocabularies: the inline card could say "a User
/// with role operator" but not "on this credential"; the page could say "on
/// this credential" but not "a User". One tester, both vocabularies.
#[tokio::test]
async fn the_two_policy_testers_become_the_one_that_can_say_the_most() {
    let (ctx, cookie) = admin_session().await;

    assert!(
        !templates_dir().join("partials/policy_tester.html").exists(),
        "the inline tester partial is retired"
    );
    for (path, src) in all_templates() {
        assert!(
            !src.contains("partials/policy_tester.html"),
            "{}: nothing includes the retired inline tester",
            rel(&path)
        );
    }

    let id = seeded_policy_id(&ctx).await;
    let uri = format!("/security/{id}");
    let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_contains(
        &body,
        &uri,
        "'/security/tester?policy=' + policy.id",
        "the detail page sends the reader to the one tester, prefilled",
    );
    assert_contains(&body, &uri, "Test this policy", "and says what it opens");
    assert!(
        !body.contains("inline-tester-grid"),
        "{uri}: the inline tester's own form is gone"
    );

    let uri = "/security/tester";
    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_contains(
        &body,
        uri,
        r#"<optgroup label="Users">"#,
        "the merged tester can name a User principal",
    );
    assert_contains(
        &body,
        uri,
        r#"id="tester-role""#,
        "with the role that decides what the User may do",
    );
    assert_contains(
        &body,
        uri,
        r#"id="tester-tags""#,
        "and the workspace tags the inline card could express",
    );
    for any in [
        r#"value="Credential:*""#,
        r#"value="McpServer:*""#,
        r#"value="WorkspaceResource:*""#,
    ] {
        assert_contains(
            &body,
            uri,
            any,
            "and a resource of a type rather than one concrete row",
        );
    }
    assert_contains(&body, uri, "Any credential", "named as such");
    assert!(
        body.contains("/api/v1/users"),
        "{uri}: the User group is the real user list"
    );
}

/// Save Scenario, a Load select and a bare × were three header controls for a
/// `localStorage` convenience. One menu.
#[tokio::test]
async fn the_tester_scenario_controls_are_one_menu() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/security/tester";
    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        uri,
        "acOverflowMenu()",
        "the scenario controls are one menu",
    );
    assert_contains(&body, uri, ">Scenarios<", "labelled for what it holds");
    assert_contains(
        &body,
        uri,
        r#"role="menu""#,
        "and it is a menu, not a row of buttons",
    );
    for item in ["Save scenario", "Clear all scenarios"] {
        assert_contains(&body, uri, item, "every scenario action is an item of it");
    }
    assert!(
        !body.contains("tester-scenario-controls"),
        "{uri}: the three-control cluster is gone"
    );
}

// ---------------------------------------------------------------------------
// Detail pages: one Access tab, one meta line, one header grammar
// (§1.6, §1.8, §1.14, §2.1)
// ---------------------------------------------------------------------------

/// "MCP servers bound to this workspace" and "who consented to what" answer the
/// same question — what can this workspace reach — and each rendered one
/// centred sentence in its own tab. One Access tab, two sections.
#[tokio::test]
async fn the_workspace_detail_merges_mcp_servers_and_consents_into_one_access_tab() {
    let (ctx, cookie) = admin_session().await;
    let id = a_workspace(&ctx, "access-tab-ws").await;
    let uri = format!("/workspaces/{id}");
    let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        &uri,
        r#"activeTab === 'access'"#,
        "the two tabs are one Access tab",
    );
    assert!(
        !body.contains("activeTab === 'consents'"),
        "{uri}: Consents is a section of Access, not a tab"
    );
    assert!(
        !body.contains("activeTab === 'mcp'"),
        "{uri}: and so is the MCP server list"
    );
    // Both sections, and everything they carried, are still there.
    for needle in [
        "MCP servers this workspace can reach",
        "Consent grants",
        "loadMcpServers()",
        "loadConsents()",
        ">Revoke consent<",
    ] {
        assert_contains(&body, &uri, needle, "the merged tab keeps both sections");
    }
    assert_eq!(
        body.matches(r#"role="tab""#).count(),
        3,
        "{uri}: Details, Access and History — three tabs"
    );
}

/// The MCP detail told the reader to go to the Workspaces tab to manage the
/// bindings the Permissions tab was talking about. Same merge, same shape as
/// the workspace's — and the edit-mode Enabled checkbox becomes the header
/// button every other detail page uses.
#[tokio::test]
async fn the_mcp_detail_merges_workspaces_and_permissions_into_one_access_tab() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/mcp-servers/00000000-0000-0000-0000-0000000000ff";
    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        uri,
        r#"activeTab === 'access'"#,
        "the two tabs are one Access tab",
    );
    assert!(
        !body.contains("activeTab === 'permissions'"),
        "{uri}: Permissions is a section of Access, not a tab"
    );
    assert!(
        !body.contains("activeTab === 'workspaces'"),
        "{uri}: and so is the workspace binding table"
    );
    for needle in [
        "Workspaces with access",
        "Permission grants",
        r#"data-testid="share-with-workspace""#,
        "Available Cedar Actions",
    ] {
        assert_contains(&body, uri, needle, "the merged tab keeps both sections");
    }
    assert_eq!(
        body.matches(r#"class="tab-btn""#).count(),
        3,
        "{uri}: Tools, Access and History — three tabs"
    );

    // Enabled stops being an edit-mode checkbox.
    assert_contains(
        &body,
        uri,
        r#"data-testid="mcp-toggle""#,
        "the header carries Disable/Enable",
    );
    let at = body
        .find(r#"data-testid="mcp-toggle""#)
        .expect("the toggle is on the page");
    let element = element_around(&body, at);
    assert!(
        element.contains("btn-secondary"),
        "{uri}: Enable is not the page's primary action; saw:\n{element}"
    );
    assert!(
        !body.contains(r#"x-model="editForm.enabled""#),
        "{uri}: the state is not behind Edit → checkbox → Save any more"
    );
}

/// Created / Owner / ID were a third titled section on every detail page,
/// competing with the entity for the reader's attention. They are one small
/// line under the title, with the uuid carrying a copy affordance rather than
/// a row of its own.
#[tokio::test]
async fn every_detail_surface_shows_its_metadata_as_one_meta_line() {
    let (ctx, cookie) = admin_session().await;
    let ws = a_workspace(&ctx, "meta-line-ws").await;
    let cred = a_credential(&ctx, &cookie, "meta-line-cred").await;

    for uri in [
        format!("/workspaces/{ws}"),
        format!("/credentials/{cred}"),
        "/mcp-servers/00000000-0000-0000-0000-0000000000ff".to_string(),
    ] {
        let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
        assert_eq!(status, StatusCode::OK);
        assert_contains(
            &body,
            &uri,
            r#"class="detail-meta-line""#,
            "the metadata is one line under the title",
        );
        assert_contains(
            &body,
            &uri,
            "copyId()",
            "and the id can be copied rather than selected by hand",
        );
        assert_contains(
            &body,
            &uri,
            r#"class="mono-sm detail-meta-id""#,
            "the id sits on that line rather than in a row of its own",
        );
        assert!(
            !body.contains(r#"<div class="detail-label">Created</div>"#),
            "{uri}: the creation date is not a titled row any more"
        );
        assert!(
            !body.contains(r#"detail-section-label">Metadata<"#),
            "{uri}: and there is no Metadata section left to hold them"
        );
    }

    let css = vault_css();
    assert!(
        css.contains(".detail-meta-line"),
        "vault.css must style the meta line"
    );
}

/// `openEaModal(action)` had two labels — "… and N others — View all" when
/// there were more than five principals, "Details" when there were fewer.
/// One opener, one word.
#[tokio::test]
async fn the_effective_access_opener_is_always_called_view() {
    let (ctx, cookie) = admin_session().await;
    let cred = a_credential(&ctx, &cookie, "ea-opener-cred").await;
    let uri = format!("/credentials/{cred}");
    let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert!(
        !body.contains("View all"),
        "{uri}: one label for one action"
    );
    assert!(
        !body.contains(r#"title="View details">Details<"#),
        "{uri}: and it is not called Details either"
    );
    assert_eq!(
        body.matches(r#">View</button>"#).count(),
        1,
        "{uri}: the effective-access opener is one button labelled View"
    );
    // The modal it opens gains the footer Close every other modal has.
    assert_contains(
        &body,
        &uri,
        r#"data-testid="ea-modal-close""#,
        "the effective-access modal closes from its footer too",
    );
}

/// Restore was the product's only `btn-warning`, which made an amber button
/// the loudest thing on the History tab. The confirm dialog carries the
/// warning; the button is secondary.
#[test]
fn restore_is_a_secondary_button_and_nothing_is_a_warning_button() {
    let mut offenders = Vec::new();
    for (path, src) in all_templates() {
        if src.contains("btn-warning") {
            offenders.push(rel(&path));
        }
    }
    assert!(
        offenders.is_empty(),
        "a destructive-ish confirm is an outlined button whose dialog carries the warning; \
         these still ship a filled amber one: {offenders:?}"
    );
}

// ---------------------------------------------------------------------------
// Lists: one filter row, inert row tags (§1.4, §1.7)
// ---------------------------------------------------------------------------

/// A tag on a row and a tag in the toolbar looked identical and did the same
/// thing, so every row carried one click target per tag competing with the row
/// itself. The toolbar is the filter; a row tag is a label.
#[tokio::test]
async fn a_tag_on_a_row_is_a_label_and_the_toolbar_is_the_filter() {
    let (ctx, cookie) = admin_session().await;

    for uri in ["/credentials", "/workspaces"] {
        let (status, body) = get_page(&ctx.app, uri, &cookie).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            !body.contains("md-row-tag-btn"),
            "{uri}: a row tag is a label, not a second copy of the toolbar filter"
        );
        assert!(
            !body.contains(r#"@click.stop="toggleTag(t)""#),
            "{uri}: and it does not filter on click"
        );
        // The toolbar keeps the filter, and keeps reporting its state.
        assert_contains(
            &body,
            uri,
            r#"@click="toggleTag(tag)""#,
            "the toolbar chips still filter",
        );
        assert_contains(
            &body,
            uri,
            r#":aria-pressed="tagFilter.includes(tag) ? 'true' : 'false'""#,
            "and still say whether they are on",
        );
    }
}

/// The vault select was a full-width row above a half-width search. It belongs
/// beside the tag chips, and vaults get the entry point they lacked from the
/// page where credentials live.
#[tokio::test]
async fn the_credential_list_filters_from_one_row_that_links_to_the_vaults() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/credentials";
    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(
        body.matches(r#"class="md-tag-filters""#).count(),
        1,
        "{uri}: the vault select and the tag chips share one filter row"
    );
    assert_contains(
        &body,
        uri,
        r#"id="cred-vault-filter""#,
        "the vault filter is still the control the UAT drives",
    );
    assert_contains(
        &body,
        uri,
        r#"href="/settings#vaults-section""#,
        "and vaults have an entry point from where credentials live",
    );
    assert_contains(&body, uri, "Manage vaults", "labelled for what it opens");
}

// ---------------------------------------------------------------------------
// New credential: order, and the rare fields behind a disclosure (§1.5)
// ---------------------------------------------------------------------------

/// Service and "Allowed URL pattern" describe the same thing — where this
/// secret may go — and the pattern sat after Vault and Tags, below the fold of
/// a 900px screen. It moves up under Service; Description and Target Identity,
/// which almost nobody fills in, go behind an Advanced disclosure.
#[tokio::test]
async fn the_new_credential_form_puts_the_url_pattern_under_service() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/credentials/new";
    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    let service = body.find(r#"id="cred-service""#).expect("Service field");
    let pattern = body
        .find(r#"id="cred-url-pattern""#)
        .expect("Allowed URL pattern field");
    let vault = body.find(r#"id="cred-vault""#).expect("Vault field");
    assert!(
        service < pattern && pattern < vault,
        "{uri}: the URL pattern belongs directly under Service, above Vault and Tags"
    );

    // The rare fields keep their ids and their copy; they are just folded away.
    let advanced = body
        .find(r#"class="form-advanced""#)
        .expect("an Advanced disclosure");
    assert!(
        advanced < body.find(r#"id="cred-description""#).expect("Description"),
        "{uri}: Description is inside the Advanced disclosure"
    );
    assert!(
        advanced
            < body
                .find(r#"id="cred-target-identity""#)
                .expect("Target Identity"),
        "{uri}: and so is Target Identity"
    );
    assert_contains(&body, uri, ">Advanced<", "the disclosure says what it is");
}

/// Twenty-seven template cards is fourteen rows of grid that pushed Name below
/// the fold. Show the ones people pick and offer the rest.
#[tokio::test]
async fn the_template_picker_shows_a_shortlist_and_offers_the_rest() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/credentials/new";
    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        uri,
        "showAllTemplates",
        "the grid starts at a shortlist",
    );
    assert_contains(
        &body,
        uri,
        "templateShortlist",
        "and the shortlist is named, not a slice hidden in a filter",
    );
    assert_contains(
        &body,
        uri,
        r#"data-testid="show-all-templates""#,
        "with one control that opens the rest",
    );
    // Once a template is picked the picker collapses to one line.
    assert_contains(
        &body,
        uri,
        r#"data-testid="change-template""#,
        "and collapses to 'Template: X · Change' once one is chosen",
    );
}

// ---------------------------------------------------------------------------
// The nav says what the pages say (§1.1)
// ---------------------------------------------------------------------------

/// The page title, the back links and the tester breadcrumb all say "policy";
/// only the nav item said "Security".
#[tokio::test]
async fn the_nav_calls_the_policy_pages_policies() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/dashboard";
    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        uri,
        r#"<span class="nav-label">Policies</span>"#,
        "the nav item is named for the pages behind it",
    );
    assert!(
        !body.contains(r#"<span class="nav-label">Security</span>"#),
        "{uri}: nothing is called Security any more"
    );
    // The URL is unchanged; only the label moved.
    assert_contains(
        &body,
        uri,
        r#"href="/security" class="nav-link"#,
        "and it still points at /security",
    );
}

// ---------------------------------------------------------------------------
// Audit: the export offers what the API serves (§1.17)
// ---------------------------------------------------------------------------

/// The API serves CSV, JSONL and syslog; the page exposed one of them behind a
/// button called "Export CSV".
#[tokio::test]
async fn the_audit_export_offers_every_format_the_api_serves() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/audit";
    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert!(
        !body.contains(">Export CSV<"),
        "{uri}: one format is not the whole export"
    );
    assert_contains(&body, uri, ">Export<", "the trigger names the action");
    assert_contains(
        &body,
        uri,
        "acOverflowMenu()",
        "and it opens the shared menu",
    );
    for (label, path) in [
        (">CSV<", "/api/v1/audit/export"),
        (">JSONL<", "/api/v1/audit/export/jsonl"),
        (">Syslog<", "/api/v1/audit/export/syslog"),
    ] {
        assert_contains(&body, uri, label, "every format the API serves is offered");
        assert_contains(&body, uri, path, "and points at the route that serves it");
    }
    // The filters the reader set travel with the export.
    assert_contains(
        &body,
        uri,
        "exportParams()",
        "the export carries the page's filters",
    );
}

// ---------------------------------------------------------------------------
// Settings: one primary per card, one pattern per toggle (§1.15)
// ---------------------------------------------------------------------------

/// Six filled orange buttons at once, and an About card whose only content was
/// a version string the rail now carries at its foot.
#[tokio::test]
async fn settings_drops_the_about_card_and_demotes_its_secondary_actions() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/settings";
    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert!(
        !body.contains(r#">About</h3>"#),
        "{uri}: the version lives at the foot of the rail, not in a card"
    );
    assert!(
        !body.contains("Version {{ version }}") && !body.contains(">Agent Cordon</h3>"),
        "{uri}: and nothing is left of the card"
    );
    assert_contains(
        &body,
        uri,
        r#"class="settings-rail-version""#,
        "the rail still carries the version",
    );

    // The four section-opening actions are outlined, not filled.
    for (needle, what) in [
        (">Add Provider<", "adding an SSO provider"),
        (">Add User<", "adding a user"),
        (">Add Client<", "adding an OAuth client"),
        (r#"id="reseal-btn""#, "re-sealing the credential store"),
    ] {
        let at = body
            .find(needle)
            .unwrap_or_else(|| panic!("{uri}: expected to find {needle} ({what})"));
        let element = element_around(&body, at);
        assert!(
            element.contains("btn-secondary"),
            "{uri}: {what} is not the page's primary action; saw:\n{element}"
        );
    }
}

/// One state, one affordance: the OIDC providers table used a Disable/Enable
/// button and the OAuth clients table a toggle switch for the same thing.
#[tokio::test]
async fn settings_toggles_a_provider_the_same_way_it_toggles_a_client() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/settings";
    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    assert_contains(
        &body,
        uri,
        r#"class="toggle-switch provider-toggle""#,
        "a provider is toggled by a switch, as a client is",
    );
    assert_contains(
        &body,
        uri,
        r#"@change="toggleProvider(p)""#,
        "and the switch is what calls the API",
    );
    assert!(
        !body.contains(r#"x-text="p.enabled ? 'Disable' : 'Enable'""#),
        "{uri}: the Disable/Enable button is replaced by the switch"
    );
    assert_eq!(
        body.matches("toggle-switch").count(),
        2,
        "{uri}: two tables, two switches, one pattern"
    );
}

// ---------------------------------------------------------------------------
// Dashboard: three counts, one activity table (§1.3, §2.2, §3.11)
// ---------------------------------------------------------------------------

/// The third tile said "All systems operational" and linked to the audit log,
/// and the page carried two five-row tables with separate empty states, one of
/// which was empty on most instances most of the time.
#[tokio::test]
async fn the_dashboard_counts_mcp_servers_and_merges_the_two_activity_tables() {
    let (ctx, cookie) = admin_session().await;
    let uri = "/dashboard";
    let (status, body) = get_page(&ctx.app, uri, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    // The health sentence is a line under the title, not a tile.
    assert!(
        !body.contains("All systems operational"),
        "{uri}: a health sentence is not a count, and it did not link to health"
    );
    assert_contains(
        &body,
        uri,
        r#"class="dash-health-line""#,
        "health is one line under the page title",
    );
    assert_contains(
        &body,
        uri,
        r#"href="/mcp-servers" class="dash-card"#,
        "the third tile counts the third entity",
    );
    assert_contains(
        &body,
        uri,
        "stats.mcp_servers_total",
        "and shows the count it fetched",
    );

    // One table, one empty state, one link out.
    assert_eq!(
        body.matches(r#"class="dash-section""#).count(),
        1,
        "{uri}: one Recent activity section, not two"
    );
    assert_contains(&body, uri, ">Recent activity<", "named for what it holds");
    assert_contains(
        &body,
        uri,
        "View audit log",
        "with the way to the rest on the same baseline",
    );
    assert!(
        !body.contains("Recent Credential Vending") && !body.contains("Recent MCP Activity"),
        "{uri}: the two tables merged"
    );
    assert_contains(
        &body,
        uri,
        "recentActivity",
        "and one list feeds the merged table",
    );

    // The first-run card is a plain bordered card: the dashboard has no
    // primary action, so nothing on it is orange.
    let css = vault_css();
    let card = css_rule(&css, ".dash-cta-card {");
    assert!(
        !card.contains("--accent"),
        "the dashboard carries no orange after the first run:\n{card}"
    );
}

// ---------------------------------------------------------------------------
// Iconography: the sprite, not the fallback font (§3.6)
// ---------------------------------------------------------------------------

/// `✕ × ↑ ↓ ⋯` render in whatever the fallback font happens to provide and sit
/// at the wrong baseline. Every one of them that is a button's whole label
/// becomes a symbol from the sprite; the accessible name it already carried
/// stays.
#[test]
fn no_button_is_labelled_with_a_text_glyph() {
    let glyphs = [
        ("&times;", "x"),
        ("&#10005;", "x"),
        ("&#8943;", "more-horizontal"),
        ("&uarr;", "arrow-up"),
        ("&darr;", "arrow-down"),
        ("\u{2715}", "x"),
        ("\u{00d7}", "x"),
        ("\u{2191}", "arrow-up"),
        ("\u{2193}", "arrow-down"),
        ("\u{22ef}", "more-horizontal"),
    ];

    let mut offenders = Vec::new();
    for (path, src) in all_templates() {
        // Only the rendered markup, not the comments explaining the change.
        for (i, line) in src.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("<!--")
                || trimmed.starts_with("{#")
                || trimmed.starts_with('*')
                || trimmed.starts_with("//")
            {
                continue;
            }
            if !line.contains("</button>") && !line.contains("<button") {
                continue;
            }
            for (glyph, replacement) in glyphs {
                if line.contains(glyph) {
                    offenders.push(format!(
                        "{}:{} — {glyph} should be <use href=\"/icons.svg#{replacement}\">",
                        rel(&path),
                        i + 1
                    ));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a button's label is a sprite symbol, not a character the fallback font \
         may or may not have:\n  {}",
        offenders.join("\n  ")
    );
}

/// Every sprite reference names a symbol the sprite actually defines, and every
/// icon-only button still says what it does.
#[test]
fn every_sprite_reference_resolves_and_every_icon_button_is_named() {
    let sprite = std::fs::read_to_string(static_dir().join("icons.svg")).expect("read the sprite");

    let mut missing = Vec::new();
    let mut unnamed = Vec::new();
    for (path, src) in all_templates() {
        let mut from = 0;
        while let Some(at) = src[from..].find(r#"<use href="/icons.svg#"#) {
            let start = from + at + r#"<use href="/icons.svg#"#.len();
            let end = start + src[start..].find('"').expect("closing quote");
            let name = &src[start..end];
            if !sprite.contains(&format!("id=\"{name}\"")) {
                missing.push(format!("{}: #{name}", rel(&path)));
            }
            from = end;
        }

        // An icon that is a button's whole label carries its name in an
        // attribute; an icon inside a control with visible text is decorative
        // and is marked `aria-hidden` instead.
        for (i, line) in src.lines().enumerate() {
            if !line.contains(r#"<use href="/icons.svg#"#) {
                continue;
            }
            let head: usize = src.lines().take(i).map(|l| l.len() + 1).sum();
            let open = match src[..head].rfind("<button") {
                Some(at) => at,
                None => continue, // not a button; the link's own text names it
            };
            let close = src[open..]
                .find("</button>")
                .map(|at| open + at)
                .unwrap_or(src.len());
            if close < head {
                continue; // the button closed before this icon
            }
            let element = &src[open..close];
            let visible_text = element
                .rsplit('>')
                .next()
                .map(|t| !t.trim().is_empty())
                .unwrap_or(false);
            if !element.contains("aria-label") && !element.contains("sr-only") && !visible_text {
                unnamed.push(format!("{}:{}", rel(&path), i + 1));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "a `<use>` that names no symbol renders as nothing: {missing:?}"
    );
    assert!(
        unnamed.is_empty(),
        "an icon-only control needs an accessible name: {unnamed:?}"
    );
}

// ---------------------------------------------------------------------------
// Credential detail hero: a segmented Grant/Deny, tabs at card width (§3.11)
// ---------------------------------------------------------------------------

/// Grant and Deny are one choice with two values, not two buttons that swap
/// `btn-primary` for `btn-danger`. A segmented control says which is chosen
/// once, in the one attribute a screen reader reads for a radio.
#[tokio::test]
async fn the_grant_and_deny_choice_is_one_segmented_control() {
    let (ctx, cookie) = admin_session().await;
    let id = a_credential(&ctx, &cookie, "ctl-segmented-cred").await;

    for uri in [
        format!("/credentials/{id}"),
        "/mcp-servers/00000000-0000-0000-0000-0000000000ff".to_string(),
    ] {
        let (status, body) = get_page(&ctx.app, &uri, &cookie).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_contains(
            &body,
            &uri,
            r#"role="radiogroup""#,
            "Grant and Deny are one choice",
        );
        assert_contains(
            &body,
            &uri,
            r#"aria-label="Grant or deny""#,
            "and the choice says what it is",
        );
        assert_contains(
            &body,
            &uri,
            r#":aria-checked="grantMode === 'grant' ? 'true' : 'false'""#,
            "Grant says whether it is the chosen value",
        );
        assert_contains(
            &body,
            &uri,
            r#":aria-checked="grantMode === 'deny' ? 'true' : 'false'""#,
            "and so does Deny",
        );
        assert!(
            !body.contains(r#":aria-pressed="grantMode"#),
            "{uri}: a radio reports `aria-checked`, not `aria-pressed`"
        );
        // The colour is the segment that is on, not a red button waiting.
        assert!(
            !body.contains(r#":class="grantMode === 'deny' ? 'btn-danger' : 'btn-ghost'""#),
            "{uri}: the segments share one style; the segment that is on is the one marked"
        );
    }
}

/// The tab strip was capped at 640px inside a card that is not, so it stopped
/// short of the card's right edge on every detail page.
#[test]
fn the_detail_tab_strip_is_as_wide_as_the_card_it_sits_in() {
    let css = vault_css();
    let rule = css_rule(&css, ".detail-tabs {");
    assert!(
        !rule.contains("max-width"),
        "vault.css: the tab strip takes the card's width (uat/artifacts/reviews/DESIGN-REVIEW.md §2.3):\n{rule}"
    );
    let seg = css_rule(&css, ".segmented {");
    assert!(
        seg.contains("display"),
        "vault.css must style the segmented control:\n{seg}"
    );
}
