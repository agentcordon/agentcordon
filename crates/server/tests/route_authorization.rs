//! Every admin API route that names a resource in its path must authorize
//! against that resource, not against `System`, and must refuse a signed-in
//! user who does not own it.
//!
//! A `System`-scoped check answers "may this user manage workspaces at
//! all", which is how an operator came to manage other tenants' workspaces.
//! The observable for that is the `policy_evaluated` audit row each
//! evaluation writes: it names the resource type and id the decision was
//! made about.
//!
//! A scoped evaluation is not by itself a refusal, so each row also carries
//! an [`Access`] classification: what a signed-in operator who owns nothing
//! gets, and whether the resource's owner and a non-root admin get through.
//! The stranger's refusal is the security property; the owner and admin
//! columns are what stop a route from "passing" by being broken for
//! everybody.
//!
//! The table classifies every parameterized admin path found in the router
//! source. A route that is still `System`-scoped is listed with the reason
//! so the gap is explicit; a new parameterized route that is not in the
//! table fails the test until it is classified.

use std::collections::BTreeSet;

use axum::http::{Method, StatusCode};
use serde_json::{json, Value};

use agent_cordon_core::domain::user::{UserId, UserRole};
use agent_cordon_core::storage::AuditFilter;
use agent_cordon_server::test_helpers::{TestAppBuilder, TestContext};

use crate::common::{
    create_root_user, create_test_user, login_user_combined, send_json_auto_csrf, TEST_PASSWORD,
};

#[derive(Clone, Copy)]
enum Expect {
    /// Must evaluate against a concrete resource.
    Scoped,
    /// Still evaluates against `System`; the reason is documented.
    SystemAllowed(&'static str),
}

/// Whether a principal reaches the route's work at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Pass {
    /// Not refused. The route may still answer 404 or 409 for its own
    /// reasons — a missing history entry, a binding that is not there.
    Through,
    /// Refused with 403.
    Refused,
}

/// Who reaches a resource that another user owns.
#[derive(Clone, Copy)]
enum Access {
    /// The resource has an owner. A signed-in operator who owns nothing is
    /// refused with `stranger`; `owner` and `admin` say whether the
    /// resource's owner and a non-root admin get through.
    Owned {
        stranger: StatusCode,
        owner: Pass,
        admin: Pass,
        why: &'static str,
    },
    /// The resource has no owner and the action is admin-only: every
    /// operator is refused, every admin gets through.
    AdminOnly(&'static str),
    /// Ownership is not this route's model. The reason says what is.
    Unowned(&'static str),
}

/// The common shape: a stranger gets 403.
fn owned(owner: Pass, admin: Pass, why: &'static str) -> Access {
    Access::Owned {
        stranger: StatusCode::FORBIDDEN,
        owner,
        admin,
        why,
    }
}

/// The same, for routes that report a refusal as "not found" rather than
/// telling the caller the resource exists.
fn owned_as_missing(owner: Pass, admin: Pass, why: &'static str) -> Access {
    Access::Owned {
        stranger: StatusCode::NOT_FOUND,
        owner,
        admin,
        why,
    }
}

struct Route {
    method: Method,
    /// Path template as registered, e.g. `/credentials/{id}`.
    template: &'static str,
    body: Option<Value>,
    expect: Expect,
    access: Access,
}

fn route(
    method: Method,
    template: &'static str,
    body: Option<Value>,
    expect: Expect,
    access: Access,
) -> Route {
    Route {
        method,
        template,
        body,
        expect,
        access,
    }
}

/// Paths the router registers with at least one `{param}`, read from the
/// admin API source so the table cannot silently fall behind.
fn registered_parameterized_paths() -> BTreeSet<String> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/routes/admin_api");
    let mut paths = BTreeSet::new();
    let mut stack = vec![dir];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).expect("read admin_api dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("read source");
            // `.route("/x/{id}", ...)` possibly split over lines.
            let mut rest = src.as_str();
            while let Some(i) = rest.find(".route(") {
                rest = &rest[i + 7..];
                let trimmed = rest.trim_start();
                if let Some(stripped) = trimmed.strip_prefix('"') {
                    if let Some(end) = stripped.find('"') {
                        let p = &stripped[..end];
                        if p.contains('{') {
                            paths.insert(p.to_string());
                        }
                    }
                }
            }
        }
    }
    paths
}

struct Seeds {
    credential_id: String,
    credential_name: String,
    workspace_id: String,
    policy_id: String,
    mcp_server_id: String,
    /// The id of a vault the seeding user owns, holding one credential.
    vault_id: String,
    /// A user id that is a plausible target for a share or a consent.
    target_user_id: String,
}

impl Seeds {
    fn empty() -> Self {
        Seeds {
            credential_id: String::new(),
            credential_name: String::new(),
            workspace_id: String::new(),
            policy_id: String::new(),
            mcp_server_id: String::new(),
            vault_id: String::new(),
            target_user_id: String::new(),
        }
    }
}

/// An MCP server owned by `owner`. There is no `POST /mcp-servers`: a server
/// is created by import or by provisioning from the catalog, neither of which
/// can name an arbitrary owner, so this fixture writes to the store.
async fn seed_mcp_server(ctx: &TestContext, owner: &UserId) -> String {
    use agent_cordon_core::domain::mcp::{McpAuthMethod, McpServer, McpServerId, McpTransport};
    let now = chrono::Utc::now();
    let server = McpServer {
        id: McpServerId(uuid::Uuid::new_v4()),
        workspace_id: None,
        name: format!("route-mcp-{}", uuid::Uuid::new_v4().simple()),
        upstream_url: "https://mcp.example.test/rpc".to_string(),
        transport: McpTransport::Http,
        allowed_tools: None,
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: vec![],
        required_credentials: None,
        auth_method: McpAuthMethod::default(),
        template_key: None,
        discovered_tools: None,
        created_by_user: Some(owner.clone()),
    };
    ctx.store
        .create_mcp_server(&server)
        .await
        .expect("create mcp server");
    server.id.0.to_string()
}

/// A workspace owned by `owner`. There is no HTTP creation path — a
/// workspace is created by approving an OAuth registration — so this is the
/// one fixture that writes to the store.
async fn seed_workspace(ctx: &TestContext, owner: &UserId) -> String {
    use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
    let now = chrono::Utc::now();
    let ws = Workspace {
        id: WorkspaceId(uuid::Uuid::new_v4()),
        name: format!("route-ws-{}", uuid::Uuid::new_v4().simple()),
        status: WorkspaceStatus::Active,
        pk_hash: Some(format!(
            "{:0>64}",
            format!("{:x}", uuid::Uuid::new_v4().as_u128())
        )),
        encryption_public_key: None,
        tags: vec![],
        owner_id: Some(owner.clone()),
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };
    ctx.store.create_workspace(&ws).await.expect("create ws");
    ws.id.0.to_string()
}

/// Create a credential through the API, optionally in a vault named by id.
/// Returns `(id, name)`.
async fn create_credential(
    ctx: &TestContext,
    cookie: &str,
    vault_id: Option<&str>,
) -> (String, String) {
    let name = format!("route-cred-{}", uuid::Uuid::new_v4().simple());
    let mut body = json!({ "name": name, "service": "svc", "secret_value": "s3cret" });
    if let Some(v) = vault_id {
        body["vault_id"] = json!(v);
    }
    let (status, resp) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/credentials",
        None,
        Some(cookie),
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seed credential: {resp}");
    (resp["data"]["id"].as_str().unwrap().to_string(), name)
}

/// A vault owned by the caller. Returns its id — every vault route names a
/// vault by id, because a display name identifies nothing on its own.
async fn seed_vault(ctx: &TestContext, cookie: &str) -> String {
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/vaults",
        None,
        Some(cookie),
        Some(json!({ "name": format!("route-vault-{}", uuid::Uuid::new_v4().simple()) })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seed vault: {body}");
    body["data"]["id"].as_str().unwrap().to_string()
}

/// A stored policy that grants nothing: a `forbid` whose condition never
/// holds. The sweep must not seed `permit(principal, action, resource)` —
/// that policy makes every route answer 200 for everyone.
async fn seed_policy(ctx: &TestContext, cookie: &str) -> String {
    let (status, body) = send_json_auto_csrf(
        &ctx.app,
        Method::POST,
        "/api/v1/policies",
        None,
        Some(cookie),
        Some(json!({
            "name": format!("route-policy-{}", uuid::Uuid::new_v4().simple()),
            "cedar_policy": "forbid(principal is AgentCordon::User, \
                action == AgentCordon::Action::\"list\", \
                resource is AgentCordon::System) \
                when { principal.role == \"no-such-role\" };"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seed policy: {body}");
    body["data"]["id"].as_str().unwrap().to_string()
}

fn table(seeds: &Seeds) -> Vec<Route> {
    use Expect::*;
    let ws = &seeds.workspace_id;
    let target = &seeds.target_user_id;
    // Repeated notes, written once.
    const CRED: &str = "a credential belongs to the user who created it; default policy 2b \
        scopes even an admin to their own, so only root reaches another user's";
    const WORKSPACE: &str = "admins reach every workspace (2a); an operator reaches only the \
        ones they own (2e-owner)";
    const MCP: &str = "admins manage any MCP server (2e-mcp); an operator only the ones they \
        created";
    const TAGS: &str = "tagging a workspace is `manage_tags`, which no operator holds: adding \
        `production` to a workspace you own is how an operator satisfied an \
        environment-isolation policy";
    /// A provider client carries no owner, so the check names `System`.
    /// Giving it one is the next phase's authorization-model work; until
    /// then the action itself is the boundary.
    const OAUTH_CLIENT_SYSTEM: &str =
        "manage_oauth_provider_clients applies to System only (the row has no owner)";
    const OAUTH_CLIENT_ADMIN: &str =
        "rewriting the registration every MCP server at an origin authenticates with needs \
         `manage_oauth_provider_clients`, which the default policy grants to admins only";

    const VAULT_OWNER: &str = "a vault belongs to the user who created it: the owner acts on \
        it at any role, and `manage_vaults` — an admin grant — does not make an admin the owner";
    const VAULT_GRANT: &str = "granting a share is the owner's act alone, at any role; an admin \
        who owns nothing in the vault is refused, because `manage_vaults` would otherwise let \
        any admin hand out another user's credentials";
    const VAULT_REVOKE: &str = "revoking is the owner's act and an admin's: `manage_vaults` \
        exists so someone can cut off a share they did not make. The owner's 404 here is a \
        missing share, not a refusal";
    const VAULT_NO_CEDAR: &str = "there is no Vault resource type; ownership is the whole \
        check, and `manage_vaults` is System-wide when it is consulted at all";

    vec![
        // --- credentials: the resource is the credential ---
        route(
            Method::GET,
            "/credentials/{id}",
            None,
            Scoped,
            owned(Pass::Through, Pass::Refused, CRED),
        ),
        route(
            Method::PUT,
            "/credentials/{id}",
            Some(json!({})),
            Scoped,
            owned(Pass::Through, Pass::Refused, CRED),
        ),
        route(
            Method::DELETE,
            "/credentials/{id}",
            None,
            Scoped,
            owned(Pass::Through, Pass::Refused, CRED),
        ),
        route(
            Method::POST,
            "/credentials/{id}/reveal",
            Some(json!({})),
            Scoped,
            owned_as_missing(
                Pass::Through,
                Pass::Refused,
                "a forbid on `unprotect` is reported as 404 so the caller cannot learn that the \
                 credential exists",
            ),
        ),
        route(
            Method::GET,
            "/credentials/{id}/secret-history",
            None,
            Scoped,
            owned(Pass::Through, Pass::Refused, CRED),
        ),
        route(
            Method::POST,
            "/credentials/{id}/secret-history/{history_id}/restore",
            Some(json!({})),
            Scoped,
            owned(Pass::Through, Pass::Refused, CRED),
        ),
        route(
            Method::POST,
            "/credentials/{id}/vend",
            Some(json!({})),
            SystemAllowed("workspace-bearer route; a session is refused before any evaluation"),
            Access::Unowned(
                "workspace-bearer route; a browser session is refused with 401 before any \
                 evaluation, so there is no owner to compare",
            ),
        ),
        route(
            Method::GET,
            "/credentials/by-name/{name}",
            None,
            Scoped,
            owned_as_missing(
                Pass::Through,
                Pass::Refused,
                "name resolution filters candidates through Cedar; a name the caller may not see \
                 is reported as not found rather than forbidden",
            ),
        ),
        route(
            Method::POST,
            "/credentials/vend-device/{name}",
            Some(json!({})),
            SystemAllowed("workspace-bearer route; a session is refused before any evaluation"),
            Access::Unowned(
                "workspace-bearer route; a browser session is refused with 401 before any \
                 evaluation, so there is no owner to compare",
            ),
        ),
        route(
            Method::GET,
            "/credentials/{id}/permissions",
            None,
            Scoped,
            owned(Pass::Through, Pass::Refused, CRED),
        ),
        route(
            Method::POST,
            "/credentials/{id}/permissions",
            Some(json!({ "workspace_id": ws, "permission": "read" })),
            Scoped,
            owned(Pass::Through, Pass::Refused, CRED),
        ),
        route(
            Method::PUT,
            "/credentials/{id}/permissions",
            Some(json!({ "permissions": [{ "workspace_id": ws, "permission": "read" }] })),
            Scoped,
            owned(Pass::Through, Pass::Refused, CRED),
        ),
        route(
            Method::DELETE,
            "/credentials/{id}/permissions/{agent_id}/{permission}",
            None,
            Scoped,
            owned(Pass::Through, Pass::Refused, CRED),
        ),
        // --- workspaces: the resource is the workspace with its owner ---
        route(
            Method::GET,
            "/workspaces/{id}",
            None,
            Scoped,
            owned(Pass::Through, Pass::Through, WORKSPACE),
        ),
        route(
            Method::PUT,
            "/workspaces/{id}",
            Some(json!({})),
            Scoped,
            owned(Pass::Through, Pass::Through, WORKSPACE),
        ),
        route(
            Method::DELETE,
            "/workspaces/{id}",
            None,
            Scoped,
            owned(Pass::Through, Pass::Through, WORKSPACE),
        ),
        route(
            Method::GET,
            "/workspaces/{id}/consents",
            None,
            Scoped,
            owned(Pass::Through, Pass::Through, WORKSPACE),
        ),
        route(
            Method::DELETE,
            "/workspaces/{id}/consents/{user_id}",
            None,
            Scoped,
            owned(Pass::Through, Pass::Through, WORKSPACE),
        ),
        route(
            Method::POST,
            "/workspaces/{id}/tags",
            Some(json!({ "tag": "route-tag" })),
            Scoped,
            owned(Pass::Refused, Pass::Through, TAGS),
        ),
        route(
            Method::DELETE,
            "/workspaces/{id}/tags/{tag}",
            None,
            Scoped,
            owned(Pass::Refused, Pass::Through, TAGS),
        ),
        route(
            Method::POST,
            "/workspaces/{id}/revoke",
            Some(json!({})),
            Scoped,
            owned(Pass::Through, Pass::Through, WORKSPACE),
        ),
        // --- policies: the resource is policy administration ---
        route(
            Method::GET,
            "/policies/{id}",
            None,
            Scoped,
            Access::AdminOnly(
                "Cedar policy administration is `manage_policies` on a PolicyResource, granted \
                 to admins only (2a); a policy has no owner",
            ),
        ),
        route(
            Method::PUT,
            "/policies/{id}",
            Some(json!({})),
            Scoped,
            Access::AdminOnly(
                "Cedar policy administration is `manage_policies` on a PolicyResource, granted \
                 to admins only (2a); a policy has no owner",
            ),
        ),
        route(
            Method::DELETE,
            "/policies/{id}",
            None,
            Scoped,
            Access::AdminOnly(
                "Cedar policy administration is `manage_policies` on a PolicyResource, granted \
                 to admins only (2a); a policy has no owner",
            ),
        ),
        // --- MCP servers: the resource is the server with its owner ---
        route(
            Method::GET,
            "/mcp-servers/{id}",
            None,
            Scoped,
            owned(Pass::Through, Pass::Through, MCP),
        ),
        route(
            Method::PUT,
            "/mcp-servers/{id}",
            Some(json!({})),
            Scoped,
            owned(Pass::Through, Pass::Through, MCP),
        ),
        route(
            Method::DELETE,
            "/mcp-servers/{id}",
            None,
            Scoped,
            owned(Pass::Through, Pass::Through, MCP),
        ),
        route(
            Method::POST,
            "/mcp-servers/{id}/generate-policies",
            Some(json!({ "tools": ["echo"], "agent_tags": ["route"] })),
            Scoped,
            owned(Pass::Through, Pass::Through, MCP),
        ),
        route(
            Method::POST,
            "/mcp-servers/{id}/discover-tools",
            None,
            Scoped,
            owned(Pass::Through, Pass::Through, MCP),
        ),
        route(
            Method::GET,
            "/mcp-servers/{id}/permissions",
            None,
            Scoped,
            owned(Pass::Through, Pass::Through, MCP),
        ),
        route(
            Method::POST,
            "/mcp-servers/{id}/permissions",
            Some(json!({ "workspace_id": ws, "permission": "mcp_tool_call:echo" })),
            Scoped,
            owned(Pass::Through, Pass::Through, MCP),
        ),
        route(
            Method::DELETE,
            "/mcp-servers/{id}/permissions/{agent_id}/{permission}",
            None,
            Scoped,
            owned(Pass::Through, Pass::Through, MCP),
        ),
        route(
            Method::GET,
            "/mcp-servers/{id}/workspaces",
            None,
            Scoped,
            owned(Pass::Through, Pass::Through, MCP),
        ),
        route(
            Method::POST,
            "/mcp-servers/{id}/workspaces",
            Some(json!({ "workspace_ids": [ws] })),
            Scoped,
            owned(Pass::Through, Pass::Through, MCP),
        ),
        route(
            Method::DELETE,
            "/mcp-servers/{id}/workspaces/{workspace_id}",
            None,
            Scoped,
            owned(Pass::Through, Pass::Through, MCP),
        ),
        // --- still System-scoped: no resource type in the schema yet ---
        route(
            Method::GET,
            "/users/{id}",
            None,
            SystemAllowed("manage_users has no User resource"),
            Access::AdminOnly(
                "manage_users is granted to admins only (2a); there is no User resource type to \
                 scope against",
            ),
        ),
        route(
            Method::PUT,
            "/users/{id}",
            Some(json!({})),
            SystemAllowed("manage_users has no User resource"),
            Access::AdminOnly(
                "manage_users is granted to admins only (2a); there is no User resource type to \
                 scope against",
            ),
        ),
        route(
            Method::DELETE,
            "/users/{id}",
            None,
            SystemAllowed("manage_users has no User resource"),
            Access::AdminOnly(
                "manage_users is granted to admins only (2a); there is no User resource type to \
                 scope against",
            ),
        ),
        route(
            Method::POST,
            "/users/{id}/change-password",
            Some(json!({ "new_password": "another-strong-password-123!" })),
            SystemAllowed("manage_users has no User resource"),
            Access::AdminOnly(
                "manage_users is granted to admins only (2a); there is no User resource type to \
                 scope against",
            ),
        ),
        route(
            Method::PATCH,
            "/vaults/{id}",
            Some(json!({ "name": "route-renamed" })),
            SystemAllowed(VAULT_NO_CEDAR),
            owned(Pass::Through, Pass::Refused, VAULT_OWNER),
        ),
        route(
            Method::DELETE,
            "/vaults/{id}",
            None,
            SystemAllowed(VAULT_NO_CEDAR),
            // The owner's 409 is the vault's own answer — it still holds the
            // seeded credential — not a refusal.
            owned(Pass::Through, Pass::Refused, VAULT_OWNER),
        ),
        route(
            Method::GET,
            "/vaults/{id}/credentials",
            None,
            SystemAllowed(VAULT_NO_CEDAR),
            Access::Unowned(
                "the list is filtered to the caller's own credentials and the vaults shared with \
                 them, so a stranger gets 200 and an empty list rather than a refusal; \
                 `vault_ownership::vault_contents_are_scoped_to_the_owner` asserts the filtering",
            ),
        ),
        route(
            Method::GET,
            "/vaults/{id}/shares",
            None,
            SystemAllowed(VAULT_NO_CEDAR),
            owned(
                Pass::Through,
                Pass::Through,
                "the share list names who else the vault reaches, so it is gated per-vault: the \
                 owner reads it, an admin reads every vault by `manage_vaults`, and a signed-in \
                 stranger is refused",
            ),
        ),
        route(
            Method::POST,
            "/vaults/{id}/shares",
            Some(json!({ "user_id": target, "permission": "read" })),
            SystemAllowed(VAULT_NO_CEDAR),
            owned(Pass::Through, Pass::Refused, VAULT_GRANT),
        ),
        route(
            Method::DELETE,
            "/vaults/{id}/shares/{user_id}",
            None,
            SystemAllowed(VAULT_NO_CEDAR),
            owned(Pass::Through, Pass::Through, VAULT_REVOKE),
        ),
        route(
            Method::GET,
            "/oidc-providers/{id}",
            None,
            SystemAllowed("manage_oidc_providers applies to System only"),
            Access::AdminOnly("manage_oidc_providers is granted to admins only (2a)"),
        ),
        route(
            Method::PUT,
            "/oidc-providers/{id}",
            Some(json!({})),
            SystemAllowed("manage_oidc_providers applies to System only"),
            Access::AdminOnly("manage_oidc_providers is granted to admins only (2a)"),
        ),
        route(
            Method::DELETE,
            "/oidc-providers/{id}",
            None,
            SystemAllowed("manage_oidc_providers applies to System only"),
            Access::AdminOnly("manage_oidc_providers is granted to admins only (2a)"),
        ),
        route(
            Method::GET,
            "/oauth-provider-clients/{id}",
            None,
            SystemAllowed("reading a provider client is manage_mcp_servers on System"),
            Access::Unowned(
                "reading stays on `manage_mcp_servers` so an operator can see which client \
                 an origin uses; the response never carries the client secret",
            ),
        ),
        route(
            Method::PUT,
            "/oauth-provider-clients/{id}",
            Some(json!({ "label": "renamed" })),
            SystemAllowed(OAUTH_CLIENT_SYSTEM),
            Access::AdminOnly(OAUTH_CLIENT_ADMIN),
        ),
        route(
            Method::DELETE,
            "/oauth-provider-clients/{id}",
            None,
            SystemAllowed(OAUTH_CLIENT_SYSTEM),
            Access::AdminOnly(OAUTH_CLIENT_ADMIN),
        ),
        route(
            Method::POST,
            "/oauth-provider-clients/{id}/reregister",
            Some(json!({})),
            SystemAllowed(OAUTH_CLIENT_SYSTEM),
            Access::AdminOnly(OAUTH_CLIENT_ADMIN),
        ),
        route(
            Method::GET,
            "/audit/{id}",
            None,
            SystemAllowed("view_audit; tenant scoping is applied in the handler"),
            Access::Unowned(
                "view_audit; tenant scoping is applied in the handler, not by an owner on the \
                 resource",
            ),
        ),
    ]
}

/// Fill a template's parameters with ids that exist.
fn fill(template: &str, seeds: &Seeds) -> String {
    let name = seeds.credential_name.as_str();
    template
        .replace(
            "{id}",
            match template.split('/').nth(1) {
                Some("credentials") => &seeds.credential_id,
                Some("workspaces") => &seeds.workspace_id,
                Some("policies") => &seeds.policy_id,
                Some("mcp-servers") => &seeds.mcp_server_id,
                Some("vaults") => &seeds.vault_id,
                _ => "00000000-0000-0000-0000-000000000000",
            },
        )
        .replace("{history_id}", "00000000-0000-0000-0000-000000000001")
        .replace("{agent_id}", &seeds.workspace_id)
        .replace("{workspace_id}", &seeds.workspace_id)
        .replace("{user_id}", &seeds.target_user_id)
        .replace(
            "{permission}",
            if template.starts_with("/mcp-servers") {
                "mcp_tool_call:echo"
            } else {
                "read"
            },
        )
        .replace("{name}", name)
        .replace("{tag}", "route-tag")
}

async fn policy_evaluations(ctx: &TestContext) -> Vec<(String, String, Option<String>)> {
    ctx.store
        .list_audit_events_filtered(&AuditFilter {
            limit: 1000,
            event_type: Some("policy_evaluated".to_string()),
            ..Default::default()
        })
        .await
        .expect("audit list")
        .into_iter()
        .map(|e| (e.id.to_string(), e.resource_type, e.resource_id))
        .collect()
}

#[tokio::test]
async fn every_parameterized_admin_route_is_classified() {
    let registered = registered_parameterized_paths();
    let seeds = Seeds::empty();
    let tabled: BTreeSet<String> = table(&seeds)
        .into_iter()
        .map(|r| r.template.to_string())
        .collect();
    for r in table(&seeds) {
        if let Expect::SystemAllowed(reason) = r.expect {
            eprintln!("System-scoped: {} {} ({reason})", r.method, r.template);
        }
        if let Access::Unowned(reason) = r.access {
            eprintln!("Not owner-scoped: {} {} ({reason})", r.method, r.template);
        }
    }
    let missing: Vec<_> = registered.difference(&tabled).collect();
    assert!(
        missing.is_empty(),
        "parameterized admin routes not classified in this test: {missing:?}"
    );
}

#[tokio::test]
async fn resource_routes_authorize_against_the_resource() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let root = create_root_user(&*ctx.store, "route-root", TEST_PASSWORD).await;
    let bystander = create_test_user(
        &*ctx.store,
        "route-bystander",
        TEST_PASSWORD,
        UserRole::Viewer,
    )
    .await;
    let cookie = login_user_combined(&ctx.app, "route-root", TEST_PASSWORD).await;

    let mut failures = Vec::new();
    // Deletes run last, deepest path first, so a deleted parent does not
    // turn later rows into 404s before their evaluation.
    let mut rows = table(&Seeds::empty());
    rows.sort_by_key(|r| {
        (
            r.method == Method::DELETE,
            std::cmp::Reverse(r.template.matches('/').count()),
        )
    });
    for r in rows {
        let Expect::Scoped = r.expect else { continue };
        // Every row gets its own resources, so a delete in an earlier row
        // cannot turn a later one into a 404 before its evaluation.
        let seeds = fresh_seeds(&ctx, &cookie, &cookie, &root.id, &bystander.id).await;
        let row = find_row(&seeds, &r.method, r.template);
        let uri = format!("/api/v1{}", fill(r.template, &seeds));
        let before: BTreeSet<String> = policy_evaluations(&ctx)
            .await
            .into_iter()
            .map(|(id, _, _)| id)
            .collect();
        let (status, body) = send_json_auto_csrf(
            &ctx.app,
            r.method.clone(),
            &uri,
            None,
            Some(&cookie),
            row.body.clone(),
        )
        .await;
        // A 404 after the evaluation (a missing consent, history entry) is
        // fine; a 404 before it shows up as no scoped evaluation below.
        let new: Vec<_> = policy_evaluations(&ctx)
            .await
            .into_iter()
            .filter(|(id, _, _)| !before.contains(id))
            .collect();
        let scoped = new.iter().any(|(_, kind, _)| kind != "system");
        if !scoped {
            failures.push(format!(
                "{} {} ({uri}) -> {status} {body} evaluated {:?}",
                r.method,
                r.template,
                new.iter()
                    .map(|(_, k, id)| (k.clone(), id.clone()))
                    .collect::<Vec<_>>()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "routes that did not authorize against their resource:\n{}",
        failures.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Ownership sweep
// ---------------------------------------------------------------------------

/// A complete set of resources owned by `owner`, plus a policy and a share
/// target. Every row of the sweep gets its own set, so a DELETE in one row
/// cannot turn a later row into a 404 that hides a missing refusal.
async fn fresh_seeds(
    ctx: &TestContext,
    owner_cookie: &str,
    policy_cookie: &str,
    owner: &UserId,
    bystander: &UserId,
) -> Seeds {
    let (credential_id, credential_name) = create_credential(ctx, owner_cookie, None).await;
    let vault_id = seed_vault(ctx, owner_cookie).await;
    create_credential(ctx, owner_cookie, Some(&vault_id)).await;
    Seeds {
        credential_id,
        credential_name,
        workspace_id: seed_workspace(ctx, owner).await,
        // Only an admin may create a policy, so this never comes from the
        // owner's session.
        policy_id: seed_policy(ctx, policy_cookie).await,
        mcp_server_id: seed_mcp_server(ctx, owner).await,
        vault_id,
        // A third party, never the caller: withdrawing one's own consent is
        // self-service and skips the workspace gate this table is about.
        target_user_id: bystander.0.to_string(),
    }
}

/// The table row for `method` + `template`, rebuilt against real seeds so
/// its request body names ids that exist.
fn find_row(seeds: &Seeds, method: &Method, template: &'static str) -> Route {
    table(seeds)
        .into_iter()
        .find(|r| r.method == method && r.template == template)
        .expect("row is in the table")
}

/// Every owner-scoped route refuses a signed-in user who owns nothing.
///
/// This is the check that would have caught the operator-manages-every-
/// workspace bug: the route evaluated a real Cedar decision, it just
/// evaluated it against `System`. A scoped evaluation proves the shape of
/// the question; only the status proves the answer.
#[tokio::test]
async fn a_signed_in_stranger_is_refused_on_every_owned_route() {
    let ctx = TestAppBuilder::new().build().await;
    let owner = create_test_user(
        &*ctx.store,
        "sweep-owner",
        TEST_PASSWORD,
        UserRole::Operator,
    )
    .await;
    create_test_user(
        &*ctx.store,
        "sweep-stranger",
        TEST_PASSWORD,
        UserRole::Operator,
    )
    .await;
    let bystander = create_test_user(
        &*ctx.store,
        "sweep-bystander",
        TEST_PASSWORD,
        UserRole::Viewer,
    )
    .await;
    // Policies and vault credentials are seeded through the API, which needs
    // a caller who may create them; root bypasses Cedar.
    create_root_user(&*ctx.store, "sweep-root", TEST_PASSWORD).await;
    let owner_cookie = login_user_combined(&ctx.app, "sweep-owner", TEST_PASSWORD).await;
    let root_cookie = login_user_combined(&ctx.app, "sweep-root", TEST_PASSWORD).await;
    let stranger_cookie = login_user_combined(&ctx.app, "sweep-stranger", TEST_PASSWORD).await;

    let mut failures = Vec::new();
    for r in table(&Seeds::empty()) {
        let expected = match r.access {
            Access::Owned { stranger, .. } => stranger,
            Access::AdminOnly(_) => StatusCode::FORBIDDEN,
            Access::Unowned(_) => continue,
        };
        let seeds = fresh_seeds(&ctx, &owner_cookie, &root_cookie, &owner.id, &bystander.id).await;
        let row = find_row(&seeds, &r.method, r.template);
        let uri = format!("/api/v1{}", fill(r.template, &seeds));
        let (status, body) = send_json_auto_csrf(
            &ctx.app,
            r.method.clone(),
            &uri,
            None,
            Some(&stranger_cookie),
            row.body.clone(),
        )
        .await;
        if status != expected {
            failures.push(format!(
                "{} {} -> {status}, expected {expected}: {}\n    {body}",
                r.method,
                r.template,
                access_why(&r.access),
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "routes that did not refuse a user who owns nothing:\n{}",
        failures.join("\n")
    );
}

/// The counterpart: the owner and a non-root admin reach exactly what the
/// table says. Without this, a route that refused everybody — a broken
/// handler, a policy typo — would pass the sweep above.
#[tokio::test]
async fn the_owner_and_an_admin_reach_what_the_table_says() {
    let ctx = TestAppBuilder::new().build().await;
    let owner = create_test_user(
        &*ctx.store,
        "reach-owner",
        TEST_PASSWORD,
        UserRole::Operator,
    )
    .await;
    create_test_user(&*ctx.store, "reach-admin", TEST_PASSWORD, UserRole::Admin).await;
    let bystander = create_test_user(
        &*ctx.store,
        "reach-bystander",
        TEST_PASSWORD,
        UserRole::Viewer,
    )
    .await;
    create_root_user(&*ctx.store, "reach-root", TEST_PASSWORD).await;
    let owner_cookie = login_user_combined(&ctx.app, "reach-owner", TEST_PASSWORD).await;
    let admin_cookie = login_user_combined(&ctx.app, "reach-admin", TEST_PASSWORD).await;
    let root_cookie = login_user_combined(&ctx.app, "reach-root", TEST_PASSWORD).await;

    let mut failures = Vec::new();
    for r in table(&Seeds::empty()) {
        let (owner_pass, admin_pass) = match r.access {
            Access::Owned { owner, admin, .. } => (owner, admin),
            Access::AdminOnly(_) => (Pass::Refused, Pass::Through),
            Access::Unowned(_) => continue,
        };
        for (who, cookie, want) in [
            ("owner", &owner_cookie, owner_pass),
            ("admin", &admin_cookie, admin_pass),
        ] {
            let seeds =
                fresh_seeds(&ctx, &owner_cookie, &root_cookie, &owner.id, &bystander.id).await;
            let row = find_row(&seeds, &r.method, r.template);
            let uri = format!("/api/v1{}", fill(r.template, &seeds));
            let (status, body) = send_json_auto_csrf(
                &ctx.app,
                r.method.clone(),
                &uri,
                None,
                Some(cookie),
                row.body.clone(),
            )
            .await;
            // A route that hides a refusal behind 404 refuses with 404.
            let refusal = match r.access {
                Access::Owned { stranger, .. } => stranger,
                _ => StatusCode::FORBIDDEN,
            };
            let got = if status == refusal {
                Pass::Refused
            } else {
                Pass::Through
            };
            if got != want {
                failures.push(format!(
                    "{} {} as {who} -> {status} ({got:?}), expected {want:?}: {}\n    {body}",
                    r.method,
                    r.template,
                    access_why(&r.access),
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "routes whose owner/admin access did not match the table:\n{}",
        failures.join("\n")
    );
}

fn access_why(access: &Access) -> &'static str {
    match access {
        Access::Owned { why, .. } => why,
        Access::AdminOnly(why) => why,
        Access::Unowned(why) => why,
    }
}
