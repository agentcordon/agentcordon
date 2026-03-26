use super::*;
use crate::domain::credential::{CredentialId, StoredCredential};
use crate::domain::policy::PolicyDecisionResult;
use crate::domain::user::{User, UserId, UserRole};
use crate::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
use crate::error::PolicyError;
use crate::policy::{PolicyContext, PolicyEngine, PolicyPrincipal, PolicyResource};
use chrono::Utc;
use uuid::Uuid;

/// Helper: build a workspace (agent) with the given roles.
fn make_agent(name: &str, roles: Vec<&str>, enabled: bool) -> Workspace {
    Workspace {
        id: WorkspaceId(Uuid::new_v4()),
        name: name.to_string(),
        tags: roles.into_iter().map(String::from).collect(),
        enabled,
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Helper: build a workspace with the given roles and a specific user owner.
fn make_agent_with_owner(name: &str, roles: Vec<&str>, enabled: bool, owner: &User) -> Workspace {
    Workspace {
        id: WorkspaceId(Uuid::new_v4()),
        name: name.to_string(),
        tags: roles.into_iter().map(String::from).collect(),
        enabled,
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        owner_id: Some(owner.id.clone()),
        parent_id: None,
        tool_name: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Helper: build a user with the given role.
fn make_user(username: &str, role: UserRole, is_root: bool) -> User {
    User {
        id: UserId(Uuid::new_v4()),
        username: username.to_string(),
        display_name: None,
        password_hash: "not-a-real-hash".to_string(),
        role,
        is_root,
        enabled: true,
        show_advanced: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Helper: build a stored credential owned by a specific agent.
/// Sets `created_by_user` to the agent's `owner_id` for the v1.5.4
/// ownership model (Credential.owner -> User).
fn make_credential_owned_by(
    name: &str,
    service: &str,
    scopes: Vec<&str>,
    owner: &Workspace,
) -> StoredCredential {
    StoredCredential {
        id: CredentialId(Uuid::new_v4()),
        name: name.to_string(),
        service: service.to_string(),
        encrypted_value: vec![],
        nonce: vec![],
        scopes: scopes.into_iter().map(String::from).collect(),
        metadata: serde_json::Value::Null,
        created_by: Some(owner.id.clone()),
        created_by_user: owner.owner_id.clone(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: None,
        transform_name: None,
        vault: "default".to_string(),
        credential_type: "generic".to_string(),
        tags: vec![],
        key_version: 1,
    }
}

/// Helper: build a stored credential with a random owner.
fn make_credential(name: &str, service: &str, scopes: Vec<&str>) -> StoredCredential {
    StoredCredential {
        id: CredentialId(Uuid::new_v4()),
        name: name.to_string(),
        service: service.to_string(),
        encrypted_value: vec![],
        nonce: vec![],
        scopes: scopes.into_iter().map(String::from).collect(),
        metadata: serde_json::Value::Null,
        created_by: Some(WorkspaceId(Uuid::new_v4())),
        created_by_user: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: None,
        transform_name: None,
        vault: "default".to_string(),
        credential_type: "generic".to_string(),
        tags: vec![],
        key_version: 1,
    }
}

/// Helper: build a stored credential directly owned by a specific user.
/// Used for testing user-scoped credential policies (2a-cred, 2b, etc.).
fn make_credential_for_user(
    name: &str,
    service: &str,
    scopes: Vec<&str>,
    owner: &User,
) -> StoredCredential {
    StoredCredential {
        id: CredentialId(Uuid::new_v4()),
        name: name.to_string(),
        service: service.to_string(),
        encrypted_value: vec![],
        nonce: vec![],
        scopes: scopes.into_iter().map(String::from).collect(),
        metadata: serde_json::Value::Null,
        created_by: None,
        created_by_user: Some(owner.id.clone()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        allowed_url_pattern: None,
        expires_at: None,
        transform_script: None,
        transform_name: None,
        vault: "default".to_string(),
        credential_type: "generic".to_string(),
        tags: vec![],
        key_version: 1,
    }
}

/// Helper: create a permission grant.
/// Load the default policies from the embedded file.
fn default_policies() -> Vec<(String, String)> {
    let source = include_str!("../../../../../policies/default.cedar");
    vec![("default".to_string(), source.to_string())]
}

/// Convenience: empty policy context.
fn empty_ctx() -> PolicyContext {
    PolicyContext {
        target_url: None,
        requested_scopes: vec![],
        ..Default::default()
    }
}

// -----------------------------------------------------------------------
// AGENT TESTS (regression -- existing behavior preserved)
// -----------------------------------------------------------------------

#[test]
fn admin_agent_is_allowed_to_access_credential() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let admin = make_agent("admin-bot", vec!["admin"], true);
    let cred = make_credential("slack-token", "slack", vec!["chat:write"]);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&admin),
            "access",
            &PolicyResource::Credential { credential: cred },
            &PolicyContext {
                target_url: None,
                requested_scopes: vec!["chat:write".to_string()],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn non_admin_agent_denied_access_credentials_by_default() {
    // With blanket policies 5b/5c removed, non-admin agents without explicit grants
    // are denied credential access (deny-by-default).
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let agent = make_agent("worker-bot", vec!["viewer"], true);
    let cred = make_credential("slack-token", "slack", vec!["chat:write"]);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&agent),
            "access",
            &PolicyResource::Credential { credential: cred },
            &PolicyContext {
                target_url: None,
                requested_scopes: vec!["chat:write".to_string()],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn non_admin_agent_cannot_delete_credentials_by_default() {
    // Default policies do NOT grant delete on credentials to non-admin/non-owner agents.
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let agent = make_agent("worker-bot", vec!["viewer"], true);
    let cred = make_credential("slack-token", "slack", vec!["chat:write"]);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&agent),
            "delete",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn admin_can_manage_policies() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let admin = make_agent("admin-bot", vec!["admin"], true);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&admin),
            "manage_policies",
            &PolicyResource::PolicyAdmin,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn non_admin_cannot_manage_policies() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let agent = make_agent("worker-bot", vec!["viewer"], true);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&agent),
            "manage_policies",
            &PolicyResource::PolicyAdmin,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn reload_policies_adds_new_permit() {
    // Test that reloading policies picks up new rules. We test with
    // manage_permissions (not granted by default to non-owner agents)
    // and add a policy that permits it for "viewer"-tagged agents.
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let agent = make_agent("worker-bot", vec!["viewer"], true);
    let cred = make_credential("slack-token", "slack", vec!["chat:write"]);

    // Initially denied (manage_permissions requires ownership or admin)
    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&agent),
            "manage_permissions",
            &PolicyResource::Credential {
                credential: cred.clone(),
            },
            &empty_ctx(),
        )
        .expect("evaluate");
    assert_eq!(result.decision, PolicyDecisionResult::Forbid);

    // Reload with a policy that permits viewers to manage_permissions
    let viewer_policy = r#"
        permit(
            principal is AgentCordon::Workspace,
            action == AgentCordon::Action::"manage_permissions",
            resource is AgentCordon::Credential
        ) when {
            principal.tags.contains("viewer")
        };
    "#;

    engine
        .reload_policies(vec![
            (
                "default".to_string(),
                include_str!("../../../../../policies/default.cedar").to_string(),
            ),
            ("viewer-access".to_string(), viewer_policy.to_string()),
        ])
        .expect("reload");

    // Now allowed
    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&agent),
            "manage_permissions",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");
    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn invalid_policy_returns_parse_error() {
    let result = CedarPolicyEngine::new(vec![(
        "bad".to_string(),
        "this is not valid cedar".to_string(),
    )]);
    match result {
        Err(PolicyError::Parse(msg)) => {
            assert!(
                msg.contains("bad"),
                "error should reference policy id: {msg}"
            );
        }
        Err(other) => panic!("expected Parse error, got: {other:?}"),
        Ok(_) => panic!("expected error for invalid policy, got Ok"),
    }
}

#[test]
fn reload_with_invalid_policy_leaves_existing_set() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");

    // Attempt reload with broken policy
    let result = engine.reload_policies(vec![(
        "broken".to_string(),
        "not valid cedar at all".to_string(),
    )]);
    assert!(result.is_err());

    // Original policies should still be in effect
    let admin = make_agent("admin-bot", vec!["admin"], true);
    let cred = make_credential("slack-token", "slack", vec!["chat:write"]);
    let decision = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&admin),
            "access",
            &PolicyResource::Credential { credential: cred },
            &PolicyContext {
                target_url: None,
                requested_scopes: vec!["chat:write".to_string()],
                ..Default::default()
            },
        )
        .expect("evaluate after failed reload");
    assert_eq!(decision.decision, PolicyDecisionResult::Permit);
}

#[test]
fn system_resource_operations() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let admin = make_agent("admin-bot", vec!["admin"], true);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&admin),
            "list",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

// --- Per-credential permission tests ---

// Owner-match (policy 1b) intentionally excludes `access` — workspaces must
// not see raw credential secrets. They use `vend_credential` to proxy requests.
#[test]
fn owner_can_access_own_credential() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let user = make_user("owner-user", UserRole::Operator, false);
    let owner = make_agent_with_owner("owner-bot", vec![], true, &user);
    let cred = make_credential_owned_by("my-token", "slack", vec!["chat:write"], &owner);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&owner),
            "access",
            &PolicyResource::Credential { credential: cred },
            &PolicyContext {
                target_url: None,
                requested_scopes: vec!["chat:write".to_string()],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn owner_can_delete_own_credential() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let user = make_user("owner-user", UserRole::Operator, false);
    let owner = make_agent_with_owner("owner-bot", vec![], true, &user);
    let cred = make_credential_owned_by("my-token", "slack", vec![], &owner);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&owner),
            "delete",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

/// Helper: build default policies + a grant policy for testing.
fn policies_with_grant(
    agent: &Workspace,
    cred: &StoredCredential,
    cedar_action: &str,
) -> Vec<(String, String)> {
    let mut policies = default_policies();
    policies.push((
        format!("grant_{}_{}", cred.id.0, agent.id.0),
        format!(
            "permit(\n  principal == AgentCordon::Workspace::\"{}\",\n  action == AgentCordon::Action::\"{}\",\n  resource == AgentCordon::Credential::\"{}\"\n);",
            agent.id.0, cedar_action, cred.id.0
        ),
    ));
    policies
}

#[test]
fn reader_grant_allows_list_credential() {
    let reader = make_agent("reader-bot", vec![], true);
    let cred = make_credential("slack-token", "slack", vec!["chat:write"]);
    let engine =
        CedarPolicyEngine::new(policies_with_grant(&reader, &cred, "list")).expect("engine init");

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&reader),
            "list",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn reader_grant_does_not_allow_access_credential() {
    // A "list" grant only permits listing, not direct access. With blanket policy 5c
    // removed, access requires an explicit "access" grant.
    let reader = make_agent("reader-bot", vec![], true);
    let cred = make_credential("slack-token", "slack", vec!["chat:write"]);
    let engine =
        CedarPolicyEngine::new(policies_with_grant(&reader, &cred, "list")).expect("engine init");

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&reader),
            "access",
            &PolicyResource::Credential { credential: cred },
            &PolicyContext {
                target_url: None,
                requested_scopes: vec!["chat:write".to_string()],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn reader_grant_cannot_delete_credential() {
    let reader = make_agent("reader-bot", vec![], true);
    let cred = make_credential("slack-token", "slack", vec!["chat:write"]);
    let engine =
        CedarPolicyEngine::new(policies_with_grant(&reader, &cred, "list")).expect("engine init");

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&reader),
            "delete",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn delegated_use_grant_allows_access_credential() {
    let agent = make_agent("worker-bot", vec![], true);
    let cred = make_credential("slack-token", "slack", vec!["chat:write"]);
    let engine =
        CedarPolicyEngine::new(policies_with_grant(&agent, &cred, "access")).expect("engine init");

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&agent),
            "access",
            &PolicyResource::Credential { credential: cred },
            &PolicyContext {
                target_url: None,
                requested_scopes: vec!["chat:write".to_string()],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn delete_grant_allows_delete_credential() {
    let agent = make_agent("cleanup-bot", vec![], true);
    let cred = make_credential("old-token", "slack", vec![]);
    let engine =
        CedarPolicyEngine::new(policies_with_grant(&agent, &cred, "delete")).expect("engine init");

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&agent),
            "delete",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn no_grants_denies_all_credential_actions_for_unowned_agents() {
    // With owner-scoped policies, an ownerless agent (no owner_id) is denied
    // ALL credential actions without explicit per-credential grants.
    // `access` and `delete` require grants or ownership. `list` and
    // `vend_credential` now also require ownership matching.
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let agent = make_agent("stranger-bot", vec![], true);
    let cred = make_credential("private-token", "github", vec![]);

    // ALL credential actions should be DENIED for ownerless agents without grants
    for action in &["access", "delete", "list", "vend_credential"] {
        let result = engine
            .evaluate(
                &PolicyPrincipal::Workspace(&agent),
                action,
                &PolicyResource::Credential {
                    credential: cred.clone(),
                },
                &empty_ctx(),
            )
            .expect("evaluate");

        assert_eq!(
            result.decision,
            PolicyDecisionResult::Forbid,
            "action '{}' should be denied for ownerless agent without grants",
            action
        );
    }
}

#[test]
fn owner_agent_allowed_list_and_vend_own_credentials() {
    // With owner-scoped policies, an agent with an owner can list and vend
    // their owner's credentials, but NOT access or delete without explicit grants.
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let user = make_user("owner-user", UserRole::Operator, false);
    let agent = make_agent_with_owner("worker-bot", vec![], true, &user);
    let cred = make_credential_owned_by("my-token", "github", vec![], &agent);

    // list and vend_credential should be ALLOWED via ownership policies (1b, 1d)
    for action in &["list", "vend_credential"] {
        let result = engine
            .evaluate(
                &PolicyPrincipal::Workspace(&agent),
                action,
                &PolicyResource::Credential {
                    credential: cred.clone(),
                },
                &empty_ctx(),
            )
            .expect("evaluate");

        assert_eq!(
            result.decision,
            PolicyDecisionResult::Permit,
            "action '{}' should be allowed for owner agent",
            action
        );
    }

    // access should still be DENIED (1b excludes access intentionally)
    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&agent),
            "access",
            &PolicyResource::Credential {
                credential: cred.clone(),
            },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(
        result.decision,
        PolicyDecisionResult::Forbid,
        "access should be denied even for owner — workspaces use vend_credential"
    );
}

#[test]
fn admin_overrides_permissions() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let admin = make_agent("admin-bot", vec!["admin"], true);
    let cred = make_credential("any-token", "any-service", vec![]);

    // Admin can access even with no permissions granted
    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&admin),
            "access",
            &PolicyResource::Credential { credential: cred },
            &PolicyContext {
                target_url: None,
                requested_scopes: vec![],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn workspace_cannot_manage_permissions() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let user = make_user("owner-user", UserRole::Operator, false);
    let owner = make_agent_with_owner("owner-bot", vec![], true, &user);
    let cred = make_credential_owned_by("my-token", "slack", vec![], &owner);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&owner),
            "manage_permissions",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn non_owner_cannot_manage_permissions() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let agent = make_agent("random-bot", vec![], true);
    let cred = make_credential("someone-elses-token", "github", vec![]);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&agent),
            "manage_permissions",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

// --- vend_credential tests ---

#[test]
fn admin_can_vend_credential_any_credential() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let admin = make_agent("admin-bot", vec!["admin"], true);
    let cred = make_credential("github-pat", "github", vec!["repo"]);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&admin),
            "vend_credential",
            &PolicyResource::Credential { credential: cred },
            &PolicyContext {
                target_url: Some("https://api.github.com/repos/foo".to_string()),
                requested_scopes: vec!["repo".to_string()],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn delegated_use_grant_allows_vend_credential() {
    let agent = make_agent("worker-bot", vec![], true);
    let cred = make_credential("github-pat", "github", vec!["repo"]);
    let engine = CedarPolicyEngine::new(policies_with_grant(&agent, &cred, "vend_credential"))
        .expect("engine init");

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&agent),
            "vend_credential",
            &PolicyResource::Credential { credential: cred },
            &PolicyContext {
                target_url: Some("https://api.github.com/repos/foo".to_string()),
                requested_scopes: vec!["repo".to_string()],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn enabled_agent_allowed_vend_own_credential_via_default_policy() {
    // Default policy 1d grants enabled workspaces `vend_credential` for their
    // owner's credentials. Agents use credentials through the proxy — they
    // never see raw secrets.
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let user = make_user("owner-user", UserRole::Operator, false);
    let agent = make_agent_with_owner("worker-bot", vec![], true, &user);
    let cred = make_credential_owned_by("github-pat", "github", vec!["repo"], &agent);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&agent),
            "vend_credential",
            &PolicyResource::Credential { credential: cred },
            &PolicyContext {
                target_url: Some("https://api.github.com/repos/foo".to_string()),
                requested_scopes: vec!["repo".to_string()],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn enabled_agent_denied_vend_other_users_credential() {
    // With owner-scoped policy 1d, an enabled workspace cannot vend credentials
    // belonging to a different user.
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let user = make_user("owner-user", UserRole::Operator, false);
    let agent = make_agent_with_owner("worker-bot", vec![], true, &user);
    let other_user = make_user("other-user", UserRole::Operator, false);
    let other_agent = make_agent_with_owner("other-bot", vec![], true, &other_user);
    let cred = make_credential_owned_by("other-pat", "github", vec!["repo"], &other_agent);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&agent),
            "vend_credential",
            &PolicyResource::Credential { credential: cred },
            &PolicyContext {
                target_url: Some("https://api.github.com/repos/foo".to_string()),
                requested_scopes: vec!["repo".to_string()],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn ownerless_agent_denied_vend_via_default_policy() {
    // Workspaces without an owner cannot vend credentials via policy 1d
    // (which requires `principal has owner`). They need explicit per-credential
    // grants instead.
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let agent = make_agent("orphan-bot", vec![], true);
    let cred = make_credential("github-pat", "github", vec!["repo"]);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&agent),
            "vend_credential",
            &PolicyResource::Credential { credential: cred },
            &PolicyContext {
                target_url: Some("https://api.github.com/repos/foo".to_string()),
                requested_scopes: vec!["repo".to_string()],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn list_grant_does_not_allow_access() {
    // A "list" grant only permits listing. `access` (raw secret visibility)
    // requires an explicit access grant. `vend_credential` is allowed via
    // default policy 1d regardless.
    let agent = make_agent("reader-bot", vec![], true);
    let cred = make_credential("github-pat", "github", vec!["repo"]);
    let engine =
        CedarPolicyEngine::new(policies_with_grant(&agent, &cred, "list")).expect("engine init");

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&agent),
            "access",
            &PolicyResource::Credential { credential: cred },
            &PolicyContext {
                target_url: Some("https://api.github.com/repos/foo".to_string()),
                requested_scopes: vec![],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn owner_can_vend_credential_own_credential() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let user = make_user("owner-user", UserRole::Operator, false);
    let owner = make_agent_with_owner("owner-bot", vec![], true, &user);
    let cred = make_credential_owned_by("my-pat", "github", vec!["repo"], &owner);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&owner),
            "vend_credential",
            &PolicyResource::Credential { credential: cred },
            &PolicyContext {
                target_url: Some("https://api.github.com/repos/foo".to_string()),
                requested_scopes: vec!["repo".to_string()],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn vend_credential_context_includes_target_url() {
    // Verify that target_url is properly passed to Cedar context.
    let agent = make_agent("worker-bot", vec![], true);
    let cred = make_credential("api-key", "service", vec![]);
    let engine = CedarPolicyEngine::new(policies_with_grant(&agent, &cred, "vend_credential"))
        .expect("engine init");

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&agent),
            "vend_credential",
            &PolicyResource::Credential { credential: cred },
            &PolicyContext {
                target_url: Some("https://api.example.com/v1/data?query=test".to_string()),
                requested_scopes: vec![],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
    assert!(result.errors.is_empty(), "no evaluation errors expected");
}

// -----------------------------------------------------------------------
// USER TESTS (new -- F-004)
// -----------------------------------------------------------------------

#[test]
fn root_user_bypasses_cedar_evaluation() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let root = make_user("root", UserRole::Admin, true);

    // Root should be allowed to do anything, even without a matching policy
    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&root),
            "manage_policies",
            &PolicyResource::PolicyAdmin,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
    assert!(result.reasons.contains(&"root_bypass".to_string()));
}

#[test]
fn root_user_bypasses_even_for_unusual_actions() {
    // Root bypass is unconditional -- it doesn't depend on the action or resource
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let root = make_user("root", UserRole::Admin, true);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&root),
            "manage_users",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
    assert!(result.reasons.contains(&"root_bypass".to_string()));
}

#[test]
fn admin_user_can_manage_policies() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let admin = make_user("admin-user", UserRole::Admin, false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&admin),
            "manage_policies",
            &PolicyResource::PolicyAdmin,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn admin_user_can_manage_users() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let admin = make_user("admin-user", UserRole::Admin, false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&admin),
            "manage_users",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn admin_user_can_manage_agents() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let admin = make_user("admin-user", UserRole::Admin, false);
    let agent = make_agent("some-agent", vec![], true);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&admin),
            "manage_workspaces",
            &PolicyResource::WorkspaceResource { workspace: agent },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn admin_user_can_manage_enrollments() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let admin = make_user("admin-user", UserRole::Admin, false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&admin),
            "manage_enrollments",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn admin_user_can_view_audit() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let admin = make_user("admin-user", UserRole::Admin, false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&admin),
            "view_audit",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn admin_user_can_list_own_credentials() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let admin = make_user("admin-user", UserRole::Admin, false);
    let cred = make_credential_for_user("slack-token", "slack", vec!["chat:write"], &admin);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&admin),
            "list",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn admin_user_cannot_list_other_users_credentials() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let admin = make_user("admin-user", UserRole::Admin, false);
    let other = make_user("other-user", UserRole::Operator, false);
    let cred = make_credential_for_user("other-token", "slack", vec![], &other);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&admin),
            "list",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn operator_user_can_list_own_credentials() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let operator = make_user("ops-user", UserRole::Operator, false);
    let cred = make_credential_for_user("slack-token", "slack", vec!["chat:write"], &operator);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&operator),
            "list",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn operator_user_cannot_list_other_users_credentials() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let operator = make_user("ops-user", UserRole::Operator, false);
    let other = make_user("other-user", UserRole::Operator, false);
    let cred = make_credential_for_user("other-token", "slack", vec![], &other);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&operator),
            "list",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn operator_user_can_create_credentials() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let operator = make_user("ops-user", UserRole::Operator, false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&operator),
            "create",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn operator_user_can_delete_own_credentials() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let operator = make_user("ops-user", UserRole::Operator, false);
    let cred = make_credential_for_user("old-token", "slack", vec![], &operator);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&operator),
            "delete",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn operator_user_cannot_manage_permissions() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let operator = make_user("ops-user", UserRole::Operator, false);
    let cred = make_credential_for_user("slack-token", "slack", vec![], &operator);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&operator),
            "manage_permissions",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn operator_user_can_manage_agents() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let operator = make_user("ops-user", UserRole::Operator, false);
    let agent = make_agent("some-agent", vec![], true);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&operator),
            "manage_workspaces",
            &PolicyResource::WorkspaceResource { workspace: agent },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn operator_user_can_manage_enrollments() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let operator = make_user("ops-user", UserRole::Operator, false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&operator),
            "manage_enrollments",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn operator_user_can_view_audit() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let operator = make_user("ops-user", UserRole::Operator, false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&operator),
            "view_audit",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn operator_user_cannot_manage_policies() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let operator = make_user("ops-user", UserRole::Operator, false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&operator),
            "manage_policies",
            &PolicyResource::PolicyAdmin,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn operator_user_cannot_manage_users() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let operator = make_user("ops-user", UserRole::Operator, false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&operator),
            "manage_users",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn viewer_user_can_list_system() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let viewer = make_user("view-user", UserRole::Viewer, false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&viewer),
            "list",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn viewer_user_can_list_own_credentials() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let viewer = make_user("view-user", UserRole::Viewer, false);
    let cred = make_credential_for_user("slack-token", "slack", vec![], &viewer);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&viewer),
            "list",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn viewer_user_cannot_list_other_users_credentials() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let viewer = make_user("view-user", UserRole::Viewer, false);
    let other = make_user("other-user", UserRole::Operator, false);
    let cred = make_credential_for_user("other-token", "slack", vec![], &other);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&viewer),
            "list",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn viewer_user_can_view_audit() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let viewer = make_user("view-user", UserRole::Viewer, false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&viewer),
            "view_audit",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn viewer_user_cannot_create_credentials() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let viewer = make_user("view-user", UserRole::Viewer, false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&viewer),
            "create",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn viewer_user_cannot_delete_credentials() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let viewer = make_user("view-user", UserRole::Viewer, false);
    let cred = make_credential("slack-token", "slack", vec![]);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&viewer),
            "delete",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn viewer_user_cannot_manage_permissions() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let viewer = make_user("view-user", UserRole::Viewer, false);
    let cred = make_credential("slack-token", "slack", vec![]);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&viewer),
            "manage_permissions",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn viewer_user_cannot_manage_agents() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let viewer = make_user("view-user", UserRole::Viewer, false);
    let agent = make_agent("some-agent", vec![], true);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&viewer),
            "manage_workspaces",
            &PolicyResource::WorkspaceResource { workspace: agent },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn viewer_user_cannot_manage_enrollments() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let viewer = make_user("view-user", UserRole::Viewer, false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&viewer),
            "manage_enrollments",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn viewer_user_cannot_manage_policies() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let viewer = make_user("view-user", UserRole::Viewer, false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&viewer),
            "manage_policies",
            &PolicyResource::PolicyAdmin,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn viewer_user_cannot_manage_users() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let viewer = make_user("view-user", UserRole::Viewer, false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&viewer),
            "manage_users",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn operator_user_can_list_system_credentials() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let operator = make_user("ops-user", UserRole::Operator, false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&operator),
            "list",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

// -----------------------------------------------------------------------
// AgentResource tests
// -----------------------------------------------------------------------

#[test]
fn admin_user_can_manage_agents_at_system_level() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let admin = make_user("admin-user", UserRole::Admin, false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&admin),
            "manage_workspaces",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn operator_user_can_manage_agents_at_system_level() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let operator = make_user("ops-user", UserRole::Operator, false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&operator),
            "manage_workspaces",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn viewer_user_cannot_manage_agents_at_system_level() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let viewer = make_user("view-user", UserRole::Viewer, false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&viewer),
            "manage_workspaces",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

// -----------------------------------------------------------------------
// Schema validation tests (S-005)
// -----------------------------------------------------------------------

#[test]
fn validate_policy_text_accepts_valid_policy() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");

    let valid_policy = r#"
        permit(
            principal is AgentCordon::Workspace,
            action == AgentCordon::Action::"access",
            resource is AgentCordon::Credential
        ) when {
            principal.tags.contains("custom-role")
        };
    "#;

    let result = engine.validate_policy_text(valid_policy);
    assert!(
        result.is_ok(),
        "valid policy should pass validation: {:?}",
        result
    );
}

#[test]
fn validate_policy_text_rejects_syntax_error() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");

    let bad_syntax = "permit( this is not valid cedar ;";

    let result = engine.validate_policy_text(bad_syntax);
    assert!(result.is_err(), "syntactically invalid policy should fail");
    let err = result.unwrap_err();
    assert!(
        matches!(err, PolicyError::Parse(_)),
        "should be a parse error, got: {err}"
    );
}

#[test]
fn validate_policy_text_rejects_unknown_action() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");

    let bad_schema_policy = r#"
        permit(
            principal is AgentCordon::Workspace,
            action == AgentCordon::Action::"nonexistent_action",
            resource is AgentCordon::Credential
        );
    "#;

    let result = engine.validate_policy_text(bad_schema_policy);
    assert!(
        result.is_err(),
        "policy with unknown action should fail schema validation"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(err, PolicyError::Validation(_)),
        "should be a validation error, got: {err}"
    );
}

#[test]
fn validate_policy_text_rejects_unknown_entity_type() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");

    let bad_entity = r#"
        permit(
            principal is AgentCordon::NonExistentType,
            action == AgentCordon::Action::"access",
            resource is AgentCordon::Credential
        );
    "#;

    let result = engine.validate_policy_text(bad_entity);
    assert!(
        result.is_err(),
        "policy with unknown entity type should fail schema validation"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(err, PolicyError::Validation(_)),
        "should be a validation error, got: {err}"
    );
}

#[test]
fn validate_policy_text_rejects_wrong_attribute() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");

    let bad_attr = r#"
        permit(
            principal is AgentCordon::Workspace,
            action == AgentCordon::Action::"access",
            resource is AgentCordon::Credential
        ) when {
            principal.nonexistent_attr == "foo"
        };
    "#;

    let result = engine.validate_policy_text(bad_attr);
    assert!(
        result.is_err(),
        "policy with unknown attribute should fail schema validation"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(err, PolicyError::Validation(_)),
        "should be a validation error, got: {err}"
    );
}

// -----------------------------------------------------------------------
// R-001: `update` action tests
// -----------------------------------------------------------------------

#[test]
fn admin_agent_can_update_credential() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let admin = make_agent("admin-bot", vec!["admin"], true);
    let cred = make_credential("slack-token", "slack", vec![]);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&admin),
            "update",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn owner_agent_can_update_own_credential() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let user = make_user("owner-user", UserRole::Operator, false);
    let owner = make_agent_with_owner("owner-bot", vec![], true, &user);
    let cred = make_credential_owned_by("my-token", "slack", vec![], &owner);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&owner),
            "update",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn writer_grant_allows_update_credential() {
    let writer = make_agent("writer-bot", vec![], true);
    let cred = make_credential("slack-token", "slack", vec![]);
    let engine =
        CedarPolicyEngine::new(policies_with_grant(&writer, &cred, "update")).expect("engine init");

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&writer),
            "update",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn non_owner_non_writer_agent_cannot_update_credential() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let agent = make_agent("random-bot", vec![], true);
    let cred = make_credential("slack-token", "slack", vec![]);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&agent),
            "update",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn admin_user_can_update_own_credential() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let admin = make_user("admin-user", UserRole::Admin, false);
    let cred = make_credential_for_user("slack-token", "slack", vec![], &admin);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&admin),
            "update",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn operator_user_can_update_own_credential() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let operator = make_user("ops-user", UserRole::Operator, false);
    let cred = make_credential_for_user("slack-token", "slack", vec![], &operator);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&operator),
            "update",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn viewer_user_cannot_update_credential() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let viewer = make_user("view-user", UserRole::Viewer, false);
    let cred = make_credential("slack-token", "slack", vec![]);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&viewer),
            "update",
            &PolicyResource::Credential { credential: cred },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

// -----------------------------------------------------------------------
// R-002: `rotate_key` action tests
// -----------------------------------------------------------------------

#[test]
fn admin_user_can_rotate_agent_key() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let admin = make_user("admin-user", UserRole::Admin, false);
    let agent = make_agent("some-agent", vec![], true);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&admin),
            "rotate_key",
            &PolicyResource::WorkspaceResource { workspace: agent },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn operator_user_cannot_rotate_agent_key() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let operator = make_user("ops-user", UserRole::Operator, false);
    let agent = make_agent("some-agent", vec![], true);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&operator),
            "rotate_key",
            &PolicyResource::WorkspaceResource { workspace: agent },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

#[test]
fn viewer_user_cannot_rotate_agent_key() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let viewer = make_user("view-user", UserRole::Viewer, false);
    let agent = make_agent("some-agent", vec![], true);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&viewer),
            "rotate_key",
            &PolicyResource::WorkspaceResource { workspace: agent },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Forbid);
}

// -----------------------------------------------------------------------
// R-003: AgentResource owner attribute tests
// -----------------------------------------------------------------------

#[test]
fn agent_resource_with_owner_evaluates_correctly() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let admin = make_user("admin-user", UserRole::Admin, false);

    // Create an agent with an owner
    let mut agent = make_agent("owned-agent", vec![], true);
    agent.owner_id = Some(crate::domain::user::UserId(Uuid::new_v4()));

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&admin),
            "manage_workspaces",
            &PolicyResource::WorkspaceResource { workspace: agent },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

#[test]
fn agent_resource_without_owner_evaluates_correctly() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let admin = make_user("admin-user", UserRole::Admin, false);

    // Agent without an owner (legacy)
    let agent = make_agent("legacy-agent", vec![], true);
    assert!(agent.owner_id.is_none());

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&admin),
            "manage_workspaces",
            &PolicyResource::WorkspaceResource { workspace: agent },
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(result.decision, PolicyDecisionResult::Permit);
}

// -----------------------------------------------------------------------
// R-006: Disabled principal forbid rule tests
// -----------------------------------------------------------------------

#[test]
fn disabled_admin_agent_is_denied() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    // Agent with admin role but disabled
    let disabled_admin = make_agent("disabled-admin", vec!["admin"], false);
    let cred = make_credential("slack-token", "slack", vec!["chat:write"]);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&disabled_admin),
            "access",
            &PolicyResource::Credential { credential: cred },
            &PolicyContext {
                target_url: None,
                requested_scopes: vec!["chat:write".to_string()],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(
        result.decision,
        PolicyDecisionResult::Forbid,
        "disabled admin agent should be denied by forbid rule"
    );
}

#[test]
fn disabled_admin_agent_denied_manage_policies() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let disabled_admin = make_agent("disabled-admin", vec!["admin"], false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&disabled_admin),
            "manage_policies",
            &PolicyResource::PolicyAdmin,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(
        result.decision,
        PolicyDecisionResult::Forbid,
        "disabled admin agent should be denied manage_policies"
    );
}

#[test]
fn disabled_admin_user_is_denied() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let mut disabled_admin = make_user("disabled-admin", UserRole::Admin, false);
    disabled_admin.enabled = false;

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&disabled_admin),
            "manage_users",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(
        result.decision,
        PolicyDecisionResult::Forbid,
        "disabled admin user should be denied by forbid rule"
    );
}

#[test]
fn disabled_operator_user_is_denied() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let mut disabled_op = make_user("disabled-ops", UserRole::Operator, false);
    disabled_op.enabled = false;

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&disabled_op),
            "list",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(
        result.decision,
        PolicyDecisionResult::Forbid,
        "disabled operator user should be denied by forbid rule"
    );
}

#[test]
fn disabled_owner_agent_cannot_access_own_credential() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    // Owner agent, but disabled -- forbid rule overrides ownership permit
    let user = make_user("owner-user", UserRole::Operator, false);
    let disabled_owner = make_agent_with_owner("disabled-owner", vec![], false, &user);
    let cred = make_credential_owned_by("my-token", "slack", vec![], &disabled_owner);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&disabled_owner),
            "access",
            &PolicyResource::Credential { credential: cred },
            &PolicyContext {
                target_url: None,
                requested_scopes: vec![],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(
        result.decision,
        PolicyDecisionResult::Forbid,
        "disabled owner agent should be denied even for own credentials"
    );
}

#[test]
fn disabled_viewer_user_is_denied() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let mut disabled_viewer = make_user("disabled-viewer", UserRole::Viewer, false);
    disabled_viewer.enabled = false;

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&disabled_viewer),
            "view_audit",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(
        result.decision,
        PolicyDecisionResult::Forbid,
        "disabled viewer user should be denied by forbid rule"
    );
}

#[test]
fn disabled_non_admin_agent_is_denied() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    // Agent with no special roles, disabled
    let disabled_agent = make_agent("disabled-viewer-bot", vec!["viewer"], false);
    let cred = make_credential("some-token", "test", vec![]);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&disabled_agent),
            "access",
            &PolicyResource::Credential { credential: cred },
            &PolicyContext {
                target_url: None,
                requested_scopes: vec![],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(
        result.decision,
        PolicyDecisionResult::Forbid,
        "disabled non-admin agent should be denied by forbid rule"
    );
}

// -----------------------------------------------------------------------
// R-007: Workspace manage_policies — implicit deny + admin permit
// -----------------------------------------------------------------------

#[test]
fn non_admin_workspace_denied_manage_policies_by_implicit_deny() {
    // No permit grants non-admin workspaces manage_policies, so Cedar denies implicitly.
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let agent = make_agent("custom-bot", vec!["custom-policy-role"], true);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&agent),
            "manage_policies",
            &PolicyResource::PolicyAdmin,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(
        result.decision,
        PolicyDecisionResult::Forbid,
        "non-admin workspace has no permit for manage_policies — implicit deny"
    );
}

#[test]
fn admin_workspace_can_manage_policies() {
    // Admin workspaces get manage_policies via the blanket permit (1a).
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let admin = make_agent("admin-bot", vec!["admin"], true);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&admin),
            "manage_policies",
            &PolicyResource::PolicyAdmin,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(
        result.decision,
        PolicyDecisionResult::Permit,
        "admin workspace should be allowed manage_policies via permit 1a"
    );
}

// -----------------------------------------------------------------------
// Schema validation with new actions
// -----------------------------------------------------------------------

#[test]
fn validate_update_action_policy() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");

    let policy = r#"
        permit(
            principal is AgentCordon::Workspace,
            action == AgentCordon::Action::"update",
            resource is AgentCordon::Credential
        ) when {
            principal.tags.contains("editor")
        };
    "#;

    let result = engine.validate_policy_text(policy);
    assert!(
        result.is_ok(),
        "update action policy should validate: {:?}",
        result
    );
}

#[test]
fn validate_rotate_key_action_policy() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");

    let policy = r#"
        permit(
            principal is AgentCordon::User,
            action == AgentCordon::Action::"rotate_key",
            resource is AgentCordon::WorkspaceResource
        ) when {
            principal.role == "admin"
        };
    "#;

    let result = engine.validate_policy_text(policy);
    assert!(
        result.is_ok(),
        "rotate_key action policy should validate: {:?}",
        result
    );
}

// -----------------------------------------------------------------------
// DEVICE POLICY TESTS
// -----------------------------------------------------------------------

/// Helper: build a Workspace for device tests.
fn make_device(id: &str, name: &str, enabled: bool) -> Workspace {
    Workspace {
        id: WorkspaceId(Uuid::parse_str(id).unwrap_or_else(|_| Uuid::new_v4())),
        name: name.to_string(),
        enabled,
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        tags: vec![],
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn enabled_device_allowed_vend_own_credential_via_default_policy() {
    // Default policy 1d grants enabled workspaces (including devices)
    // `vend_credential` for their owner's credentials. Devices use
    // credentials through the proxy.
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let user = make_user("device-owner", UserRole::Operator, false);
    let device = make_agent_with_owner("test-device", vec![], true, &user);
    let cred = make_credential_owned_by("github-pat", "github", vec!["repo"], &device);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&device),
            "vend_credential",
            &PolicyResource::Credential { credential: cred },
            &PolicyContext {
                target_url: Some("https://api.github.com/repos/foo".to_string()),
                requested_scopes: vec!["repo".to_string()],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(
        result.decision,
        PolicyDecisionResult::Permit,
        "enabled device should be allowed vend_credential for own credentials via default policy 1d"
    );
}

#[test]
fn disabled_device_denied_vend_credential() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let device = make_device("sc-2", "disabled-device", false);
    let cred = make_credential("github-pat", "github", vec!["repo"]);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&device),
            "vend_credential",
            &PolicyResource::Credential { credential: cred },
            &PolicyContext {
                target_url: Some("https://api.github.com/repos/foo".to_string()),
                requested_scopes: vec!["repo".to_string()],
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(
        result.decision,
        PolicyDecisionResult::Forbid,
        "disabled device should be denied vend_credential"
    );
}

#[test]
fn enabled_device_allowed_mcp_tool_call() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let device = make_device("sc-3", "mcp-device", true);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&device),
            "mcp_tool_call",
            &PolicyResource::McpServer {
                id: "mcp-1".to_string(),
                name: "test-mcp".to_string(),
                enabled: true,
                tags: vec![],
            },
            &PolicyContext {
                tool_name: Some("my_tool".to_string()),
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(
        result.decision,
        PolicyDecisionResult::Permit,
        "enabled device should be allowed mcp_tool_call on enabled McpServer"
    );
}

#[test]
fn disabled_device_denied_mcp_tool_call() {
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let device = make_device("sc-4", "disabled-mcp-device", false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&device),
            "mcp_tool_call",
            &PolicyResource::McpServer {
                id: "mcp-2".to_string(),
                name: "test-mcp".to_string(),
                enabled: true,
                tags: vec![],
            },
            &PolicyContext {
                tool_name: Some("my_tool".to_string()),
                ..Default::default()
            },
        )
        .expect("evaluate");

    assert_eq!(
        result.decision,
        PolicyDecisionResult::Forbid,
        "disabled device should be denied mcp_tool_call"
    );
}

// -----------------------------------------------------------------------
// CEDAR REASONS VECTOR TESTS
// -----------------------------------------------------------------------
// These tests validate Cedar's `reasons` (diagnostics) behavior:
// - Implicit deny (no matching permit or forbid) → empty reasons
// - Explicit forbid → reasons contains the forbid policy ID
// - Permit match → reasons contains the permit policy ID

#[test]
fn implicit_deny_has_empty_reasons() {
    // A viewer user trying manage_workspaces on System — no permit matches
    // (only operators get manage_workspaces), and no forbid fires either.
    // Cedar returns Deny with empty reasons (implicit deny-by-default).
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let viewer = make_user("readonly-viewer", UserRole::Viewer, false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&viewer),
            "manage_workspaces",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(
        result.decision,
        PolicyDecisionResult::Forbid,
        "viewer should be denied manage_workspaces (no matching permit)"
    );
    assert!(
        result.reasons.is_empty(),
        "implicit deny should have empty reasons, got: {:?}",
        result.reasons
    );
}

#[test]
fn explicit_forbid_has_non_empty_reasons() {
    // A disabled workspace (enabled=false) tries to list system resources.
    // Forbid rule 3a fires (!principal.enabled), so reasons should contain
    // the forbid policy ID.
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let disabled_ws = make_agent("disabled-bot", vec!["admin"], false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::Workspace(&disabled_ws),
            "list",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(
        result.decision,
        PolicyDecisionResult::Forbid,
        "disabled workspace should be denied by forbid rule 3a"
    );
    assert!(
        !result.reasons.is_empty(),
        "explicit forbid should have non-empty reasons (forbid policy ID)"
    );
}

#[test]
fn permit_match_has_non_empty_reasons() {
    // An admin user performs list on System — permit 2a fires.
    // The reasons vector should contain the matching permit policy ID.
    let engine = CedarPolicyEngine::new(default_policies()).expect("engine init");
    let admin = make_user("admin-user", UserRole::Admin, false);

    let result = engine
        .evaluate(
            &PolicyPrincipal::User(&admin),
            "list",
            &PolicyResource::System,
            &empty_ctx(),
        )
        .expect("evaluate");

    assert_eq!(
        result.decision,
        PolicyDecisionResult::Permit,
        "admin user should be allowed to list system resources"
    );
    assert!(
        !result.reasons.is_empty(),
        "permit match should have non-empty reasons (permit policy ID)"
    );
}
