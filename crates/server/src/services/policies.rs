//! Policy service: Cedar policy CRUD, the grant/deny policies written by the
//! permissions routes, and the policy-engine reload that every one of those
//! writes must be followed by.
//!
//! The database is the single source of truth for Cedar policies; the
//! engine is a cache of the enabled set. Every method here that changes a
//! policy row reloads the engine before it returns.

use std::sync::Arc;

use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::mcp::McpServerId;
use agent_cordon_core::domain::policy::{PolicyDecisionResult, PolicyId, StoredPolicy};
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_core::policy::{actions, templates, PolicyResource};

use crate::authz::Authz;
use crate::events::{UiEvent, UiEventBus};
use crate::extractors::{AuthenticatedActor, AuthenticatedUser};
use crate::response::ApiError;
use crate::state::SharedStore;

use super::write_audit;

/// Input for [`PolicyService::create`].
pub struct NewPolicy {
    pub name: String,
    pub description: Option<String>,
    pub cedar_policy: String,
    pub enabled: Option<bool>,
}

/// Input for [`PolicyService::update`]; `None` leaves a field unchanged.
pub struct PolicyChanges {
    pub name: Option<String>,
    pub description: Option<String>,
    pub cedar_policy: Option<String>,
    pub enabled: Option<bool>,
}

/// The name of the policy seeded on first boot from `policies/default.cedar`.
/// The seed only runs when the policy table holds nothing enabled, so a
/// deleted `default` never comes back on a running install.
pub const DEFAULT_POLICY_NAME: &str = "default";

/// What an operator is told when a change would leave the engine with no
/// enabled policy. The Cedar engine then loads an empty set, which permits
/// nothing; only the root bypass survives.
const LOCKOUT_CONSEQUENCE: &str =
    "it is the last enabled policy — with none enabled every operator, viewer and workspace is \
     refused and only the root user can still sign in. Per-credential grants do not count: they \
     permit a workspace one action, never a person a page. Enable another policy first.";

/// True for the per-grant rows [`PolicyService::ensure_grant`] writes, which
/// are named `grant:…` / `deny:…` and are managed by the permissions UI rather
/// than authored on the policy pages.
pub fn is_generated_grant(policy_name: &str) -> bool {
    policy_name.starts_with("grant:") || policy_name.starts_with("deny:")
}

/// One requested credential grant: `(workspace, permission name)`.
pub struct PermissionGrant {
    pub workspace_id: WorkspaceId,
    pub permission: String,
}

#[derive(Clone)]
pub struct PolicyService {
    store: SharedStore,
    authz: Arc<Authz>,
    ui_event_bus: UiEventBus,
}

impl PolicyService {
    pub fn new(store: SharedStore, authz: Arc<Authz>, ui_event_bus: UiEventBus) -> Self {
        Self {
            store,
            authz,
            ui_event_bus,
        }
    }

    /// Reload all enabled policies from DB into the policy engine.
    ///
    /// The database is the single source of truth for Cedar policies.
    /// If zero enabled policies exist, an empty policy set is loaded (deny-all).
    pub async fn reload_engine(&self) -> Result<(), ApiError> {
        let db_policies = self.store.get_all_enabled_policies().await?;
        let sources: Vec<(String, String)> = db_policies
            .into_iter()
            .map(|p| (p.id.0.to_string(), p.cedar_policy))
            .collect();

        if sources.is_empty() {
            tracing::warn!("no enabled policies in database — deny-all is in effect");
        }

        self.authz
            .reload_policies(sources)
            .map_err(|e| ApiError::Internal(format!("failed to reload policies: {e}")))?;
        Ok(())
    }

    /// True when `id` is the only *authored* policy the engine would still
    /// load.
    ///
    /// The `grant:`/`deny:` rows the permissions UI writes are excluded, and
    /// deliberately so. Each of them permits one workspace one action on one
    /// credential or MCP server; none of them grants a person so much as a
    /// page. An install with a hundred grants and no authored policy answers
    /// 403 to every operator and viewer exactly as an empty one does, so
    /// counting grants here would make the guard read "safe" in precisely the
    /// topology the review broke (UI review B1).
    async fn is_last_enabled(&self, id: &PolicyId) -> Result<bool, ApiError> {
        let enabled: Vec<StoredPolicy> = self
            .store
            .get_all_enabled_policies()
            .await?
            .into_iter()
            .filter(|p| !is_generated_grant(&p.name))
            .collect();
        Ok(enabled.len() == 1 && enabled[0].id.0 == id.0)
    }

    /// Refuse a change that would leave zero enabled policies.
    async fn refuse_lockout(&self, policy: &StoredPolicy, verb: &str) -> Result<(), ApiError> {
        if policy.enabled && self.is_last_enabled(&policy.id).await? {
            return Err(ApiError::Conflict(format!(
                "policy '{}' cannot be {verb}: {LOCKOUT_CONSEQUENCE}",
                policy.name
            )));
        }
        Ok(())
    }

    /// The policy, or 404.
    pub async fn load(&self, id: &PolicyId) -> Result<StoredPolicy, ApiError> {
        self.store
            .get_policy(id)
            .await?
            .ok_or_else(|| ApiError::NotFound("policy not found".to_string()))
    }

    // ------------------------------------------------------------------
    // CRUD
    // ------------------------------------------------------------------

    pub async fn create(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        new: NewPolicy,
    ) -> Result<StoredPolicy, ApiError> {
        let policy_decision = self
            .authz
            .authorize(auth, actions::MANAGE_POLICIES, &PolicyResource::PolicyAdmin)
            .await?;

        // Validate the Cedar policy text: syntax parse + schema validation (structured errors)
        self.authz
            .validate_policy_text_detailed(&new.cedar_policy)
            .map_err(|errors| ApiError::PolicyValidation { errors })?;

        let now = chrono::Utc::now();
        let policy = StoredPolicy {
            id: PolicyId(Uuid::new_v4()),
            name: new.name,
            description: new.description,
            cedar_policy: new.cedar_policy,
            enabled: new.enabled.unwrap_or(true),
            is_system: false,
            created_at: now,
            updated_at: now,
        };

        self.store.store_policy(&policy).await?;
        self.reload_engine().await?;

        let event = AuditEvent::builder(AuditEventType::PolicyCreated)
            .action("create")
            .user_actor(&auth.user)
            .resource("policy", &policy.id.0.to_string())
            .correlation_id(corr)
            .decision(
                AuditDecision::Permit,
                Some(&policy_decision.reasons.join(", ")),
            )
            .details(serde_json::json!({ "policy_name": policy.name }))
            .build();
        write_audit(&*self.store, &event).await;

        self.ui_event_bus.emit(UiEvent::PolicyChanged {
            policy_name: policy.name.clone(),
        });

        Ok(policy)
    }

    pub async fn update(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        id: &PolicyId,
        changes: PolicyChanges,
    ) -> Result<StoredPolicy, ApiError> {
        let policy_decision = self
            .authz
            .authorize(auth, actions::MANAGE_POLICIES, &PolicyResource::PolicyAdmin)
            .await?;

        let loaded = self.load(id).await?;
        let mut policy = loaded.clone();

        if let Some(name) = changes.name {
            policy.name = name;
        }
        if let Some(desc) = changes.description {
            policy.description = Some(desc);
        }
        if let Some(cedar) = changes.cedar_policy {
            // Validate updated Cedar policy text: syntax parse + schema validation (structured errors)
            self.authz
                .validate_policy_text_detailed(&cedar)
                .map_err(|errors| ApiError::PolicyValidation { errors })?;
            policy.cedar_policy = cedar;
        }
        if let Some(enabled) = changes.enabled {
            // Disabling the only enabled policy locks the install out just as
            // deleting it would, so it is refused the same way. Every other
            // edit — including to `default` — goes through.
            if !enabled {
                self.refuse_lockout(&loaded, "disabled").await?;
            }
            policy.enabled = enabled;
        }
        policy.updated_at = chrono::Utc::now();

        self.store.update_policy(&policy).await?;
        self.reload_engine().await?;

        let event = AuditEvent::builder(AuditEventType::PolicyUpdated)
            .action("update")
            .user_actor(&auth.user)
            .resource("policy", &policy.id.0.to_string())
            .correlation_id(corr)
            .decision(
                AuditDecision::Permit,
                Some(&policy_decision.reasons.join(", ")),
            )
            .details(serde_json::json!({ "policy_name": policy.name }))
            .build();
        write_audit(&*self.store, &event).await;

        self.ui_event_bus.emit(UiEvent::PolicyChanged {
            policy_name: policy.name.clone(),
        });

        Ok(policy)
    }

    pub async fn delete(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        id: &PolicyId,
    ) -> Result<(), ApiError> {
        let policy_decision = self
            .authz
            .authorize(auth, actions::MANAGE_POLICIES, &PolicyResource::PolicyAdmin)
            .await?;

        let policy = self.load(id).await?;

        // The seeded default is the whole authorization model of a fresh
        // install and the seed only re-runs when the table holds nothing
        // enabled, so a delete here is not a mistake anyone can undo from the
        // console. It stays editable and, once another policy is enabled,
        // disablable.
        if policy.name == DEFAULT_POLICY_NAME {
            return Err(ApiError::Conflict(format!(
                "policy '{DEFAULT_POLICY_NAME}' is the built-in default and cannot be deleted; \
                 edit it, or disable it once another policy is enabled"
            )));
        }
        self.refuse_lockout(&policy, "deleted").await?;

        self.store.delete_policy(id).await?;
        self.reload_engine().await?;

        let event = AuditEvent::builder(AuditEventType::PolicyDeleted)
            .action("delete")
            .user_actor(&auth.user)
            .resource("policy", &id.0.to_string())
            .correlation_id(corr)
            .decision(
                AuditDecision::Permit,
                Some(&policy_decision.reasons.join(", ")),
            )
            .details(serde_json::json!({ "policy_name": policy.name }))
            .build();
        write_audit(&*self.store, &event).await;

        self.ui_event_bus.emit(UiEvent::PolicyChanged {
            policy_name: policy.name.clone(),
        });

        Ok(())
    }

    // ------------------------------------------------------------------
    // Grant / deny policies (idempotent, engine reloaded)
    // ------------------------------------------------------------------

    /// Low-level idempotent grant: delete any existing policy with this name,
    /// create a new one. Does **not** reload the policy engine — call
    /// [`reload_engine`](Self::reload_engine) after batching multiple grants.
    async fn store_grant(
        &self,
        name: String,
        cedar_text: String,
        description: String,
    ) -> Result<StoredPolicy, ApiError> {
        let _ = self.store.delete_policy_by_name(&name).await;

        let now = chrono::Utc::now();
        let policy = StoredPolicy {
            id: PolicyId(Uuid::new_v4()),
            name,
            description: Some(description),
            cedar_policy: cedar_text,
            enabled: true,
            is_system: false,
            created_at: now,
            updated_at: now,
        };

        self.store.store_policy(&policy).await?;
        Ok(policy)
    }

    /// Idempotent grant: delete existing policy by name, create new one, reload engine.
    pub async fn ensure_grant(
        &self,
        name: String,
        cedar_text: String,
        description: String,
    ) -> Result<StoredPolicy, ApiError> {
        let policy = self.store_grant(name, cedar_text, description).await?;
        self.reload_engine().await?;
        Ok(policy)
    }

    /// Create a single credential grant or deny policy (idempotent + reload).
    pub async fn ensure_credential_grant(
        &self,
        cred_id: &CredentialId,
        workspace_id: &WorkspaceId,
        cedar_action: &str,
        perm_name: &str,
        mode: &str,
    ) -> Result<StoredPolicy, ApiError> {
        // Resolve human-readable names for the policy description.
        let cred_name = self
            .store
            .get_credential(cred_id)
            .await
            .ok()
            .flatten()
            .map(|c| c.name)
            .unwrap_or_else(|| cred_id.0.to_string());
        let ws_name = self
            .store
            .get_workspace(workspace_id)
            .await
            .ok()
            .flatten()
            .map(|w| w.name)
            .unwrap_or_else(|| workspace_id.0.to_string());

        let is_deny = mode == "deny";
        let policy_name = format!("{}:{}:{}:{}", mode, cred_id.0, workspace_id.0, cedar_action);
        let cedar_text = if is_deny {
            templates::credential_deny_policy(
                &workspace_id.0.to_string(),
                cedar_action,
                &cred_id.0.to_string(),
            )
        } else {
            templates::credential_grant_policy(
                &workspace_id.0.to_string(),
                cedar_action,
                &cred_id.0.to_string(),
            )
        };
        let description = format!(
            "{} {} on \"{}\" for workspace \"{}\"",
            if is_deny { "Deny" } else { "Grant" },
            perm_name,
            cred_name,
            ws_name,
        );
        self.ensure_grant(policy_name, cedar_text, description)
            .await
    }

    /// Create a single MCP grant or deny policy (idempotent + reload).
    pub async fn ensure_mcp_grant(
        &self,
        server_id: &McpServerId,
        workspace_id: &WorkspaceId,
        permission: &str,
        mode: &str,
    ) -> Result<StoredPolicy, ApiError> {
        // Resolve human-readable names for the policy description.
        let server_name = self
            .store
            .get_mcp_server(server_id)
            .await
            .ok()
            .flatten()
            .map(|s| s.name)
            .unwrap_or_else(|| server_id.0.to_string());
        let ws_name = self
            .store
            .get_workspace(workspace_id)
            .await
            .ok()
            .flatten()
            .map(|w| w.name)
            .unwrap_or_else(|| workspace_id.0.to_string());

        let is_deny = mode == "deny";
        let server_id_str = server_id.0.to_string();
        let workspace_id_str = workspace_id.0.to_string();

        let (policy_name, cedar_text) =
            if let Some(tool_name) = permission.strip_prefix("mcp_tool_call:") {
                let name = format!(
                    "{}:mcp:{}:{}:mcp_tool_call:{}",
                    mode, server_id_str, workspace_id.0, tool_name
                );
                let policy = if is_deny {
                    templates::mcp_tool_deny_policy(&workspace_id_str, tool_name, &server_id_str)
                } else {
                    templates::mcp_tool_grant_policy(&workspace_id_str, tool_name, &server_id_str)
                };
                (name, policy)
            } else {
                let name = format!(
                    "{}:mcp:{}:{}:{}",
                    mode, server_id_str, workspace_id.0, permission
                );
                let policy = if is_deny {
                    templates::mcp_deny_policy(&workspace_id_str, permission, &server_id_str)
                } else {
                    templates::mcp_grant_policy(&workspace_id_str, permission, &server_id_str)
                };
                (name, policy)
            };

        let description = format!(
            "{} {} on MCP server \"{}\" for workspace \"{}\"",
            if is_deny { "Deny" } else { "Grant" },
            permission,
            server_name,
            ws_name,
        );

        self.ensure_grant(policy_name, cedar_text, description)
            .await
    }

    /// Delete every grant policy for a credential (cascade on credential
    /// delete) and reload so the deleted grants stop applying at once.
    pub async fn delete_grants_for_credential(
        &self,
        cred_id: &CredentialId,
    ) -> Result<(), ApiError> {
        let grant_prefix = format!("grant:{}:", cred_id.0);
        self.store
            .delete_policies_by_name_prefix(&grant_prefix)
            .await?;
        self.reload_engine().await
    }

    /// Delete every grant and deny policy for an MCP server (cascade on
    /// server delete). The caller reloads after its own delete.
    pub async fn delete_grants_for_mcp_server(
        &self,
        server_id: &McpServerId,
    ) -> Result<(), ApiError> {
        let grant_prefix = format!("grant:mcp:{}:", server_id.0);
        let deny_prefix = format!("deny:mcp:{}:", server_id.0);
        self.store
            .delete_policies_by_name_prefix(&grant_prefix)
            .await?;
        self.store
            .delete_policies_by_name_prefix(&deny_prefix)
            .await?;
        Ok(())
    }

    /// Delete every Cedar grant policy that names a workspace (cascade on
    /// workspace delete). Reloads the engine only when something was deleted.
    pub async fn delete_grants_for_workspace(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<(), ApiError> {
        let mut policies_deleted = false;
        if let Ok(policies) = self.store.list_policies().await {
            let workspace_id_str = workspace_id.0.to_string();
            for policy in &policies {
                if policy.name.starts_with("grant:") && policy.name.contains(&workspace_id_str) {
                    self.store.delete_policy(&policy.id).await.ok();
                    policies_deleted = true;
                }
            }
        }
        if policies_deleted {
            self.reload_engine().await?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Credential permission grants (the /credentials/{id}/permissions routes)
    // ------------------------------------------------------------------

    /// Load credential, then check manage_permissions policy or credential ownership.
    pub async fn load_and_authorize_permissions(
        &self,
        actor: &AuthenticatedActor,
        cred_id: &CredentialId,
    ) -> Result<StoredCredential, ApiError> {
        let cred = self
            .store
            .get_credential(cred_id)
            .await?
            .ok_or_else(|| ApiError::NotFound("credential not found".to_string()))?;

        // Try Cedar manage_permissions first (admin path). Use
        // check_with_reasons because we want to fall back to ownership rather
        // than raise on Forbid here.
        if let Ok(decision) = self
            .authz
            .request(actor, &uuid::Uuid::new_v4().to_string())
            .check_with_reasons(
                actions::MANAGE_PERMISSIONS,
                &PolicyResource::Credential {
                    credential: cred.clone(),
                },
            )
            .await
        {
            if decision.decision != PolicyDecisionResult::Forbid {
                return Ok(cred);
            }
        }

        // Fallback: allow if the actor owns the credential
        match actor {
            AuthenticatedActor::User(user) => {
                if cred.created_by_user.as_ref() == Some(&user.id) {
                    return Ok(cred);
                }
            }
            AuthenticatedActor::Workspace { workspace, .. } => {
                if cred
                    .created_by
                    .as_ref()
                    .map(|id| id.0 == workspace.id.0)
                    .unwrap_or(false)
                {
                    return Ok(cred);
                }
            }
        }

        Err(ApiError::Forbidden("access denied by policy".to_string()))
    }

    /// Grant (or deny) a list of permissions on a credential to a workspace.
    /// Returns the permission names granted, in order.
    pub async fn grant_credential_permissions(
        &self,
        actor: &AuthenticatedActor,
        corr: &str,
        cred_id: &CredentialId,
        target_workspace: &WorkspaceId,
        permissions: &[String],
        mode: &str,
    ) -> Result<Vec<String>, ApiError> {
        self.load_and_authorize_permissions(actor, cred_id).await?;

        // Verify target workspace exists
        self.store
            .get_workspace(target_workspace)
            .await?
            .ok_or_else(|| ApiError::NotFound("target workspace not found".to_string()))?;

        let mut granted = Vec::new();
        for perm in permissions {
            let cedar_actions = templates::permission_to_actions(perm);

            for cedar_action in &cedar_actions {
                self.ensure_credential_grant(cred_id, target_workspace, cedar_action, perm, mode)
                    .await?;
            }

            granted.push(perm.clone());

            // Audit event per permission
            let (ws_id, ws_name, u_id, u_name) = actor.audit_actor_fields();
            let event = AuditEvent::builder(AuditEventType::CredentialUpdated)
                .action("grant_permission")
                .actor_fields(ws_id, ws_name, u_id, u_name)
                .resource("credential", &cred_id.0.to_string())
                .correlation_id(corr)
                .decision(AuditDecision::Permit, Some("bypass:manage_permissions"))
                .details(serde_json::json!({
                    "target_agent_id": target_workspace.0.to_string(),
                    "permission": perm,
                    "mode": mode,
                }))
                .build();
            write_audit(&*self.store, &event).await;
        }

        // Emit UI event for browser auto-refresh (credential detail page)
        self.ui_event_bus.emit(UiEvent::CredentialUpdated {
            credential_id: cred_id.0,
        });

        Ok(granted)
    }

    /// Replace every grant on a credential with `grants`.
    pub async fn set_credential_permissions(
        &self,
        actor: &AuthenticatedActor,
        corr: &str,
        cred_id: &CredentialId,
        grants: &[PermissionGrant],
    ) -> Result<(), ApiError> {
        self.load_and_authorize_permissions(actor, cred_id).await?;

        // Delete all existing grant policies for this credential
        let prefix = format!("grant:{}:", cred_id.0);
        self.store.delete_policies_by_name_prefix(&prefix).await?;

        // Create new grant policies
        for grant in grants {
            let cedar_actions = templates::permission_to_actions(&grant.permission);
            for cedar_action in &cedar_actions {
                self.ensure_credential_grant(
                    cred_id,
                    &grant.workspace_id,
                    cedar_action,
                    &grant.permission,
                    "grant",
                )
                .await?;
            }
        }

        // Audit event for bulk permission set
        let (ws_id, ws_name, u_id, u_name) = actor.audit_actor_fields();
        let event = AuditEvent::builder(AuditEventType::CredentialUpdated)
            .action("set_permissions")
            .actor_fields(ws_id, ws_name, u_id, u_name)
            .resource("credential", &cred_id.0.to_string())
            .correlation_id(corr)
            .decision(AuditDecision::Permit, Some("bypass:manage_permissions"))
            .details(serde_json::json!({
                "permissions": grants.iter().map(|g| serde_json::json!({
                    "workspace_id": g.workspace_id.0.to_string(),
                    "permission": g.permission,
                })).collect::<Vec<_>>(),
            }))
            .build();
        write_audit(&*self.store, &event).await;

        self.ui_event_bus.emit(UiEvent::CredentialUpdated {
            credential_id: cred_id.0,
        });

        Ok(())
    }

    /// Remove one permission grant on a credential from a workspace.
    pub async fn revoke_credential_permission(
        &self,
        actor: &AuthenticatedActor,
        corr: &str,
        cred_id: &CredentialId,
        target_workspace: &WorkspaceId,
        permission: &str,
    ) -> Result<(), ApiError> {
        self.load_and_authorize_permissions(actor, cred_id).await?;

        // Delete the Cedar grant policies for this permission
        let cedar_actions = templates::permission_to_actions(permission);
        for cedar_action in &cedar_actions {
            let policy_name = format!(
                "grant:{}:{}:{}",
                cred_id.0, target_workspace.0, cedar_action
            );
            self.store.delete_policy_by_name(&policy_name).await?;
        }

        self.reload_engine().await?;

        // Audit event for permission revocation
        let (ws_id, ws_name, u_id, u_name) = actor.audit_actor_fields();
        let event = AuditEvent::builder(AuditEventType::CredentialUpdated)
            .action("revoke_permission")
            .actor_fields(ws_id, ws_name, u_id, u_name)
            .resource("credential", &cred_id.0.to_string())
            .correlation_id(corr)
            .decision(AuditDecision::Permit, Some("bypass:manage_permissions"))
            .details(serde_json::json!({
                "target_agent_id": target_workspace.0.to_string(),
                "permission": permission,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        self.ui_event_bus.emit(UiEvent::CredentialUpdated {
            credential_id: cred_id.0,
        });

        Ok(())
    }

    /// Record that an administrator probed a policy decision with the policy
    /// tester. The evaluation itself is the Authz seam's (which emits its own
    /// `PolicyEvaluated` row for the hypothetical principal); this is the row
    /// that names the administrator who asked.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_policy_test(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        authorize_reasons: &[String],
        decision: PolicyDecisionResult,
        test_action: &str,
        test_principal_type: &str,
        test_resource_type: &str,
        test_decision: &str,
    ) {
        let audit_decision = match decision {
            PolicyDecisionResult::Permit => AuditDecision::Permit,
            PolicyDecisionResult::Forbid => AuditDecision::Forbid,
        };
        let event = AuditEvent::builder(AuditEventType::PolicyEvaluated)
            .action("test_policy")
            .user_actor(&auth.user)
            .resource_type("policy")
            .correlation_id(corr)
            .decision(audit_decision, Some(&authorize_reasons.join(", ")))
            .details(serde_json::json!({
                "test_action": test_action,
                "test_principal_type": test_principal_type,
                "test_resource_type": test_resource_type,
                "test_decision": test_decision,
            }))
            .build();
        write_audit(&*self.store, &event).await;
    }
}
