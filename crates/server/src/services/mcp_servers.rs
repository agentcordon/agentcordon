//! MCP server service: update and delete, workspace bindings, per-workspace
//! permission grants, and provisioning from the template catalog.

use std::sync::Arc;

use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::credential::CredentialId;
use agent_cordon_core::domain::mcp::{McpAuthMethod, McpServer, McpServerId, McpTransport};
use agent_cordon_core::domain::mcp_oauth::McpOAuthState;
use agent_cordon_core::domain::policy::{PolicyDecision, StoredPolicy};
use agent_cordon_core::domain::user::UserId;
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId};
use agent_cordon_core::policy::{actions, PolicyResource};

use crate::authz::Authz;
use crate::config::AppConfig;
use crate::events::{UiEvent, UiEventBus};
use crate::extractors::AuthenticatedUser;
use crate::response::ApiError;
use crate::routes::admin_api::mcp_servers::discover::{ApiKeyPlacement, DiscoveryCredential};
use crate::state::SharedStore;
use crate::templates::McpServerTemplate;

use super::credentials::{decrypt_secret, CredentialService, NewCredentialParams};
use super::policies::PolicyService;
use super::write_audit;

/// The Cedar resource for one MCP server, carrying its owner so the shipped
/// policy can scope operators to the servers they own.
pub fn mcp_server_resource(server: &McpServer) -> PolicyResource {
    PolicyResource::McpServer {
        id: server.id.0.to_string(),
        name: server.name.clone(),
        enabled: server.enabled,
        tags: server.tags.clone(),
        owner: server.created_by_user.clone(),
    }
}

/// What [`McpServerService::add_workspace_bindings`] did.
pub struct BindingOutcome {
    pub server: McpServer,
    pub added: Vec<String>,
    pub already_bound: Vec<String>,
}

/// What [`McpServerService::provision`] produced.
pub struct ProvisionOutcome {
    pub server: McpServer,
    pub workspace: Workspace,
    /// Why the install's tool-discovery probe failed, if it did.
    ///
    /// Discovery is best-effort and a failure never fails the install, but
    /// it leaves a server with no tools and nothing said so: the install
    /// reported success, the detail page said "No tools registered", and
    /// there was no way to tell that from a server that genuinely exposes
    /// none. The reason travels to the install response, and
    /// [`AuditEventType::McpToolDiscoveryFailed`] records it.
    pub tool_discovery_error: Option<String>,
}

/// Why one `mcp_tool_call` was refused. The variant names the audit row's
/// `reason`, so an operator reading the log can tell a per-tool Deny from a
/// typo'd server name without re-deriving it from the Cedar reasons.
pub enum ToolCallDenial<'a> {
    /// No server of that name resolves for this workspace's owner.
    UnknownServer,
    /// The server exists and is switched off — the documented
    /// immediate-revocation path, not a missing registration.
    ServerDisabled,
    /// The tool is not in the server's `allowed_tools` allow-list.
    ToolNotAllowed,
    /// Cedar said forbid. Carries the contributing reasons.
    Policy(&'a [String]),
}

/// Input for [`McpServerService::provision`].
pub struct ProvisionInput {
    pub workspace_id: WorkspaceId,
    /// Use an existing credential by ID.
    pub credential_id: Option<CredentialId>,
    /// Create a new credential with this secret value.
    pub secret_value: Option<String>,
}

#[derive(Clone)]
pub struct McpServerService {
    store: SharedStore,
    authz: Arc<Authz>,
    ui_event_bus: UiEventBus,
    policies: PolicyService,
    credentials: CredentialService,
    config: AppConfig,
}

impl McpServerService {
    pub fn new(
        store: SharedStore,
        authz: Arc<Authz>,
        ui_event_bus: UiEventBus,
        policies: PolicyService,
        credentials: CredentialService,
        config: AppConfig,
    ) -> Self {
        Self {
            store,
            authz,
            ui_event_bus,
            policies,
            credentials,
            config,
        }
    }

    /// The server, or 404.
    pub async fn load(&self, id: &McpServerId) -> Result<McpServer, ApiError> {
        self.store
            .get_mcp_server(id)
            .await?
            .ok_or_else(|| ApiError::NotFound("MCP server not found".to_string()))
    }

    /// Load and require `manage_mcp_servers` on this server (with its owner).
    pub async fn load_and_authorize(
        &self,
        auth: &AuthenticatedUser,
        id: &McpServerId,
    ) -> Result<(McpServer, PolicyDecision), ApiError> {
        let server = self.load(id).await?;
        let decision = self
            .authz
            .authorize(
                auth,
                actions::MANAGE_MCP_SERVERS,
                &mcp_server_resource(&server),
            )
            .await?;
        Ok((server, decision))
    }

    fn emit_changed(&self, server_name: &str) {
        self.ui_event_bus.emit(UiEvent::McpServerChanged {
            server_name: server_name.to_string(),
        });
    }

    // ------------------------------------------------------------------
    // Update / delete
    // ------------------------------------------------------------------

    /// Rename and/or enable/disable one MCP server. `None` for either field
    /// leaves it untouched. Disabling is the documented immediate-revocation
    /// path: a disabled server is filtered out of workspace sync and the
    /// default policy's forbid on `!resource.enabled` refuses its tool calls.
    pub async fn update(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        id: &McpServerId,
        name: Option<String>,
        enabled: Option<bool>,
        allowed_tools: Option<Vec<String>>,
    ) -> Result<McpServer, ApiError> {
        let (mut server, policy_decision) = self.load_and_authorize(auth, id).await?;

        let enabled_changed = enabled.is_some_and(|e| e != server.enabled);
        if let Some(enabled) = enabled {
            server.enabled = enabled;
        }

        let allowed_tools_changed = allowed_tools
            .as_ref()
            .is_some_and(|t| Some(t) != server.allowed_tools.as_ref());
        if let Some(requested) = allowed_tools {
            // Every name has to be one the server actually publishes.
            // Refusing the whole request, naming each stray, is what keeps a
            // typo from silently narrowing an agent's access to nothing.
            let known = discovered_tool_names(&server);
            let unknown: Vec<&str> = requested
                .iter()
                .filter(|t| !known.iter().any(|k| k == *t))
                .map(String::as_str)
                .collect();
            if !unknown.is_empty() {
                return Err(ApiError::BadRequest(format!(
                    "MCP server '{}' has no tool named {}. Its tools are: {}",
                    server.name,
                    unknown
                        .iter()
                        .map(|t| format!("'{t}'"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    if known.is_empty() {
                        "none — run tool discovery first".to_string()
                    } else {
                        known.join(", ")
                    }
                )));
            }
            server.allowed_tools = Some(requested);
        }

        if let Some(name) = name {
            let trimmed = name.trim().to_string();
            if trimmed.is_empty() {
                return Err(ApiError::BadRequest("name cannot be empty".to_string()));
            }
            if trimmed.contains('.') {
                return Err(ApiError::BadRequest(
                    "name must not contain '.' (dots break scope format)".to_string(),
                ));
            }
            server.name = trimmed;
        }
        server.updated_at = chrono::Utc::now();

        self.store.update_mcp_server(&server).await?;

        let event = AuditEvent::builder(AuditEventType::McpServerUpdated)
            .action("update")
            .user_actor(&auth.user)
            .resource("mcp_server", &server.id.0.to_string())
            .correlation_id(corr)
            .decision(
                AuditDecision::Permit,
                Some(&policy_decision.reasons.join(", ")),
            )
            .details(serde_json::json!({
                "server_name": server.name,
                "enabled": server.enabled,
                "enabled_changed": enabled_changed,
                "allowed_tools": server.allowed_tools,
                "allowed_tools_changed": allowed_tools_changed,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        self.emit_changed(&server.name);

        Ok(server)
    }

    pub async fn delete(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        id: &McpServerId,
    ) -> Result<(), ApiError> {
        let (server, policy_decision) = self.load_and_authorize(auth, id).await?;

        // Cascade: delete all MCP grant/deny policies for this server (keyed by server ID)
        self.policies
            .delete_grants_for_mcp_server(&server.id)
            .await?;

        self.store.delete_mcp_server(id).await?;

        // Reload policy engine so deleted grant policies take effect
        self.policies.reload_engine().await?;

        let event = AuditEvent::builder(AuditEventType::McpServerDeleted)
            .action("delete")
            .user_actor(&auth.user)
            .resource("mcp_server", &server.id.0.to_string())
            .correlation_id(corr)
            .decision(
                AuditDecision::Permit,
                Some(&policy_decision.reasons.join(", ")),
            )
            .details(serde_json::json!({
                "server_name": server.name,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        self.emit_changed(&server.name);

        Ok(())
    }

    // ------------------------------------------------------------------
    // Workspace bindings
    // ------------------------------------------------------------------

    /// Bind the server to each workspace. Every workspace is checked before
    /// any row is written, so a refused one means no partial writes.
    pub async fn add_workspace_bindings(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        id: &McpServerId,
        workspace_ids: &[Uuid],
    ) -> Result<BindingOutcome, ApiError> {
        let (server, policy_decision) = self.load_and_authorize(auth, id).await?;

        let is_admin = auth.is_admin();

        if !is_admin {
            let owner_match = server
                .created_by_user
                .as_ref()
                .map(|u| u == &auth.user.id)
                .unwrap_or(false);
            if !owner_match {
                return Err(ApiError::Forbidden(
                    "only the MCP server owner may share it".to_string(),
                ));
            }
        }

        // Pre-check every workspace BEFORE any insert — no partial writes.
        let mut workspaces: Vec<Workspace> = Vec::with_capacity(workspace_ids.len());
        for ws_uuid in workspace_ids {
            let ws_id = WorkspaceId(*ws_uuid);
            let ws =
                self.store.get_workspace(&ws_id).await?.ok_or_else(|| {
                    ApiError::NotFound(format!("workspace {} not found", ws_uuid))
                })?;

            if !is_admin {
                let same_owner = match (ws.owner_id.as_ref(), server.created_by_user.as_ref()) {
                    (Some(ws_owner), Some(mcp_owner)) => ws_owner == mcp_owner,
                    _ => false,
                };
                if !same_owner {
                    return Err(ApiError::Forbidden(format!(
                        "workspace {} is not owned by the MCP server's owner",
                        ws_uuid
                    )));
                }
            }
            workspaces.push(ws);
        }

        let mut added: Vec<String> = Vec::new();
        let mut already_bound: Vec<String> = Vec::new();
        for ws in &workspaces {
            let was_added = self
                .store
                .add_mcp_server_workspace(id, &ws.id, Some(&auth.user.id))
                .await?;
            if was_added {
                added.push(ws.id.0.to_string());

                let event = AuditEvent::builder(AuditEventType::McpServerSharedWithWorkspace)
                    .action("share")
                    .user_actor(&auth.user)
                    .resource("mcp_server", &id.0.to_string())
                    .correlation_id(corr)
                    .decision(
                        AuditDecision::Permit,
                        Some(&policy_decision.reasons.join(", ")),
                    )
                    .details(serde_json::json!({
                        "workspace_id": ws.id.0.to_string(),
                        "workspace_name": ws.name,
                    }))
                    .build();
                write_audit(&*self.store, &event).await;
            } else {
                already_bound.push(ws.id.0.to_string());
            }
        }

        // Issue #32 — notify the MCP servers list page so its Workspaces column
        // refreshes after a binding mutation.
        if !added.is_empty() {
            self.emit_changed(&server.name);
        }

        Ok(BindingOutcome {
            server,
            added,
            already_bound,
        })
    }

    /// Remove one workspace binding. The last binding cannot be removed;
    /// delete the server instead.
    pub async fn remove_workspace_binding(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        id: &McpServerId,
        workspace_id: Uuid,
    ) -> Result<(), ApiError> {
        let (server, policy_decision) = self.load_and_authorize(auth, id).await?;

        let is_admin = auth.is_admin();

        if !is_admin {
            let owner_match = server
                .created_by_user
                .as_ref()
                .map(|u| u == &auth.user.id)
                .unwrap_or(false);
            if !owner_match {
                return Err(ApiError::Forbidden(
                    "only the MCP server owner may unshare it".to_string(),
                ));
            }

            let target_ws_id = WorkspaceId(workspace_id);
            let ws = self
                .store
                .get_workspace(&target_ws_id)
                .await?
                .ok_or_else(|| {
                    ApiError::NotFound(format!("workspace {} not found", workspace_id))
                })?;
            let same_owner = match (ws.owner_id.as_ref(), server.created_by_user.as_ref()) {
                (Some(ws_owner), Some(mcp_owner)) => ws_owner == mcp_owner,
                _ => false,
            };
            if !same_owner {
                return Err(ApiError::Forbidden(format!(
                    "workspace {} is not owned by the MCP server's owner",
                    workspace_id
                )));
            }
        }

        let target_ws_id = WorkspaceId(workspace_id);

        // Last-binding guard. State invariant — applies to admins too.
        let count = self.store.count_workspaces_for_mcp_server(id).await?;
        if count <= 1 {
            return Err(ApiError::Conflict(
                "cannot remove last workspace binding — delete the MCP server instead".to_string(),
            ));
        }

        let removed = self
            .store
            .remove_mcp_server_workspace(id, &target_ws_id)
            .await?;
        if !removed {
            return Err(ApiError::NotFound(
                "no binding exists between this MCP and workspace".to_string(),
            ));
        }

        let event = AuditEvent::builder(AuditEventType::McpServerUnsharedFromWorkspace)
            .action("unshare")
            .user_actor(&auth.user)
            .resource("mcp_server", &id.0.to_string())
            .correlation_id(corr)
            .decision(
                AuditDecision::Permit,
                Some(&policy_decision.reasons.join(", ")),
            )
            .details(serde_json::json!({
                "workspace_id": workspace_id.to_string(),
            }))
            .build();
        write_audit(&*self.store, &event).await;

        // Issue #32 — notify the MCP servers list page so its Workspaces column
        // refreshes after a binding mutation.
        self.emit_changed(&server.name);

        Ok(())
    }

    // ------------------------------------------------------------------
    // Permissions (grant/deny policies keyed by server id)
    // ------------------------------------------------------------------

    /// Grant (or deny) one permission on the server to a workspace.
    pub async fn grant_permission(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        id: &McpServerId,
        target_workspace: &WorkspaceId,
        permission: &str,
        mode: &str,
    ) -> Result<StoredPolicy, ApiError> {
        let (server, _) = self.load_and_authorize(auth, id).await?;

        // Verify workspace exists
        self.store
            .get_workspace(target_workspace)
            .await?
            .ok_or_else(|| ApiError::NotFound("workspace not found".to_string()))?;

        // Create grant/deny policy via grant service (idempotent + engine reload)
        let stored_policy = self
            .policies
            .ensure_mcp_grant(&server.id, target_workspace, permission, mode)
            .await?;

        self.emit_changed(&stored_policy.name);

        let event = AuditEvent::builder(AuditEventType::McpServerUpdated)
            .action("grant_mcp_permission")
            .user_actor(&auth.user)
            .resource("mcp_server", &id.0.to_string())
            .correlation_id(corr)
            .decision(AuditDecision::Permit, Some("bypass:manage_mcp_servers"))
            .details(serde_json::json!({
                "target_agent_id": target_workspace.0.to_string(),
                "permission": permission,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        Ok(stored_policy)
    }

    /// Revoke one permission (grant or deny) on the server from a workspace.
    pub async fn revoke_permission(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        id: &McpServerId,
        agent_id: Uuid,
        permission: &str,
    ) -> Result<(), ApiError> {
        let (server, _) = self.load_and_authorize(auth, id).await?;

        // Try grant first, then deny — matches the naming format used in grant_permission().
        let grant_name = format!("grant:mcp:{}:{}:{}", server.id.0, agent_id, permission);
        let deny_name = format!("deny:mcp:{}:{}:{}", server.id.0, agent_id, permission);

        let deleted_grant = self.store.delete_policy_by_name(&grant_name).await?;
        let policy_name = if deleted_grant {
            grant_name
        } else {
            let deleted_deny = self.store.delete_policy_by_name(&deny_name).await?;
            if !deleted_deny {
                return Err(ApiError::NotFound(
                    "permission policy not found".to_string(),
                ));
            }
            deny_name
        };

        self.policies.reload_engine().await?;

        self.emit_changed(&policy_name);

        let event = AuditEvent::builder(AuditEventType::McpServerUpdated)
            .action("revoke_mcp_permission")
            .user_actor(&auth.user)
            .resource("mcp_server", &id.0.to_string())
            .correlation_id(corr)
            .decision(AuditDecision::Permit, Some("bypass:manage_mcp_servers"))
            .details(serde_json::json!({
                "target_agent_id": agent_id.to_string(),
                "permission": permission,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        Ok(())
    }

    // ------------------------------------------------------------------
    // Tool discovery
    // ------------------------------------------------------------------

    /// Write what a probe found onto the record. Returns how many tools were
    /// stored; an empty result stores nothing and leaves the record alone.
    async fn store_discovered_tools(
        &self,
        server: &McpServer,
        tools: Vec<agent_cordon_core::domain::mcp::McpTool>,
    ) -> usize {
        if tools.is_empty() {
            tracing::debug!(server = %server.name, "tool discovery returned empty list");
            return 0;
        }
        let count = tools.len();
        let mut updated = server.clone();
        // A record nobody has narrowed mirrors what the upstream publishes.
        // A narrowed one keeps its allow-list — rediscovery must not undo an
        // operator's decision — and gains only the record of the new tools,
        // which the Tools tab then offers as unticked boxes.
        if is_narrowed(server) {
            let found = tool_names(&tools);
            updated.allowed_tools = Some(
                server
                    .allowed_tools
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|name| found.contains(name))
                    .collect(),
            );
        } else {
            updated.allowed_tools = Some(tool_names(&tools));
        }
        updated.discovered_tools = Some(tools);
        if let Err(e) = self.store.update_mcp_server(&updated).await {
            tracing::warn!(error = %e, server = %server.name, "failed to update discovered tools");
            return 0;
        }
        count
    }

    /// Record a failed probe: a warning in the log and an audit row naming
    /// the server and the reason, so "installed but no tools" is never
    /// silent again.
    async fn audit_discovery_failure(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        server: &McpServer,
        reason: &str,
    ) {
        tracing::warn!(
            server = %server.name,
            upstream_url = %server.upstream_url,
            reason = %reason,
            "MCP tool discovery failed"
        );
        let event = AuditEvent::builder(AuditEventType::McpToolDiscoveryFailed)
            .action("discover_tools")
            .user_actor(&auth.user)
            .resource("mcp_server", &server.id.0.to_string())
            .correlation_id(corr)
            .decision(AuditDecision::Error, Some("tool discovery failed"))
            .details(serde_json::json!({
                "server_name": server.name,
                "upstream_url": server.upstream_url,
                "reason": reason,
            }))
            .build();
        write_audit(&*self.store, &event).await;
    }

    /// Probe the upstream and record the result: tools onto the record, a
    /// failure into the audit log. `Err` carries the reason.
    async fn probe_and_record(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        server: &McpServer,
        credential: Option<DiscoveryCredential<'_>>,
    ) -> Result<usize, String> {
        match crate::routes::admin_api::mcp_servers::discover::attempt_tool_discovery(
            &self.config,
            server,
            credential,
        )
        .await
        {
            Ok(tools) => Ok(self.store_discovered_tools(server, tools).await),
            Err(e) => {
                self.audit_discovery_failure(auth, corr, server, &e).await;
                Err(e)
            }
        }
    }

    /// Re-run tool discovery against a server's upstream, presenting the
    /// credential the broker would present.
    ///
    /// The install-time probe is best-effort, so a server whose upstream was
    /// unreachable — behind the SSRF guard, or simply down — is left with no
    /// tools and, before this, no way back except delete and reinstall.
    pub async fn rediscover_tools(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        id: &McpServerId,
    ) -> Result<usize, ApiError> {
        let (server, _) = self.load_and_authorize(auth, id).await?;

        // The credential the server carries, opened the way the broker opens
        // it: an upstream OAuth credential is exchanged for a fresh access
        // token, everything else is presented where its type says it goes.
        let cred = match server
            .required_credentials
            .as_deref()
            .and_then(|c| c.first())
        {
            Some(cred_id) => self.store.get_credential(cred_id).await?,
            None => None,
        };
        let secret: Option<(String, OwnedPlacement)> = match &cred {
            None => None,
            Some(cred) if super::upstream_tokens::is_upstream_oauth(&cred.credential_type) => {
                let workspace = self
                    .store
                    .list_workspaces_for_mcp_server(id)
                    .await?
                    .into_iter()
                    .next();
                let (ws_id, ws_name) = workspace.ok_or_else(|| {
                    ApiError::Conflict(
                        "this MCP server is not bound to a workspace, so no upstream token can be \
                         minted for discovery"
                            .to_string(),
                    )
                })?;
                let token = super::upstream_tokens::access_token_for(
                    &self.credentials,
                    cred,
                    super::upstream_tokens::TokenActor {
                        workspace_id: &ws_id,
                        workspace_name: &ws_name,
                    },
                )
                .await?;
                Some((token.access_token, OwnedPlacement::Bearer))
            }
            Some(cred) => decrypt_secret(&self.credentials.key_ring, cred)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .map(|secret| (secret, credential_placement(cred))),
        };

        let credential = secret
            .as_ref()
            .map(|(secret, placement)| DiscoveryCredential {
                secret,
                placement: placement.as_ref(),
            });

        let count = self
            .probe_and_record(auth, corr, &server, credential)
            .await
            .map_err(|e| ApiError::BadGateway(format!("tool discovery failed: {e}")))?;

        self.emit_changed(&server.name);

        let event = AuditEvent::builder(AuditEventType::McpServerUpdated)
            .action("discover_tools")
            .user_actor(&auth.user)
            .resource("mcp_server", &server.id.0.to_string())
            .correlation_id(corr)
            .decision(AuditDecision::Permit, Some("manage_mcp_servers"))
            .details(serde_json::json!({
                "server_name": server.name,
                "tool_count": count,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        Ok(count)
    }

    // ------------------------------------------------------------------
    // Provisioning from the catalog
    // ------------------------------------------------------------------

    /// Provision an MCP server from a catalog template for a workspace:
    /// create the server record, create or link a credential, bind the
    /// workspace, probe the upstream for tools, and audit. A credential the
    /// upstream rejects rolls the whole provision back.
    pub async fn provision(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        template: &McpServerTemplate,
        input: ProvisionInput,
    ) -> Result<ProvisionOutcome, ApiError> {
        // 1. Cedar policy check: manage_mcp_servers.
        let policy_decision = self
            .authz
            .authorize(auth, actions::MANAGE_MCP_SERVERS, &PolicyResource::System)
            .await?;

        // 3. Verify workspace exists
        let workspace_id = input.workspace_id;
        let workspace = self
            .store
            .get_workspace(&workspace_id)
            .await?
            .ok_or_else(|| ApiError::NotFound("workspace not found".to_string()))?;

        // 4. Check for duplicate: user already has server with this template_key
        let user_servers = self.store.list_mcp_servers_by_user(&auth.user.id).await?;
        if user_servers
            .iter()
            .any(|s| s.template_key.as_deref() == Some(&template.key))
        {
            return Err(ApiError::Conflict(format!(
                "you already have an MCP server from template '{}'",
                template.key
            )));
        }

        // 5. Resolve auth method from template
        let auth_method = McpAuthMethod::from_str_opt(&template.auth_method).unwrap_or_default();

        // 6. Resolve credential
        let credential_id = match (&input.credential_id, &input.secret_value) {
            (Some(cred_id), _) => {
                // Verify credential exists and is accessible to this workspace.
                // Non-admin users can only use credentials they own; admin can use any.
                let cred = self.credentials.load(cred_id).await?;

                // Verify the credential belongs to this user or workspace
                if !auth.is_root {
                    let owned = cred.created_by_user.as_ref() == Some(&auth.user.id)
                        || cred.created_by.as_ref() == Some(&workspace_id);
                    if !owned {
                        return Err(ApiError::Forbidden(
                            "credential does not belong to this user or workspace".to_string(),
                        ));
                    }
                }
                Some(cred_id.clone())
            }
            (None, Some(secret)) => {
                // Where the template says its key goes. A template that names
                // no placement keeps the historical bearer behaviour, so every
                // template that shipped before this field is unaffected.
                let (credential_type, credential_metadata, transform_name) =
                    api_key_credential_shape(template);
                // Create new credential from template metadata
                let service = template
                    .credential_template_key
                    .clone()
                    .unwrap_or_else(|| template.key.clone());
                let cred_name = format!("{}-{}", template.key, workspace.name);
                let cred = self
                    .credentials
                    .store_unaudited(NewCredentialParams {
                        name: cred_name,
                        service,
                        secret_value: secret.clone(),
                        credential_type: credential_type.to_string(),
                        scopes: vec![],
                        metadata: credential_metadata,
                        tags: vec![format!("mcp:{}", template.key)],
                        vault_id: None,
                        created_by: None,
                        created_by_user: Some(auth.user.id.clone()),
                        allowed_url_pattern: Some(format!("{}*", template.upstream_url)),
                        expires_at: None,
                        transform_script: None,
                        // The typed API-key credentials carry their own
                        // injection (the broker reads the name out of the
                        // metadata), so a transform on top would send the key
                        // twice. Only the untyped bearer default needs one.
                        transform_name: transform_name.map(str::to_string),
                        description: Some(format!(
                            "Auto-created for MCP server '{}' on workspace '{}'",
                            template.name, workspace.name
                        )),
                        target_identity: None,
                    })
                    .await?;
                Some(cred.id)
            }
            (None, None) => {
                if auth_method == McpAuthMethod::ApiKey {
                    return Err(ApiError::BadRequest(
                        "credential_id or secret_value required for API key auth method"
                            .to_string(),
                    ));
                }
                None
            }
        };

        // 7. Create MCP server record
        let now = chrono::Utc::now();
        let transport = McpTransport::from_str_opt(&template.transport).unwrap_or_default();
        let server = McpServer {
            id: McpServerId(Uuid::new_v4()),
            // #37: workspace ownership lives in `mcp_server_workspaces`.
            workspace_id: None,
            name: template.key.clone(),
            upstream_url: template.upstream_url.clone(),
            transport,
            allowed_tools: None,
            enabled: true,
            created_by: None,
            created_at: now,
            updated_at: now,
            tags: template.tags.clone(),
            required_credentials: credential_id.as_ref().map(|id| vec![id.clone()]),
            auth_method,
            template_key: Some(template.key.clone()),
            discovered_tools: None,
            created_by_user: Some(auth.user.id.clone()),
        };
        self.store.create_mcp_server(&server).await?;

        // 7a. Bind the new MCP to its originating workspace in the junction. Without
        // this row, post-migration-010 broker sync (which joins through
        // `mcp_server_workspaces`) returns zero MCPs for this workspace even
        // though the record exists. The migration only backfills pre-existing
        // rows; new provisions must insert their own junction row.
        self.store
            .add_mcp_server_workspace(&server.id, &workspace_id, Some(&auth.user.id))
            .await?;

        // 7b. Best-effort tool discovery — call tools/list on the upstream MCP server.
        // This populates allowed_tools so that `agentcordon mcp-tools` works immediately
        // after provisioning. Failures are non-fatal (tools can be discovered later).
        //
        // When credential_id was used (no secret_value), decrypt the existing credential
        // so discovery can authenticate against upstream servers that require auth on tools/list.
        let discovery_secret: Option<String> = match (&input.credential_id, &input.secret_value) {
            (_, Some(secret)) => Some(secret.clone()),
            (Some(cred_id), None) => self
                .store
                .get_credential(cred_id)
                .await
                .ok()
                .flatten()
                .and_then(|cred| {
                    decrypt_secret(&self.credentials.key_ring, &cred)
                        .ok()
                        .and_then(|bytes| String::from_utf8(bytes).ok())
                }),
            _ => None,
        };

        // Validate the credential by probing the upstream MCP server. If discovery
        // fails specifically with an authentication error (HTTP 401/403), we reject
        // the install BEFORE persisting the server — this catches the "wrong key
        // pasted into install form" failure mode. Other failures (network errors,
        // upstream not reachable) are non-fatal: the user may be installing for a
        // server they'll bring online later.
        let provided_credential = discovery_secret.is_some();
        // Probe the upstream the way the broker will call it. A server that
        // wants `X-API-Key` answers a bearer probe with 401, and a 401 during
        // discovery rolls the whole install back.
        let discovery_placement = api_key_discovery_placement(template);
        let tool_discovery_error =
            match crate::routes::admin_api::mcp_servers::discover::attempt_tool_discovery(
                &self.config,
                &server,
                discovery_secret
                    .as_deref()
                    .map(|secret| DiscoveryCredential {
                        secret,
                        placement: discovery_placement,
                    }),
            )
            .await
            {
                Ok(tools) => {
                    self.store_discovered_tools(&server, tools).await;
                    None
                }
                Err(e) => {
                    // Check if the error is an auth error (HTTP 401/403). The discovery
                    // helper formats these as "HTTP 401" or "HTTP 403".
                    let is_auth_error = e.contains("HTTP 401") || e.contains("HTTP 403");
                    if is_auth_error && provided_credential {
                        tracing::warn!(server = %server.name, error = %e, "credential rejected by upstream during provision");
                        // Roll back: delete the server we just created so the user can retry.
                        let _ = self.store.delete_mcp_server(&server.id).await;
                        if let Some(cid) = &credential_id {
                            let _ = self.store.delete_credential(cid).await;
                        }
                        return Err(ApiError::BadRequest(format!(
                            "The credential you provided was rejected by the MCP server ({e}). \
                         Please check the secret and try again."
                        )));
                    }
                    // The install stands, but a server with no tools and no
                    // explanation reads as a successful install of a useless
                    // server. Audit it and hand the reason back to the caller.
                    self.audit_discovery_failure(auth, corr, &server, &e).await;
                    Some(e)
                }
            };

        let server_id_str = server.id.0.to_string();
        let workspace_id_str = workspace_id.0.to_string();

        self.emit_changed(&server.name);

        // 10. Audit event
        let event = AuditEvent::builder(AuditEventType::McpServerProvisioned)
            .action("provision")
            .user_actor(&auth.user)
            .resource("mcp_server", &server_id_str)
            .correlation_id(corr)
            .decision(
                AuditDecision::Permit,
                Some(&policy_decision.reasons.join(", ")),
            )
            .details(serde_json::json!({
                "template_key": template.key,
                "server_name": template.name,
                "workspace_id": workspace_id_str,
                "workspace_name": workspace.name,
                "auth_method": template.auth_method,
                "has_credential": credential_id.is_some(),
                "tool_discovery_error": tool_discovery_error,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        Ok(ProvisionOutcome {
            server,
            workspace,
            tool_discovery_error,
        })
    }
}

/// The credential a template's API key should become: its `credential_type`,
/// the metadata the broker needs to inject it, and the transform (if any).
///
/// A template that declares `api_key_header` (or `api_key_query`) names where
/// the upstream expects its key, and provisioning creates the matching typed
/// credential — the broker reads `header_name` / `param_name` out of the
/// metadata and injects accordingly, with no transform. A template that
/// declares neither keeps the original behaviour, `Authorization: Bearer
/// <key>` via the `bearer` transform on a `generic` credential, so every
/// template that shipped before this field behaves exactly as it did.
fn api_key_credential_shape(
    template: &McpServerTemplate,
) -> (&'static str, serde_json::Value, Option<&'static str>) {
    if let Some(header_name) = template
        .api_key_header
        .as_deref()
        .map(str::trim)
        .filter(|h| !h.is_empty())
    {
        return (
            "api_key_header",
            serde_json::json!({ "header_name": header_name }),
            None,
        );
    }
    if let Some(param_name) = template
        .api_key_query
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        return (
            "api_key_query",
            serde_json::json!({ "param_name": param_name }),
            None,
        );
    }
    ("generic", serde_json::json!({}), Some("bearer"))
}

/// An [`ApiKeyPlacement`] that owns its header or parameter name, so a
/// rediscovery can read the placement out of a stored credential and still
/// hand the borrowed form to the probe.
enum OwnedPlacement {
    Bearer,
    Header(String),
    Query(String),
}

impl OwnedPlacement {
    fn as_ref(&self) -> ApiKeyPlacement<'_> {
        match self {
            OwnedPlacement::Bearer => ApiKeyPlacement::Bearer,
            OwnedPlacement::Header(name) => ApiKeyPlacement::Header(name),
            OwnedPlacement::Query(name) => ApiKeyPlacement::Query(name),
        }
    }
}

/// Where a stored credential's secret goes on the wire — the same reading
/// the broker makes from the credential's type and metadata, so a
/// rediscovery probes the upstream exactly the way a tool call will.
fn credential_placement(
    cred: &agent_cordon_core::domain::credential::StoredCredential,
) -> OwnedPlacement {
    let metadata_str = |field: &str| {
        cred.metadata
            .get(field)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    match cred.credential_type.as_str() {
        "api_key_header" => metadata_str("header_name")
            .map(OwnedPlacement::Header)
            .unwrap_or(OwnedPlacement::Bearer),
        "api_key_query" => metadata_str("param_name")
            .map(OwnedPlacement::Query)
            .unwrap_or(OwnedPlacement::Bearer),
        _ => OwnedPlacement::Bearer,
    }
}

/// The placement `api_key_credential_shape` chose, in the form tool discovery
/// needs it. The two must not disagree: discovery is the request that decides
/// whether the install survives.
fn api_key_discovery_placement(template: &McpServerTemplate) -> ApiKeyPlacement<'_> {
    match api_key_credential_shape(template).0 {
        "api_key_header" => ApiKeyPlacement::Header(
            template
                .api_key_header
                .as_deref()
                .unwrap_or_default()
                .trim(),
        ),
        "api_key_query" => {
            ApiKeyPlacement::Query(template.api_key_query.as_deref().unwrap_or_default().trim())
        }
        _ => ApiKeyPlacement::Bearer,
    }
}

/// Only alphanumerics, hyphens, underscores, and dots: what may appear
/// inside a generated Cedar policy without becoming policy syntax.
pub(crate) fn is_safe_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// The Cedar text that lets workspaces tagged `tag` call `tool_name` on one
/// server. Validates its inputs itself so a caller cannot inject policy.
fn generate_cedar_policy(tag: &str, tool_name: &str, server_id: &str) -> Result<String, ApiError> {
    if !is_safe_identifier(tag) {
        return Err(ApiError::BadRequest(format!(
            "unsafe tag value for Cedar policy generation: '{}'",
            tag
        )));
    }
    if !is_safe_identifier(tool_name) {
        return Err(ApiError::BadRequest(format!(
            "unsafe tool_name value for Cedar policy generation: '{}'",
            tool_name
        )));
    }
    if server_id.is_empty() || !server_id.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return Err(ApiError::BadRequest(format!(
            "unsafe server_id value for Cedar policy generation: '{}'",
            server_id
        )));
    }
    Ok(format!(
        r#"// Auto-generated: Allow agents tagged "{tag}" to use tool "{tool_name}" on MCP server "{server_id}"
permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"mcp_tool_call",
  resource == AgentCordon::McpServer::"{server_id}"
) when {{
  principal.tags.contains("{tag}") &&
  context.tool_name == "{tool_name}"
}};"#,
    ))
}

/// Every tool the record currently knows about: the allow-list if it has
/// one, else whatever discovery found.
fn current_tool_names(server: &McpServer) -> Vec<String> {
    match server.allowed_tools.as_deref() {
        Some(names) if !names.is_empty() => names.to_vec(),
        _ => server
            .discovered_tools
            .as_deref()
            .map(tool_names)
            .unwrap_or_default(),
    }
}

/// Guard the policy generator's inputs: bounded in size, and safe to
/// interpolate into Cedar text.
fn validate_grant_inputs(tools: &[String], agent_tags: &[String]) -> Result<(), ApiError> {
    if tools.len() > 50 {
        return Err(ApiError::BadRequest(
            "maximum 50 tools per request".to_string(),
        ));
    }
    if agent_tags.len() > 50 {
        return Err(ApiError::BadRequest(
            "maximum 50 agent_tags per request".to_string(),
        ));
    }
    for tool_name in tools {
        if !is_safe_identifier(tool_name) {
            return Err(ApiError::BadRequest(format!(
                "invalid tool name '{}': must be 1-128 alphanumeric, hyphen, underscore, or dot characters",
                tool_name
            )));
        }
    }
    for tag in agent_tags {
        if !is_safe_identifier(tag) {
            return Err(ApiError::BadRequest(format!(
                "invalid agent tag '{}': must be 1-128 alphanumeric, hyphen, underscore, or dot characters",
                tag
            )));
        }
    }
    Ok(())
}

/// The names of a tool list, in order — what `allowed_tools` holds.
fn tool_names(tools: &[agent_cordon_core::domain::mcp::McpTool]) -> Vec<String> {
    tools.iter().map(|t| t.name.clone()).collect()
}

/// Every tool this server publishes: what discovery found, falling back to
/// the bare `allowed_tools` names for a record that was never discovered
/// against. This is the set an `allowed_tools` narrowing must be a subset of.
pub fn discovered_tool_names(server: &McpServer) -> Vec<String> {
    match server.discovered_tools.as_deref() {
        Some(tools) if !tools.is_empty() => tool_names(tools),
        _ => server.allowed_tools.clone().unwrap_or_default(),
    }
}

/// True when this record's tool list has been deliberately narrowed rather
/// than merely mirroring what discovery last found.
///
/// It decides whether rediscovery may widen the list. A server nobody has
/// narrowed takes every tool the upstream now publishes, the way it always
/// has; a narrowed one keeps its allow-list and gains only the record of the
/// new tool, ready for an operator to tick.
pub fn is_narrowed(server: &McpServer) -> bool {
    let Some(allowed) = server.allowed_tools.as_deref() else {
        return false;
    };
    let Some(discovered) = server.discovered_tools.as_deref() else {
        return false;
    };
    // Something the upstream publishes that the allow-list leaves out.
    discovered.iter().any(|t| !allowed.contains(&t.name))
}

/// What one generated per-tool grant is called.
///
/// The generator used to name its rows `mcp-<server>-<tool>-<tag>`, which no
/// name predicate recognised: the Policies list showed them as ordinary
/// authored policies and the last-enabled-policy guard counted them, so a
/// documented operator step quietly took the seeded `default` policy out of
/// its own protection. They share the Access tab's `grant:` convention
/// instead, which [`is_generated_grant`](crate::services::policies::is_generated_grant)
/// and the Policies list both already know.
///
/// The `tag:` segment is what separates these from the Access tab's own
/// `grant:mcp:{server}:{workspace_uuid}:…` rows: the permissions listing
/// reads the segment after the server id as a workspace UUID and skips
/// anything that is not one.
///
/// `tag` and `tool` have been through
/// `is_safe_identifier`, which admits no `:`, so the name parses back.
pub fn generated_grant_name(server_id: &str, tag: &str, tool: &str) -> String {
    format!("grant:mcp:{server_id}:tag:{tag}:mcp_tool_call:{tool}")
}

/// A policy `generate_policies` created.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GeneratedPolicy {
    pub id: String,
    pub name: String,
    pub cedar_policy: String,
}

/// One server as an agent's upload describes it.
#[derive(Debug, Clone)]
pub struct ImportEntry {
    pub name: String,
    pub transport: Option<String>,
    pub url: Option<String>,
    /// Tools with whatever metadata the uploading workspace knows, stored
    /// the way discovery stores them: names in `allowed_tools`, the full
    /// entries in `discovered_tools`.
    pub tools: Option<Vec<agent_cordon_core::domain::mcp::McpTool>>,
    pub required_credentials: Option<Vec<String>>,
}

/// What `import` did with one entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ImportOutcome {
    pub name: String,
    pub id: String,
    /// `created`, `existing`, or `updated`.
    pub status: String,
}

impl McpServerService {
    /// Create one grant policy per (tool, tag) for this server, skipping
    /// names that already exist, then reload the engine once.
    ///
    /// `tools`/`agent_tags` are what the caller asked for. `None` means "what
    /// this server has": every tool it currently knows about, and every tag
    /// the workspaces it is bound to carry. An explicit empty list, or a
    /// default that resolves to nothing, is a 400 — silently creating no
    /// policies would read as success.
    pub async fn generate_policies(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        id: &McpServerId,
        tools: Option<&[String]>,
        agent_tags: Option<&[String]>,
    ) -> Result<Vec<GeneratedPolicy>, ApiError> {
        let (server, policy_decision) = self.load_and_authorize(auth, id).await?;

        let tools = match tools {
            Some(explicit) => {
                if explicit.is_empty() {
                    return Err(ApiError::BadRequest(
                        "tools list cannot be empty".to_string(),
                    ));
                }
                explicit.to_vec()
            }
            None => {
                let known = current_tool_names(&server);
                if known.is_empty() {
                    return Err(ApiError::BadRequest(format!(
                        "MCP server '{}' has no known tools to generate policies for: run tool discovery or name the tools in the request",
                        server.name
                    )));
                }
                known
            }
        };
        let agent_tags = match agent_tags {
            Some(explicit) => {
                if explicit.is_empty() {
                    return Err(ApiError::BadRequest(
                        "agent_tags list cannot be empty".to_string(),
                    ));
                }
                explicit.to_vec()
            }
            None => {
                let bound = self.bound_workspace_tags(id).await?;
                if bound.is_empty() {
                    return Err(ApiError::BadRequest(format!(
                        "no agent_tags given and the workspaces bound to MCP server '{}' carry no tags: tag a workspace or name the tags in the request",
                        server.name
                    )));
                }
                bound
            }
        };
        validate_grant_inputs(&tools, &agent_tags)?;
        let (tools, agent_tags) = (tools.as_slice(), agent_tags.as_slice());

        let existing_names: std::collections::HashSet<String> = self
            .store
            .list_policies()
            .await?
            .into_iter()
            .map(|p| p.name)
            .collect();

        let server_id_str = server.id.0.to_string();
        let mut created = Vec::new();
        for tool_name in tools {
            for tag in agent_tags {
                let policy_name = generated_grant_name(&server_id_str, tag, tool_name);
                if existing_names.contains(&policy_name) {
                    tracing::info!(policy_name = %policy_name, "skipping duplicate policy");
                    continue;
                }
                let cedar_text = generate_cedar_policy(tag, tool_name, &server_id_str)?;
                self.authz.validate_policy_text(&cedar_text).map_err(|e| {
                    ApiError::Internal(format!(
                        "generated policy failed validation for tool '{}', tag '{}': {}",
                        tool_name, tag, e
                    ))
                })?;
                let now = chrono::Utc::now();
                let policy = StoredPolicy {
                    id: agent_cordon_core::domain::policy::PolicyId(Uuid::new_v4()),
                    name: policy_name.clone(),
                    description: Some(format!(
                        "Auto-generated: Allow agents tagged \"{}\" to use tool \"{}\" on MCP server \"{}\"",
                        tag, tool_name, server.name
                    )),
                    cedar_policy: cedar_text.clone(),
                    enabled: true,
                    is_system: false,
                    created_at: now,
                    updated_at: now,
                };
                self.store.store_policy(&policy).await?;
                created.push(GeneratedPolicy {
                    id: policy.id.0.to_string(),
                    name: policy_name,
                    cedar_policy: cedar_text,
                });
            }
        }

        self.policies.reload_engine().await?;
        for p in &created {
            self.ui_event_bus.emit(UiEvent::PolicyChanged {
                policy_name: p.name.clone(),
            });
        }

        let policy_names: Vec<String> = created.iter().map(|p| p.name.clone()).collect();
        let event = AuditEvent::builder(AuditEventType::McpPoliciesGenerated)
            .action("generate_policies")
            .user_actor(&auth.user)
            .resource("mcp_server", &server.id.0.to_string())
            .correlation_id(corr)
            .decision(
                AuditDecision::Permit,
                Some(&policy_decision.reasons.join(", ")),
            )
            .details(serde_json::json!({
                "server_name": server.name,
                "policy_count": created.len(),
                "policy_names": policy_names,
                "tools": tools,
                "agent_tags": agent_tags,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        Ok(created)
    }

    /// Every tag carried by the workspaces this MCP server is bound to,
    /// in first-seen order and without duplicates. This is the tag set an
    /// omitted `agent_tags` means.
    async fn bound_workspace_tags(&self, id: &McpServerId) -> Result<Vec<String>, ApiError> {
        let mut tags: Vec<String> = Vec::new();
        for (workspace_id, _) in self.store.list_workspaces_for_mcp_server(id).await? {
            let Some(workspace) = self.store.get_workspace(&workspace_id).await? else {
                continue;
            };
            for tag in workspace.tags {
                if !tags.contains(&tag) {
                    tags.push(tag);
                }
            }
        }
        Ok(tags)
    }

    /// Register the servers an agent uploaded for `workspace_id`: a new
    /// (workspace, name) pair is created and bound in the junction; an
    /// existing one is kept, gaining tools if it had none.
    pub async fn import(
        &self,
        actor: &crate::extractors::AuthenticatedActor,
        corr: &str,
        workspace_id: WorkspaceId,
        uploading_workspace_id: Option<WorkspaceId>,
        entries: Vec<ImportEntry>,
    ) -> Result<Vec<ImportOutcome>, ApiError> {
        self.authz
            .request(
                crate::authz::PolicyCaller::Principal {
                    principal: actor.policy_principal(),
                    oauth_claims: None,
                },
                corr,
            )
            .check(actions::CREATE, &PolicyResource::System)
            .await?;

        let now = chrono::Utc::now();
        let created_by_user = self
            .store
            .get_workspace(&workspace_id)
            .await?
            .and_then(|ws| ws.owner_id);

        let mut results = Vec::new();
        for mut entry in entries {
            let name = entry.name.trim().to_string();
            if name.is_empty() || name.contains('.') {
                continue;
            }

            if let Some(existing) = self
                .store
                .get_mcp_server_by_workspace_and_name(&workspace_id, &name)
                .await?
            {
                // An upload fills in what the record is missing and nothing
                // else: names for a server that has none, and the tool
                // metadata for one whose tools are still bare names.
                let mut updated = existing.clone();
                let mut changed = false;
                if let Some(tools) = entry.tools.take().filter(|t| !t.is_empty()) {
                    if updated.allowed_tools.is_none() {
                        updated.allowed_tools = Some(tool_names(&tools));
                        changed = true;
                    }
                    if updated.discovered_tools.is_none() {
                        updated.discovered_tools = Some(tools);
                        changed = true;
                    }
                }
                let status = if changed {
                    self.store.update_mcp_server(&updated).await?;
                    "updated"
                } else {
                    "existing"
                };
                results.push(ImportOutcome {
                    name,
                    id: existing.id.0.to_string(),
                    status: status.to_string(),
                });
                continue;
            }

            let transport = match entry.transport.as_deref() {
                Some("sse") => McpTransport::Sse,
                Some("http") | None => McpTransport::Http,
                Some(other) => {
                    return Err(ApiError::BadRequest(format!(
                        "unsupported transport '{}' for MCP server '{}'",
                        other, name
                    )));
                }
            };

            let tools = entry.tools.filter(|t| !t.is_empty());
            let server = McpServer {
                id: McpServerId(Uuid::new_v4()),
                // The junction is the source of truth; the legacy column stays None.
                workspace_id: None,
                name: name.clone(),
                upstream_url: entry.url.unwrap_or_default(),
                transport,
                allowed_tools: tools.as_deref().map(tool_names),
                enabled: true,
                created_by: uploading_workspace_id.clone(),
                created_at: now,
                updated_at: now,
                tags: vec![],
                required_credentials: entry.required_credentials.map(|creds| {
                    creds
                        .iter()
                        .filter_map(|s| Uuid::parse_str(s).ok().map(CredentialId))
                        .collect()
                }),
                auth_method: McpAuthMethod::None,
                template_key: None,
                discovered_tools: tools,
                created_by_user: created_by_user.clone(),
            };
            self.store.create_mcp_server(&server).await?;
            self.store
                .add_mcp_server_workspace(&server.id, &workspace_id, created_by_user.as_ref())
                .await?;

            let mut builder = AuditEvent::builder(AuditEventType::McpServerRegistered)
                .action("import")
                .resource("mcp_server", &server.id.0.to_string())
                .correlation_id(corr)
                .decision(AuditDecision::Permit, None)
                .details(serde_json::json!({
                    "server_name": name,
                    "device_id": workspace_id.0.to_string(),
                    "source": "agent_upload",
                }));
            if let Some(ws) = &uploading_workspace_id {
                builder = builder.actor_fields(Some(ws.clone()), None, None, None);
            }
            write_audit(&*self.store, &builder.build()).await;
            self.emit_changed(&name);

            results.push(ImportOutcome {
                name,
                id: server.id.0.to_string(),
                status: "created".to_string(),
            });
        }
        Ok(results)
    }
}

/// What the OAuth callback learned from the provider and the template.
pub struct OAuthProvisionInput<'a> {
    pub template: &'a McpServerTemplate,
    pub workspace_id: &'a WorkspaceId,
    pub token_url: &'a str,
    pub client_id: &'a str,
    pub authorization_server_url: &'a str,
    pub refresh_token: String,
    pub access_token: &'a str,
}

/// The server the callback ended up with, and whether it was created.
pub struct OAuthProvisionOutcome {
    pub server: McpServer,
    pub reused_credential: bool,
    pub reused_server: bool,
    /// Why the connection's tool-discovery probe failed, if it did. See
    /// [`ProvisionOutcome::tool_discovery_error`].
    pub tool_discovery_error: Option<String>,
}

/// Input for [`McpServerService::begin_oauth_flow`].
pub struct OAuthFlowStart<'a> {
    pub template_key: &'a str,
    pub workspace_id: WorkspaceId,
    pub user_id: UserId,
    pub redirect_uri: String,
    /// PKCE verifier; the challenge derived from it goes on the authorize URL.
    pub code_verifier: String,
    pub authorization_server_url: String,
    /// Opaque `state` parameter the callback is matched by.
    pub state_token: String,
}

impl McpServerService {
    /// Record that OAuth discovery could not resolve a provider client for a
    /// template. The initiate route turns the same error into the 4xx the
    /// admin sees; this is the row that says which template failed and why.
    pub async fn record_oauth_discovery_failure(
        &self,
        corr: &str,
        template_key: &str,
        error: &str,
    ) {
        let event = AuditEvent::builder(AuditEventType::OAuthProviderDiscoveryFailed)
            .action("discover")
            .resource("mcp_template", template_key)
            .correlation_id(corr)
            .details(serde_json::json!({
                "template_key": template_key,
                "error": error,
            }))
            .build();
        write_audit(&*self.store, &event).await;
    }

    /// Record that an administrator read one server's permission list. A
    /// read, but an audited one: who asked which server who may call it.
    pub async fn record_permissions_query(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        server_id: &Uuid,
        permission_count: usize,
    ) {
        let event = AuditEvent::builder(AuditEventType::PolicyEvaluated)
            .action("query_mcp_permissions")
            .user_actor(&auth.user)
            .resource("mcp_server", &server_id.to_string())
            .correlation_id(corr)
            .decision(AuditDecision::Permit, Some("bypass:manage_mcp_servers"))
            .details(serde_json::json!({
                "permission_count": permission_count,
            }))
            .build();
        write_audit(&*self.store, &event).await;
    }

    /// Store the single-use state row that ties one authorize redirect to the
    /// workspace, user, and PKCE verifier its callback must be answered with.
    pub async fn begin_oauth_flow(&self, start: OAuthFlowStart<'_>) -> Result<(), ApiError> {
        let now = chrono::Utc::now();
        let ttl = chrono::Duration::seconds(self.config.oidc_state_ttl_seconds as i64);
        let mcp_state = McpOAuthState {
            state: start.state_token,
            template_key: start.template_key.to_string(),
            workspace_id: start.workspace_id,
            user_id: start.user_id,
            redirect_uri: start.redirect_uri,
            code_verifier: Some(start.code_verifier),
            authorization_server_url: Some(start.authorization_server_url),
            created_at: now,
            expires_at: now + ttl,
        };
        self.store.create_mcp_oauth_state(&mcp_state).await?;
        Ok(())
    }

    /// A `mcp_tool_call` was refused. Every refusal writes one of these,
    /// whatever refused it: the unknown- and disabled-server branches, the
    /// `allowed_tools` allow-list, and a Cedar forbid.
    ///
    /// The Cedar branch also leaves a `policy_evaluated` row (the `Authz` seam
    /// emits it), but that one is generic; this is the domain event the
    /// dashboard's MCP activity widget and the workspace History tab read, and
    /// without it a per-tool Deny produced no record of the refusals it exists
    /// to cause.
    pub async fn record_tool_call_denied(
        &self,
        workspace: &Workspace,
        correlation_id: &str,
        server: Option<&McpServer>,
        server_name: &str,
        tool_name: &str,
        denial: ToolCallDenial<'_>,
    ) {
        let (reason, detail) = match denial {
            ToolCallDenial::UnknownServer => ("unknown_server", None),
            ToolCallDenial::ServerDisabled => ("server_disabled", None),
            ToolCallDenial::ToolNotAllowed => ("tool_not_allowed", None),
            ToolCallDenial::Policy(reasons) => ("policy_forbid", Some(reasons.join(", "))),
        };
        // The resource is the server's id when one resolved, so the row joins
        // to the MCP server's History tab; an unknown name has nothing to join
        // to and names itself.
        let resource_id = server
            .map(|s| s.id.0.to_string())
            .unwrap_or_else(|| server_name.to_string());
        let event = AuditEvent::builder(AuditEventType::McpToolCallDenied)
            .action(&format!("mcp_tool_call/{}", tool_name))
            .resource("mcp_server", &resource_id)
            .workspace_actor(&workspace.id, &workspace.name)
            .decision(AuditDecision::Forbid, Some(reason))
            .details(serde_json::json!({
                "server_name": server_name,
                "tool_name": tool_name,
                "policy_decision": "forbid",
                "reason": reason,
                "policy_reasons": detail,
            }))
            .correlation_id(correlation_id)
            .build();
        write_audit(&*self.store, &event).await;
    }

    /// Cedar permitted a tool call. The Authz seam already emitted the
    /// `PolicyEvaluated` row with the reasons; this is the domain event.
    pub async fn record_tool_called(
        &self,
        workspace: &Workspace,
        correlation_id: &str,
        server: &McpServer,
        server_name: &str,
        tool_name: &str,
    ) {
        let event = AuditEvent::builder(AuditEventType::McpToolCalled)
            .action("mcp_tool_call")
            .workspace_actor(&workspace.id, &workspace.name)
            .resource("mcp_server", &server.id.0.to_string())
            .correlation_id(correlation_id)
            .decision(AuditDecision::Permit, None)
            .details(serde_json::json!({
                "server_name": server_name,
                "tool_name": tool_name,
            }))
            .build();
        write_audit(&*self.store, &event).await;
    }

    /// Finish an OAuth-provisioned template: reuse or create the user's
    /// credential and server for this template, bind the server to the
    /// workspace, discover tools (best effort), and audit. One user has one
    /// credential and one server per template; a second workspace install
    /// binds to the same server.
    pub async fn provision_from_oauth(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        input: OAuthProvisionInput<'_>,
    ) -> Result<OAuthProvisionOutcome, ApiError> {
        let template = input.template;
        let workspace = self
            .store
            .get_workspace(input.workspace_id)
            .await?
            .ok_or_else(|| ApiError::NotFound("workspace not found".to_string()))?;

        let existing_cred = self
            .store
            .list_all_stored_credentials()
            .await?
            .into_iter()
            .find(|c| {
                c.created_by_user.as_ref() == Some(&auth.user.id)
                    && c.service == template.key
                    && c.credential_type == "oauth2_user_authorization"
            });
        let (cred_id, reused_credential) = match existing_cred {
            Some(c) => {
                tracing::info!(credential_id = %c.id.0, template = %template.key, user = %auth.user.id.0,
                    "reusing existing OAuth credential for second-workspace install");
                (c.id, true)
            }
            None => {
                let params = NewCredentialParams {
                    name: format!("{}-{}", template.key, workspace.name),
                    service: template.key.clone(),
                    secret_value: input.refresh_token,
                    credential_type: "oauth2_user_authorization".to_string(),
                    scopes: vec![],
                    metadata: serde_json::json!({
                        "oauth2_token_url": input.token_url,
                        "oauth2_client_id": input.client_id,
                        "authorization_server_url": input.authorization_server_url,
                        "template_key": template.key,
                    }),
                    tags: vec![format!("mcp:{}", template.key)],
                    vault_id: None,
                    created_by: None,
                    created_by_user: Some(auth.user.id.clone()),
                    allowed_url_pattern: Some(format!("{}*", template.upstream_url)),
                    expires_at: None,
                    transform_script: None,
                    transform_name: Some("bearer".to_string()),
                    description: Some(format!(
                        "OAuth2 credential for MCP server '{}' on workspace '{}'",
                        template.name, workspace.name
                    )),
                    target_identity: None,
                };
                let cred = self.credentials.store_unaudited(params).await?;
                (cred.id, false)
            }
        };

        let existing_server = self
            .store
            .list_mcp_servers_by_user(&auth.user.id)
            .await?
            .into_iter()
            .find(|s| s.template_key.as_deref() == Some(template.key.as_str()));
        let (server, reused_server) = match existing_server {
            Some(s) => {
                tracing::info!(server_id = %s.id.0, template = %template.key, user = %auth.user.id.0,
                    "reusing existing MCP server for second-workspace install");
                (s, true)
            }
            None => {
                let now = chrono::Utc::now();
                let s = McpServer {
                    id: McpServerId(Uuid::new_v4()),
                    // The junction is the source of truth; the legacy column stays None.
                    workspace_id: None,
                    name: template.key.clone(),
                    upstream_url: template.upstream_url.clone(),
                    transport: McpTransport::from_str_opt(&template.transport).unwrap_or_default(),
                    allowed_tools: None,
                    enabled: true,
                    created_by: None,
                    created_at: now,
                    updated_at: now,
                    tags: template.tags.clone(),
                    required_credentials: Some(vec![cred_id.clone()]),
                    auth_method: McpAuthMethod::OAuth2,
                    template_key: Some(template.key.clone()),
                    discovered_tools: None,
                    created_by_user: Some(auth.user.id.clone()),
                };
                self.store.create_mcp_server(&s).await?;
                self.store
                    .add_mcp_server_workspace(&s.id, input.workspace_id, Some(&auth.user.id))
                    .await?;
                (s, false)
            }
        };

        // Best-effort tool discovery with the access token just issued. A
        // failure leaves the connection standing and is audited, the same as
        // on the marketplace path.
        let tool_discovery_error = self
            .probe_and_record(
                auth,
                corr,
                &server,
                Some(DiscoveryCredential::bearer(input.access_token)),
            )
            .await
            .err();

        self.emit_changed(&server.name);

        let event = AuditEvent::builder(AuditEventType::McpServerProvisioned)
            .action("provision")
            .user_actor(&auth.user)
            .resource("mcp_server", &server.id.0.to_string())
            .correlation_id(corr)
            .decision(AuditDecision::Permit, Some("oauth2_user_authorization"))
            .details(serde_json::json!({
                "template_key": template.key,
                "server_name": template.name,
                "workspace_id": input.workspace_id.0.to_string(),
                "workspace_name": workspace.name,
                "auth_method": "oauth2",
                "source": "oauth2",
                "reused_credential": reused_credential,
                "reused_server": reused_server,
                "tool_discovery_error": tool_discovery_error,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        Ok(OAuthProvisionOutcome {
            server,
            reused_credential,
            reused_server,
            tool_discovery_error,
        })
    }
}
