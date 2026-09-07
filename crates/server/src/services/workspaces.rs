//! Workspace service: metadata and tag changes, the lifecycle transitions
//! (enable, disable, revoke) that the `Workspace` type decides, deletion
//! with its cascades, and the bind operation that ties a signing key hash
//! to a user's workspace and OAuth client.

use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::user::{User, UserId};
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
use agent_cordon_core::oauth2::tokens::generate_client_id;
use agent_cordon_core::oauth2::types::{OAuthClient, OAuthScope};
use agent_cordon_core::policy::{actions, claim_keys, PolicyPrincipal, PolicyResource};

use crate::authz::{Authz, PolicyCaller};
use crate::events::{UiEvent, UiEventBus};
use crate::extractors::AuthenticatedUser;
use crate::response::ApiError;
use crate::state::SharedStore;

use super::policies::PolicyService;
use super::write_audit;

/// Input for [`WorkspaceService::update`]; `None` leaves a field unchanged.
pub struct WorkspaceChanges {
    pub name: Option<String>,
    pub tags: Option<Vec<String>>,
    pub enabled: Option<bool>,
    pub owner_id: Option<Uuid>,
}

/// How [`WorkspaceService::bind_key_hash`] should leave the OAuth client
/// for the key hash.
pub enum ClientBinding<'a> {
    /// Device-flow approval: reuse the key's existing client, binding it to
    /// the workspace by id, or mint a public client with these scopes.
    ReuseOrCreate { scopes: &'a [OAuthScope] },
    /// Consent-form registration: replace whatever client the key hash had
    /// with a fresh public client carrying this redirect URI.
    Replace {
        redirect_uri: &'a str,
        scopes: Vec<OAuthScope>,
        corr: &'a str,
    },
}

/// May `auth` re-register the key hash of `existing`?
///
/// Two rules. A workspace that is not `Active` (or is disabled) is never
/// re-registered: the operator who revoked it decided so, and a fresh key
/// is the way to start over. An active workspace is re-registered only by
/// its owner or an admin: holding manage-workspaces in general is not
/// enough, because re-registration hands the caller that workspace's
/// grants.
pub fn refuse_reregistration_unless_allowed(
    existing: &Workspace,
    auth: &AuthenticatedUser,
) -> Result<(), ApiError> {
    if !existing.is_active() {
        return Err(ApiError::Forbidden(format!(
            "workspace '{}' is {}; register a new identity instead",
            existing.name,
            existing.status.as_str()
        )));
    }
    let is_admin = auth.is_admin();
    let is_owner = existing.owner_id.as_ref() == Some(&auth.user.id);
    if !is_admin && !is_owner {
        return Err(ApiError::Forbidden(
            "only the workspace's owner or an admin can re-register it".to_string(),
        ));
    }
    Ok(())
}

#[derive(Clone)]
pub struct WorkspaceService {
    store: SharedStore,
    authz: Arc<Authz>,
    ui_event_bus: UiEventBus,
    policies: PolicyService,
}

impl WorkspaceService {
    pub fn new(
        store: SharedStore,
        authz: Arc<Authz>,
        ui_event_bus: UiEventBus,
        policies: PolicyService,
    ) -> Self {
        Self {
            store,
            authz,
            ui_event_bus,
            policies,
        }
    }

    /// The workspace, or 404.
    pub async fn load(&self, id: &WorkspaceId) -> Result<Workspace, ApiError> {
        self.store
            .get_workspace(id)
            .await?
            .ok_or_else(|| ApiError::NotFound("workspace not found".to_string()))
    }

    /// Load and require `manage_workspaces` on this workspace (with its owner).
    async fn load_and_authorize(
        &self,
        auth: &AuthenticatedUser,
        id: &WorkspaceId,
    ) -> Result<(Workspace, agent_cordon_core::domain::policy::PolicyDecision), ApiError> {
        let workspace = self.load(id).await?;
        let decision = self
            .authz
            .authorize(
                auth,
                actions::MANAGE_WORKSPACES,
                &PolicyResource::WorkspaceResource {
                    workspace: workspace.clone(),
                },
            )
            .await?;
        Ok((workspace, decision))
    }

    // ------------------------------------------------------------------
    // Update / delete
    // ------------------------------------------------------------------

    pub async fn update(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        id: &WorkspaceId,
        changes: WorkspaceChanges,
    ) -> Result<Workspace, ApiError> {
        let (mut workspace, policy_decision) = self.load_and_authorize(auth, id).await?;

        if let Some(name) = changes.name {
            workspace.name = name;
        }
        if let Some(tags) = changes.tags {
            // Non-admin users cannot assign the "admin" tag
            let is_admin = auth.is_admin();
            if !is_admin && tags.iter().any(|t| t.eq_ignore_ascii_case("admin")) {
                return Err(ApiError::Forbidden(
                    "only admins can assign the \"admin\" tag".to_string(),
                ));
            }
            workspace.tags = tags;
        }
        if let Some(enabled) = changes.enabled {
            // A lifecycle transition, checked by the workspace type: a revoked
            // or pending workspace cannot be toggled on.
            let transition = if enabled {
                workspace.enable()
            } else {
                workspace.disable()
            };
            transition.map_err(|e| ApiError::Conflict(e.to_string()))?;
        }
        if let Some(owner_id) = changes.owner_id {
            // SECURITY: workspace.owner_id is an authorization input under the
            // owner-based MCP/credential default policies. Allowing arbitrary
            // re-parenting would let any caller with `manage_workspaces` (operators
            // and admins) escalate privileges by reassigning their workspace to
            // another user. Only root may change ownership.
            if !auth.is_root {
                return Err(ApiError::Forbidden(
                    "only root may change workspace owner_id".to_string(),
                ));
            }
            workspace.owner_id = Some(UserId(owner_id));
        }
        workspace.updated_at = chrono::Utc::now();

        self.store.update_workspace(&workspace).await?;

        let event = AuditEvent::builder(AuditEventType::WorkspaceUpdated)
            .action("update")
            .user_actor(&auth.user)
            .resource("workspace", &workspace.id.0.to_string())
            .correlation_id(corr)
            .decision(
                AuditDecision::Permit,
                Some(&policy_decision.reasons.join(", ")),
            )
            .details(serde_json::json!({ "updated_workspace": workspace.name }))
            .build();
        write_audit(&*self.store, &event).await;

        self.ui_event_bus.emit(UiEvent::WorkspaceUpdated {
            workspace_id: workspace.id.0,
        });

        Ok(workspace)
    }

    /// Delete a workspace, its grant policies, and the OAuth client bound to
    /// its key so the key hash is free for re-registration.
    pub async fn delete(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        id: &WorkspaceId,
    ) -> Result<(), ApiError> {
        let (target_workspace, policy_decision) = self.load_and_authorize(auth, id).await?;

        // Cascade: delete all Cedar grant policies for this workspace
        self.policies.delete_grants_for_workspace(id).await?;

        // Cascade: hard-delete OAuth client (and tokens/codes/consents) for this workspace's pk_hash
        // so the public_key_hash UNIQUE constraint is freed for re-registration.
        if let Some(ref pk_hash) = target_workspace.pk_hash {
            if let Ok(Some(oauth_client)) = self
                .store
                .get_oauth_client_by_public_key_hash(pk_hash)
                .await
            {
                self.store
                    .delete_oauth_client(&oauth_client.client_id)
                    .await
                    .ok();
            }
        }

        let deleted = self.store.delete_workspace(id).await?;
        if !deleted {
            return Err(ApiError::NotFound("workspace not found".to_string()));
        }

        let event = AuditEvent::builder(AuditEventType::WorkspaceDeleted)
            .action("delete")
            .user_actor(&auth.user)
            .resource("workspace", &id.0.to_string())
            .correlation_id(corr)
            .decision(
                AuditDecision::Permit,
                Some(&policy_decision.reasons.join(", ")),
            )
            .details(serde_json::json!({ "deleted_workspace": target_workspace.name }))
            .build();
        write_audit(&*self.store, &event).await;

        self.ui_event_bus
            .emit(UiEvent::WorkspaceDeleted { workspace_id: id.0 });

        Ok(())
    }

    // ------------------------------------------------------------------
    // Tags
    // ------------------------------------------------------------------

    /// Cedar `manage_tags` on the workspace with the tag in context.
    async fn authorize_tag_change(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        workspace: &Workspace,
        tag: &str,
    ) -> Result<(), ApiError> {
        self.authz
            .request(
                PolicyCaller::Principal {
                    principal: PolicyPrincipal::User(&auth.user),
                    oauth_claims: None,
                },
                corr,
            )
            .with_claim(claim_keys::TAG_VALUE, serde_json::json!(tag))
            .check(
                actions::MANAGE_TAGS,
                &PolicyResource::WorkspaceResource {
                    workspace: workspace.clone(),
                },
            )
            .await
    }

    async fn audit_tag_change(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        action: &str,
        workspace: &Workspace,
        tag: &str,
    ) {
        let event = AuditEvent::builder(AuditEventType::WorkspaceUpdated)
            .action(action)
            .user_actor(&auth.user)
            .resource("workspace", &workspace.id.0.to_string())
            .correlation_id(corr)
            .decision(AuditDecision::Permit, None)
            .details(serde_json::json!({
                "tag": tag,
                "workspace_name": workspace.name,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        self.ui_event_bus.emit(UiEvent::WorkspaceUpdated {
            workspace_id: workspace.id.0,
        });
    }

    /// Add a tag (already validated by the caller) to a workspace.
    pub async fn add_tag(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        id: &WorkspaceId,
        tag: &str,
    ) -> Result<Workspace, ApiError> {
        let workspace = self.load(id).await?;
        self.authorize_tag_change(auth, corr, &workspace, tag)
            .await?;

        let now = chrono::Utc::now();

        // Add tag if not already present
        let mut updated_workspace = workspace.clone();
        if !updated_workspace.tags.iter().any(|t| t == tag) {
            updated_workspace.tags.push(tag.to_string());
        }
        updated_workspace.updated_at = now;
        self.store.update_workspace(&updated_workspace).await?;

        self.audit_tag_change(auth, corr, "add_tag", &updated_workspace, tag)
            .await;

        Ok(updated_workspace)
    }

    /// Remove a tag from a workspace.
    pub async fn remove_tag(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        id: &WorkspaceId,
        tag: &str,
    ) -> Result<Workspace, ApiError> {
        let workspace = self.load(id).await?;
        self.authorize_tag_change(auth, corr, &workspace, tag)
            .await?;

        let now = chrono::Utc::now();

        // Remove tag
        let mut updated_workspace = workspace.clone();
        updated_workspace.tags.retain(|t| t != tag);
        updated_workspace.updated_at = now;
        self.store.update_workspace(&updated_workspace).await?;

        self.audit_tag_change(auth, corr, "remove_tag", &updated_workspace, tag)
            .await;

        Ok(updated_workspace)
    }

    // ------------------------------------------------------------------
    // Revocation
    // ------------------------------------------------------------------

    /// Move a workspace to `Revoked` and cut off everything that authenticates
    /// as it: the OAuth clients bound to it, and every access and refresh token
    /// issued to those clients.
    ///
    /// Every lifecycle path that revokes goes through here so the token
    /// consequences of revocation cannot be forgotten.
    pub async fn revoke_workspace_and_tokens(
        &self,
        workspace: &Workspace,
        actor: &User,
        corr: &str,
    ) -> Result<(), ApiError> {
        // The type decides whether the transition is allowed; the store applies
        // it together with the client and token revocations in one transaction.
        let mut revoked = workspace.clone();
        revoked
            .revoke()
            .map_err(|e| ApiError::Conflict(e.to_string()))?;
        self.store.revoke_workspace(&workspace.id).await?;

        let event = AuditEvent::builder(AuditEventType::WorkspaceRevoked)
            .action("workspace_revoke")
            .user_actor(actor)
            .resource("workspace", &workspace.id.0.to_string())
            .correlation_id(corr)
            .decision(AuditDecision::Permit, Some("bypass:admin"))
            .details(serde_json::json!({ "pk_hash": workspace.pk_hash }))
            .build();
        write_audit(&*self.store, &event).await;

        self.ui_event_bus.emit(UiEvent::WorkspaceUpdated {
            workspace_id: workspace.id.0,
        });

        Ok(())
    }

    /// Revoke a workspace. Revocation is final: the workspace's tokens stop
    /// working at once and the enable toggle cannot bring it back.
    /// Authorized against the workspace and its owner.
    pub async fn revoke(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        id: &WorkspaceId,
    ) -> Result<(), ApiError> {
        let (workspace, _) = self.load_and_authorize(auth, id).await?;
        self.revoke_workspace_and_tokens(&workspace, &auth.user, corr)
            .await
    }

    // ------------------------------------------------------------------
    // Binding a key hash to a user's workspace
    // ------------------------------------------------------------------

    /// Reuse an existing workspace on re-registration or create a new one.
    ///
    /// Identity is the `pk_hash`, not the display name (#39):
    /// - Same `pk_hash` (regardless of name match) -- reuse the existing row
    /// - No matching `pk_hash` -- create a new workspace, even if another
    ///   identity already owns a workspace with the same name
    pub async fn create_or_reuse_workspace(
        &self,
        auth: &AuthenticatedUser,
        workspace_name: &str,
        pk_hash: &str,
    ) -> Result<Workspace, ApiError> {
        // #39: identity is the `pk_hash` (DB-unique), not the display name.
        // Same-key re-registration reuses the existing row and accepts a
        // possibly-different display name as a rename. Names are free to
        // collide across identities; the lookup by pk_hash is what
        // disambiguates.
        if let Some(existing) = self.store.get_workspace_by_pk_hash(pk_hash).await? {
            // Re-registration never changes lifecycle state. A revoked or
            // disabled workspace stays that way; the operator who revoked it
            // decided so, and a fresh key is the way to start over.
            refuse_reregistration_unless_allowed(&existing, auth)?;
            let mut updated = existing;
            updated.name = workspace_name.to_string();
            updated.pk_hash = Some(pk_hash.to_string());
            updated.updated_at = Utc::now();
            self.store.update_workspace(&updated).await?;
            tracing::info!(
                workspace_id = %updated.id.0,
                workspace_name = %workspace_name,
                "reused existing workspace on re-registration"
            );
            return Ok(updated);
        }

        // No workspace yet for this identity — create a fresh one. The name may
        // collide with another tenant's workspace; that's allowed.
        let now = Utc::now();
        let workspace = Workspace {
            id: WorkspaceId(Uuid::new_v4()),
            name: workspace_name.to_string(),
            status: WorkspaceStatus::Active,
            pk_hash: Some(pk_hash.to_string()),
            encryption_public_key: None,
            tags: vec![],
            owner_id: Some(UserId(auth.user.id.0)),
            parent_id: None,
            tool_name: None,
            created_at: now,
            updated_at: now,
        };
        self.store.create_workspace(&workspace).await?;
        Ok(workspace)
    }

    /// Bind a signing key hash to `auth`'s workspace: create or reuse the
    /// workspace row, then leave an OAuth client for the key that is bound
    /// to that workspace by id. Both the device-flow approval and the
    /// consent-form registration end here.
    ///
    /// The caller has already authorized `manage_workspaces` and validated
    /// the name and hash.
    pub async fn bind_key_hash(
        &self,
        auth: &AuthenticatedUser,
        workspace_name: &str,
        pk_hash: &str,
        binding: ClientBinding<'_>,
    ) -> Result<(Workspace, OAuthClient), ApiError> {
        match binding {
            ClientBinding::ReuseOrCreate { scopes } => {
                let workspace = self
                    .create_or_reuse_workspace(auth, workspace_name, pk_hash)
                    .await?;

                // Ensure an OAuth client exists for this key, bound to the workspace by
                // id. The access token issued after this approval inherits that binding.
                // Re-registrations of the same pk_hash reuse the existing client; one
                // registered ahead of the workspace is bound here.
                let existing_client = self
                    .store
                    .get_oauth_client_by_public_key_hash(pk_hash)
                    .await?;
                let client = if let Some(mut client) = existing_client {
                    if client.workspace_id.as_ref() != Some(&workspace.id) {
                        self.store
                            .bind_oauth_client_workspace(&client.client_id, &workspace.id)
                            .await?;
                        client.workspace_id = Some(workspace.id.clone());
                    }
                    client
                } else {
                    let client = OAuthClient {
                        id: Uuid::new_v4(),
                        client_id: generate_client_id(),
                        client_secret_hash: None,
                        workspace_name: workspace_name.to_string(),
                        public_key_hash: pk_hash.to_string(),
                        workspace_id: Some(workspace.id.clone()),
                        redirect_uris: vec![],
                        allowed_scopes: scopes.to_vec(),
                        created_by_user: UserId(auth.user.id.0),
                        created_at: chrono::Utc::now(),
                        revoked_at: None,
                    };
                    self.store.create_oauth_client(&client).await?;
                    client
                };
                Ok((workspace, client))
            }
            ClientBinding::Replace {
                redirect_uri,
                scopes,
                corr,
            } => {
                // Reuse existing workspace if it has the same pk_hash (re-registration),
                // or create a new one. This prevents duplicate workspaces on `agentcordon register`
                // after a client-side state reset. The client is bound to it by id.
                let workspace = self
                    .create_or_reuse_workspace(auth, workspace_name, pk_hash)
                    .await?;

                let client_id = generate_client_id();
                let now = Utc::now();

                let client = OAuthClient {
                    id: Uuid::new_v4(),
                    client_id: client_id.clone(),
                    client_secret_hash: None,
                    workspace_name: workspace_name.to_string(),
                    public_key_hash: pk_hash.to_string(),
                    workspace_id: Some(workspace.id.clone()),
                    redirect_uris: vec![redirect_uri.to_string()],
                    allowed_scopes: scopes,
                    created_by_user: UserId(auth.user.id.0),
                    created_at: now,
                    revoked_at: None,
                };

                // The schema enforces UNIQUE on public_key_hash, so a
                // re-registration (the CLI cleared its local state but the
                // server still has the old client) replaces the previous
                // client, with its tokens, in the same transaction that
                // inserts the new one.
                if let Some(replaced) = self.store.replace_oauth_client(&client).await? {
                    tracing::info!(
                        client_id = %replaced,
                        pk_hash = %pk_hash,
                        "deleted existing OAuth client for re-registration"
                    );
                }

                // Audit: client created via consent
                let event = AuditEvent::builder(AuditEventType::Oauth2TokenAcquired)
                    .action("oauth_client_created_via_consent")
                    .user_actor(&auth.user)
                    .resource("oauth_client", &client.id.to_string())
                    .correlation_id(corr)
                    .decision(AuditDecision::Permit, Some("client created during consent"))
                    .details(serde_json::json!({
                        "client_id": client_id,
                        "workspace_name": workspace_name,
                    }))
                    .build();
                write_audit(&*self.store, &event).await;

                tracing::info!(
                    client_id = %client_id,
                    workspace_name = %workspace_name,
                    "OAuth client created via consent flow"
                );

                Ok((workspace, client))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use agent_cordon_core::crypto::password::hash_password;
    use agent_cordon_core::domain::user::{User, UserId, UserRole};
    use agent_cordon_core::storage::Store;
    use uuid::Uuid;

    use crate::extractors::AuthenticatedUser;
    use crate::test_helpers::TestAppBuilder;

    async fn make_admin_auth(store: &dyn Store, username: &str) -> AuthenticatedUser {
        let password_hash = hash_password("test-pass-123!").expect("hash");
        let now = chrono::Utc::now();
        let user = User {
            id: UserId(Uuid::new_v4()),
            username: username.to_string(),
            display_name: Some(username.to_string()),
            password_hash,
            role: UserRole::Admin,
            is_root: false,
            enabled: true,
            created_at: now,
            updated_at: now,
        };
        store.create_user(&user).await.expect("create user");
        AuthenticatedUser {
            user,
            is_root: false,
        }
    }

    /// Issue #39: two distinct identities registering a workspace with the
    /// same name should both succeed — workspace names are not unique.
    #[tokio::test]
    async fn create_or_reuse_workspace_allows_duplicate_names_under_different_keys() {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let svc = &ctx.state.services.workspaces;
        let auth_a = make_admin_auth(&*ctx.store, "alice").await;
        let auth_b = make_admin_auth(&*ctx.store, "bob").await;

        svc.create_or_reuse_workspace(&auth_a, "dev", "pk_hash_alice")
            .await
            .expect("first registration succeeds");

        svc.create_or_reuse_workspace(&auth_b, "dev", "pk_hash_bob")
            .await
            .expect("second registration with same name but different key must also succeed");

        let workspaces = ctx.store.list_workspaces().await.expect("list");
        let named_dev: Vec<_> = workspaces.iter().filter(|w| w.name == "dev").collect();
        assert_eq!(
            named_dev.len(),
            2,
            "two distinct workspaces named 'dev' should coexist; got {}",
            named_dev.len()
        );
    }

    /// Idempotent re-registration must survive even when *another tenant*
    /// is squatting on the same display name. Reproduces the bug where the
    /// implementation looked up by name (not by pk_hash), so Alice's second
    /// `register --name dev` after Bob also registered `dev` ended up
    /// creating a duplicate Alice row.
    #[tokio::test]
    async fn create_or_reuse_workspace_is_idempotent_even_when_name_collides_with_other_tenant() {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let svc = &ctx.state.services.workspaces;
        let auth_alice = make_admin_auth(&*ctx.store, "alice").await;
        let auth_bob = make_admin_auth(&*ctx.store, "bob").await;

        svc.create_or_reuse_workspace(&auth_alice, "dev", "pk_hash_alice")
            .await
            .expect("alice initial register");
        svc.create_or_reuse_workspace(&auth_bob, "dev", "pk_hash_bob")
            .await
            .expect("bob register with same name, different key");

        // Alice re-registers. Identity is the key, not the name.
        svc.create_or_reuse_workspace(&auth_alice, "dev", "pk_hash_alice")
            .await
            .expect("alice re-register should reuse her existing workspace");

        let workspaces = ctx.store.list_workspaces().await.expect("list");
        let alice_dev: Vec<_> = workspaces
            .iter()
            .filter(|w| w.name == "dev" && w.pk_hash.as_deref() == Some("pk_hash_alice"))
            .collect();
        assert_eq!(
            alice_dev.len(),
            1,
            "alice must end up with exactly one 'dev' workspace; got {}",
            alice_dev.len()
        );
        let total_dev = workspaces.iter().filter(|w| w.name == "dev").count();
        assert_eq!(total_dev, 2, "alice's + bob's = 2 'dev' workspaces total");
    }

    /// Re-registration with a different name should rename the workspace —
    /// otherwise `register --name new-label` is a no-op after the first run.
    #[tokio::test]
    async fn create_or_reuse_workspace_renames_on_same_key_with_different_name() {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let svc = &ctx.state.services.workspaces;
        let auth = make_admin_auth(&*ctx.store, "alice").await;

        svc.create_or_reuse_workspace(&auth, "old-name", "pk_hash_alice")
            .await
            .expect("first register");
        svc.create_or_reuse_workspace(&auth, "new-name", "pk_hash_alice")
            .await
            .expect("rename via re-register");

        let workspaces = ctx.store.list_workspaces().await.expect("list");
        let alice_owned: Vec<_> = workspaces
            .iter()
            .filter(|w| w.pk_hash.as_deref() == Some("pk_hash_alice"))
            .collect();
        assert_eq!(alice_owned.len(), 1, "still one workspace for alice");
        assert_eq!(
            alice_owned[0].name, "new-name",
            "renamed to the value supplied at re-registration"
        );
    }

    /// Same-key re-registration must stay idempotent: a single row, possibly
    /// re-enabled, with the same identity.
    #[tokio::test]
    async fn create_or_reuse_workspace_is_idempotent_for_same_key() {
        let ctx = TestAppBuilder::new().with_admin().build().await;
        let svc = &ctx.state.services.workspaces;
        let auth = make_admin_auth(&*ctx.store, "alice").await;

        svc.create_or_reuse_workspace(&auth, "dev", "pk_hash_alice")
            .await
            .expect("first registration");
        svc.create_or_reuse_workspace(&auth, "dev", "pk_hash_alice")
            .await
            .expect("second registration with same key reuses the existing workspace");

        let workspaces = ctx.store.list_workspaces().await.expect("list");
        let named_dev: Vec<_> = workspaces.iter().filter(|w| w.name == "dev").collect();
        assert_eq!(
            named_dev.len(),
            1,
            "same-key re-registration must not create a duplicate row"
        );
    }
}
