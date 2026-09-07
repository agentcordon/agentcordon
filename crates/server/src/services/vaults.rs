//! Vault service: the vault row's whole life — create, list, rename,
//! delete — and its share list.
//!
//! A vault is a row with an owner, so every question this service answers is
//! a question about that owner. The owner (or root) renames, deletes,
//! shares and unshares; `manage_vaults`, which the default policy grants to
//! admins, is an audit power on top: it reads any vault's share list and
//! revokes any share, but it never hands out a share, because that would let
//! an admin pass another user's secrets on.
//!
//! One vault is not owned by anyone: the system default, which every user
//! may put a credential in and no one may rename, share or delete.

use std::sync::Arc;

use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::domain::user::{User, UserId};
use agent_cordon_core::domain::vault::{Vault, VaultShare, DEFAULT_VAULT_ID};
use agent_cordon_core::policy::{actions, PolicyResource};

use crate::authz::Authz;
use crate::events::{UiEvent, UiEventBus};
use crate::extractors::AuthenticatedActor;
use crate::response::ApiError;
use crate::state::SharedStore;

use super::write_audit;

/// Cedar has no `Vault` resource type — `manage_vaults` is a System-wide
/// grant — so the vault a decision was about would otherwise be lost. Every
/// vault decision carries the concrete vault in the claim bag under this key,
/// which is what puts its id on the `policy_evaluated` audit row.
const VAULT_ID_CLAIM: &str = "vault_id";

/// The longest a vault's display name may be.
const MAX_VAULT_NAME_LEN: usize = 100;

/// The only share level the authorization model supports today. `write` and
/// `admin` are refused rather than stored as a promise nothing keeps.
const READ: &str = "read";

/// A vault as the API reports it: the row, plus why the caller can see it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VaultView {
    pub id: String,
    pub name: String,
    pub owner_user_id: Option<UserId>,
    /// `true` for the one vault nobody owns and everybody may use.
    pub is_default: bool,
    /// The username of whoever shared this vault with the caller, when the
    /// caller sees it through a share rather than by owning it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_by: Option<String>,
    /// The share's permission level, when this vault is shared with the
    /// caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<Vault> for VaultView {
    fn from(v: Vault) -> Self {
        VaultView {
            is_default: v.is_default(),
            id: v.id,
            name: v.name,
            owner_user_id: v.owner_user_id,
            shared_by: None,
            permission: None,
            created_at: v.created_at,
            updated_at: v.updated_at,
        }
    }
}

#[derive(Clone)]
pub struct VaultService {
    store: SharedStore,
    authz: Arc<Authz>,
    ui_event_bus: UiEventBus,
}

impl VaultService {
    pub fn new(store: SharedStore, authz: Arc<Authz>, ui_event_bus: UiEventBus) -> Self {
        Self {
            store,
            authz,
            ui_event_bus,
        }
    }

    /// Ask the policy engine whether this caller is trusted with vaults at
    /// large: `manage_vaults` is granted to admins by the default policy, and
    /// root bypasses Cedar. The vault rides along as a context claim so the
    /// audit row records which vault the decision was about.
    ///
    /// A deny is a value, not an error, because the callers disagree about
    /// what follows one: reading a share list and revoking one fall back to
    /// the ownership rule, and granting one never consults this at all.
    async fn manage_vaults_permitted(
        &self,
        actor: &AuthenticatedActor,
        corr: &str,
        vault_id: &str,
    ) -> Result<bool, ApiError> {
        let decision = self
            .authz
            .request(
                crate::authz::PolicyCaller::Principal {
                    principal: actor.policy_principal(),
                    oauth_claims: None,
                },
                corr,
            )
            .claim(VAULT_ID_CLAIM, vault_id)
            .check_with_reasons(actions::MANAGE_VAULTS, &PolicyResource::System)
            .await?;
        Ok(matches!(decision.decision, PolicyDecisionResult::Permit))
    }

    /// The vault with this id, or 404.
    pub async fn load(&self, id: &str) -> Result<Vault, ApiError> {
        self.store
            .get_vault(id)
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("vault '{id}' not found")))
    }

    /// The caller must be a user: a workspace owns no vaults.
    fn require_user(actor: &AuthenticatedActor, denial: &str) -> Result<User, ApiError> {
        match actor {
            AuthenticatedActor::User(user) => Ok(user.clone()),
            AuthenticatedActor::Workspace { .. } => Err(ApiError::Forbidden(denial.to_string())),
        }
    }

    /// Renaming, deleting, sharing and unsharing belong to the vault's owner,
    /// or to root. Holding `manage_vaults` in general is not enough: that
    /// would let any admin hand out another user's credentials.
    fn require_owner(user: &User, vault: &Vault) -> Result<(), ApiError> {
        if user.is_root || vault.is_owned_by(&user.id) {
            Ok(())
        } else {
            Err(ApiError::Forbidden(
                "only the vault's owner can do this".to_string(),
            ))
        }
    }

    /// The system default vault is shared infrastructure, not a user's
    /// possession: it has no owner to rename, share or delete it.
    fn refuse_default(vault: &Vault, what: &str) -> Result<(), ApiError> {
        if vault.is_default() {
            return Err(ApiError::Forbidden(format!(
                "the default vault cannot be {what}"
            )));
        }
        Ok(())
    }

    /// A display name that is neither empty nor unreasonably long. Uniqueness
    /// is a separate question, and an owner-scoped one:
    /// [`check_name_free`](Self::check_name_free).
    fn validate_name(name: &str) -> Result<String, ApiError> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(ApiError::BadRequest("vault name is required".to_string()));
        }
        if trimmed.chars().count() > MAX_VAULT_NAME_LEN {
            return Err(ApiError::BadRequest(format!(
                "vault name must be at most {MAX_VAULT_NAME_LEN} characters"
            )));
        }
        Ok(trimmed.to_string())
    }

    /// Refuse a vault name this owner already uses.
    ///
    /// A vault name is the only thing the credential form's picker shows, so
    /// two of a user's vaults called `operator-vault` make the picker a
    /// guess. Names stay free across owners: two users may each have a
    /// `production`, and neither learns of the other's.
    ///
    /// Service-level only — existing installs already hold duplicates, so a
    /// unique index would refuse to build.
    async fn check_name_free(
        &self,
        owner: &UserId,
        name: &str,
        except: Option<&str>,
    ) -> Result<(), ApiError> {
        let owned = self.store.list_vaults_owned_by(owner).await?;
        let clash = owned
            .iter()
            .any(|v| v.name == name && except.is_none_or(|id| v.id != id));
        if clash {
            return Err(ApiError::Conflict(format!(
                "you already have a vault named '{name}'; pick another name or rename the \
                 existing one"
            )));
        }
        Ok(())
    }

    /// Where a credential may be placed: the caller's own vault, the system
    /// default, or — for root — any vault at all. `None` means the caller
    /// named no vault, which is the default.
    ///
    /// Joining another user's vault is what this refuses. Without it, a user
    /// could put a credential in a vault someone else shares onward, or read
    /// their way into one by moving a credential into it.
    pub async fn resolve_placement(
        &self,
        actor: &AuthenticatedActor,
        vault_id: Option<&str>,
    ) -> Result<Vault, ApiError> {
        let Some(vault_id) = vault_id.map(str::trim).filter(|v| !v.is_empty()) else {
            return self.load(DEFAULT_VAULT_ID).await;
        };
        let vault = self.load(vault_id).await?;
        if vault.is_default() {
            return Ok(vault);
        }
        let permitted = match actor {
            AuthenticatedActor::User(user) => user.is_root || vault.is_owned_by(&user.id),
            // A workspace has no vaults of its own; it writes to the default.
            AuthenticatedActor::Workspace { .. } => false,
        };
        if permitted {
            Ok(vault)
        } else {
            Err(ApiError::Forbidden(format!(
                "vault '{}' belongs to another user",
                vault.name
            )))
        }
    }

    // ------------------------------------------------------------------
    // Vault lifecycle
    // ------------------------------------------------------------------

    /// Create a vault owned by the caller. Anyone the policy engine lets
    /// create credentials may create somewhere to put them.
    pub async fn create(
        &self,
        actor: &AuthenticatedActor,
        corr: &str,
        name: &str,
    ) -> Result<Vault, ApiError> {
        let user = Self::require_user(actor, "workspaces cannot create vaults")?;
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

        let name = Self::validate_name(name)?;
        self.check_name_free(&user.id, &name, None).await?;
        let now = chrono::Utc::now();
        let vault = Vault {
            id: Uuid::new_v4().to_string(),
            name,
            owner_user_id: Some(user.id.clone()),
            created_at: now,
            updated_at: now,
        };
        self.store.create_vault(&vault).await?;

        self.audit(
            actor,
            corr,
            AuditEventType::VaultCreated,
            "create",
            &vault,
            None,
        )
        .await;
        self.ui_event_bus.emit(UiEvent::VaultChanged {
            vault_id: vault.id.clone(),
        });
        Ok(vault)
    }

    /// The vaults this caller can see: the ones they own, the ones shared
    /// with them, and — for a `manage_vaults` holder — every vault on the
    /// install. The system default is always in the list; everyone uses it.
    pub async fn list(
        &self,
        actor: &AuthenticatedActor,
        corr: &str,
    ) -> Result<Vec<VaultView>, ApiError> {
        self.authz
            .request(
                crate::authz::PolicyCaller::Principal {
                    principal: actor.policy_principal(),
                    oauth_claims: None,
                },
                corr,
            )
            .check(actions::LIST, &PolicyResource::System)
            .await?;

        let AuthenticatedActor::User(user) = actor else {
            // A workspace owns no vaults and is party to no shares.
            return Ok(Vec::new());
        };

        // The claim names the vault a decision was about; this one is about
        // all of them at once.
        if self.manage_vaults_permitted(actor, corr, "*").await? {
            let all = self.store.list_vaults().await?;
            return Ok(all.into_iter().map(VaultView::from).collect());
        }

        let mut views: Vec<VaultView> = Vec::new();
        if let Some(default) = self.store.get_vault(DEFAULT_VAULT_ID).await? {
            views.push(default.into());
        }
        for vault in self.store.list_vaults_owned_by(&user.id).await? {
            views.push(vault.into());
        }
        for share in self.store.get_vault_shares_for_user(&user.id).await? {
            let Some(vault) = self.store.get_vault(&share.vault_id).await? else {
                continue;
            };
            if views.iter().any(|v| v.id == vault.id) {
                continue;
            }
            let mut view = VaultView::from(vault);
            view.shared_by = self
                .store
                .get_user(&share.shared_by_user_id)
                .await?
                .map(|u| u.username);
            view.permission = Some(share.permission_level);
            views.push(view);
        }
        Ok(views)
    }

    /// Rename a vault. The name is a label, so this changes nothing else.
    pub async fn rename(
        &self,
        actor: &AuthenticatedActor,
        corr: &str,
        id: &str,
        name: &str,
    ) -> Result<Vault, ApiError> {
        let user = Self::require_user(actor, "workspaces cannot rename vaults")?;
        let vault = self.load(id).await?;
        Self::refuse_default(&vault, "renamed")?;
        Self::require_owner(&user, &vault)?;

        let name = Self::validate_name(name)?;
        // Scoped to the vault's owner, not the caller: root renaming someone
        // else's vault is held to that owner's namespace, not its own.
        let owner = vault.owner_user_id.as_ref().unwrap_or(&user.id);
        self.check_name_free(owner, &name, Some(id)).await?;
        self.store.rename_vault(id, &name).await?;
        let renamed = self.load(id).await?;

        self.audit(
            actor,
            corr,
            AuditEventType::VaultRenamed,
            "rename",
            &renamed,
            Some(serde_json::json!({ "previous_name": vault.name })),
        )
        .await;
        self.ui_event_bus.emit(UiEvent::VaultChanged {
            vault_id: renamed.id.clone(),
        });
        Ok(renamed)
    }

    /// Delete an empty vault. A vault that still holds credentials is a
    /// conflict, not a cascade: deleting it would take the credentials with
    /// it, which is never what "remove this grouping" meant.
    pub async fn delete(
        &self,
        actor: &AuthenticatedActor,
        corr: &str,
        id: &str,
    ) -> Result<(), ApiError> {
        let user = Self::require_user(actor, "workspaces cannot delete vaults")?;
        let vault = self.load(id).await?;
        Self::refuse_default(&vault, "deleted")?;
        Self::require_owner(&user, &vault)?;

        let held = self.store.count_credentials_in_vault(id).await?;
        if held > 0 {
            return Err(ApiError::Conflict(format!(
                "vault '{}' still holds {held} credential(s); move or delete them first",
                vault.name
            )));
        }

        self.store.delete_vault(id).await?;
        self.audit(
            actor,
            corr,
            AuditEventType::VaultDeleted,
            "delete",
            &vault,
            None,
        )
        .await;
        self.ui_event_bus.emit(UiEvent::VaultChanged {
            vault_id: vault.id.clone(),
        });
        Ok(())
    }

    // ------------------------------------------------------------------
    // Shares
    // ------------------------------------------------------------------

    /// Read a vault's share list.
    ///
    /// The list names every user this vault reaches, so a signed-in stranger
    /// is refused rather than handed the roster. A caller the policy engine
    /// trusts with vaults at large reads any vault's list — that is what
    /// `manage_vaults` is for, and an admin who cannot see who a vault
    /// reaches cannot audit it; everyone else must own this one.
    pub async fn list_shares(
        &self,
        actor: &AuthenticatedActor,
        corr: &str,
        id: &str,
    ) -> Result<Vec<VaultShare>, ApiError> {
        let user = Self::require_user(actor, "workspaces cannot read vault share lists")?;
        let vault = self.load(id).await?;
        if !self.manage_vaults_permitted(actor, corr, id).await? {
            Self::require_owner(&user, &vault)?;
        }
        Ok(self.store.list_vault_shares(id).await?)
    }

    /// Share a vault with another user.
    ///
    /// Granting is the owner's act and nobody else's, whatever role they
    /// hold: an admin's `manage_vaults` reads and revokes, it does not give
    /// away someone else's credentials.
    pub async fn share(
        &self,
        actor: &AuthenticatedActor,
        corr: &str,
        id: &str,
        target_user_id: &str,
        permission: Option<String>,
    ) -> Result<VaultShare, ApiError> {
        let sharer = Self::require_user(actor, "workspaces cannot share vaults")?;
        let vault = self.load(id).await?;
        Self::refuse_default(&vault, "shared")?;
        Self::require_owner(&sharer, &vault)?;

        let target_user_uuid = Uuid::parse_str(target_user_id)
            .map_err(|_| ApiError::BadRequest("invalid user_id format".to_string()))?;
        let target_user = self
            .store
            .get_user(&UserId(target_user_uuid))
            .await?
            .ok_or_else(|| ApiError::NotFound("target user not found".to_string()))?;

        let permission_level = permission.unwrap_or_else(|| READ.to_string());
        match permission_level.as_str() {
            READ => {}
            "write" | "admin" => {
                return Err(ApiError::BadRequest(format!(
                    "permission '{permission_level}' is not supported yet; a share grants '{READ}'"
                )));
            }
            _ => {
                return Err(ApiError::BadRequest(format!("permission must be '{READ}'")));
            }
        }

        let share = VaultShare {
            id: Uuid::new_v4().to_string(),
            vault_id: vault.id.clone(),
            shared_with_user_id: target_user.id.clone(),
            permission_level: permission_level.clone(),
            shared_by_user_id: sharer.id.clone(),
            created_at: chrono::Utc::now(),
        };
        self.store.share_vault(&share).await?;

        self.audit(
            actor,
            corr,
            AuditEventType::VaultShared,
            "share",
            &vault,
            Some(serde_json::json!({
                "shared_with_user_id": target_user.id.0.to_string(),
                "permission_level": permission_level,
            })),
        )
        .await;
        self.ui_event_bus.emit(UiEvent::VaultChanged {
            vault_id: vault.id.clone(),
        });

        Ok(share)
    }

    /// Revoke a user's access to a vault. 404 when there was no share.
    ///
    /// Unlike granting, this is also an admin power: `manage_vaults` exists
    /// so someone can cut off a share they did not make.
    pub async fn unshare(
        &self,
        actor: &AuthenticatedActor,
        corr: &str,
        id: &str,
        target_user_id: &str,
    ) -> Result<(), ApiError> {
        let user = Self::require_user(actor, "workspaces cannot unshare vaults")?;
        let vault = self.load(id).await?;
        Self::refuse_default(&vault, "shared")?;
        if !self.manage_vaults_permitted(actor, corr, id).await? {
            Self::require_owner(&user, &vault)?;
        }

        let target_user_uuid = Uuid::parse_str(target_user_id)
            .map_err(|_| ApiError::BadRequest("invalid user_id format".to_string()))?;

        let removed = self
            .store
            .unshare_vault(id, &UserId(target_user_uuid))
            .await?;
        if !removed {
            return Err(ApiError::NotFound("vault share not found".to_string()));
        }

        self.audit(
            actor,
            corr,
            AuditEventType::VaultUnshared,
            "unshare",
            &vault,
            Some(serde_json::json!({ "removed_user_id": target_user_id })),
        )
        .await;
        self.ui_event_bus.emit(UiEvent::VaultChanged {
            vault_id: vault.id.clone(),
        });
        Ok(())
    }

    /// One audit row per vault state change, naming the vault by id and
    /// carrying its display name in the details.
    async fn audit(
        &self,
        actor: &AuthenticatedActor,
        corr: &str,
        event_type: AuditEventType,
        action: &str,
        vault: &Vault,
        extra: Option<serde_json::Value>,
    ) {
        let (ws_id, ws_name, u_id, u_name) = actor.audit_actor_fields();
        let mut details = serde_json::json!({ "vault_name": vault.name });
        if let (Some(map), Some(serde_json::Value::Object(more))) = (details.as_object_mut(), extra)
        {
            map.extend(more);
        }
        let event = AuditEvent::builder(event_type)
            .action(action)
            .actor_fields(ws_id, ws_name, u_id, u_name)
            .resource("vault", &vault.id)
            .correlation_id(corr)
            .decision(AuditDecision::Permit, Some("bypass:self-service"))
            .details(details)
            .build();
        write_audit(&*self.store, &event).await;
    }
}
