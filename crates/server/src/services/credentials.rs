//! Credential service: create, update, rotate, restore, delete, reveal, and
//! the vend operation that hands a sealed secret to a broker.
//!
//! This is the only code in the server that opens a credential's ciphertext
//! or seals a new one. Every state change here writes its audit row and UI
//! event; the vend and reveal paths write theirs too because handing out a
//! secret is the event operators most want to see.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use agent_cordon_core::crypto::key_ring::KeyRing;
use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::credential::{
    CredentialAccess, CredentialId, CredentialUpdate, StoredCredential,
};
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::domain::user::UserId;
use agent_cordon_core::domain::vault::{Vault, DEFAULT_VAULT_ID};
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId};
use agent_cordon_core::error::CryptoError;
use agent_cordon_core::oauth2::OAuth2TokenManager;
use agent_cordon_core::policy::{
    actions, claim_keys, PolicyContext, PolicyPrincipal, PolicyResource,
};
use agent_cordon_core::proxy::url_match::{validate_url_pattern, URL_PATTERN_GRAMMAR};
use agent_cordon_core::transform::rhai_engine::{
    compile_transform_script, BUILTIN_TRANSFORM_NAMES,
};

use crate::authz::{Authz, PolicyCaller};
use crate::crypto_helpers::{
    encrypt_material_for_device, reencrypt_credential_for_device, workspace_encryption_point,
    ReencryptedEnvelope,
};
use crate::events::{UiEvent, UiEventBus};
use crate::extractors::{AuthenticatedActor, AuthenticatedUser, AuthenticatedWorkspace};
use crate::response::ApiError;
use crate::state::SharedStore;

use super::policies::PolicyService;
use super::upstream_tokens::{self, TokenActor, UpstreamTokenError};
use super::vaults::VaultService;
use super::write_audit;

/// Known credential types. Unknown types are rejected at creation time.
pub const KNOWN_CREDENTIAL_TYPES: &[&str] = &[
    "generic",
    "aws",
    "api_key_header",
    "api_key_query",
    "oauth2_client_credentials",
    "oauth2_user_authorization",
];

/// Validate a credential type string against known types.
pub fn validate_credential_type(credential_type: &str) -> Result<(), ApiError> {
    if !KNOWN_CREDENTIAL_TYPES.contains(&credential_type) {
        return Err(ApiError::BadRequest(format!(
            "unknown credential_type '{}': valid types are {}",
            credential_type,
            KNOWN_CREDENTIAL_TYPES.join(", ")
        )));
    }
    Ok(())
}

/// The metadata key an API-key credential type needs before the broker can
/// inject it: `api_key_header` names the header, `api_key_query` the query
/// parameter. Every other type needs nothing.
fn required_metadata_key(credential_type: &str) -> Option<&'static str> {
    match credential_type {
        "api_key_header" => Some("header_name"),
        "api_key_query" => Some("param_name"),
        _ => None,
    }
}

/// Refuse a credential whose type needs metadata the broker will look for at
/// injection time. Without it the broker has nothing to name the header (or
/// the parameter) with and drops the credential at the first call, which is
/// far later and far quieter than a 400 here.
pub fn validate_credential_metadata(
    credential_type: &str,
    metadata: &serde_json::Value,
) -> Result<(), ApiError> {
    let Some(key) = required_metadata_key(credential_type) else {
        return Ok(());
    };
    let present = metadata
        .get(key)
        .and_then(|v| v.as_str())
        .is_some_and(|v| !v.trim().is_empty());
    if !present {
        return Err(ApiError::BadRequest(format!(
            "credential_type '{credential_type}' requires a non-empty metadata.{key}"
        )));
    }
    Ok(())
}

/// Refuse transform settings that could never run: a name outside the
/// built-in set, or a script that does not parse. An empty value means
/// "clear" and is not validated.
pub fn validate_transform(
    transform_name: Option<&str>,
    transform_script: Option<&str>,
) -> Result<(), ApiError> {
    if let Some(name) = transform_name.filter(|n| !n.is_empty()) {
        if !BUILTIN_TRANSFORM_NAMES.contains(&name) {
            return Err(ApiError::BadRequest(format!(
                "unknown transform_name '{name}'; expected one of: {}",
                BUILTIN_TRANSFORM_NAMES.join(", ")
            )));
        }
    }
    if let Some(script) = transform_script.filter(|s| !s.is_empty()) {
        compile_transform_script(script)
            .map_err(|e| ApiError::BadRequest(format!("transform_script is invalid: {e}")))?;
    }
    Ok(())
}

/// Seal a secret value under the current master key, with the credential ID
/// as additional authenticated data. Returns `(ciphertext, nonce, key_version)`;
/// the version is what the row must store next to the ciphertext.
pub fn encrypt_secret(
    encryptor: &KeyRing,
    secret: &str,
    cred_id: &CredentialId,
) -> Result<(Vec<u8>, Vec<u8>, i64), ApiError> {
    Ok(encryptor.encrypt_versioned(secret.as_bytes(), cred_id.0.to_string().as_bytes())?)
}

/// Open a credential's sealed value with the master key its `key_version`
/// names (falling back across the ring for rows written before versions
/// meant anything).
pub fn decrypt_secret(
    encryptor: &KeyRing,
    cred: &StoredCredential,
) -> Result<Vec<u8>, CryptoError> {
    encryptor.decrypt_versioned(
        &cred.encrypted_value,
        &cred.nonce,
        cred.id.0.to_string().as_bytes(),
        cred.key_version,
    )
}

/// Parameters for building a new `StoredCredential`.
pub struct NewCredentialParams {
    pub name: String,
    pub service: String,
    pub secret_value: String,
    pub credential_type: String,
    pub scopes: Vec<String>,
    pub metadata: serde_json::Value,
    pub tags: Vec<String>,
    /// The vault the caller asked for, by id. `None` means the system
    /// default. The service resolves and authorizes it before the row is
    /// built; the request never names a vault by display name, because a
    /// name identifies nothing on its own.
    pub vault_id: Option<String>,
    pub created_by: Option<WorkspaceId>,
    pub created_by_user: Option<UserId>,
    pub allowed_url_pattern: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub transform_script: Option<String>,
    pub transform_name: Option<String>,
    pub description: Option<String>,
    pub target_identity: Option<String>,
}

/// Strip common auth scheme prefixes (`Bearer `, `token `, `Basic `) from a
/// secret value. Users frequently paste the full header value; the transform
/// layer adds the prefix back, so storing it causes double-wrapping
/// (e.g. `"Bearer Bearer ghp_..."` → 401).
///
/// Only applies to credential types where a transform adds the prefix
/// automatically (i.e. not `aws` or `oauth2_client_credentials`).
pub fn strip_auth_prefix(value: &str) -> String {
    let trimmed = value.trim();
    for prefix in &["Bearer ", "bearer ", "token ", "Token ", "Basic ", "basic "] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let rest = rest.trim();
            if !rest.is_empty() {
                return rest.to_string();
            }
        }
    }
    trimmed.to_string()
}

/// Build a `StoredCredential` from parameters.
///
/// Generates a new credential ID, encrypts the secret value using the ID as
/// AAD, and returns the fully constructed `StoredCredential` ready for storage.
///
/// For non-AWS/non-OAuth2 credential types, automatically strips common auth
/// prefixes from the secret value to prevent double-wrapping.
pub fn build_credential(
    encryptor: &KeyRing,
    params: NewCredentialParams,
    vault: &Vault,
) -> Result<StoredCredential, ApiError> {
    let cred_id = CredentialId(Uuid::new_v4());

    // Strip auth prefixes for types where the transform adds them back. The
    // API-key types send the value verbatim, so stripping would corrupt a key
    // that happens to start with one of those words.
    let secret_value = match params.credential_type.as_str() {
        "aws" | "oauth2_client_credentials" | "api_key_header" | "api_key_query" => {
            params.secret_value.clone()
        }
        _ => strip_auth_prefix(&params.secret_value),
    };

    let (encrypted_value, nonce, key_version) = encrypt_secret(encryptor, &secret_value, &cred_id)?;
    let now = Utc::now();

    Ok(StoredCredential {
        id: cred_id,
        name: params.name,
        service: params.service,
        encrypted_value,
        nonce,
        scopes: params.scopes,
        metadata: params.metadata,
        created_by: params.created_by,
        created_by_user: params.created_by_user,
        created_at: now,
        updated_at: now,
        allowed_url_pattern: params.allowed_url_pattern,
        expires_at: params.expires_at,
        transform_script: params.transform_script,
        transform_name: params.transform_name,
        vault_id: vault.id.clone(),
        vault_name: vault.name.clone(),
        credential_type: params.credential_type,
        tags: params.tags,
        description: params.description,
        target_identity: params.target_identity,
        key_version,
    })
}

/// Helper: get the actor identity strings for history tracking.
pub fn actor_identity_strings(actor: &AuthenticatedActor) -> (Option<String>, Option<String>) {
    match actor {
        AuthenticatedActor::User(user) => (Some(user.id.0.to_string()), None),
        AuthenticatedActor::Workspace { workspace, .. } => (None, Some(workspace.id.0.to_string())),
    }
}

/// Where a vended credential is about to be sent.
#[derive(Debug, Clone)]
pub struct VendTarget {
    pub method: String,
    pub url: String,
}

/// The credential's `allowed_url_pattern`, trimmed, or `None` when it is
/// absent or blank.
fn normalized_url_pattern(cred: &StoredCredential) -> Option<&str> {
    cred.allowed_url_pattern
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
}

/// Decide whether a vend may proceed for this target. A credential with an
/// allowed URL pattern is vended only for a target inside the pattern, and
/// never without a target: the broker must say where it is going.
///
/// The `Err` is the refusal reason, which the caller turns into both the
/// 403 body and the `CredentialVendDenied` audit row. It is its own error —
/// not [`ApiError::Forbidden`] — because a reader told "access denied by
/// policy" goes looking at Cedar and `/policies`, and this refusal has
/// nothing to do with either: it is the pattern on the credential.
fn check_vend_target(
    cred: &StoredCredential,
    target: Option<&VendTarget>,
) -> Result<(), UrlPatternDenial> {
    let Some(pattern) = normalized_url_pattern(cred) else {
        return Ok(());
    };
    let Some(target) = target else {
        return Err(UrlPatternDenial(format!(
            "credential '{}' is fenced to the URL pattern {pattern}; \
             a vend must name its method and target_url",
            cred.name
        )));
    };
    if !agent_cordon_core::proxy::url_match::url_matches_pattern(&target.url, pattern) {
        return Err(UrlPatternDenial(format!(
            "credential '{}' is fenced to the URL pattern {pattern}, \
             which does not cover {}. This is the credential's \
             allowed_url_pattern, not a policy decision: widen the pattern on \
             the credential, or use a credential that covers this target.",
            cred.name, target.url
        )));
    }
    Ok(())
}

/// A vend refused by the credential's `allowed_url_pattern`. Carries the
/// reason, which becomes both the audit row's decision note and the 403 body.
struct UrlPatternDenial(String);

impl From<UrlPatternDenial> for ApiError {
    fn from(denial: UrlPatternDenial) -> Self {
        ApiError::UrlPatternDenied(denial.0)
    }
}

/// Why a credential could not be sealed for a broker. The upstream case is
/// separated so a sync can report it per credential and carry on.
#[derive(Debug)]
pub enum SealError {
    /// The upstream token exchange for an OAuth-backed credential failed.
    Upstream(UpstreamTokenError),
    /// Anything else: decrypt, serialize, or ECIES failure.
    Api(ApiError),
}

impl From<SealError> for ApiError {
    fn from(e: SealError) -> Self {
        match e {
            SealError::Upstream(e) => e.into(),
            SealError::Api(e) => e,
        }
    }
}

/// What a broker receives from a vend: the sealed envelope plus the
/// metadata it needs to inject the secret.
pub struct VendOutcome {
    pub credential_type: String,
    pub transform_name: Option<String>,
    /// The pattern the target was checked against, so the broker can check
    /// again right before it injects.
    pub allowed_url_pattern: Option<String>,
    pub envelope: ReencryptedEnvelope,
    pub vend_id: String,
}

#[derive(Clone)]
pub struct CredentialService {
    pub(crate) store: SharedStore,
    pub(crate) key_ring: Arc<KeyRing>,
    authz: Arc<Authz>,
    ui_event_bus: UiEventBus,
    pub(crate) oauth2_token_manager: OAuth2TokenManager,
    policies: PolicyService,
    /// Where a credential may live, and who owns that vault.
    vaults: VaultService,
}

impl CredentialService {
    pub fn new(
        store: SharedStore,
        key_ring: Arc<KeyRing>,
        authz: Arc<Authz>,
        ui_event_bus: UiEventBus,
        oauth2_token_manager: OAuth2TokenManager,
        policies: PolicyService,
        vaults: VaultService,
    ) -> Self {
        Self {
            store,
            key_ring,
            authz,
            ui_event_bus,
            oauth2_token_manager,
            policies,
            vaults,
        }
    }

    /// The credential, or 404.
    pub async fn load(&self, id: &CredentialId) -> Result<StoredCredential, ApiError> {
        self.store
            .get_credential(id)
            .await?
            .ok_or_else(|| ApiError::NotFound("credential not found".to_string()))
    }

    /// The vaults shared *with* this caller, by id.
    ///
    /// A share is not a Cedar grant: it is the vault owner's own decision
    /// about their own credentials, and Cedar has no `Vault` resource to
    /// express it. So the read side of a share is answered here, next to the
    /// policy check rather than inside it. A workspace is never a share
    /// recipient — a share is between people.
    pub async fn shared_vault_ids(
        &self,
        actor: &AuthenticatedActor,
    ) -> Result<Vec<String>, ApiError> {
        let AuthenticatedActor::User(user) = actor else {
            return Ok(Vec::new());
        };
        self.shared_vault_ids_for_user(&user.id).await
    }

    /// The same answer for a caller already known to be a user.
    ///
    /// The dashboard's counts are taken for a `User`, never for a workspace,
    /// and they have to agree with the list the same user is shown — a tile
    /// reading `0` beside a list holding a row is the dashboard telling a
    /// share recipient they have nothing
    /// (uat/artifacts/fresh-user-native-2.md F9).
    pub async fn shared_vault_ids_for_user(
        &self,
        user_id: &agent_cordon_core::domain::user::UserId,
    ) -> Result<Vec<String>, ApiError> {
        Ok(self
            .store
            .get_vault_shares_for_user(user_id)
            .await?
            .into_iter()
            .map(|s| s.vault_id)
            .collect())
    }

    /// May this caller see this credential, and by which route? Cedar
    /// decides; a read share on the credential's vault overrides a plain
    /// deny, and the answer says which of the two allowed it.
    ///
    /// Seeing is all a share grants: revealing the secret, vending it,
    /// granting it to a workspace and re-sharing the vault all run their own
    /// checks and never consult this. That is why the route matters to the
    /// caller — a page that knows it is looking at a shared-read credential
    /// can decline to offer the four controls the server would refuse.
    pub async fn authorize_read(
        &self,
        actor: &AuthenticatedActor,
        corr: &str,
        cred: &StoredCredential,
    ) -> Result<CredentialAccess, ApiError> {
        let denial = match self
            .authz
            .request(actor, corr)
            .check(
                actions::LIST,
                &PolicyResource::Credential {
                    credential: cred.clone(),
                },
            )
            .await
        {
            Ok(()) => return Ok(CredentialAccess::Full),
            Err(ApiError::Forbidden(message)) => ApiError::Forbidden(message),
            Err(other) => return Err(other),
        };
        if self.shared_vault_ids(actor).await?.contains(&cred.vault_id) {
            return Ok(CredentialAccess::SharedRead);
        }
        Err(denial)
    }

    /// Refuse an `allowed_url_pattern` the matcher could never satisfy.
    ///
    /// The pattern is checked structurally on vend; checking it again here
    /// means a typo is a 400 on the form rather than a credential that
    /// silently refuses every request it is ever asked to sign.
    fn check_url_pattern(pattern: Option<&str>) -> Result<(), ApiError> {
        let Some(pattern) = pattern else {
            return Ok(());
        };
        validate_url_pattern(pattern).map_err(|why| {
            ApiError::BadRequest(format!(
                "allowed_url_pattern '{pattern}' {why}. Pattern grammar: {URL_PATTERN_GRAMMAR}"
            ))
        })
    }

    /// Refuse a name this owner already uses.
    ///
    /// Credential names are the CLI's addressing scheme (`agentcordon proxy
    /// <name>`), so two of an owner's credentials sharing one are a coin
    /// flip at the point of use. Names stay free across owners — a global
    /// unique index leaked one tester's credential names to another
    /// (migration 011) — so the scope is `created_by_user`, and root and
    /// admins are scoped by it too rather than exempted.
    ///
    /// The check is service-level only: existing installs already hold
    /// duplicates, so a unique index would refuse to build.
    async fn check_name_free(
        &self,
        owner: Option<&UserId>,
        name: &str,
        except: Option<&CredentialId>,
    ) -> Result<(), ApiError> {
        let Some(owner) = owner else {
            // A workspace-created credential has no owning user; its
            // collisions are caught by `create_from_workspace`.
            return Ok(());
        };
        let existing = self.store.list_credentials().await?;
        let clash = existing.iter().any(|c| {
            c.name == name
                && c.created_by_user.as_ref() == Some(owner)
                && except.is_none_or(|id| c.id.0 != id.0)
        });
        if clash {
            return Err(ApiError::Conflict(format!(
                "you already have a credential named '{name}'; pick another name or rename the \
                 existing one"
            )));
        }
        Ok(())
    }

    /// Emit a `CredentialCreated` UI event for browser auto-refresh.
    fn emit_credential_created(&self, cred_id: Uuid, cred_name: String) {
        self.ui_event_bus.emit(UiEvent::CredentialCreated {
            credential_id: cred_id,
            credential_name: cred_name,
        });
    }

    // ------------------------------------------------------------------
    // Create
    // ------------------------------------------------------------------

    /// Create a credential on behalf of a user or workspace actor
    /// (`POST /credentials`). The caller has already resolved the secret
    /// value and type-specific fields; this authorizes, validates the
    /// transform and vault, seals, stores, audits, and announces.
    pub async fn create(
        &self,
        actor: &AuthenticatedActor,
        corr: &str,
        params: NewCredentialParams,
    ) -> Result<StoredCredential, ApiError> {
        // Policy check: can this actor create credentials?
        self.authz
            .request(
                PolicyCaller::Principal {
                    principal: actor.policy_principal(),
                    oauth_claims: None,
                },
                &uuid::Uuid::new_v4().to_string(),
            )
            .check(actions::CREATE, &PolicyResource::System)
            .await?;

        validate_transform(
            params.transform_name.as_deref(),
            params.transform_script.as_deref(),
        )?;
        let vault = self
            .vaults
            .resolve_placement(actor, params.vault_id.as_deref())
            .await?;
        validate_credential_type(&params.credential_type)?;
        validate_credential_metadata(&params.credential_type, &params.metadata)?;
        Self::check_url_pattern(params.allowed_url_pattern.as_deref())?;
        self.check_name_free(params.created_by_user.as_ref(), &params.name, None)
            .await?;

        let cred = build_credential(&self.key_ring, params, &vault)?;
        self.store.store_credential(&cred).await?;

        let (ws_id, ws_name, u_id, u_name) = actor.audit_actor_fields();
        let event = AuditEvent::builder(AuditEventType::CredentialCreated)
            .action("create")
            .actor_fields(ws_id, ws_name, u_id, u_name)
            .resource("credential", &cred.id.0.to_string())
            .correlation_id(corr)
            .decision(AuditDecision::Permit, None)
            .details(serde_json::json!({
                "credential_name": cred.name,
                "service": cred.service,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        self.emit_credential_created(cred.id.0, cred.name.clone());
        Ok(cred)
    }

    /// Workspace-initiated creation (`POST /credentials/agent-store`). The
    /// caller is the authenticated workspace; `created_by` is taken from it.
    /// A name collision is a 409 with no detail about the existing row.
    pub async fn create_from_workspace(
        &self,
        auth: &AuthenticatedWorkspace,
        corr: &str,
        params: NewCredentialParams,
    ) -> Result<StoredCredential, ApiError> {
        let workspace = &auth.workspace;

        validate_credential_type(&params.credential_type)?;
        validate_credential_metadata(&params.credential_type, &params.metadata)?;

        // Cedar policy evaluation — workspace must be authorized to create
        // credentials. The Authz seam auto-emits a PolicyEvaluated audit
        // event on both permit and deny.
        self.authz
            .request(
                PolicyCaller::Principal {
                    principal: PolicyPrincipal::Workspace(workspace),
                    oauth_claims: auth.oauth_claims.clone(),
                },
                corr,
            )
            .check(actions::CREATE, &PolicyResource::System)
            .await?;

        // A workspace owns no vaults, so the only place it may write is the
        // one every principal shares.
        if params
            .vault_id
            .as_deref()
            .is_some_and(|v| v != DEFAULT_VAULT_ID)
        {
            return Err(ApiError::Forbidden(
                "a workspace can only store credentials in the default vault".to_string(),
            ));
        }
        let vault = self.vaults.load(DEFAULT_VAULT_ID).await?;
        let cred = build_credential(&self.key_ring, params, &vault)?;

        // Try to store the credential; on conflict, return 409.
        // Do NOT return metadata about the existing credential — that would leak
        // information about other workspaces' credentials on name collision.
        match self.store.store_credential(&cred).await {
            Ok(()) => {}
            Err(agent_cordon_core::error::StoreError::Conflict { .. }) => {
                return Err(ApiError::Conflict(
                    "credential with this name already exists".to_string(),
                ));
            }
            Err(e) => return Err(e.into()),
        };

        let event = AuditEvent::builder(AuditEventType::CredentialCreated)
            .action("create")
            .workspace_actor(&workspace.id, &workspace.name)
            .resource("credential", &cred.id.0.to_string())
            .correlation_id(corr)
            .decision(
                AuditDecision::Permit,
                Some("workspace-initiated credential creation"),
            )
            .details(serde_json::json!({
                "credential_name": cred.name,
                "service": cred.service,
                "source": "workspace",
                "llm_exposed": true,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        self.emit_credential_created(cred.id.0, cred.name.clone());
        Ok(cred)
    }

    /// Seal and store a credential created as a side effect of another
    /// operation (MCP provisioning). The caller has authorized and audits
    /// the operation that produced it; only the UI event is emitted here.
    pub async fn store_unaudited(
        &self,
        params: NewCredentialParams,
    ) -> Result<StoredCredential, ApiError> {
        let vault = self
            .vaults
            .load(params.vault_id.as_deref().unwrap_or(DEFAULT_VAULT_ID))
            .await?;
        let cred = build_credential(&self.key_ring, params, &vault)?;
        self.store.store_credential(&cred).await?;
        self.emit_credential_created(cred.id.0, cred.name.clone());
        Ok(cred)
    }

    // ------------------------------------------------------------------
    // Update / rotate / restore / delete
    // ------------------------------------------------------------------

    /// Update metadata and, when `new_secret` is given, rotate the secret
    /// (archiving the previous ciphertext). `changes` carries no ciphertext
    /// fields; they are filled in here.
    pub async fn update(
        &self,
        actor: &AuthenticatedActor,
        corr: &str,
        cred_id: &CredentialId,
        mut changes: CredentialUpdate,
        new_secret: Option<&str>,
    ) -> Result<StoredCredential, ApiError> {
        let cred = self.load(cred_id).await?;

        // Policy check: can this actor update this credential?
        self.authz
            .request(actor, corr)
            .check(
                actions::UPDATE,
                &PolicyResource::Credential {
                    credential: cred.clone(),
                },
            )
            .await?;

        validate_transform(
            changes.transform_name.as_deref(),
            changes.transform_script.as_deref(),
        )?;
        if let Some(vault_id) = changes.vault_id.as_deref().filter(|v| *v != cred.vault_id) {
            self.vaults.resolve_placement(actor, Some(vault_id)).await?;
        }

        // An empty pattern is how the form clears the restriction; the store
        // maps it to NULL, so it is not put to the validator.
        Self::check_url_pattern(
            changes
                .allowed_url_pattern
                .as_deref()
                .filter(|p| !p.is_empty()),
        )?;

        // A rename lands in the owner's namespace, which is the same
        // namespace a create is checked against.
        if let Some(new_name) = changes.name.as_deref().filter(|n| *n != cred.name) {
            self.check_name_free(cred.created_by_user.as_ref(), new_name, Some(cred_id))
                .await?;
        }

        // Handle secret value rotation
        let secret_rotated = new_secret.is_some();
        if let Some(new_secret) = new_secret {
            // Strip auth prefixes for non-AWS/non-OAuth2 types to prevent double-wrapping
            let cleaned_secret = match cred.credential_type.as_str() {
                "aws" | "oauth2_client_credentials" => new_secret.to_string(),
                _ => strip_auth_prefix(new_secret),
            };

            // Seal the new secret under the current master key, credential ID as AAD
            let (encrypted, nonce, key_version) =
                encrypt_secret(&self.key_ring, &cleaned_secret, cred_id)?;
            changes.encrypted_value = Some(encrypted);
            changes.nonce = Some(nonce);
            changes.key_version = Some(key_version);
        }

        if secret_rotated {
            // The old ciphertext is archived, under the master-key version
            // it was sealed with, in the same transaction that writes the
            // new one.
            let (changed_by_user, changed_by_agent) = actor_identity_strings(actor);
            self.store
                .rotate_credential_secret(
                    cred_id,
                    &changes,
                    changed_by_user.as_deref(),
                    changed_by_agent.as_deref(),
                )
                .await?;
        } else {
            self.store.update_credential(cred_id, &changes).await?;
        }

        // Evict any cached OAuth2 token when the secret is rotated
        if secret_rotated {
            self.oauth2_token_manager.evict(cred_id).await;
        }

        // Re-fetch the updated credential to return the summary
        let updated_cred =
            self.store.get_credential(cred_id).await?.ok_or_else(|| {
                ApiError::Internal("credential disappeared after update".to_string())
            })?;

        let (ws_id, ws_name, u_id, u_name) = actor.audit_actor_fields();
        let event_type = if secret_rotated {
            AuditEventType::CredentialSecretRotated
        } else {
            AuditEventType::CredentialUpdated
        };
        let mut audit_metadata = serde_json::json!({
            "credential_name": updated_cred.name,
            "service": updated_cred.service,
        });
        if secret_rotated {
            audit_metadata["secret_rotated"] = serde_json::json!(true);
        }
        let event = AuditEvent::builder(event_type)
            .action("update")
            .actor_fields(ws_id, ws_name, u_id, u_name)
            .resource("credential", &cred_id.0.to_string())
            .correlation_id(corr)
            .decision(AuditDecision::Permit, None)
            .details(audit_metadata)
            .build();
        write_audit(&*self.store, &event).await;

        self.ui_event_bus.emit(UiEvent::CredentialUpdated {
            credential_id: updated_cred.id.0,
        });

        Ok(updated_cred)
    }

    /// Delete a credential, its cached upstream token, and every grant
    /// policy that names it.
    pub async fn delete(
        &self,
        actor: &AuthenticatedActor,
        corr: &str,
        cred_id: &CredentialId,
    ) -> Result<(), ApiError> {
        let cred = self.load(cred_id).await?;

        self.authz
            .request(actor, corr)
            .check(
                actions::DELETE,
                &PolicyResource::Credential {
                    credential: cred.clone(),
                },
            )
            .await?;

        // Evict any cached OAuth2 token for this credential before deletion
        self.oauth2_token_manager.evict(cred_id).await;

        // Cascade: delete all Cedar grant policies for this credential and
        // reload so the deleted grants stop applying at once
        self.policies.delete_grants_for_credential(cred_id).await?;

        self.store.delete_credential(cred_id).await?;

        let (ws_id, ws_name, u_id, u_name) = actor.audit_actor_fields();
        let event = AuditEvent::builder(AuditEventType::CredentialDeleted)
            .action("delete")
            .actor_fields(ws_id, ws_name, u_id, u_name)
            .resource("credential", &cred_id.0.to_string())
            .correlation_id(corr)
            .decision(AuditDecision::Permit, None)
            .details(serde_json::json!({
                "credential_name": cred.name,
                "service": cred.service,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        self.ui_event_bus.emit(UiEvent::CredentialDeleted {
            credential_id: cred_id.0,
        });

        Ok(())
    }

    /// Restore a historical secret value as the current one, archiving the
    /// current value first.
    pub async fn restore_secret_history(
        &self,
        actor: &AuthenticatedActor,
        corr: &str,
        cred_id: &CredentialId,
        history_id: &str,
    ) -> Result<(), ApiError> {
        let cred = self.load(cred_id).await?;

        // Policy check: require "update" action (delegated_use-level access is checked via policy)
        self.authz
            .request(actor, &uuid::Uuid::new_v4().to_string())
            .check(
                actions::UPDATE,
                &PolicyResource::Credential {
                    credential: cred.clone(),
                },
            )
            .await?;

        // The historical ciphertext moves back onto the credential as-is, so the
        // credential must also take the master-key version it was sealed under.
        let historical = self
            .store
            .get_secret_history_value(cred_id, history_id)
            .await?
            .ok_or_else(|| ApiError::NotFound("secret history entry not found".to_string()))?;

        // Update the credential with the historical value; the CURRENT
        // ciphertext is archived, under the version it is sealed with, in
        // the same transaction.
        let (changed_by_user, changed_by_agent) = actor_identity_strings(actor);
        let updates = CredentialUpdate {
            name: None,
            service: None,
            scopes: None,
            metadata: None,
            allowed_url_pattern: None,
            expires_at: None,
            transform_script: None,
            transform_name: None,
            vault_id: None,
            tags: None,
            description: None,
            target_identity: None,
            encrypted_value: Some(historical.encrypted_value),
            nonce: Some(historical.nonce),
            key_version: Some(historical.key_version),
        };

        self.store
            .rotate_credential_secret(
                cred_id,
                &updates,
                changed_by_user.as_deref(),
                changed_by_agent.as_deref(),
            )
            .await?;

        let (ws_id, ws_name, u_id, u_name) = actor.audit_actor_fields();
        let event = AuditEvent::builder(AuditEventType::CredentialSecretRestored)
            .action("update")
            .actor_fields(ws_id, ws_name, u_id, u_name)
            .resource("credential", &cred_id.0.to_string())
            .correlation_id(corr)
            .decision(AuditDecision::Permit, None)
            .details(serde_json::json!({
                "credential_name": cred.name,
                "service": cred.service,
                "restored_from_history_id": history_id,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        self.ui_event_bus.emit(UiEvent::CredentialUpdated {
            credential_id: cred_id.0,
        });

        Ok(())
    }

    // ------------------------------------------------------------------
    // Reveal and vend: the two ways a secret leaves the server
    // ------------------------------------------------------------------

    /// Vault-style secret reveal: decrypts and returns the credential's raw
    /// secret value to a human user. Cedar `unprotect` is evaluated BEFORE
    /// decryption.
    ///
    /// A forbid answers 404 to a caller who cannot see the credential at all,
    /// so the answer never confirms the id exists, and 403 to one who can
    /// already read it — a 404 tells them nothing they could not already see,
    /// and reads as "it is gone" for a row their own list is showing.
    pub async fn reveal(
        &self,
        auth_user: &AuthenticatedUser,
        corr: &str,
        cred_id: &CredentialId,
    ) -> Result<String, ApiError> {
        // A credential nobody has is a 404 for everyone.
        let cred = self.load(cred_id).await?;

        // Cedar policy check BEFORE decryption (deny-first).
        // Root users bypass Cedar entirely (handled in evaluate).
        let decision = self
            .authz
            .request(
                PolicyCaller::Principal {
                    principal: PolicyPrincipal::User(&auth_user.user),
                    oauth_claims: None,
                },
                corr,
            )
            .with_claim(
                claim_keys::REQUESTED_SCOPES,
                serde_json::json!(Vec::<String>::new()),
            )
            .check_with_reasons(
                actions::UNPROTECT,
                &PolicyResource::Credential {
                    credential: cred.clone(),
                },
            )
            .await?;

        if decision.decision == PolicyDecisionResult::Forbid {
            // Authz auto-emitted PolicyEvaluated/Forbid. Which refusal the
            // caller gets depends on whether they can see the credential at
            // all: `authorize_read` is the same question `GET /credentials/
            // {id}` asks, and a caller it answers yes to is told "not
            // allowed", the way edit and delete already tell them.
            let actor = AuthenticatedActor::User(auth_user.user.clone());
            return match self.authorize_read(&actor, corr, &cred).await {
                Ok(_) => Err(ApiError::Forbidden("access denied by policy".to_string())),
                Err(ApiError::Forbidden(_)) => {
                    Err(ApiError::NotFound("credential not found".to_string()))
                }
                Err(other) => Err(other),
            };
        }

        // Capture policy reasoning for the reveal audit event
        let reveal_reason = if decision.reasons.is_empty() {
            None
        } else {
            Some(decision.reasons.join(", "))
        };
        let mut reveal_policy_meta = serde_json::json!({});
        agent_cordon_core::domain::audit::enrich_metadata_with_policy_reasoning(
            &mut reveal_policy_meta,
            &decision,
            None,
            None,
        );

        // Decrypt the credential secret value with credential ID as AAD
        let plaintext = decrypt_secret(&self.key_ring, &cred)?;
        let secret_value = String::from_utf8(plaintext)
            .map_err(|_| ApiError::Internal("credential value is not valid UTF-8".to_string()))?;

        // Domain audit: secret was revealed — NEVER log the secret itself.
        // Include policy reasoning so audit UI can link to contributing policies.
        let mut reveal_metadata = serde_json::json!({
            "credential_name": cred.name,
            "service": cred.service,
        });
        if let Some(policies) = reveal_policy_meta.get("contributing_policies") {
            reveal_metadata["contributing_policies"] = policies.clone();
        }
        let event = AuditEvent::builder(AuditEventType::CredentialSecretViewed)
            .action("unprotect")
            .user_actor(&auth_user.user)
            .resource("credential", &cred_id.0.to_string())
            .correlation_id(corr)
            .decision(AuditDecision::Permit, reveal_reason.as_deref())
            .details(reveal_metadata)
            .build();
        write_audit(&*self.store, &event).await;

        Ok(secret_value)
    }

    /// Produce the material a broker may hold for `cred` and seal it to
    /// `recipient_pub_bytes` (ECIES). An OAuth-backed credential is first
    /// exchanged for an upstream access token here on the server; the client
    /// secret or refresh token behind it never leaves.
    ///
    /// `vend_id_prefix` names the caller in the vend id (`vnd` for a vend,
    /// `sync` for MCP sync).
    pub async fn seal_for_broker(
        &self,
        cred: &StoredCredential,
        workspace: &Workspace,
        recipient_pub_bytes: &[u8],
        vend_id_prefix: &str,
    ) -> Result<(ReencryptedEnvelope, String), SealError> {
        let workspace_id_str = workspace.id.0.to_string();
        if upstream_tokens::is_upstream_oauth(&cred.credential_type) {
            let token = upstream_tokens::access_token_for(
                self,
                cred,
                TokenActor {
                    workspace_id: &workspace.id,
                    workspace_name: &workspace.name,
                },
            )
            .await
            .map_err(SealError::Upstream)?;
            encrypt_material_for_device(
                &cred.id,
                &workspace_id_str,
                recipient_pub_bytes,
                &token.material(),
                vend_id_prefix,
            )
            .await
            .map_err(SealError::Api)
        } else {
            reencrypt_credential_for_device(
                &self.key_ring,
                cred,
                &workspace_id_str,
                recipient_pub_bytes,
                vend_id_prefix,
            )
            .await
            .map_err(SealError::Api)
        }
    }

    /// The vend operation: expiry and target checks, Cedar `vend_credential`
    /// with the target URL in context, seal for the recipient (the broker's
    /// key when given, else the workspace's registered key), and the
    /// `CredentialVended` audit row. Both vend routes call this after their
    /// own credential lookup.
    pub async fn vend(
        &self,
        workspace: &Workspace,
        oauth_claims: Option<serde_json::Value>,
        cred: &StoredCredential,
        corr: &str,
        broker_pub_bytes: Option<Vec<u8>>,
        target: Option<&VendTarget>,
    ) -> Result<VendOutcome, ApiError> {
        if cred.is_expired() {
            return Err(ApiError::Forbidden("credential has expired".to_string()));
        }

        // A refusal here never reached Cedar, so nothing self-audited it.
        // Emit the denial row before returning: the state change a caller
        // cares about — "this workspace was refused this credential for
        // this target" — happens here.
        if let Err(denial) = check_vend_target(cred, target) {
            let reason = denial.0.clone();
            let mut denial_metadata = serde_json::json!({
                "workspace_id": workspace.id.0.to_string(),
                "credential_name": cred.name,
                "allowed_url_pattern": normalized_url_pattern(cred),
            });
            if let Some(t) = target {
                denial_metadata["target_method"] = serde_json::json!(t.method);
                denial_metadata["target_url"] = serde_json::json!(t.url);
            }
            let event = AuditEvent::builder(AuditEventType::CredentialVendDenied)
                .action("vend_credential")
                .workspace_actor(&workspace.id, &workspace.name)
                .resource("credential", &cred.id.0.to_string())
                .correlation_id(corr)
                .decision(AuditDecision::Forbid, Some(&reason))
                .details(denial_metadata)
                .build();
            write_audit(&*self.store, &event).await;
            return Err(denial.into());
        }

        // Cedar policy evaluation via the Authz seam. The target URL is in the
        // context so a policy can narrow further than the credential's pattern.
        let mut request = self.authz.request(
            PolicyCaller::Principal {
                principal: PolicyPrincipal::Workspace(workspace),
                oauth_claims,
            },
            corr,
        );
        if let Some(t) = target {
            request = request.with_claim(claim_keys::TARGET_URL, serde_json::json!(t.url));
        }
        let decision = request
            .check_with_reasons(
                actions::VEND_CREDENTIAL,
                &PolicyResource::Credential {
                    credential: cred.clone(),
                },
            )
            .await?;

        if decision.decision == PolicyDecisionResult::Forbid {
            // Authz auto-emitted PolicyEvaluated/Forbid.
            return Err(ApiError::Forbidden("access denied by policy".to_string()));
        }

        // Capture policy reasoning for the vend audit event
        let policy_reason = if decision.reasons.is_empty() {
            None
        } else {
            Some(decision.reasons.join(", "))
        };
        let mut policy_metadata = serde_json::json!({});
        agent_cordon_core::domain::audit::enrich_metadata_with_policy_reasoning(
            &mut policy_metadata,
            &decision,
            Some(&PolicyContext {
                correlation_id: Some(corr.to_string()),
                ..Default::default()
            }),
            None,
        );

        // Resolve encryption public key: prefer broker-provided key, fall back to workspace key
        let recipient = match broker_pub_bytes {
            Some(broker_bytes) => broker_bytes,
            None => workspace_encryption_point(workspace)?,
        };

        let (envelope, vend_id) = self
            .seal_for_broker(cred, workspace, &recipient, "vnd")
            .await?;

        // Domain audit: credential was vended — NEVER include credential secret values.
        // Include the policy reasoning so the audit UI can link to contributing policies.
        let mut vend_metadata = serde_json::json!({
            "workspace_id": workspace.id.0.to_string(),
            "credential_name": cred.name,
            "vend_id": vend_id,
        });
        if let Some(t) = target {
            vend_metadata["target_method"] = serde_json::json!(t.method);
            vend_metadata["target_url"] = serde_json::json!(t.url);
        }
        // Merge contributing_policies from policy evaluation into vend metadata
        if let Some(policies) = policy_metadata.get("contributing_policies") {
            vend_metadata["contributing_policies"] = policies.clone();
        }
        let event = AuditEvent::builder(AuditEventType::CredentialVended)
            .action("vend_credential")
            .workspace_actor(&workspace.id, &workspace.name)
            .resource("credential", &cred.id.0.to_string())
            .correlation_id(corr)
            .decision(AuditDecision::Permit, policy_reason.as_deref())
            .details(vend_metadata)
            .build();
        write_audit(&*self.store, &event).await;

        Ok(VendOutcome {
            credential_type: cred.credential_type.clone(),
            transform_name: cred.transform_name.clone(),
            allowed_url_pattern: normalized_url_pattern(cred).map(str::to_string),
            envelope,
            vend_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_bearer_prefix() {
        assert_eq!(strip_auth_prefix("Bearer ghp_abc123"), "ghp_abc123");
    }

    #[test]
    fn strip_bearer_lowercase() {
        assert_eq!(strip_auth_prefix("bearer ghp_abc123"), "ghp_abc123");
    }

    #[test]
    fn strip_token_prefix() {
        assert_eq!(strip_auth_prefix("token ghp_abc123"), "ghp_abc123");
    }

    #[test]
    fn strip_basic_prefix() {
        assert_eq!(strip_auth_prefix("Basic dXNlcjpwYXNz"), "dXNlcjpwYXNz");
    }

    #[test]
    fn no_prefix_unchanged() {
        assert_eq!(strip_auth_prefix("ghp_abc123"), "ghp_abc123");
    }

    #[test]
    fn whitespace_trimmed() {
        assert_eq!(strip_auth_prefix("  Bearer ghp_abc123  "), "ghp_abc123");
    }

    #[test]
    fn bearer_only_returns_unchanged() {
        // "Bearer " with nothing after it should return "Bearer" trimmed
        assert_eq!(strip_auth_prefix("Bearer "), "Bearer");
    }
}

/// What `reseal_all` did, in the shape the rotate-key route returns.
#[derive(Debug, serde::Serialize)]
pub struct ResealReport {
    pub key_version: i64,
    pub re_encrypted_count: u32,
    pub total_credentials: usize,
    pub history_re_encrypted_count: u32,
    pub total_history_entries: usize,
    pub errors: Vec<String>,
}

impl CredentialService {
    /// Re-seal every credential and every history row under the current
    /// master-key version. Each row is opened with the key its own version
    /// names, so this is the step that lets a previous secret be retired.
    /// Rows already at the current version are re-sealed too (fresh nonce),
    /// so the call is safe to repeat. One audit row summarises the run.
    pub async fn reseal_all(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
    ) -> Result<ResealReport, ApiError> {
        self.authz
            .request(
                PolicyCaller::Principal {
                    principal: agent_cordon_core::policy::PolicyPrincipal::User(&auth.user),
                    oauth_claims: None,
                },
                corr,
            )
            .with_claim(
                agent_cordon_core::policy::claim_keys::REQUESTED_SCOPES,
                serde_json::json!(Vec::<String>::new()),
            )
            .check(
                agent_cordon_core::policy::actions::ROTATE_ENCRYPTION_KEY,
                &agent_cordon_core::policy::PolicyResource::System,
            )
            .await?;

        let ring = self.key_ring.as_ref();
        let key_version = ring.current_version();
        let mut errors = Vec::new();

        let credentials = self.store.list_credentials().await?;
        let mut re_encrypted_count = 0u32;
        for summary in &credentials {
            let cred = match self.store.get_credential(&summary.id).await? {
                Some(c) => c,
                None => continue,
            };
            let aad = cred.id.0.to_string();
            let plaintext = match decrypt_secret(ring, &cred) {
                Ok(pt) => pt,
                Err(e) => {
                    errors.push(format!("credential {}: decrypt failed: {}", cred.id.0, e));
                    continue;
                }
            };
            let (encrypted, nonce, version) =
                match ring.encrypt_versioned(&plaintext, aad.as_bytes()) {
                    Ok(sealed) => sealed,
                    Err(e) => {
                        errors.push(format!("credential {}: encrypt failed: {}", cred.id.0, e));
                        continue;
                    }
                };
            let update = CredentialUpdate {
                name: None,
                service: None,
                scopes: None,
                metadata: None,
                allowed_url_pattern: None,
                expires_at: None,
                transform_script: None,
                transform_name: None,
                vault_id: None,
                tags: None,
                description: None,
                target_identity: None,
                encrypted_value: Some(encrypted),
                nonce: Some(nonce),
                key_version: Some(version),
            };
            match self.store.update_credential(&cred.id, &update).await {
                Ok(true) => re_encrypted_count += 1,
                Ok(false) => {
                    errors.push(format!("credential {}: update returned false", cred.id.0))
                }
                Err(e) => errors.push(format!("credential {}: update failed: {}", cred.id.0, e)),
            }
        }

        let history = self.store.list_all_secret_history_ciphertexts().await?;
        let mut history_re_encrypted_count = 0u32;
        for row in &history {
            let aad = row.credential_id.0.to_string();
            let plaintext = match ring.decrypt_versioned(
                &row.encrypted_value,
                &row.nonce,
                aad.as_bytes(),
                row.key_version,
            ) {
                Ok(pt) => pt,
                Err(e) => {
                    errors.push(format!("history {}: decrypt failed: {}", row.id, e));
                    continue;
                }
            };
            let (encrypted, nonce, version) =
                match ring.encrypt_versioned(&plaintext, aad.as_bytes()) {
                    Ok(sealed) => sealed,
                    Err(e) => {
                        errors.push(format!("history {}: encrypt failed: {}", row.id, e));
                        continue;
                    }
                };
            match self
                .store
                .update_secret_history_ciphertext(&row.id, &encrypted, &nonce, version)
                .await
            {
                Ok(true) => history_re_encrypted_count += 1,
                Ok(false) => errors.push(format!("history {}: update returned false", row.id)),
                Err(e) => errors.push(format!("history {}: update failed: {}", row.id, e)),
            }
        }

        // Not `CredentialSecretRotated`: no secret changed value here, only
        // the key they are sealed under, and an operator asking "has anyone
        // re-sealed this store?" should not have to read the Resource column
        // of a dozen genuine rotations to find out.
        let event = AuditEvent::builder(AuditEventType::MasterKeyResealed)
            .action("rotate_encryption_key")
            .user_actor(&auth.user)
            .resource_type("system")
            .correlation_id(corr)
            .decision(AuditDecision::Permit, None)
            .details(serde_json::json!({
                "key_version": key_version,
                "re_encrypted_count": re_encrypted_count,
                "history_re_encrypted_count": history_re_encrypted_count,
                "error_count": errors.len(),
            }))
            .build();
        write_audit(&*self.store, &event).await;

        Ok(ResealReport {
            key_version,
            re_encrypted_count,
            total_credentials: credentials.len(),
            history_re_encrypted_count,
            total_history_entries: history.len(),
            errors,
        })
    }
}
