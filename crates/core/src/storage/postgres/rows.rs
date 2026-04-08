use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::domain::audit::AuditEvent;
use crate::domain::credential::{CredentialId, CredentialSummary, StoredCredential};
use crate::domain::mcp::{McpAuthMethod, McpServer, McpServerId, McpTransport};
use crate::domain::oidc::{OidcAuthState, OidcProvider, OidcProviderId, OidcProviderSummary};
use crate::domain::policy::{PolicyId, StoredPolicy};
use crate::domain::session::Session;
use crate::domain::user::{User, UserId};
use crate::domain::vault::VaultShare;
use crate::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
use crate::error::StoreError;

use super::{deserialize_decision, deserialize_event_type, deserialize_user_role};

// ---------------------------------------------------------------------------
// sqlx row types (intermediate representations)
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
pub(crate) struct WorkspaceRow {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub status: String,
    pub pk_hash: Option<String>,
    pub encryption_public_key: Option<String>,
    pub tags: serde_json::Value,
    pub owner_id: Option<Uuid>,
    pub parent_id: Option<Uuid>,
    pub tool_name: Option<String>,
    pub enrollment_token_hash: Option<String>,
    pub last_authenticated_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl WorkspaceRow {
    pub fn into_workspace(self) -> Result<Workspace, StoreError> {
        let status = WorkspaceStatus::from_str(&self.status).map_err(|_| {
            StoreError::Database(format!("invalid workspace status: {}", self.status))
        })?;
        Ok(Workspace {
            id: WorkspaceId(self.id),
            name: self.name,
            enabled: self.enabled,
            status,
            pk_hash: self.pk_hash,
            encryption_public_key: self.encryption_public_key,
            tags: serde_json::from_value(self.tags).unwrap_or_default(),
            owner_id: self.owner_id.map(UserId),
            parent_id: self.parent_id.map(WorkspaceId),
            tool_name: self.tool_name,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct UserRow {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub password_hash: String,
    pub role: String,
    pub is_root: bool,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl UserRow {
    pub fn into_user(self) -> Result<User, StoreError> {
        Ok(User {
            id: UserId(self.id),
            username: self.username,
            display_name: self.display_name,
            password_hash: self.password_hash,
            role: deserialize_user_role(&self.role)?,
            is_root: self.is_root,
            enabled: self.enabled,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct SessionRow {
    pub id: String,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

impl From<SessionRow> for Session {
    fn from(r: SessionRow) -> Self {
        Session {
            id: r.id,
            user_id: UserId(r.user_id),
            created_at: r.created_at,
            expires_at: r.expires_at,
            last_seen_at: r.last_seen_at,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct PolicyRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub cedar_policy: String,
    pub enabled: bool,
    pub is_system: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<PolicyRow> for StoredPolicy {
    fn from(r: PolicyRow) -> Self {
        StoredPolicy {
            id: PolicyId(r.id),
            name: r.name,
            description: r.description,
            cedar_policy: r.cedar_policy,
            enabled: r.enabled,
            is_system: r.is_system,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct CredentialRow {
    pub id: Uuid,
    pub name: String,
    pub service: String,
    pub encrypted_value: Vec<u8>,
    pub nonce: Vec<u8>,
    pub scopes: serde_json::Value,
    pub metadata: serde_json::Value,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub allowed_url_pattern: Option<String>,
    pub created_by_user: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
    pub transform_script: Option<String>,
    pub transform_name: Option<String>,
    pub vault: String,
    pub credential_type: String,
    pub tags: serde_json::Value,
    pub key_version: i32,
    pub description: Option<String>,
    pub target_identity: Option<String>,
}

impl From<CredentialRow> for StoredCredential {
    fn from(r: CredentialRow) -> Self {
        StoredCredential {
            id: CredentialId(r.id),
            name: r.name,
            service: r.service,
            encrypted_value: r.encrypted_value,
            nonce: r.nonce,
            scopes: serde_json::from_value(r.scopes).unwrap_or_default(),
            metadata: r.metadata,
            created_by: r.created_by.map(WorkspaceId),
            created_by_user: r.created_by_user.map(UserId),
            created_at: r.created_at,
            updated_at: r.updated_at,
            allowed_url_pattern: r.allowed_url_pattern,
            expires_at: r.expires_at,
            transform_script: r.transform_script,
            transform_name: r.transform_name,
            vault: r.vault,
            credential_type: r.credential_type,
            tags: serde_json::from_value(r.tags).unwrap_or_default(),
            description: r.description,
            target_identity: r.target_identity,
            key_version: r.key_version as i64,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct CredentialSummaryRow {
    pub id: Uuid,
    pub name: String,
    pub service: String,
    pub scopes: serde_json::Value,
    pub metadata: serde_json::Value,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub allowed_url_pattern: Option<String>,
    pub created_by_user: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
    pub transform_script: Option<String>,
    pub transform_name: Option<String>,
    pub vault: String,
    pub credential_type: String,
    pub tags: serde_json::Value,
    pub description: Option<String>,
    pub target_identity: Option<String>,
}

impl From<CredentialSummaryRow> for CredentialSummary {
    fn from(r: CredentialSummaryRow) -> Self {
        let expired = r.expires_at.map(|exp| Utc::now() > exp).unwrap_or(false);
        CredentialSummary {
            id: CredentialId(r.id),
            name: r.name,
            service: r.service,
            scopes: serde_json::from_value(r.scopes).unwrap_or_default(),
            metadata: r.metadata,
            created_by: r.created_by.map(WorkspaceId),
            created_by_user: r.created_by_user.map(UserId),
            created_at: r.created_at,
            allowed_url_pattern: r.allowed_url_pattern,
            expires_at: r.expires_at,
            expired,
            transform_script: r.transform_script,
            transform_name: r.transform_name,
            vault: r.vault,
            credential_type: r.credential_type,
            tags: serde_json::from_value(r.tags).unwrap_or_default(),
            description: r.description,
            target_identity: r.target_identity,
            owner_username: None,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct AuditRow {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub correlation_id: String,
    pub event_type: String,
    pub workspace_id: Option<Uuid>,
    pub workspace_name: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub decision: String,
    pub decision_reason: Option<String>,
    pub metadata: serde_json::Value,
    pub user_id: Option<String>,
    pub user_name: Option<String>,
}

impl AuditRow {
    pub fn into_event(self) -> Result<AuditEvent, StoreError> {
        Ok(AuditEvent {
            id: self.id,
            timestamp: self.timestamp,
            correlation_id: self.correlation_id,
            event_type: deserialize_event_type(&self.event_type)?,
            workspace_id: self.workspace_id.map(WorkspaceId),
            workspace_name: self.workspace_name,
            user_id: self.user_id,
            user_name: self.user_name,
            action: self.action,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
            decision: deserialize_decision(&self.decision)?,
            decision_reason: self.decision_reason,
            metadata: self.metadata,
        })
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct VaultShareRow {
    pub id: String,
    pub vault_name: String,
    pub shared_with_user_id: Uuid,
    pub permission_level: String,
    pub shared_by_user_id: Uuid,
    pub created_at: DateTime<Utc>,
}

impl From<VaultShareRow> for VaultShare {
    fn from(r: VaultShareRow) -> Self {
        VaultShare {
            id: r.id,
            vault_name: r.vault_name,
            shared_with_user_id: UserId(r.shared_with_user_id),
            permission_level: r.permission_level,
            shared_by_user_id: UserId(r.shared_by_user_id),
            created_at: r.created_at,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct McpServerRow {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub name: String,
    pub upstream_url: String,
    pub transport: String,
    pub credential_bindings: serde_json::Value,
    pub allowed_tools: Option<serde_json::Value>,
    pub enabled: bool,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub tags: serde_json::Value,
    pub required_credentials: Option<serde_json::Value>,
    pub auth_method: String,
    pub template_key: Option<String>,
    pub discovered_tools: Option<serde_json::Value>,
    pub created_by_user: Option<String>,
}

impl From<McpServerRow> for McpServer {
    fn from(r: McpServerRow) -> Self {
        let _ = r.credential_bindings;
        let allowed_tools: Option<Vec<String>> =
            r.allowed_tools.and_then(|v| serde_json::from_value(v).ok());
        let tags: Vec<String> = serde_json::from_value(r.tags).unwrap_or_default();
        let required_credentials: Option<Vec<CredentialId>> =
            r.required_credentials.and_then(|v| {
                let strings: Vec<String> = serde_json::from_value(v).ok()?;
                let ids: Result<Vec<CredentialId>, _> = strings
                    .iter()
                    .map(|s| Uuid::parse_str(s).map(CredentialId))
                    .collect();
                ids.ok()
            });
        let created_by = r
            .created_by
            .and_then(|s| Uuid::parse_str(&s).ok().map(WorkspaceId));
        let discovered_tools = r
            .discovered_tools
            .and_then(|v| serde_json::from_value(v).ok());
        McpServer {
            id: McpServerId(r.id),
            workspace_id: WorkspaceId(r.workspace_id),
            name: r.name,
            upstream_url: r.upstream_url,
            transport: McpTransport::from_str_opt(&r.transport).unwrap_or_default(),
            allowed_tools,
            enabled: r.enabled,
            created_by,
            created_at: r.created_at,
            updated_at: r.updated_at,
            tags,
            required_credentials,
            auth_method: McpAuthMethod::from_str_opt(&r.auth_method).unwrap_or_default(),
            template_key: r.template_key,
            discovered_tools,
            created_by_user: r
                .created_by_user
                .and_then(|s| Uuid::parse_str(&s).ok().map(UserId)),
        }
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct OidcProviderRow {
    pub id: Uuid,
    pub name: String,
    pub issuer_url: String,
    pub client_id: String,
    pub encrypted_client_secret: Vec<u8>,
    pub nonce: Vec<u8>,
    pub scopes: serde_json::Value,
    pub role_mapping: serde_json::Value,
    pub auto_provision: bool,
    pub enabled: bool,
    pub username_claim: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<OidcProviderRow> for OidcProvider {
    fn from(r: OidcProviderRow) -> Self {
        OidcProvider {
            id: OidcProviderId(r.id),
            name: r.name,
            issuer_url: r.issuer_url,
            client_id: r.client_id,
            encrypted_client_secret: r.encrypted_client_secret,
            nonce: r.nonce,
            scopes: serde_json::from_value(r.scopes).unwrap_or_default(),
            role_mapping: r.role_mapping,
            auto_provision: r.auto_provision,
            enabled: r.enabled,
            username_claim: r.username_claim,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct OidcProviderSummaryRow {
    pub id: Uuid,
    pub name: String,
    pub issuer_url: String,
    pub client_id: String,
    pub scopes: serde_json::Value,
    pub role_mapping: serde_json::Value,
    pub auto_provision: bool,
    pub enabled: bool,
    pub username_claim: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<OidcProviderSummaryRow> for OidcProviderSummary {
    fn from(r: OidcProviderSummaryRow) -> Self {
        OidcProviderSummary {
            id: OidcProviderId(r.id),
            name: r.name,
            issuer_url: r.issuer_url,
            client_id: r.client_id,
            scopes: serde_json::from_value(r.scopes).unwrap_or_default(),
            role_mapping: r.role_mapping,
            auto_provision: r.auto_provision,
            enabled: r.enabled,
            username_claim: r.username_claim,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct OidcAuthStateRow {
    pub state: String,
    pub nonce: String,
    pub provider_id: Uuid,
    pub redirect_uri: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl From<OidcAuthStateRow> for OidcAuthState {
    fn from(r: OidcAuthStateRow) -> Self {
        OidcAuthState {
            state: r.state,
            nonce: r.nonce,
            provider_id: OidcProviderId(r.provider_id),
            redirect_uri: r.redirect_uri,
            created_at: r.created_at,
            expires_at: r.expires_at,
        }
    }
}
