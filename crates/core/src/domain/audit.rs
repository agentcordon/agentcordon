use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::policy::PolicyDecision;
use super::user::{User, UserId};
use super::workspace::WorkspaceId;

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub correlation_id: String,
    pub event_type: AuditEventType,
    /// Unified workspace identity (replaces agent_id + device_id).
    pub workspace_id: Option<WorkspaceId>,
    pub workspace_name: Option<String>,
    pub user_id: Option<String>,
    pub user_name: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub decision: AuditDecision,
    pub decision_reason: Option<String>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    // Workspace lifecycle
    WorkspaceCreated,
    WorkspaceUpdated,
    WorkspaceDeleted,
    WorkspaceAuthenticated,
    WorkspaceAuthFailed,
    WorkspaceRegistered,
    WorkspaceRevoked,

    // Credential lifecycle
    CredentialCreated,
    CredentialUpdated,
    CredentialDeleted,
    CredentialAccessRequested,
    CredentialAccessGranted,
    CredentialAccessDenied,
    CredentialExpired,
    CredentialLeakDetected,
    CredentialSecretViewed,
    CredentialSecretRotated,
    CredentialSecretRestored,
    CredentialVended,
    CredentialVendDenied,
    CredentialStored,
    CredentialScopeCheck,
    CredentialProxyAuth,

    // Policy lifecycle
    PolicyEvaluated,
    PolicyCreated,
    PolicyUpdated,
    PolicyDeleted,

    // Auth events
    AuthFailure,

    // Token lifecycle
    TokenIssued,

    // Proxy
    ProxyRequestExecuted,
    ProxyRequestDenied,
    TransformExecuted,

    // User lifecycle
    UserCreated,
    UserUpdated,
    UserDeleted,
    UserLoginSuccess,
    UserLoginFailed,
    UserLogout,
    LoginRateLimited,

    // Vault
    VaultCreated,
    VaultRenamed,
    VaultDeleted,
    VaultShared,
    VaultUnshared,

    // OIDC
    OidcLoginSuccess,
    OidcLoginFailed,
    OidcProviderCreated,
    OidcProviderUpdated,
    OidcProviderDeleted,

    // OAuth2
    Oauth2TokenAcquired,
    Oauth2TokenFailed,

    // OAuth2 Device Authorization Grant (RFC 8628)
    DeviceCodeIssued,
    DeviceCodeApproved,
    DeviceCodeDenied,
    DeviceCodeExpired,

    // OAuth2 consent management (issue #10 / #28)
    /// User approved an OAuth consent grant for a workspace's client.
    /// Pairs with `ConsentRevoked`; a re-grant emits a fresh event rather
    /// than an Updated variant — consent is semantically a new approval,
    /// not a patch.
    ConsentGranted,
    /// Admin or self revoked an OAuth consent grant; cascades to token revocation.
    ConsentRevoked,

    // MCP
    McpServerRegistered,
    McpServerUpdated,
    McpServerDeleted,
    McpToolCallExecuted,
    McpToolCallDenied,
    McpPoliciesGenerated,
    McpToolCall,
    McpToolCalled,
    McpToolDenied,
    McpServerProvisioned,
    /// A `tools/list` probe against an MCP server's upstream failed.
    /// Discovery is best-effort — the install still stands — so this row is
    /// the only durable record of why a server has no tools.
    McpToolDiscoveryFailed,
    McpServerSharedWithWorkspace,
    McpServerUnsharedFromWorkspace,

    // OAuth Provider Clients
    //
    // `rename_all = "snake_case"` splits the `OAuth` acronym and would spell
    // these `o_auth_provider_…`, which is the name nobody writing a filter or
    // a SIEM rule would guess. Each variant names itself instead, and keeps
    // the mangled spelling as a read-side alias so rows already on disk still
    // deserialize.
    #[serde(
        rename = "oauth_provider_client_created",
        alias = "o_auth_provider_client_created"
    )]
    OAuthProviderClientCreated,
    #[serde(
        rename = "oauth_provider_client_updated",
        alias = "o_auth_provider_client_updated"
    )]
    OAuthProviderClientUpdated,
    #[serde(
        rename = "oauth_provider_client_deleted",
        alias = "o_auth_provider_client_deleted"
    )]
    OAuthProviderClientDeleted,
    #[serde(
        rename = "oauth_provider_client_rotated",
        alias = "o_auth_provider_client_rotated"
    )]
    OAuthProviderClientRotated,
    #[serde(
        rename = "oauth_provider_discovery_failed",
        alias = "o_auth_provider_discovery_failed"
    )]
    OAuthProviderDiscoveryFailed,

    // Master key
    /// Every credential and history row was re-sealed under the current
    /// master-key version (`POST /api/v1/admin/rotate-key`). Distinct from
    /// `CredentialSecretRotated`, which is one secret changing value: this
    /// one changes no secret, only the key the store is sealed with, and it
    /// is the row that answers "has anyone re-sealed this store?".
    MasterKeyResealed,

    // Subprocess
    SubprocessSpawned,
    SubprocessCrashed,
    SubprocessRespawned,

    // SSE
    SseConnected,
    SseDisconnected,

    // Demo
    DemoTokenIssued,
    DemoDataRemoved,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    Permit,
    Forbid,
    Error,
    NotApplicable,
}

// ---------------------------------------------------------------------------
// Policy reasoning helpers
// ---------------------------------------------------------------------------

/// Project a [`PolicyContext`](crate::policy::PolicyContext) claim bag into
/// the `evaluated_context` JSON object historically emitted as part of policy
/// audit metadata. Only the canonical Cedar context keys (target_url,
/// tool_name, credential_name, tag_value, justification) are surfaced; other
/// claims are intentionally not echoed into audit so callers cannot dump
/// arbitrary blobs by polluting the bag.
fn build_evaluated_context_from_claims(
    claims: &std::collections::HashMap<String, serde_json::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    use crate::policy::claim_keys;
    let mut eval_ctx = serde_json::Map::new();
    for key in [
        claim_keys::TARGET_URL,
        claim_keys::TOOL_NAME,
        claim_keys::CREDENTIAL_NAME,
        claim_keys::TAG_VALUE,
        claim_keys::JUSTIFICATION,
    ] {
        if let Some(v) = claims.get(key).and_then(|v| v.as_str()) {
            if !v.is_empty() {
                eval_ctx.insert(key.to_string(), serde_json::Value::String(v.to_string()));
            }
        }
    }
    eval_ctx
}

/// Enrich an audit metadata JSON value with policy reasoning fields.
pub fn enrich_metadata_with_policy_reasoning(
    metadata: &mut serde_json::Value,
    decision: &PolicyDecision,
    context: Option<&crate::policy::PolicyContext>,
    justification: Option<&str>,
) {
    if !metadata.is_object() {
        *metadata = serde_json::json!({});
    }
    let map = metadata.as_object_mut().unwrap();

    let effect = if decision.decision == crate::domain::policy::PolicyDecisionResult::Permit {
        "permit"
    } else {
        "forbid"
    };
    let contributing: Vec<serde_json::Value> = decision
        .reasons
        .iter()
        .map(|r| {
            let (policy_id, statement_index) = match r.rfind('_') {
                Some(pos) => {
                    let suffix = &r[pos + 1..];
                    match suffix.parse::<usize>() {
                        Ok(idx) => (&r[..pos], Some(idx)),
                        Err(_) => (r.as_str(), None),
                    }
                }
                None => (r.as_str(), None),
            };
            let mut entry = serde_json::json!({ "id": policy_id, "effect": effect });
            if let Some(idx) = statement_index {
                entry
                    .as_object_mut()
                    .unwrap()
                    .insert("statement_index".to_string(), serde_json::json!(idx));
            }
            entry
        })
        .collect();
    map.insert(
        "contributing_policies".to_string(),
        serde_json::Value::Array(contributing),
    );

    if let Some(ctx) = context {
        let eval_ctx = build_evaluated_context_from_claims(&ctx.claims);
        if !eval_ctx.is_empty() {
            map.insert(
                "evaluated_context".to_string(),
                serde_json::Value::Object(eval_ctx),
            );
        }
    }

    if let Some(j) = justification {
        if !j.is_empty() {
            map.insert(
                "justification".to_string(),
                serde_json::Value::String(j.to_string()),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// AuditEvent Builder
// ---------------------------------------------------------------------------

pub struct AuditEventBuilder {
    event_type: AuditEventType,
    action: String,
    resource_type: String,
    resource_id: Option<String>,
    workspace_id: Option<WorkspaceId>,
    workspace_name: Option<String>,
    user_id: Option<String>,
    user_name: Option<String>,
    decision: AuditDecision,
    decision_reason: Option<String>,
    metadata: serde_json::Value,
    correlation_id: Option<String>,
}

impl AuditEvent {
    /// Create a new builder for the given event type.
    pub fn builder(event_type: AuditEventType) -> AuditEventBuilder {
        AuditEventBuilder {
            event_type,
            action: String::new(),
            resource_type: String::new(),
            resource_id: None,
            workspace_id: None,
            workspace_name: None,
            user_id: None,
            user_name: None,
            decision: AuditDecision::Permit,
            decision_reason: None,
            metadata: serde_json::Value::Null,
            correlation_id: None,
        }
    }
}

impl AuditEventBuilder {
    /// Set the action (e.g., "create", "delete", "issue_token").
    pub fn action(mut self, action: &str) -> Self {
        self.action = action.to_string();
        self
    }

    /// Set resource type and ID.
    pub fn resource(mut self, resource_type: &str, resource_id: &str) -> Self {
        self.resource_type = resource_type.to_string();
        self.resource_id = Some(resource_id.to_string());
        self
    }

    /// Set resource type only (no specific ID).
    pub fn resource_type(mut self, resource_type: &str) -> Self {
        self.resource_type = resource_type.to_string();
        self
    }

    /// Set actor from a User.
    pub fn user_actor(mut self, user: &User) -> Self {
        self.user_id = Some(user.id.0.to_string());
        self.user_name = Some(user.username.clone());
        self
    }

    /// Set actor from a user ID and name directly.
    pub fn user_actor_raw(mut self, user_id: &UserId, username: &str) -> Self {
        self.user_id = Some(user_id.0.to_string());
        self.user_name = Some(username.to_string());
        self
    }

    /// Set workspace actor fields (replaces agent_actor and device methods).
    pub fn workspace_actor(mut self, workspace_id: &WorkspaceId, workspace_name: &str) -> Self {
        self.workspace_id = Some(workspace_id.clone());
        self.workspace_name = Some(workspace_name.to_string());
        self
    }

    /// Set decision and optional reason.
    pub fn decision(mut self, decision: AuditDecision, reason: Option<&str>) -> Self {
        self.decision = decision;
        self.decision_reason = reason.map(|s| s.to_string());
        self
    }

    /// Set metadata JSON.
    pub fn details(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }

    /// Merge policy reasoning into metadata.
    pub fn with_policy_reasoning(
        mut self,
        decision: &PolicyDecision,
        context: &crate::policy::PolicyContext,
    ) -> Self {
        let contributing: Vec<serde_json::Value> = decision
            .reasons
            .iter()
            .map(|r| {
                let effect =
                    if decision.decision == crate::domain::policy::PolicyDecisionResult::Permit {
                        "permit"
                    } else {
                        "forbid"
                    };
                let (policy_id, statement_index) = match r.rfind('_') {
                    Some(pos) => {
                        let suffix = &r[pos + 1..];
                        match suffix.parse::<usize>() {
                            Ok(idx) => (&r[..pos], Some(idx)),
                            Err(_) => (r.as_str(), None),
                        }
                    }
                    None => (r.as_str(), None),
                };
                let mut entry = serde_json::json!({ "id": policy_id, "effect": effect });
                if let Some(idx) = statement_index {
                    entry
                        .as_object_mut()
                        .unwrap()
                        .insert("statement_index".to_string(), serde_json::json!(idx));
                }
                entry
            })
            .collect();

        let eval_ctx = build_evaluated_context_from_claims(&context.claims);

        let meta = match self.metadata {
            serde_json::Value::Object(ref mut map) => {
                map.insert(
                    "contributing_policies".to_string(),
                    serde_json::Value::Array(contributing.clone()),
                );
                if !eval_ctx.is_empty() {
                    map.insert(
                        "evaluated_context".to_string(),
                        serde_json::Value::Object(eval_ctx.clone()),
                    );
                }
                serde_json::Value::Object(map.clone())
            }
            serde_json::Value::Null => {
                let mut map = serde_json::Map::new();
                map.insert(
                    "contributing_policies".to_string(),
                    serde_json::Value::Array(contributing.clone()),
                );
                if !eval_ctx.is_empty() {
                    map.insert(
                        "evaluated_context".to_string(),
                        serde_json::Value::Object(eval_ctx.clone()),
                    );
                }
                serde_json::Value::Object(map)
            }
            _ => {
                let mut map = serde_json::Map::new();
                map.insert("original".to_string(), self.metadata.clone());
                map.insert(
                    "contributing_policies".to_string(),
                    serde_json::Value::Array(contributing.clone()),
                );
                if !eval_ctx.is_empty() {
                    map.insert(
                        "evaluated_context".to_string(),
                        serde_json::Value::Object(eval_ctx.clone()),
                    );
                }
                serde_json::Value::Object(map)
            }
        };
        self.metadata = meta;

        if !decision.reasons.is_empty() {
            self.decision_reason = Some(decision.reasons.join(", "));
        }

        self
    }

    /// Set actor fields from the `audit_actor_fields()` tuple returned by
    /// `AuthenticatedActor` (workspace_id, workspace_name, user_id, user_name).
    pub fn actor_fields(
        mut self,
        workspace_id: Option<WorkspaceId>,
        workspace_name: Option<String>,
        user_id: Option<String>,
        user_name: Option<String>,
    ) -> Self {
        self.workspace_id = workspace_id;
        self.workspace_name = workspace_name;
        self.user_id = user_id;
        self.user_name = user_name;
        self
    }

    /// Set only the user_name field (e.g. for login failures where user_id is unknown).
    pub fn user_name_only(mut self, name: &str) -> Self {
        self.user_name = Some(name.to_string());
        self
    }

    /// Set only the workspace_name field (when a user-facing workspace name is
    /// known but no fully-resolved `WorkspaceId` is available yet — e.g. a
    /// device-code row that carries `workspace_name_prefill`).
    pub fn workspace_name_only(mut self, name: &str) -> Self {
        self.workspace_name = Some(name.to_string());
        self
    }

    /// Set correlation ID (defaults to a new UUID if not set).
    pub fn correlation_id(mut self, corr_id: &str) -> Self {
        self.correlation_id = Some(corr_id.to_string());
        self
    }

    /// Build the final `AuditEvent`.
    pub fn build(self) -> AuditEvent {
        AuditEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            correlation_id: self
                .correlation_id
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
            event_type: self.event_type,
            workspace_id: self.workspace_id,
            workspace_name: self.workspace_name,
            user_id: self.user_id,
            user_name: self.user_name,
            action: self.action,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
            decision: self.decision,
            decision_reason: self.decision_reason,
            metadata: self.metadata,
        }
    }
}
