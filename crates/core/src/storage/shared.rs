//! Backend-independent storage helpers: the parts of the store that are
//! about the schema and the domain rather than about the driver.
//!
//! Contains:
//! - Enum serialization/deserialization (enums are stored as strings)
//! - SQL column list constants
//! - Dynamic SQL builders for audit filters and credential updates
//! - Shared audit event logging

use crate::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use crate::domain::credential::CredentialUpdate;
use crate::domain::time::format_timestamp;
use crate::domain::user::UserRole;
use crate::error::StoreError;
use crate::storage::AuditFilter;

// ---------------------------------------------------------------------------
// Event type serialization
// ---------------------------------------------------------------------------

pub fn serialize_event_type(et: &AuditEventType) -> Result<String, StoreError> {
    let json = serde_json::to_string(et)
        .map_err(|e| StoreError::Database(format!("failed to serialize event_type: {}", e)))?;
    Ok(json.trim_matches('"').to_string())
}

pub fn deserialize_event_type(s: &str) -> Result<AuditEventType, StoreError> {
    // Try serde first (covers all snake_case variants), fall back to manual map for compat
    let quoted = format!("\"{}\"", s);
    if let Ok(et) = serde_json::from_str::<AuditEventType>(&quoted) {
        return Ok(et);
    }
    // Backward compat: accept old names from existing audit records
    match s {
        "credential_stored" => Ok(AuditEventType::CredentialCreated),
        other => Err(StoreError::Database(format!(
            "unknown event_type: {}",
            other
        ))),
    }
}

// ---------------------------------------------------------------------------
// Audit decision serialization
// ---------------------------------------------------------------------------

pub fn serialize_decision(d: &AuditDecision) -> Result<String, StoreError> {
    let json = serde_json::to_string(d)
        .map_err(|e| StoreError::Database(format!("failed to serialize decision: {}", e)))?;
    Ok(json.trim_matches('"').to_string())
}

pub fn deserialize_decision(s: &str) -> Result<AuditDecision, StoreError> {
    match s {
        "permit" => Ok(AuditDecision::Permit),
        "forbid" => Ok(AuditDecision::Forbid),
        "error" => Ok(AuditDecision::Error),
        "not_applicable" => Ok(AuditDecision::NotApplicable),
        // Backward compat: accept old values from existing audit records
        "allow" => Ok(AuditDecision::Permit),
        "deny" => Ok(AuditDecision::Forbid),
        other => Err(StoreError::Database(format!("unknown decision: {}", other))),
    }
}

// ---------------------------------------------------------------------------
// User role serialization
// ---------------------------------------------------------------------------

pub fn serialize_user_role(role: &UserRole) -> &'static str {
    match role {
        UserRole::Admin => "admin",
        UserRole::Operator => "operator",
        UserRole::Viewer => "viewer",
    }
}

pub fn deserialize_user_role(s: &str) -> Result<UserRole, StoreError> {
    match s {
        "admin" => Ok(UserRole::Admin),
        "operator" => Ok(UserRole::Operator),
        "viewer" => Ok(UserRole::Viewer),
        other => Err(StoreError::Database(format!(
            "unknown user role: {}",
            other
        ))),
    }
}

// ---------------------------------------------------------------------------
// JSON serialization helpers
// ---------------------------------------------------------------------------

pub fn serialize_tags(tags: &[String]) -> Result<String, StoreError> {
    serde_json::to_string(tags)
        .map_err(|e| StoreError::Database(format!("failed to serialize tags: {}", e)))
}

pub fn serialize_scopes(scopes: &[String]) -> Result<String, StoreError> {
    serde_json::to_string(scopes)
        .map_err(|e| StoreError::Database(format!("failed to serialize scopes: {}", e)))
}

pub fn serialize_metadata(value: &serde_json::Value) -> Result<String, StoreError> {
    serde_json::to_string(value)
        .map_err(|e| StoreError::Database(format!("failed to serialize metadata: {}", e)))
}

// ---------------------------------------------------------------------------
// SQL column list constants
// ---------------------------------------------------------------------------
// Centralising them here means a schema change only needs one update.

/// Columns for the `workspaces` table (SELECT).
pub const WORKSPACE_COLUMNS: &str = "id, name, enabled, status, pk_hash, encryption_public_key, tags, owner_id, parent_id, tool_name, enrollment_token_hash, last_authenticated_at, created_at, updated_at";

/// Columns for the `audit_events` table (SELECT / INSERT).
/// Uses the new workspace_id/workspace_name columns from the v2.0 migration.
pub const AUDIT_COLUMNS: &str = "id, timestamp, correlation_id, event_type, workspace_id, workspace_name, action, resource_type, resource_id, decision, decision_reason, metadata, user_id, user_name";

/// Columns for the `credentials` table — INSERT, in the order
/// `store_credential` binds them.
pub const CREDENTIAL_INSERT_COLUMNS: &str = "id, name, service, encrypted_value, nonce, scopes, metadata, created_by, created_at, updated_at, allowed_url_pattern, created_by_user, expires_at, transform_script, transform_name, vault_id, credential_type, tags, key_version, description, target_identity";

/// What every credential SELECT reads from: the row joined to its vault, so
/// a summary can carry the vault's display name without a second query. The
/// join is LEFT so a row whose vault has somehow gone still comes back.
pub const CREDENTIAL_SOURCE: &str = "credentials c LEFT JOIN vaults v ON v.id = c.vault_id";

/// Columns for the `credentials` table — full row (SELECT), qualified for
/// [`CREDENTIAL_SOURCE`].
pub const CREDENTIAL_COLUMNS: &str = "c.id, c.name, c.service, c.encrypted_value, c.nonce, c.scopes, c.metadata, c.created_by, c.created_at, c.updated_at, c.allowed_url_pattern, c.created_by_user, c.expires_at, c.transform_script, c.transform_name, c.vault_id, v.name, c.credential_type, c.tags, c.key_version, c.description, c.target_identity";

/// Columns for the `credentials` table — summary (no encrypted_value / nonce / key_version),
/// qualified for [`CREDENTIAL_SOURCE`].
pub const CREDENTIAL_SUMMARY_COLUMNS: &str = "c.id, c.name, c.service, c.scopes, c.metadata, c.created_by, c.created_at, c.allowed_url_pattern, c.created_by_user, c.expires_at, c.transform_script, c.transform_name, c.vault_id, v.name, c.credential_type, c.tags, c.description, c.target_identity";

/// Columns for the `users` table (SELECT).
pub const USER_COLUMNS: &str =
    "id, username, display_name, password_hash, role, is_root, enabled, created_at, updated_at";

/// Columns for the `policies` table (SELECT).
pub const POLICY_COLUMNS: &str =
    "id, name, description, cedar_policy, enabled, created_at, updated_at";

/// Columns for the `sessions` table (SELECT).
pub const SESSION_COLUMNS: &str = "id, user_id, created_at, expires_at, last_seen_at";

/// Columns for the `servers` table (SELECT).
pub const SERVER_COLUMNS: &str = "id, name, client_id, client_secret_hash, expected_audience, enabled, tags, created_by, created_at, updated_at";

/// Columns for the `mcp_servers` table (SELECT).
pub const MCP_SERVER_COLUMNS: &str = "id, workspace_id, name, upstream_url, transport, credential_bindings, allowed_tools, enabled, created_by, created_at, updated_at, tags, required_credentials, auth_method, template_key, discovered_tools, created_by_user";

/// Columns for the `oidc_providers` table (SELECT, full).
pub const OIDC_PROVIDER_COLUMNS: &str = "id, name, issuer_url, client_id, encrypted_client_secret, nonce, scopes, role_mapping, auto_provision, enabled, username_claim, created_at, updated_at";

/// Columns for the `oidc_providers` table (SELECT, summary — no encrypted secret/nonce).
pub const OIDC_PROVIDER_SUMMARY_COLUMNS: &str = "id, name, issuer_url, client_id, scopes, role_mapping, auto_provision, enabled, username_claim, created_at, updated_at";

// ---------------------------------------------------------------------------
// Audit filter SQL builder
// ---------------------------------------------------------------------------

/// Result of building a dynamic audit filter query.
/// The `sql` field contains the full SELECT with WHERE/ORDER/LIMIT.
/// The `param_values` field lists the parameter values in bind order.
pub struct AuditFilterQuery {
    pub sql: String,
    pub param_values: Vec<String>,
    pub limit: u32,
    pub offset: u32,
}

/// Build a dynamic audit filter SQL query.
///
/// Returns the complete SQL string and the ordered list of string parameter
/// values to bind. The caller binds them in order. `limit` and `offset` are
/// appended last.
pub fn build_audit_filter_sql(filter: &AuditFilter) -> AuditFilterQuery {
    let base = format!("SELECT {} FROM audit_events", AUDIT_COLUMNS);
    let mut conditions = Vec::new();
    let mut param_values: Vec<String> = Vec::new();

    if let Some(rt) = &filter.resource_type {
        conditions.push("resource_type = ?".to_string());
        param_values.push(rt.to_string());
    }
    if let Some(ri) = &filter.resource_id {
        conditions.push("resource_id = ?".to_string());
        param_values.push(ri.to_string());
    }
    match filter.source.as_deref() {
        Some("device") => conditions.push("workspace_id IS NOT NULL".to_string()),
        Some("server") => conditions.push("workspace_id IS NULL".to_string()),
        _ => {} // "all" or omitted — no filter
    }
    if let Some(action) = &filter.action {
        conditions.push("action = ?".to_string());
        param_values.push(action.to_string());
    }
    if let Some(decision) = &filter.decision {
        conditions.push("decision = ?".to_string());
        param_values.push(decision.to_string());
    }
    if let Some(event_type) = &filter.event_type {
        conditions.push("event_type = ?".to_string());
        param_values.push(event_type.to_string());
    }
    if let Some(workspace_id) = &filter.workspace_id {
        conditions.push("workspace_id = ?".to_string());
        param_values.push(workspace_id.to_string());
    }
    if let Some(workspace_name) = &filter.workspace_name {
        conditions.push("workspace_name = ?".to_string());
        param_values.push(workspace_name.to_string());
    }
    if let Some(user_id) = &filter.user_id {
        conditions.push("user_id = ?".to_string());
        param_values.push(user_id.to_string());
    }
    if !filter.exclude_event_types.is_empty() {
        let placeholders: Vec<String> = filter
            .exclude_event_types
            .iter()
            .map(|et| {
                param_values.push(et.clone());
                "?".to_string()
            })
            .collect();
        conditions.push(format!("event_type NOT IN ({})", placeholders.join(", ")));
    }

    let mut sql = base;
    if !conditions.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&conditions.join(" AND "));
    }
    sql.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");

    AuditFilterQuery {
        sql,
        param_values,
        limit: filter.limit,
        offset: filter.offset,
    }
}

// ---------------------------------------------------------------------------
// Credential update SQL builder
// ---------------------------------------------------------------------------

/// The kind of value a credential update parameter holds.
#[derive(Debug, Clone)]
pub enum CredentialParamValue {
    String(String),
    Bytes(Vec<u8>),
    Int64(i64),
}

/// Result of building a dynamic credential UPDATE query.
pub struct CredentialUpdateQuery {
    pub sql: String,
    pub params: Vec<CredentialParamValue>,
    /// Whether there were actual field changes (vs. just touching updated_at).
    pub has_changes: bool,
}

/// Build a dynamic UPDATE SQL for credential patches.
///
/// The credential id is bound by the caller as the final parameter.
pub fn build_credential_update_sql(
    updates: &CredentialUpdate,
) -> Result<CredentialUpdateQuery, StoreError> {
    let mut set_clauses: Vec<String> = Vec::new();
    let mut params: Vec<CredentialParamValue> = Vec::new();

    if let Some(ref name) = updates.name {
        set_clauses.push("name = ?".to_string());
        params.push(CredentialParamValue::String(name.clone()));
    }
    if let Some(ref service) = updates.service {
        set_clauses.push("service = ?".to_string());
        params.push(CredentialParamValue::String(service.clone()));
    }
    if let Some(ref scopes) = updates.scopes {
        let scopes_json = serde_json::to_string(scopes)
            .map_err(|e| StoreError::Database(format!("serialize scopes: {}", e)))?;
        set_clauses.push("scopes = ?".to_string());
        params.push(CredentialParamValue::String(scopes_json));
    }
    if let Some(ref metadata) = updates.metadata {
        let metadata_json = serde_json::to_string(metadata)
            .map_err(|e| StoreError::Database(format!("serialize metadata: {}", e)))?;
        set_clauses.push("metadata = ?".to_string());
        params.push(CredentialParamValue::String(metadata_json));
    }
    if let Some(ref url_pattern) = updates.allowed_url_pattern {
        if url_pattern.is_empty() {
            // Empty string means "clear the restriction" — set DB column to NULL
            set_clauses.push("allowed_url_pattern = NULL".to_string());
        } else {
            set_clauses.push("allowed_url_pattern = ?".to_string());
            params.push(CredentialParamValue::String(url_pattern.clone()));
        }
    }
    if let Some(ref expires_at) = updates.expires_at {
        set_clauses.push("expires_at = ?".to_string());
        params.push(CredentialParamValue::String(format_timestamp(expires_at)));
    }
    // An empty transform clears the column, the same way an empty URL pattern does.
    if let Some(ref transform_script) = updates.transform_script {
        if transform_script.is_empty() {
            set_clauses.push("transform_script = NULL".to_string());
        } else {
            set_clauses.push("transform_script = ?".to_string());
            params.push(CredentialParamValue::String(transform_script.clone()));
        }
    }
    if let Some(ref transform_name) = updates.transform_name {
        if transform_name.is_empty() {
            set_clauses.push("transform_name = NULL".to_string());
        } else {
            set_clauses.push("transform_name = ?".to_string());
            params.push(CredentialParamValue::String(transform_name.clone()));
        }
    }
    if let Some(ref vault_id) = updates.vault_id {
        set_clauses.push("vault_id = ?".to_string());
        params.push(CredentialParamValue::String(vault_id.clone()));
    }
    if let Some(ref tags) = updates.tags {
        let tags_json = serde_json::to_string(tags)
            .map_err(|e| StoreError::Database(format!("serialize tags: {}", e)))?;
        set_clauses.push("tags = ?".to_string());
        params.push(CredentialParamValue::String(tags_json));
    }
    if let Some(ref description) = updates.description {
        set_clauses.push("description = ?".to_string());
        params.push(CredentialParamValue::String(description.clone()));
    }
    if let Some(ref target_identity) = updates.target_identity {
        set_clauses.push("target_identity = ?".to_string());
        params.push(CredentialParamValue::String(target_identity.clone()));
    }
    if let Some(ref encrypted_value) = updates.encrypted_value {
        set_clauses.push("encrypted_value = ?".to_string());
        params.push(CredentialParamValue::Bytes(encrypted_value.clone()));
    }
    if let Some(ref nonce) = updates.nonce {
        set_clauses.push("nonce = ?".to_string());
        params.push(CredentialParamValue::Bytes(nonce.clone()));
    }
    if let Some(key_version) = updates.key_version {
        set_clauses.push("key_version = ?".to_string());
        params.push(CredentialParamValue::Int64(key_version));
    }

    let has_changes = !set_clauses.is_empty();

    if !has_changes {
        // Nothing to update — just touch updated_at
        let sql = "UPDATE credentials SET updated_at = ? WHERE id = ?".to_string();
        return Ok(CredentialUpdateQuery {
            sql,
            params: Vec::new(), // caller handles now + id
            has_changes: false,
        });
    }

    // Always update updated_at
    let now = format_timestamp(&chrono::Utc::now());
    set_clauses.push("updated_at = ?".to_string());
    params.push(CredentialParamValue::String(now));

    // The caller appends the credential id as the final bind parameter.
    let sql = format!(
        "UPDATE credentials SET {} WHERE id = ?",
        set_clauses.join(", ")
    );

    Ok(CredentialUpdateQuery {
        sql,
        params,
        has_changes: true,
    })
}

// ---------------------------------------------------------------------------
// Shared audit event logging
// ---------------------------------------------------------------------------

/// Emit a structured tracing::info log for an audit event.
///
/// Both backends must log every audit event identically. Centralising the
/// call here prevents drift between the two implementations.
///
/// Optional fields (`resource_id`, `workspace_name`, `user_name`) are logged
/// as Display strings with an empty fallback for `None`, so absent values
/// render as empty rather than the literal string `"None"` that `{:?}` on an
/// `Option::None` produces.
pub fn log_audit_event(event: &AuditEvent) {
    let resource_id = event.resource_id.as_deref().unwrap_or("");
    let workspace_name = event.workspace_name.as_deref().unwrap_or("");
    let user_name = event.user_name.as_deref().unwrap_or("");
    tracing::info!(
        audit_event_id = %event.id,
        event_type = ?event.event_type,
        correlation_id = %event.correlation_id,
        action = %event.action,
        resource_type = %event.resource_type,
        resource_id = %resource_id,
        decision = ?event.decision,
        workspace_name = %workspace_name,
        user_name = %user_name,
        "audit_event"
    );
}
