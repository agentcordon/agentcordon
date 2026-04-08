//! Workspace-authenticated sync endpoints for devices.
//!
//! These endpoints allow authenticated devices (workspace identity JWT) to
//! sync Cedar policies and receive server-push events.

use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::policy::PolicyEngine;

use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::policy::{actions, PolicyContext, PolicyPrincipal, PolicyResource};

use crate::events::UiEvent;
use crate::extractors::AuthenticatedWorkspace;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

/// A single Cedar policy entry for device sync.
#[derive(Serialize)]
pub(super) struct PolicySyncEntry {
    id: String,
    name: String,
    cedar_policy: String,
}

/// Response for `GET /api/v1/workspaces/policies`.
#[derive(Serialize)]
pub(super) struct PolicySyncResponse {
    policies: Vec<PolicySyncEntry>,
}

/// GET /api/v1/workspaces/policies -- sync enabled Cedar policies relevant to this workspace.
///
/// Auth: workspace identity JWT (Authorization: Bearer).
/// Returns only policies the requesting workspace needs for local evaluation:
/// - System/default policies (not per-entity grants or denies)
/// - Per-entity grant/deny policies that specifically reference this workspace
///
/// Per-entity policies follow the naming conventions:
/// - `grant:{cred_id}:{workspace_id}:{action}`
/// - `deny:{cred_id}:{workspace_id}:{action}`
/// - `grant:mcp:{server_id}:{workspace_id}:{action}`
/// - `deny:mcp:{server_id}:{workspace_id}:{action}`
pub(super) async fn sync_policies(
    State(state): State<AppState>,
    workspace: AuthenticatedWorkspace,
) -> Result<Json<ApiResponse<PolicySyncResponse>>, ApiError> {
    let policies = state.store.get_all_enabled_policies().await?;
    let workspace_id_str = workspace.workspace.id.0.to_string();

    let entries: Vec<PolicySyncEntry> = policies
        .into_iter()
        .filter(|p| is_policy_relevant_to_workspace(p, &workspace_id_str))
        .map(|p| PolicySyncEntry {
            id: p.id.0.to_string(),
            name: p.name,
            cedar_policy: p.cedar_policy,
        })
        .collect();

    Ok(Json(ApiResponse::ok(PolicySyncResponse {
        policies: entries,
    })))
}

/// Determine whether a policy is relevant to a specific workspace.
///
/// A policy is relevant if:
/// 1. It is NOT a per-entity grant/deny (i.e., its name does not start with
///    `grant:` or `deny:`), meaning it is a system/default policy, OR
/// 2. It IS a per-entity grant/deny that references the workspace, checked via
///    the policy name containing the workspace UUID or the Cedar text containing
///    the `Workspace::"{workspace_id}"` entity reference.
fn is_policy_relevant_to_workspace(
    policy: &agent_cordon_core::domain::policy::StoredPolicy,
    workspace_id: &str,
) -> bool {
    let is_per_entity = policy.name.starts_with("grant:") || policy.name.starts_with("deny:");
    if !is_per_entity {
        // System/default policy -- always include
        return true;
    }
    // Per-entity grant/deny: include only if it references this workspace.
    // Check the policy name (contains the workspace UUID as a segment) and
    // the Cedar text (contains the Workspace entity reference).
    policy.name.contains(workspace_id) || policy.cedar_policy.contains(workspace_id)
}

// ---------------------------------------------------------------------------
// MCP server sync
// ---------------------------------------------------------------------------

/// Optional query parameters for `GET /api/v1/workspaces/mcp-servers`.
#[derive(Deserialize, Default)]
pub(super) struct McpSyncQuery {
    /// When true, include ECIES-encrypted credential envelopes in the response.
    #[serde(default)]
    pub include_credentials: bool,
    /// Base64url-encoded uncompressed P-256 public key (65 bytes).
    /// Required when `include_credentials` is true.
    pub broker_public_key: Option<String>,
}

/// A single MCP server entry for device sync.
#[derive(Serialize)]
pub(super) struct McpServerSyncEntry {
    pub id: String,
    pub name: String,
    pub transport: String,
    pub url: Option<String>,
    pub tools: Vec<String>,
    pub enabled: bool,
    pub required_credentials: Option<Vec<String>>,
    pub auth_method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_envelopes: Option<Vec<McpCredentialEnvelope>>,
}

/// An ECIES-encrypted credential envelope for a single credential.
#[derive(Serialize)]
pub(super) struct McpCredentialEnvelope {
    pub credential_name: String,
    pub credential_type: String,
    pub transform_name: Option<String>,
    pub encrypted_envelope: EncryptedEnvelopeResponse,
}

/// Wire format for an ECIES encrypted envelope.
#[derive(Serialize)]
pub(super) struct EncryptedEnvelopeResponse {
    pub version: u8,
    pub ephemeral_public_key: String,
    pub ciphertext: String,
    pub nonce: String,
    pub aad: String,
}

/// Response for `GET /api/v1/workspaces/mcp-servers`.
#[derive(Serialize)]
pub(super) struct McpServerSyncResponse {
    pub servers: Vec<McpServerSyncEntry>,
}

use crate::crypto_helpers::parse_broker_public_key;

/// Cedar policy check: can this workspace see this MCP server?
///
/// Evaluates `mcp_list_tools` against the McpServer entity (with owner) for the
/// authenticated workspace. Used to filter MCP server and tool listings before
/// returning them to the broker.
fn workspace_can_view_mcp_server(
    state: &AppState,
    workspace: &AuthenticatedWorkspace,
    server: &agent_cordon_core::domain::mcp::McpServer,
) -> bool {
    let decision = state.policy_engine.evaluate(
        &PolicyPrincipal::Workspace(&workspace.workspace),
        actions::MCP_LIST_TOOLS,
        &PolicyResource::McpServer {
            id: server.id.0.to_string(),
            name: server.name.clone(),
            enabled: server.enabled,
            tags: server.tags.clone(),
            owner: server.created_by_user.clone(),
        },
        &PolicyContext::default(),
    );
    matches!(
        decision,
        Ok(d) if d.decision == PolicyDecisionResult::Permit
    )
}

/// GET /api/v1/workspaces/mcp-servers -- list MCP servers for the authenticated workspace.
///
/// Auth: workspace identity JWT (Authorization: Bearer).
/// Returns all enabled MCP servers belonging to this workspace so the device
/// can populate its local cache and serve them to agents.
///
/// Optional query params:
/// - `include_credentials=true` — include ECIES-encrypted credential envelopes
/// - `broker_public_key=<base64url>` — P-256 public key for envelope encryption
pub(super) async fn sync_mcp_servers(
    State(state): State<AppState>,
    workspace: AuthenticatedWorkspace,
    Query(query): Query<McpSyncQuery>,
) -> Result<Json<ApiResponse<McpServerSyncResponse>>, ApiError> {
    // Validate: include_credentials requires broker_public_key
    let broker_pub_bytes = if query.include_credentials {
        let key_str = query.broker_public_key.as_deref().ok_or_else(|| {
            ApiError::BadRequest(
                "broker_public_key is required when include_credentials=true".to_string(),
            )
        })?;
        Some(parse_broker_public_key(key_str)?)
    } else {
        None
    };

    // Cedar-filter MCP servers by `mcp_list_tools` for this workspace.
    // Under the owner-based default policy, workspaces only see servers owned
    // by the same user (plus any with explicit grants).
    let all_servers = state.store.list_mcp_servers().await?;
    let servers: Vec<_> = all_servers
        .into_iter()
        .filter(|s| s.enabled)
        .filter(|s| workspace_can_view_mcp_server(&state, &workspace, s))
        .collect();

    let mut entries = Vec::new();
    for s in servers {
        let credential_envelopes = if let Some(ref pub_bytes) = broker_pub_bytes {
            // Encrypt each required credential for the broker
            let envelopes = encrypt_server_credentials(&state, &workspace, &s, pub_bytes).await?;
            if envelopes.is_empty() {
                None
            } else {
                Some(envelopes)
            }
        } else {
            None
        };

        entries.push(McpServerSyncEntry {
            id: s.id.0.to_string(),
            name: s.name.clone(),
            transport: s.transport.to_string(),
            url: if s.upstream_url.is_empty() {
                None
            } else {
                Some(s.upstream_url)
            },
            tools: s.allowed_tools.unwrap_or_default(),
            enabled: s.enabled,
            required_credentials: s
                .required_credentials
                .map(|creds| creds.iter().map(|c| c.0.to_string()).collect()),
            auth_method: s.auth_method.to_string(),
            credential_envelopes,
        });
    }

    Ok(Json(ApiResponse::ok(McpServerSyncResponse {
        servers: entries,
    })))
}

/// For a given MCP server, look up each required credential, check Cedar
/// authorization, decrypt (AES-GCM), re-encrypt (ECIES) to the broker's
/// public key, and return the envelopes. Unauthorized or missing credentials
/// are silently excluded.
async fn encrypt_server_credentials(
    state: &AppState,
    workspace: &AuthenticatedWorkspace,
    server: &agent_cordon_core::domain::mcp::McpServer,
    broker_pub_bytes: &[u8],
) -> Result<Vec<McpCredentialEnvelope>, ApiError> {
    let cred_ids = match &server.required_credentials {
        Some(ids) if !ids.is_empty() => ids,
        _ => return Ok(Vec::new()),
    };

    let mut envelopes = Vec::new();
    let ws_id_str = workspace.workspace.id.0.to_string();

    for cred_id in cred_ids {
        // Look up credential
        let cred = match state.store.get_credential(cred_id).await? {
            Some(c) => c,
            None => {
                tracing::warn!(credential_id = %cred_id.0, server = %server.name, "required credential not found, skipping");
                continue;
            }
        };

        // Skip expired credentials
        if cred.is_expired() {
            tracing::warn!(credential_id = %cred_id.0, server = %server.name, "required credential expired, skipping");
            continue;
        }

        // Cedar policy check: can this workspace vend this credential?
        let decision = state.policy_engine.evaluate(
            &PolicyPrincipal::Workspace(&workspace.workspace),
            actions::VEND_CREDENTIAL,
            &PolicyResource::Credential {
                credential: cred.clone(),
            },
            &PolicyContext::default(),
        )?;

        if decision.decision == PolicyDecisionResult::Forbid {
            tracing::debug!(credential_id = %cred_id.0, server = %server.name, "credential not authorized for workspace, skipping");
            continue;
        }

        // For oauth2_user_authorization credentials, include token exchange
        // metadata inside the ECIES envelope so the broker can refresh tokens.
        let (envelope, _vend_id) = if cred.credential_type == "oauth2_user_authorization" {
            let mut meta = std::collections::HashMap::new();
            if let Some(token_url) = cred
                .metadata
                .get("oauth2_token_url")
                .and_then(|v| v.as_str())
            {
                meta.insert("oauth2_token_url".to_string(), token_url.to_string());
            }
            if let Some(cid) = cred
                .metadata
                .get("oauth2_client_id")
                .and_then(|v| v.as_str())
            {
                meta.insert("oauth2_client_id".to_string(), cid.to_string());
            }
            // Include client_secret from the OAuth provider client row that
            // owns this credential. Look up by authorization_server_url stored
            // in credential metadata at provisioning time.
            if let Some(as_url) = cred
                .metadata
                .get("authorization_server_url")
                .and_then(|v| v.as_str())
            {
                let lookup = state
                    .store
                    .get_oauth_provider_client_by_authorization_server_url(as_url)
                    .await;
                match lookup {
                    Ok(Some(app))
                        if app.enabled
                            && app.encrypted_client_secret.is_some()
                            && app.nonce.is_some() =>
                    {
                        let enc = app.encrypted_client_secret.as_ref().unwrap();
                        let n = app.nonce.as_ref().unwrap();
                        match state
                            .encryptor
                            .decrypt(enc, n, app.id.0.to_string().as_bytes())
                        {
                            Ok(secret_bytes) => {
                                if let Ok(secret) = String::from_utf8(secret_bytes) {
                                    meta.insert("oauth2_client_secret".to_string(), secret);
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    authorization_server_url = %as_url,
                                    "failed to decrypt OAuth provider client secret for sync"
                                );
                            }
                        }
                    }
                    Ok(_) => {
                        tracing::debug!(
                            authorization_server_url = %as_url,
                            "no enabled OAuth provider client for credential sync"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            authorization_server_url = %as_url,
                            "failed to look up OAuth provider client for credential sync"
                        );
                    }
                }
            }
            crate::crypto_helpers::reencrypt_credential_with_metadata(
                state.encryptor.as_ref(),
                &cred,
                &ws_id_str,
                broker_pub_bytes,
                meta,
            )
            .await?
        } else {
            crate::crypto_helpers::reencrypt_credential_for_device(
                state.encryptor.as_ref(),
                &cred,
                &ws_id_str,
                broker_pub_bytes,
            )
            .await?
        };

        envelopes.push(McpCredentialEnvelope {
            credential_name: cred.name.clone(),
            credential_type: cred.credential_type.clone(),
            transform_name: cred.transform_name.clone(),
            encrypted_envelope: EncryptedEnvelopeResponse {
                version: envelope.version,
                ephemeral_public_key: envelope.ephemeral_public_key,
                ciphertext: envelope.ciphertext,
                nonce: envelope.nonce,
                aad: envelope.aad,
            },
        });
    }

    Ok(envelopes)
}

// ---------------------------------------------------------------------------
// MCP tool sync
// ---------------------------------------------------------------------------

/// A single MCP tool entry for device sync.
#[derive(Serialize)]
pub(super) struct McpToolSyncEntry {
    pub server: String,
    pub tool: String,
    pub description: Option<String>,
    pub input_schema: Option<serde_json::Value>,
}

/// GET /api/v1/workspaces/mcp-tools -- list MCP tools from all enabled servers.
///
/// Auth: workspace identity JWT (Authorization: Bearer).
/// Cedar-filtered: only returns tools from servers the workspace can list.
pub(super) async fn sync_mcp_tools(
    State(state): State<AppState>,
    workspace: AuthenticatedWorkspace,
) -> Result<Json<ApiResponse<Vec<McpToolSyncEntry>>>, ApiError> {
    let servers = state.store.list_mcp_servers().await?;

    let entries: Vec<McpToolSyncEntry> = servers
        .into_iter()
        .filter(|s| s.enabled)
        .filter(|s| workspace_can_view_mcp_server(&state, &workspace, s))
        .flat_map(|s| {
            let server_name = s.name.clone();
            // Prefer discovered_tools (has descriptions) over allowed_tools (names only)
            if let Some(discovered) = s.discovered_tools {
                discovered
                    .into_iter()
                    .map(move |tool| McpToolSyncEntry {
                        server: server_name.clone(),
                        tool: tool.name,
                        description: tool.description,
                        input_schema: tool.input_schema,
                    })
                    .collect::<Vec<_>>()
            } else {
                s.allowed_tools
                    .unwrap_or_default()
                    .into_iter()
                    .map(|tool_name| McpToolSyncEntry {
                        server: server_name.clone(),
                        tool: tool_name,
                        description: None,
                        input_schema: None,
                    })
                    .collect::<Vec<_>>()
            }
        })
        .collect();

    Ok(Json(ApiResponse::ok(entries)))
}

// ---------------------------------------------------------------------------
// MCP tool reporting
// ---------------------------------------------------------------------------

/// Request body for `POST /api/v1/workspaces/mcp-report-tools`.
#[derive(Deserialize)]
pub(super) struct ReportToolsRequest {
    server_name: String,
    tools: Vec<ReportedTool>,
}

#[derive(Deserialize)]
pub(super) struct ReportedTool {
    name: String,
    #[allow(dead_code)]
    description: Option<String>,
}

/// POST /api/v1/workspaces/mcp-report-tools -- workspace reports discovered tools for an MCP server.
///
/// Auth: workspace identity JWT (Authorization: Bearer).
/// Updates `allowed_tools` on the matching MCP server record so the web UI
/// and policy engine know which tools are available.
pub(super) async fn report_tools(
    State(state): State<AppState>,
    workspace: AuthenticatedWorkspace,
    Json(req): Json<ReportToolsRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let ws_id = &workspace.workspace.id;

    // Look up by name, scoped to the requesting workspace's own servers.
    let all_servers = state.store.list_mcp_servers().await?;
    let server = all_servers
        .into_iter()
        .find(|s| {
            s.name == req.server_name && s.enabled && s.workspace_id == workspace.workspace.id
        })
        .ok_or_else(|| ApiError::NotFound(format!("MCP server '{}' not found", req.server_name)))?;

    let tool_names: Vec<String> = req.tools.iter().map(|t| t.name.clone()).collect();
    let tool_count = tool_names.len();

    let mut updated = server.clone();
    updated.allowed_tools = Some(tool_names);
    updated.updated_at = chrono::Utc::now();
    state.store.update_mcp_server(&updated).await?;

    // Notify UI of updated tools
    state.ui_event_bus.emit(UiEvent::McpServerChanged {
        server_name: req.server_name.clone(),
    });

    tracing::info!(
        server = %req.server_name,
        workspace = %ws_id.0,
        tools = tool_count,
        "workspace reported MCP tools"
    );

    Ok(Json(ApiResponse::ok(serde_json::json!({
        "server_name": req.server_name,
        "tools_updated": tool_count,
    }))))
}
