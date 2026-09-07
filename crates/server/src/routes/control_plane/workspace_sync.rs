//! Workspace-authenticated sync endpoints for the broker.
//!
//! The broker lists the MCP servers and tools bound to its workspace here,
//! optionally receiving ECIES-encrypted credential envelopes. OAuth-backed
//! credentials are exchanged for upstream access tokens on the server
//! (`crate::services::upstream_tokens`) before they are sealed.

use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::policy::{actions, PolicyPrincipal, PolicyResource};
use axum::{
    extract::{Query, State},
    Json,
};

use crate::extractors::AuthenticatedWorkspace;
use crate::response::{ApiError, ApiResponse};
use crate::services::credentials::SealError;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// MCP server sync
// ---------------------------------------------------------------------------

pub(super) use agent_cordon_core::wire::mcp::{
    McpCredentialEnvelope, McpServerSyncEntry, McpServerSyncResponse, McpSyncQuery,
    McpToolSyncEntry,
};
use agent_cordon_core::wire::EncryptedEnvelopeWire;

use crate::crypto_helpers::parse_broker_public_key;

/// The one-line description of the catalog template a server was
/// provisioned from. An MCP server record carries no description of its
/// own; the template it came from is the only place one exists, so this is
/// what the broker (and `agentcordon mcp-servers`) can show.
fn template_description(state: &AppState, template_key: Option<&str>) -> Option<String> {
    let key = template_key?;
    state
        .catalog
        .mcp_templates
        .iter()
        .find(|t| t.key == key)
        .map(|t| t.description.clone())
}

/// Cedar policy check: can this workspace see this MCP server?
///
/// Evaluates `mcp_list_tools` against the McpServer entity (with owner) for the
/// authenticated workspace. Used to filter MCP server and tool listings before
/// returning them to the broker.
async fn workspace_can_view_mcp_server(
    state: &AppState,
    workspace: &AuthenticatedWorkspace,
    server: &agent_cordon_core::domain::mcp::McpServer,
) -> bool {
    let decision = state
        .authz
        .request(
            crate::authz::PolicyCaller::Principal {
                principal: PolicyPrincipal::Workspace(&workspace.workspace),
                oauth_claims: workspace.oauth_claims.clone(),
            },
            &uuid::Uuid::new_v4().to_string(),
        )
        .check_with_reasons(
            actions::MCP_LIST_TOOLS,
            &PolicyResource::McpServer {
                id: server.id.0.to_string(),
                name: server.name.clone(),
                enabled: server.enabled,
                tags: server.tags.clone(),
                owner: server.created_by_user.clone(),
            },
        )
        .await;
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

    // Join through `mcp_server_workspaces` — returns only enabled MCPs bound to
    // this workspace via the junction. Cedar policy 3a (same-owner) is still
    // evaluated as a defense-in-depth gate on top of the routing junction.
    let bound_servers = state
        .store
        .list_mcp_servers_for_workspace(&workspace.workspace.id)
        .await?;
    let mut servers: Vec<_> = Vec::new();
    for s in bound_servers.into_iter() {
        if workspace_can_view_mcp_server(&state, &workspace, &s).await {
            servers.push(s);
        }
    }

    let mut entries = Vec::new();
    for s in servers {
        let (credential_envelopes, credential_error) = if let Some(ref pub_bytes) = broker_pub_bytes
        {
            // Encrypt each required credential for the broker
            let sealed = encrypt_server_credentials(&state, &workspace, &s, pub_bytes).await?;
            (
                (!sealed.envelopes.is_empty()).then_some(sealed.envelopes),
                (!sealed.errors.is_empty()).then(|| sealed.errors.join("; ")),
            )
        } else {
            (None, None)
        };

        entries.push(McpServerSyncEntry {
            id: s.id.0.to_string(),
            name: s.name.clone(),
            description: template_description(&state, s.template_key.as_deref()),
            transport: s.transport.to_string(),
            url: if s.upstream_url.is_empty() {
                None
            } else {
                Some(s.upstream_url)
            },
            tools_are_authoritative: s.allowed_tools.is_some(),
            tools: s.allowed_tools.unwrap_or_default(),
            enabled: s.enabled,
            required_credentials: s
                .required_credentials
                .map(|creds| creds.iter().map(|c| c.0.to_string()).collect()),
            auth_method: s.auth_method.to_string(),
            credential_envelopes,
            credential_error,
        });
    }

    Ok(Json(ApiResponse::ok(McpServerSyncResponse {
        servers: entries,
    })))
}

/// The credentials sealed for one MCP server, and the ones that could not be.
struct SealedCredentials {
    envelopes: Vec<McpCredentialEnvelope>,
    /// One entry per credential the server could not produce a token for.
    errors: Vec<String>,
}

/// For a given MCP server, look up each required credential, check Cedar
/// authorization, produce the material the broker may hold, and seal it
/// (ECIES) to the broker's public key. Unauthorized or missing credentials
/// are silently excluded; an upstream token exchange that fails is reported
/// in `errors` so the rest of the sync still lands.
async fn encrypt_server_credentials(
    state: &AppState,
    workspace: &AuthenticatedWorkspace,
    server: &agent_cordon_core::domain::mcp::McpServer,
    broker_pub_bytes: &[u8],
) -> Result<SealedCredentials, ApiError> {
    let mut sealed = SealedCredentials {
        envelopes: Vec::new(),
        errors: Vec::new(),
    };
    let cred_ids = match &server.required_credentials {
        Some(ids) if !ids.is_empty() => ids,
        _ => return Ok(sealed),
    };

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
        let decision = state
            .authz
            .request(
                crate::authz::PolicyCaller::Principal {
                    principal: PolicyPrincipal::Workspace(&workspace.workspace),
                    oauth_claims: workspace.oauth_claims.clone(),
                },
                &uuid::Uuid::new_v4().to_string(),
            )
            .check_with_reasons(
                actions::VEND_CREDENTIAL,
                &PolicyResource::Credential {
                    credential: cred.clone(),
                },
            )
            .await?;

        if decision.decision == PolicyDecisionResult::Forbid {
            tracing::debug!(credential_id = %cred_id.0, server = %server.name, "credential not authorized for workspace, skipping");
            continue;
        }

        // OAuth-backed credentials: the broker gets an upstream access
        // token, never the refresh token or client secret behind it. An
        // exchange that fails is reported so the rest of the sync lands.
        let (envelope, _vend_id) = match state
            .services
            .credentials
            .seal_for_broker(&cred, &workspace.workspace, broker_pub_bytes, "sync")
            .await
        {
            Ok(sealed) => sealed,
            Err(SealError::Upstream(e)) => {
                tracing::warn!(
                    error = %e,
                    credential_id = %cred_id.0,
                    server = %server.name,
                    "upstream token exchange failed during MCP sync"
                );
                sealed.errors.push(e.to_string());
                continue;
            }
            Err(SealError::Api(e)) => return Err(e),
        };

        sealed.envelopes.push(McpCredentialEnvelope {
            credential_name: cred.name.clone(),
            credential_type: cred.credential_type.clone(),
            transform_name: cred.transform_name.clone(),
            encrypted_envelope: EncryptedEnvelopeWire {
                version: envelope.version,
                ephemeral_public_key: envelope.ephemeral_public_key,
                ciphertext: envelope.ciphertext,
                nonce: envelope.nonce,
                aad: envelope.aad,
            },
        });
    }

    Ok(sealed)
}

// ---------------------------------------------------------------------------
// MCP tool sync
// ---------------------------------------------------------------------------

/// GET /api/v1/workspaces/mcp-tools -- list MCP tools from all enabled servers.
///
/// Auth: workspace identity JWT (Authorization: Bearer).
/// Cedar-filtered: only returns tools from servers the workspace can list.
pub(super) async fn sync_mcp_tools(
    State(state): State<AppState>,
    workspace: AuthenticatedWorkspace,
) -> Result<Json<ApiResponse<Vec<McpToolSyncEntry>>>, ApiError> {
    let bound_servers = state
        .store
        .list_mcp_servers_for_workspace(&workspace.workspace.id)
        .await?;
    let mut filtered = Vec::new();
    for s in bound_servers.into_iter() {
        if workspace_can_view_mcp_server(&state, &workspace, &s).await {
            filtered.push(s);
        }
    }
    let entries: Vec<McpToolSyncEntry> = filtered
        .into_iter()
        .flat_map(|s| {
            let server_name = s.name.clone();
            // Prefer discovered_tools (it has the descriptions and schemas)
            // over allowed_tools (names only), but only for the tools
            // `allowed_tools` admits: it is the allow-list, and a broker must
            // never be handed a tool an operator has narrowed away.
            if let Some(discovered) = s.discovered_tools {
                let allowed = s.allowed_tools;
                discovered
                    .into_iter()
                    .filter(|tool| {
                        allowed
                            .as_deref()
                            .is_none_or(|names| names.contains(&tool.name))
                    })
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
