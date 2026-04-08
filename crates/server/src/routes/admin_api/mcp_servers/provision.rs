//! MCP server provisioning from the template catalog.
//!
//! `POST /api/v1/mcp-servers/provision` — one-click provisioning of an MCP
//! server from a catalog template. Creates the server record, optionally
//! creates or links a credential, and emits an audit event.
//!
//! No Cedar policy is auto-generated — the default policy already permits
//! workspaces to list tools and call tools on enabled MCP servers.

use axum::{extract::State, Json};
use serde::Deserialize;
use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::credential::CredentialId;
use agent_cordon_core::domain::mcp::{McpAuthMethod, McpServer, McpServerId, McpTransport};
use agent_cordon_core::domain::workspace::WorkspaceId;

use agent_cordon_core::crypto::SecretEncryptor;
use crate::credential_service::{self, NewCredentialParams};
use crate::events::UiEvent;
use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

use super::{check_manage_mcp_servers, McpServerResponse};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProvisionRequest {
    pub template_key: String,
    pub workspace_id: Uuid,
    /// Use an existing credential by ID.
    pub credential_id: Option<Uuid>,
    /// Create a new credential with this secret value.
    pub secret_value: Option<String>,
}

/// `POST /api/v1/mcp-servers/provision`
///
/// Provision an MCP server from a catalog template for a workspace.
pub(crate) async fn provision_from_catalog(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<ProvisionRequest>,
) -> Result<Json<ApiResponse<McpServerResponse>>, ApiError> {
    // 1. Cedar policy check: manage_mcp_servers.
    let policy_decision = check_manage_mcp_servers(&state, &auth)?;

    // 2. Look up template
    let template = state
        .mcp_templates
        .iter()
        .find(|t| t.key == req.template_key)
        .ok_or_else(|| {
            ApiError::NotFound(format!(
                "MCP template '{}' not found",
                req.template_key
            ))
        })?
        .clone();

    // 3. Verify workspace exists
    let workspace_id = WorkspaceId(req.workspace_id);
    let workspace = state
        .store
        .get_workspace(&workspace_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("workspace not found".to_string()))?;

    // 4. Check for duplicate: user already has server with this template_key
    let user_servers = state
        .store
        .list_mcp_servers_by_user(&auth.user.id)
        .await?;
    if user_servers
        .iter()
        .any(|s| s.template_key.as_deref() == Some(&req.template_key))
    {
        return Err(ApiError::Conflict(format!(
            "you already have an MCP server from template '{}'",
            req.template_key
        )));
    }

    // 5. Resolve auth method from template
    let auth_method = McpAuthMethod::from_str_opt(&template.auth_method).unwrap_or_default();

    // 6. Resolve credential
    let credential_id = match (&req.credential_id, &req.secret_value) {
        (Some(cid), _) => {
            // Verify credential exists and is accessible to this workspace.
            // Non-admin users can only use credentials they own; admin can use any.
            let cred_id = CredentialId(*cid);
            let cred = state
                .store
                .get_credential(&cred_id)
                .await?
                .ok_or_else(|| ApiError::NotFound("credential not found".to_string()))?;

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
            Some(cred_id)
        }
        (None, Some(secret)) => {
            // Create new credential from template metadata
            let service = template
                .credential_template_key
                .clone()
                .unwrap_or_else(|| template.key.clone());
            let cred_name = format!("{}-{}", template.key, workspace.name);
            let cred = credential_service::build_credential(
                state.encryptor.as_ref(),
                NewCredentialParams {
                    name: cred_name.clone(),
                    service,
                    secret_value: secret.clone(),
                    credential_type: "generic".to_string(),
                    scopes: vec![],
                    metadata: serde_json::json!({}),
                    tags: vec![format!("mcp:{}", template.key)],
                    vault: "default".to_string(),
                    created_by: None,
                    created_by_user: Some(auth.user.id.clone()),
                    allowed_url_pattern: Some(format!("{}*", template.upstream_url)),
                    expires_at: None,
                    transform_script: None,
                    // TODO: When OAuth2 MCP templates are supported, the transform should
                    // come from the template's auth configuration, not hardcoded as "bearer".
                    transform_name: Some("bearer".to_string()),
                    description: Some(format!(
                        "Auto-created for MCP server '{}' on workspace '{}'",
                        template.name, workspace.name
                    )),
                    target_identity: None,
                },
            )?;
            state.store.store_credential(&cred).await?;
            credential_service::emit_credential_created(
                &state,
                cred.id.0,
                cred_name,
            );
            Some(cred.id)
        }
        (None, None) => {
            if auth_method == McpAuthMethod::ApiKey {
                return Err(ApiError::BadRequest(
                    "credential_id or secret_value required for API key auth method".to_string(),
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
        workspace_id: workspace_id.clone(),
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
    state.store.create_mcp_server(&server).await?;

    // 7b. Best-effort tool discovery — call tools/list on the upstream MCP server.
    // This populates allowed_tools so that `agentcordon mcp-tools` works immediately
    // after provisioning. Failures are non-fatal (tools can be discovered later).
    //
    // When credential_id was used (no secret_value), decrypt the existing credential
    // so discovery can authenticate against upstream servers that require auth on tools/list.
    let discovery_secret: Option<String> = match (&req.credential_id, &req.secret_value) {
        (_, Some(secret)) => Some(secret.clone()),
        (Some(cid), None) => {
            let cred_id = CredentialId(*cid);
            state
                .store
                .get_credential(&cred_id)
                .await
                .ok()
                .flatten()
                .and_then(|cred| {
                    state
                        .encryptor
                        .decrypt(
                            &cred.encrypted_value,
                            &cred.nonce,
                            cred.id.0.to_string().as_bytes(),
                        )
                        .ok()
                        .and_then(|bytes| String::from_utf8(bytes).ok())
                })
        }
        _ => None,
    };

    // Validate the credential by probing the upstream MCP server. If discovery
    // fails specifically with an authentication error (HTTP 401/403), we reject
    // the install BEFORE persisting the server — this catches the "wrong key
    // pasted into install form" failure mode. Other failures (network errors,
    // upstream not reachable) are non-fatal: the user may be installing for a
    // server they'll bring online later.
    let provided_credential = discovery_secret.is_some();
    match super::discover::attempt_tool_discovery(&state, &server, discovery_secret.as_deref()).await {
        Ok(tools) if !tools.is_empty() => {
            let mut updated = server.clone();
            updated.allowed_tools = Some(tools.iter().map(|t| t.name.clone()).collect());
            updated.discovered_tools = Some(tools);
            if let Err(e) = state.store.update_mcp_server(&updated).await {
                tracing::warn!(error = %e, server = %server.name, "failed to update discovered tools");
            }
        }
        Ok(_) => {
            tracing::debug!(server = %server.name, "tool discovery returned empty list");
        }
        Err(e) => {
            // Check if the error is an auth error (HTTP 401/403). The discovery
            // helper formats these as "HTTP 401" or "HTTP 403".
            let is_auth_error = e.contains("HTTP 401") || e.contains("HTTP 403");
            if is_auth_error && provided_credential {
                tracing::warn!(server = %server.name, error = %e, "credential rejected by upstream during provision");
                // Roll back: delete the server we just created so the user can retry.
                let _ = state.store.delete_mcp_server(&server.id).await;
                if let Some(cid) = &credential_id {
                    let _ = state.store.delete_credential(cid).await;
                }
                return Err(ApiError::BadRequest(format!(
                    "The credential you provided was rejected by the MCP server ({e}). \
                     Please check the secret and try again."
                )));
            }
            tracing::debug!(server = %server.name, error = %e, "tool discovery failed (non-fatal)");
        }
    }

    let server_id_str = server.id.0.to_string();
    let workspace_id_str = workspace_id.0.to_string();

    // Emit UI event
    state.ui_event_bus.emit(UiEvent::McpServerChanged {
        server_name: server.name.clone(),
    });

    // 10. Audit event
    let event = AuditEvent::builder(AuditEventType::McpServerProvisioned)
        .action("provision")
        .user_actor(&auth.user)
        .resource("mcp_server", &server_id_str)
        .correlation_id(&corr.0)
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
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    // 11. Return response
    let mut resp = McpServerResponse::from_server(&server);
    resp.workspace_name = Some(workspace.name);
    Ok(Json(ApiResponse::ok(resp)))
}
