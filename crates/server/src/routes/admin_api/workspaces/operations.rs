use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_core::policy::{
    actions, PolicyContext, PolicyEngine, PolicyPrincipal, PolicyResource,
};

use crate::events::UiEvent;
use crate::extractors::{AuthenticatedUser, AuthenticatedWorkspace};
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

use super::{PermissionsResponse, WorkspaceResponse};

// ============================================================================
// Tag Management
// ============================================================================

#[derive(Deserialize)]
pub(super) struct AddTagRequest {
    tag: String,
}

/// POST /api/v1/workspaces/{id}/tags — add a tag to a workspace (user auth required).
pub(super) async fn add_workspace_tag(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
    Json(req): Json<AddTagRequest>,
) -> Result<Json<ApiResponse<WorkspaceResponse>>, ApiError> {
    let target_id = WorkspaceId(id);
    let tag = req.tag.trim().to_string();
    if tag.is_empty() || tag.len() > 128 {
        return Err(ApiError::BadRequest(
            "tag must be 1-128 characters".to_string(),
        ));
    }

    // Non-admin users cannot assign the "admin" tag
    let is_admin =
        auth.user.role == agent_cordon_core::domain::user::UserRole::Admin || auth.is_root;
    if !is_admin && tag.eq_ignore_ascii_case("admin") {
        return Err(ApiError::Forbidden(
            "only admins can assign the \"admin\" tag".to_string(),
        ));
    }

    let workspace = state
        .store
        .get_workspace(&target_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("workspace not found".to_string()))?;

    // Evaluate Cedar manage_tags policy
    let decision = state.policy_engine.evaluate(
        &PolicyPrincipal::User(&auth.user),
        actions::MANAGE_TAGS,
        &PolicyResource::WorkspaceResource {
            workspace: workspace.clone(),
        },
        &PolicyContext {
            tag_value: Some(tag.clone()),
            correlation_id: Some(corr.0.clone()),
            ..Default::default()
        },
    )?;

    let now = chrono::Utc::now();

    if decision.decision == PolicyDecisionResult::Forbid {
        // Audit: denied
        let event = AuditEvent::builder(AuditEventType::WorkspaceUpdated)
            .action("add_tag")
            .user_actor(&auth.user)
            .resource("workspace", &workspace.id.0.to_string())
            .correlation_id(&corr.0)
            .decision(AuditDecision::Forbid, Some(&decision.reasons.join(", ")))
            .details(serde_json::json!({
                "tag": tag,
                "workspace_name": workspace.name,
            }))
            .build();
        if let Err(e) = state.store.append_audit_event(&event).await {
            tracing::warn!(error = %e, "Failed to write audit event");
        }
        return Err(ApiError::Forbidden("access denied by policy".to_string()));
    }

    // Add tag if not already present
    let mut updated_workspace = workspace.clone();
    if !updated_workspace.tags.contains(&tag) {
        updated_workspace.tags.push(tag.clone());
    }
    updated_workspace.updated_at = now;
    state.store.update_workspace(&updated_workspace).await?;

    // Audit: allowed
    let event = AuditEvent::builder(AuditEventType::WorkspaceUpdated)
        .action("add_tag")
        .user_actor(&auth.user)
        .resource("workspace", &updated_workspace.id.0.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some(&decision.reasons.join(", ")))
        .details(serde_json::json!({
            "tag": tag,
            "workspace_name": updated_workspace.name,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    // Emit UI event for browser auto-refresh
    state.ui_event_bus.emit(UiEvent::WorkspaceUpdated {
        workspace_id: updated_workspace.id.0,
    });

    let resp = WorkspaceResponse::from_workspace(updated_workspace);
    Ok(Json(ApiResponse::ok(resp)))
}

/// DELETE /api/v1/workspaces/{id}/tags/{tag} — remove a tag from a workspace (user auth required).
pub(super) async fn remove_workspace_tag(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path((id, tag)): Path<(Uuid, String)>,
) -> Result<Json<ApiResponse<WorkspaceResponse>>, ApiError> {
    let target_id = WorkspaceId(id);
    let tag = tag.trim().to_string();

    let workspace = state
        .store
        .get_workspace(&target_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("workspace not found".to_string()))?;

    // Evaluate Cedar manage_tags policy
    let decision = state.policy_engine.evaluate(
        &PolicyPrincipal::User(&auth.user),
        actions::MANAGE_TAGS,
        &PolicyResource::WorkspaceResource {
            workspace: workspace.clone(),
        },
        &PolicyContext {
            tag_value: Some(tag.clone()),
            correlation_id: Some(corr.0.clone()),
            ..Default::default()
        },
    )?;

    let now = chrono::Utc::now();

    if decision.decision == PolicyDecisionResult::Forbid {
        let event = AuditEvent::builder(AuditEventType::WorkspaceUpdated)
            .action("remove_tag")
            .user_actor(&auth.user)
            .resource("workspace", &workspace.id.0.to_string())
            .correlation_id(&corr.0)
            .decision(AuditDecision::Forbid, Some(&decision.reasons.join(", ")))
            .details(serde_json::json!({
                "tag": tag,
                "workspace_name": workspace.name,
            }))
            .build();
        if let Err(e) = state.store.append_audit_event(&event).await {
            tracing::warn!(error = %e, "Failed to write audit event");
        }
        return Err(ApiError::Forbidden("access denied by policy".to_string()));
    }

    // Remove tag
    let mut updated_workspace = workspace.clone();
    updated_workspace.tags.retain(|t| t != &tag);
    updated_workspace.updated_at = now;
    state.store.update_workspace(&updated_workspace).await?;

    // Audit: allowed
    let event = AuditEvent::builder(AuditEventType::WorkspaceUpdated)
        .action("remove_tag")
        .user_actor(&auth.user)
        .resource("workspace", &updated_workspace.id.0.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some(&decision.reasons.join(", ")))
        .details(serde_json::json!({
            "tag": tag,
            "workspace_name": updated_workspace.name,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    // Emit UI event for browser auto-refresh
    state.ui_event_bus.emit(UiEvent::WorkspaceUpdated {
        workspace_id: updated_workspace.id.0,
    });

    let resp = WorkspaceResponse::from_workspace(updated_workspace);
    Ok(Json(ApiResponse::ok(resp)))
}

// ============================================================================
// Workspace MCP Permissions
// ============================================================================

/// GET /api/v1/workspaces/{id}/permissions — issue MCP permissions JWT for a workspace.
///
/// Authenticates the calling workspace, validates it, evaluates Cedar policies
/// for each enabled MCP server, and returns a server-signed JWT with 3-part scopes.
pub(super) async fn get_workspace_permissions(
    State(state): State<AppState>,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    auth_ws: AuthenticatedWorkspace,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<PermissionsResponse>>, ApiError> {
    // 1. Workspace authenticated via AuthenticatedWorkspace extractor
    let oauth_claims = auth_ws.oauth_claims;
    let caller_workspace = auth_ws.workspace;
    let workspace_name = &caller_workspace.name;

    // 2. Load and validate workspace
    let workspace_id = WorkspaceId(id);
    let workspace = state
        .store
        .get_workspace(&workspace_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("workspace not found".to_string()))?;

    if !workspace.enabled {
        return Err(ApiError::Forbidden("workspace is disabled".to_string()));
    }

    // 3. List all MCP servers and evaluate Cedar policies
    let mcp_servers = state.store.list_mcp_servers().await?;
    let mut scopes = Vec::new();

    for server in &mcp_servers {
        if !server.enabled {
            continue;
        }

        // Evaluate Cedar policy for mcp_tool_call action.
        let result = state.policy_engine.evaluate(
            &PolicyPrincipal::Workspace(&workspace),
            actions::MCP_TOOL_CALL,
            &PolicyResource::McpServer {
                id: server.name.clone(),
                name: server.name.clone(),
                enabled: server.enabled,
                tags: server.tags.clone(),
            },
            &PolicyContext {
                correlation_id: Some(corr.0.clone()),
                oauth_claims: oauth_claims.clone(),
                ..Default::default()
            },
        );

        if let Ok(decision) = result {
            if decision.decision == PolicyDecisionResult::Permit {
                scopes.push(format!("{}.{}.*", workspace_name, server.name));
                scopes.push(format!("{}.{}.tools/list", workspace_name, server.name));
            }
        }
    }

    // 4. Evaluate credential scopes
    let broad_cred = state.policy_engine.evaluate(
        &PolicyPrincipal::Workspace(&workspace),
        actions::VEND_CREDENTIAL,
        &PolicyResource::System,
        &PolicyContext {
            correlation_id: Some(corr.0.clone()),
            oauth_claims: oauth_claims.clone(),
            ..Default::default()
        },
    );

    let has_broad_access = matches!(
        broad_cred,
        Ok(ref d) if d.decision == PolicyDecisionResult::Permit
    );

    if has_broad_access {
        scopes.push("credentials:delegate:*".to_string());
        scopes.push("credentials:read:*".to_string());
    } else {
        let summaries = state.store.list_credentials().await?;
        for summary in &summaries {
            let cred = match state.store.get_credential(&summary.id).await {
                Ok(Some(c)) => c,
                _ => continue,
            };
            let cred_decision = state.policy_engine.evaluate(
                &PolicyPrincipal::Workspace(&workspace),
                actions::VEND_CREDENTIAL,
                &PolicyResource::Credential { credential: cred },
                &PolicyContext {
                    credential_name: Some(summary.name.clone()),
                    correlation_id: Some(corr.0.clone()),
                    oauth_claims: oauth_claims.clone(),
                    ..Default::default()
                },
            );

            if let Ok(d) = cred_decision {
                if d.decision == PolicyDecisionResult::Permit {
                    scopes.push(format!("credentials:delegate:{}", summary.name));
                    scopes.push(format!("credentials:read:{}", summary.name));
                }
            }
        }
    }

    // 5. Issue MCP permissions JWT (300s TTL)
    let ttl = 300u64;
    let (token, _claims) = state
        .jwt_issuer
        .issue_mcp_permissions_token(
            &workspace.id.0.to_string(),
            &caller_workspace.id.0.to_string(),
            scopes,
            ttl,
        )
        .map_err(|e| ApiError::Internal(format!("failed to issue permissions token: {}", e)))?;

    // 6. Audit
    let event = AuditEvent::builder(AuditEventType::TokenIssued)
        .action("issue_mcp_permissions")
        .workspace_actor(&workspace.id, &workspace.name)
        .resource("mcp_permissions", &caller_workspace.id.0.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("bypass:mcp_permissions_token"))
        .details(serde_json::json!({
            "caller_workspace_id": caller_workspace.id.0.to_string(),
            "caller_workspace_name": workspace_name,
            "ttl_seconds": ttl,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    Ok(Json(ApiResponse::ok(PermissionsResponse {
        token,
        expires_in: ttl,
    })))
}
