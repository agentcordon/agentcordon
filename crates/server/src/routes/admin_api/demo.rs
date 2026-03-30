//! Demo / Try It API endpoint.
//!
//! GET  /api/v1/demo/try-it — returns a pre-filled curl command using demo
//! seed data so new users can test the proxy in seconds.
//! DELETE /api/v1/demo — removes all demo seed data (workspace, credential, policy).

use axum::{
    extract::State,
    routing::{delete, get},
    Json, Router,
};
use serde::Serialize;

use crate::extractors::AuthenticatedUser;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;
use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/demo/try-it", get(try_it))
        .route("/demo", delete(delete_demo_data))
}

#[derive(Serialize)]
struct TryItResponse {
    curl_command: String,
    expected_response: String,
    explanation: String,
    demo_workspace_id: uuid::Uuid,
    demo_workspace_name: String,
    demo_credential_id: uuid::Uuid,
    demo_credential_name: String,
}

/// GET /api/v1/demo/try-it — returns a curl command using demo seed data.
///
/// Requires admin session auth. Looks up demo-workspace and demo-api-key by name,
/// mints a fresh short-lived JWT for the demo workspace, and returns a ready-to-run
/// curl command targeting the device proxy.
async fn try_it(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<ApiResponse<TryItResponse>>, ApiError> {
    // Only admins can mint demo tokens -- this endpoint issues workspace JWTs
    let is_admin =
        auth.user.role == agent_cordon_core::domain::user::UserRole::Admin || auth.is_root;
    if !is_admin {
        return Err(ApiError::Forbidden(
            "only admins can use the demo try-it endpoint".to_string(),
        ));
    }

    // Look up demo workspace by name
    let workspace = state
        .store
        .get_workspace_by_name("demo-workspace")
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(
                "demo-workspace not found — demo seed data may not have been created. \
                 Set AGTCRDN_SEED_DEMO=true and restart with an empty database."
                    .to_string(),
            )
        })?;

    // Verify demo credential exists
    let credential = state
        .store
        .get_credential_by_name("demo-api-key")
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(
                "demo-api-key credential not found — demo seed data may be incomplete.".to_string(),
            )
        })?;

    // Issue a short-lived OAuth access token for the demo workspace
    let token = crate::routes::oauth::issue_demo_access_token(&state, &workspace)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to issue demo OAuth token: {e}")))?;

    // Audit: demo token issued (do NOT include the JWT value)
    let token_event = AuditEvent::builder(AuditEventType::DemoTokenIssued)
        .action("issue_token")
        .workspace_actor(&workspace.id, &workspace.name)
        .resource("workspace", &workspace.id.0.to_string())
        .decision(AuditDecision::Permit, Some("demo try-it token issued"))
        .details(serde_json::json!({
            "demo": true,
            "workspace_name": workspace.name,
        }))
        .build();
    state.store.append_audit_event(&token_event).await.ok();

    let curl_command = format!(
        "curl -X POST http://localhost:3140/api/v1/proxy/execute \\\n  -H 'Authorization: Bearer {token}' \\\n  -H 'Content-Type: application/json' \\\n  -d '{{\"credential_id\": \"demo-api-key\", \"target_url\": \"https://httpbin.org/get\", \"method\": \"GET\"}}'"
    );

    Ok(Json(ApiResponse::ok(TryItResponse {
        curl_command,
        expected_response: "A JSON response from httpbin.org showing your request headers, \
                            including the injected credential"
            .to_string(),
        explanation: "This command sends a request through the AgentCordon credential proxy. \
                      The server injects the demo-api-key credential into the upstream \
                      request to httpbin.org."
            .to_string(),
        demo_workspace_id: workspace.id.0,
        demo_workspace_name: "demo-workspace".to_string(),
        demo_credential_id: credential.id.0,
        demo_credential_name: "demo-api-key".to_string(),
    })))
}

/// DELETE /api/v1/demo — removes all demo seed data.
///
/// Deletes: demo-api-key credential, demo-allow-vend policy, demo-workspace.
/// Credential and policies are deleted BEFORE the workspace to avoid FK conflicts
/// (credentials.created_by references workspaces.id).
/// Does NOT delete audit events or example policies.
/// Requires admin session auth.
async fn delete_demo_data(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    // Only admins can delete demo data
    let is_admin =
        auth.user.role == agent_cordon_core::domain::user::UserRole::Admin || auth.is_root;
    if !is_admin {
        return Err(ApiError::Forbidden(
            "only admins can delete demo data".to_string(),
        ));
    }

    let mut deleted = Vec::new();

    // 1. Delete demo-api-key credential and its grant policies FIRST
    //    (must happen before workspace deletion due to FK: credentials.created_by -> workspaces.id)
    if let Ok(Some(cred)) = state.store.get_credential_by_name("demo-api-key").await {
        let prefix = format!("grant:{}:", cred.id.0);
        if let Err(e) = state.store.delete_policies_by_name_prefix(&prefix).await {
            tracing::warn!(error = %e, "failed to delete grant policies for demo credential");
        }
        if let Err(e) = state.store.delete_credential(&cred.id).await {
            tracing::warn!(error = %e, "failed to delete demo credential");
        } else {
            deleted.push("demo-api-key".to_string());
        }
    }

    // 2. Delete demo-allow-vend policy (find by name)
    if let Ok(policies) = state.store.list_policies().await {
        if let Some(policy) = policies.iter().find(|p| p.name == "demo-allow-vend") {
            if let Err(e) = state.store.delete_policy(&policy.id).await {
                tracing::warn!(error = %e, "failed to delete demo-allow-vend policy");
            } else {
                deleted.push("demo-allow-vend".to_string());
            }
        }
    }

    // 3. Delete demo-workspace and its grant policies LAST (after dependents are removed)
    if let Ok(Some(workspace)) = state.store.get_workspace_by_name("demo-workspace").await {
        // Delete grant policies for this workspace
        if let Ok(policies) = state.store.list_policies().await {
            for policy in &policies {
                if policy.name.starts_with("grant:")
                    && policy.name.contains(&workspace.id.0.to_string())
                {
                    if let Err(e) = state.store.delete_policy(&policy.id).await {
                        tracing::warn!(policy_name = %policy.name, error = %e, "failed to delete workspace grant policy");
                    }
                }
            }
        }
        if let Err(e) = state.store.delete_workspace(&workspace.id).await {
            tracing::warn!(error = %e, "failed to delete demo workspace");
        } else {
            deleted.push("demo-workspace".to_string());
        }
    }

    // Audit event
    let event = AuditEvent::builder(AuditEventType::DemoDataRemoved)
        .action("delete_demo_data")
        .user_actor(&auth.user)
        .resource("demo", "all")
        .decision(AuditDecision::Permit, Some("demo data removed by user"))
        .details(serde_json::json!({
            "deleted": deleted,
        }))
        .build();
    state.store.append_audit_event(&event).await.ok();

    Ok(Json(ApiResponse::ok(serde_json::json!({
        "deleted": deleted,
    }))))
}
