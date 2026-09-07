use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agent_cordon_core::domain::policy::{PolicyId, StoredPolicy};
use agent_cordon_core::policy::actions;

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::services::policies::{NewPolicy, PolicyChanges};
use crate::state::AppState;

use agent_cordon_core::policy::PolicyResource;

#[derive(Deserialize)]
pub(super) struct CreatePolicyRequest {
    name: String,
    description: Option<String>,
    cedar_policy: String,
    enabled: Option<bool>,
}

#[derive(Deserialize)]
pub(super) struct UpdatePolicyRequest {
    name: Option<String>,
    description: Option<String>,
    cedar_policy: Option<String>,
    enabled: Option<bool>,
}

// --- Cedar validation endpoint ---

#[derive(Deserialize)]
pub(super) struct ValidatePolicyRequest {
    cedar_policy: String,
}

#[derive(Serialize)]
pub(super) struct ValidateResult {
    valid: bool,
    errors: Vec<agent_cordon_core::domain::policy::PolicyValidationError>,
}

/// Validate Cedar policy text without creating/updating a policy.
/// Returns structured errors with severity for inline editor feedback.
///
/// Requires `manage_policies` permission.
pub(super) async fn validate_policy(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Json(req): Json<ValidatePolicyRequest>,
) -> Result<Json<ApiResponse<ValidateResult>>, ApiError> {
    state
        .authz
        .authorize(
            &auth,
            actions::MANAGE_POLICIES,
            &PolicyResource::PolicyAdmin,
        )
        .await?;

    if req.cedar_policy.is_empty() {
        return Err(ApiError::BadRequest("cedar_policy is required".to_string()));
    }

    match state.authz.validate_policy_text_detailed(&req.cedar_policy) {
        Ok(()) => Ok(Json(ApiResponse::ok(ValidateResult {
            valid: true,
            errors: vec![],
        }))),
        Err(errors) => Ok(Json(ApiResponse::ok(ValidateResult {
            valid: false,
            errors,
        }))),
    }
}

/// Return the Cedar schema JSON text. Admin-only.
pub(super) async fn get_schema(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<ApiResponse<String>>, ApiError> {
    state
        .authz
        .authorize(
            &auth,
            actions::MANAGE_POLICIES,
            &PolicyResource::PolicyAdmin,
        )
        .await?;
    let schema_text = agent_cordon_core::policy::schema::CEDAR_SCHEMA_JSON.to_string();
    Ok(Json(ApiResponse::ok(schema_text)))
}

/// Schema reference types for the action catalog endpoint.
#[derive(Serialize)]
struct ActionReference {
    name: String,
    description: String,
    principal_types: Vec<String>,
    resource_types: Vec<String>,
    context_attributes: Vec<ContextAttribute>,
}

#[derive(Serialize)]
struct ContextAttribute {
    name: String,
    #[serde(rename = "type")]
    attr_type: String,
}

#[derive(Serialize)]
pub(crate) struct SchemaReference {
    actions: Vec<ActionReference>,
}

/// Return a human-readable action catalog parsed from the Cedar schema.
/// Any authenticated user can access this (reference data, not sensitive).
pub(super) async fn get_schema_reference(
    State(_state): State<AppState>,
    _auth: AuthenticatedUser,
) -> Result<Json<ApiResponse<SchemaReference>>, ApiError> {
    let action_descriptions: std::collections::HashMap<&str, &str> = [
        (actions::ACCESS, "Decrypt/use a credential directly"),
        (
            actions::VEND_CREDENTIAL,
            "Use a credential via device credential vending",
        ),
        (actions::LIST, "List/view resources"),
        (actions::CREATE, "Create a new resource"),
        (actions::UPDATE, "Update resource metadata"),
        (actions::DELETE, "Delete a resource"),
        (
            actions::MANAGE_PERMISSIONS,
            "Manage per-credential permission grants",
        ),
        (
            actions::MANAGE_POLICIES,
            "Create, update, or delete Cedar policies",
        ),
        (actions::MANAGE_USERS, "Manage user accounts"),
        (
            actions::MANAGE_AGENTS,
            "View, enable, disable, or configure agents",
        ),
        (actions::VIEW_AUDIT, "View audit log entries"),
        (actions::ROTATE_KEY, "Rotate an agent's API key"),
        (
            actions::MANAGE_OIDC_PROVIDERS,
            "Manage OIDC identity providers",
        ),
        (
            actions::MANAGE_OAUTH_PROVIDER_CLIENTS,
            "Manage the OAuth client registrations AgentCordon holds at upstream              authorization servers",
        ),
        (actions::MANAGE_VAULTS, "Share or unshare credential vaults"),
        (
            actions::ROTATE_ENCRYPTION_KEY,
            "Rotate the server encryption key",
        ),
        (
            actions::MANAGE_MCP_SERVERS,
            "Manage MCP server configurations",
        ),
        (actions::MCP_TOOL_CALL, "Call a tool on an MCP server"),
        (
            actions::MCP_LIST_TOOLS,
            "List available tools on an MCP server",
        ),
        (actions::MANAGE_DEVICES, "Manage device registrations"),
        (
            actions::REGISTER_WORKSPACE,
            "Register a new workspace via OAuth",
        ),
        (
            actions::MANAGE_TAGS,
            "Add or remove tags on agents, devices, or system",
        ),
        (actions::UNPROTECT, "Reveal a credential's raw secret value"),
        (
            actions::MANAGE_CONSENTS,
            "View or revoke OAuth consent grants on a workspace",
        ),
    ]
    .into_iter()
    .collect();

    // Parse the Cedar schema JSON to extract action metadata.
    let schema_json: serde_json::Value =
        serde_json::from_str(agent_cordon_core::policy::schema::CEDAR_SCHEMA_JSON)
            .map_err(|e| ApiError::Internal(format!("failed to parse Cedar schema: {e}")))?;

    let mut actions = Vec::new();

    if let Some(ns) = schema_json.get("AgentCordon") {
        if let Some(actions_obj) = ns.get("actions").and_then(|a| a.as_object()) {
            for (action_name, action_def) in actions_obj {
                let description = action_descriptions
                    .get(action_name.as_str())
                    .unwrap_or(&"")
                    .to_string();

                let applies_to = action_def.get("appliesTo");

                let principal_types = applies_to
                    .and_then(|a| a.get("principalTypes"))
                    .and_then(|p| p.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();

                let resource_types = applies_to
                    .and_then(|a| a.get("resourceTypes"))
                    .and_then(|r| r.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();

                let context_attributes = applies_to
                    .and_then(|a| a.get("context"))
                    .and_then(|c| c.get("attributes"))
                    .and_then(|attrs| attrs.as_object())
                    .map(|attrs| {
                        attrs
                            .iter()
                            .map(|(name, def)| {
                                let attr_type =
                                    if let Some(t) = def.get("type").and_then(|t| t.as_str()) {
                                        if t == "Set" {
                                            "Set<String>".to_string()
                                        } else {
                                            t.to_string()
                                        }
                                    } else {
                                        "unknown".to_string()
                                    };
                                ContextAttribute {
                                    name: name.clone(),
                                    attr_type,
                                }
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                actions.push(ActionReference {
                    name: action_name.clone(),
                    description,
                    principal_types,
                    resource_types,
                    context_attributes,
                });
            }
        }
    }

    // Sort actions alphabetically for consistent output.
    actions.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(Json(ApiResponse::ok(SchemaReference { actions })))
}

pub(super) async fn create_policy(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<Json<ApiResponse<StoredPolicy>>, ApiError> {
    let policy = state
        .services
        .policies
        .create(
            &auth,
            &corr.0,
            NewPolicy {
                name: req.name,
                description: req.description,
                cedar_policy: req.cedar_policy,
                enabled: req.enabled,
            },
        )
        .await?;

    Ok(Json(ApiResponse::ok(policy)))
}

pub(super) async fn list_policies(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<ApiResponse<Vec<StoredPolicy>>>, ApiError> {
    state
        .authz
        .authorize(
            &auth,
            actions::MANAGE_POLICIES,
            &PolicyResource::PolicyAdmin,
        )
        .await?;

    let all_policies = state.store.list_policies().await?;

    // Tenant scoping: non-admin users only see grant policies
    // that reference their owned workspaces.
    let is_admin = auth.is_admin();
    let policies = if is_admin {
        all_policies
    } else {
        let owned = state.store.get_workspaces_by_owner(&auth.user.id).await?;
        let owned_ids: std::collections::HashSet<String> =
            owned.iter().map(|w| w.id.0.to_string()).collect();
        all_policies
            .into_iter()
            .filter(|p| owned_ids.iter().any(|wid| p.name.contains(wid)))
            .collect()
    };

    Ok(Json(ApiResponse::ok(policies)))
}

pub(super) async fn get_policy(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<StoredPolicy>>, ApiError> {
    state
        .authz
        .authorize(
            &auth,
            actions::MANAGE_POLICIES,
            &PolicyResource::PolicyAdmin,
        )
        .await?;
    let policy = state.services.policies.load(&PolicyId(id)).await?;
    Ok(Json(ApiResponse::ok(policy)))
}

pub(super) async fn update_policy(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdatePolicyRequest>,
) -> Result<Json<ApiResponse<StoredPolicy>>, ApiError> {
    let policy = state
        .services
        .policies
        .update(
            &auth,
            &corr.0,
            &PolicyId(id),
            PolicyChanges {
                name: req.name,
                description: req.description,
                cedar_policy: req.cedar_policy,
                enabled: req.enabled,
            },
        )
        .await?;

    Ok(Json(ApiResponse::ok(policy)))
}

pub(super) async fn delete_policy(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    state
        .services
        .policies
        .delete(&auth, &corr.0, &PolicyId(id))
        .await?;

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "deleted": true }),
    )))
}
