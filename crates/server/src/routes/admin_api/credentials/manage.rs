use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

use agent_cordon_core::domain::credential::{CredentialId, CredentialSummary, CredentialUpdate};
use agent_cordon_core::policy::actions;
use agent_cordon_core::policy::PolicyResource;

use crate::extractors::AuthenticatedActor;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

use super::enrich_owner_usernames;

#[derive(Deserialize)]
pub(crate) struct UpdateCredentialRequest {
    name: Option<String>,
    service: Option<String>,
    /// New secret value. When provided, the old secret is archived to history.
    secret_value: Option<String>,
    scopes: Option<Vec<String>>,
    metadata: Option<serde_json::Value>,
    allowed_url_pattern: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    transform_script: Option<String>,
    transform_name: Option<String>,
    /// Move the credential to another vault, by id.
    vault_id: Option<String>,
    tags: Option<Vec<String>>,
    description: Option<String>,
    target_identity: Option<String>,
}

pub(crate) async fn update_credential(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateCredentialRequest>,
) -> Result<Json<ApiResponse<CredentialSummary>>, ApiError> {
    let cred_id = CredentialId(id);

    // Normalize empty-string allowed_url_pattern to None (clears the restriction).
    // The JS form sends "" when the user clears the field; we treat that as "no
    // restriction" and set the DB column to NULL via the store's empty-string path.
    let allowed_url_pattern = match req.allowed_url_pattern.as_deref() {
        Some("") => Some(String::new()),
        other => other.map(String::from),
    };

    let changes = CredentialUpdate {
        name: req.name,
        service: req.service,
        scopes: req.scopes,
        metadata: req.metadata,
        allowed_url_pattern,
        expires_at: req.expires_at,
        transform_script: req.transform_script,
        transform_name: req.transform_name,
        vault_id: req.vault_id,
        tags: req.tags,
        description: req.description,
        target_identity: req.target_identity,
        encrypted_value: None,
        nonce: None,
        key_version: None,
    };

    let updated_cred = state
        .services
        .credentials
        .update(
            &actor,
            &corr.0,
            &cred_id,
            changes,
            req.secret_value.as_deref(),
        )
        .await?;

    let mut summary: CredentialSummary = updated_cred.into();
    enrich_owner_usernames(state.store.as_ref(), std::slice::from_mut(&mut summary)).await;

    Ok(Json(ApiResponse::ok(summary)))
}

pub(crate) async fn get_credential(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<CredentialSummary>>, ApiError> {
    let cred_id = CredentialId(id);
    let cred = state.services.credentials.load(&cred_id).await?;

    // Cedar, or a read share on the credential's vault. Which of the two
    // answered rides along in the response: the detail page offers reveal,
    // edit, delete and granting only to a caller the server would not refuse.
    let access = state
        .services
        .credentials
        .authorize_read(&actor, &uuid::Uuid::new_v4().to_string(), &cred)
        .await?;

    let mut summary: CredentialSummary = cred.into();
    summary.access = Some(access);
    enrich_owner_usernames(state.store.as_ref(), std::slice::from_mut(&mut summary)).await;

    Ok(Json(ApiResponse::ok(summary)))
}

/// Look up a credential by name instead of UUID.
/// Returns the same `CredentialSummary` as `GET /credentials/{id}`.
///
/// If multiple credentials match, evaluate Cedar `list` action on each and
/// return `MultipleChoices` when more than one is authorized.
pub(crate) async fn get_credential_by_name(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    Path(name): Path<String>,
) -> Result<Json<ApiResponse<CredentialSummary>>, ApiError> {
    let name_matches = state.store.list_stored_credentials_by_name(&name).await?;

    // Filter via the Authz seam (denied items silently dropped, audit per item).
    let authorized: Vec<agent_cordon_core::domain::credential::StoredCredential> = state
        .authz
        .request(&actor, &uuid::Uuid::new_v4().to_string())
        .filter(actions::LIST, name_matches.clone(), |c| {
            PolicyResource::Credential {
                credential: c.clone(),
            }
        })
        .await?;

    let cred = match authorized.len() {
        0 => {
            return Err(ApiError::NotFound(format!(
                "credential '{}' not found or not authorized",
                name
            )));
        }
        1 => authorized.into_iter().next().unwrap(),
        _ => {
            let candidates: Vec<serde_json::Value> = authorized
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "id": c.id.0.to_string(),
                        "name": c.name,
                        "service": c.service,
                        "description": c.description,
                    })
                })
                .collect();
            return Err(ApiError::MultipleChoices {
                message: format!(
                    "Multiple credentials match name '{}'. Specify by ID or use a unique name.",
                    name
                ),
                candidates,
            });
        }
    };

    let mut summary: CredentialSummary = cred.into();
    enrich_owner_usernames(state.store.as_ref(), std::slice::from_mut(&mut summary)).await;

    Ok(Json(ApiResponse::ok(summary)))
}

pub(crate) async fn delete_credential(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    state
        .services
        .credentials
        .delete(&actor, &corr.0, &CredentialId(id))
        .await?;

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "deleted": true }),
    )))
}
