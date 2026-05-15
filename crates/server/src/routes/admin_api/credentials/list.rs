use axum::{extract::State, Json};

use agent_cordon_core::domain::credential::{CredentialId, CredentialSummary, StoredCredential};
use agent_cordon_core::policy::{actions, PolicyResource};

use crate::extractors::AuthenticatedActor;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

use super::enrich_owner_usernames;

/// List credentials visible to the authenticated actor.
///
/// All principals (users and workspaces) go through per-credential Cedar
/// evaluation. Root users bypass Cedar entirely (handled inside the Cedar
/// engine), so they see everything. Admin users see everything because
/// default Cedar policies grant admins full access. Workspaces see
/// credentials permitted by default policies, grants, or tag-based access.
pub(crate) async fn list_credentials(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
) -> Result<Json<ApiResponse<Vec<CredentialSummary>>>, ApiError> {
    // OAuth scope gate: workspaces need credentials:discover to list
    actor.require_scope(agent_cordon_core::oauth2::types::OAuthScope::CredentialsDiscover)?;

    // Batch-load all credentials in 2 queries (avoids N+1).
    let all_summaries = state.store.list_credentials().await?;
    let all_stored = state.store.list_all_stored_credentials().await?;

    // Index full credentials by ID for Cedar evaluation.
    let cred_map: std::collections::HashMap<CredentialId, StoredCredential> =
        all_stored.into_iter().map(|c| (c.id.clone(), c)).collect();

    // Pair summaries with full credentials and run them through the Authz
    // filter terminal — denied items are silently dropped, each Cedar
    // evaluation auto-emits a PolicyEvaluated audit event.
    let pairs: Vec<(CredentialSummary, StoredCredential)> = all_summaries
        .into_iter()
        .filter_map(|s| cred_map.get(&s.id).map(|c| (s, c.clone())))
        .collect();
    let kept = state
        .authz
        .request(&actor, &uuid::Uuid::new_v4().to_string())
        .filter(actions::LIST, pairs, |(_, cred)| {
            PolicyResource::Credential {
                credential: cred.clone(),
            }
        })
        .await?;
    let mut allowed_creds: Vec<CredentialSummary> = kept.into_iter().map(|(s, _)| s).collect();

    enrich_owner_usernames(state.store.as_ref(), &mut allowed_creds).await;
    Ok(Json(ApiResponse::ok(allowed_creds)))
}
