use axum::{extract::State, Json};

use agent_cordon_core::domain::credential::{CredentialId, CredentialSummary, StoredCredential};
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::policy::{actions, PolicyEngine, PolicyResource};

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

    let mut allowed_creds = Vec::new();
    let principal = actor.policy_principal();
    let context = actor.policy_context(None);

    for summary in all_summaries {
        let cred = match cred_map.get(&summary.id) {
            Some(c) => c.clone(),
            None => continue,
        };

        match state.policy_engine.evaluate(
            &principal,
            actions::LIST,
            &PolicyResource::Credential { credential: cred },
            &context,
        ) {
            Ok(decision) if decision.decision != PolicyDecisionResult::Forbid => {
                allowed_creds.push(summary);
            }
            Ok(_) => {
                // Cedar denied — skip this credential
            }
            Err(e) => {
                tracing::warn!(
                    credential_id = %summary.id.0,
                    error = %e,
                    "Cedar evaluation failed for credential, skipping (deny-by-default)"
                );
            }
        }
    }

    enrich_owner_usernames(state.store.as_ref(), &mut allowed_creds).await;
    Ok(Json(ApiResponse::ok(allowed_creds)))
}
