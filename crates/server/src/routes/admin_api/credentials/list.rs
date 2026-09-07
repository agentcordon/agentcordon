use axum::{extract::State, Json};

use agent_cordon_core::domain::credential::{
    CredentialAccess, CredentialId, CredentialSummary, StoredCredential,
};
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
    // A read share is the vault owner's own decision and Cedar has no
    // `Vault` resource to carry it, so the shared vaults are unioned in
    // after the policy filter rather than folded into it. Everything goes
    // through the filter first, because a caller may hold both routes to the
    // same row — an admin the vault was shared with, say — and the row is
    // `shared_read` only when the share is the *only* thing carrying it.
    let shared_vaults = state.services.credentials.shared_vault_ids(&actor).await?;
    let kept = state
        .authz
        .request(&actor, &uuid::Uuid::new_v4().to_string())
        .filter(actions::LIST, pairs.clone(), |(_, cred)| {
            PolicyResource::Credential {
                credential: cred.clone(),
            }
        })
        .await?;
    let permitted: std::collections::HashSet<CredentialId> =
        kept.iter().map(|(s, _)| s.id.clone()).collect();

    let mut allowed_creds: Vec<CredentialSummary> = kept
        .into_iter()
        .map(|(mut s, _)| {
            s.access = Some(CredentialAccess::Full);
            s
        })
        .collect();
    for (mut summary, _) in pairs {
        if permitted.contains(&summary.id) || !shared_vaults.contains(&summary.vault_id) {
            continue;
        }
        summary.access = Some(CredentialAccess::SharedRead);
        allowed_creds.push(summary);
    }
    allowed_creds.sort_by(|a, b| a.name.cmp(&b.name));

    enrich_owner_usernames(state.store.as_ref(), &mut allowed_creds).await;
    Ok(Json(ApiResponse::ok(allowed_creds)))
}
