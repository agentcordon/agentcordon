mod crud;
mod testing;

use axum::{
    routing::{get, post},
    Router,
};

use agent_cordon_core::policy::{actions, PolicyEngine, PolicyResource};

use crate::extractors::AuthenticatedUser;
use crate::response::ApiError;
use crate::state::AppState;

use crud::{
    create_policy, delete_policy, get_policy, get_schema, get_schema_reference, list_policies,
    update_policy, validate_policy,
};
use testing::test_policy;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/policies", post(create_policy).get(list_policies))
        .route("/policies/schema", get(get_schema))
        .route("/policies/schema/reference", get(get_schema_reference))
        .route("/policies/test", post(test_policy))
        .route("/policies/validate", post(validate_policy))
        .route(
            "/policies/{id}",
            get(get_policy).put(update_policy).delete(delete_policy),
        )
}

/// Check Cedar policy for `manage_policies` on `PolicyAdmin` resource.
pub(crate) fn check_manage_policies(
    state: &AppState,
    auth: &AuthenticatedUser,
) -> Result<agent_cordon_core::domain::policy::PolicyDecision, ApiError> {
    super::check_cedar_permission(
        state,
        auth,
        actions::MANAGE_POLICIES,
        PolicyResource::PolicyAdmin,
    )
}

/// Reload all enabled policies from DB into the policy engine.
///
/// The database is the single source of truth for Cedar policies.
/// If zero enabled policies exist, an empty policy set is loaded (deny-all).
pub async fn reload_engine(state: &AppState) -> Result<(), ApiError> {
    let db_policies = state.store.get_all_enabled_policies().await?;
    let sources: Vec<(String, String)> = db_policies
        .into_iter()
        .map(|p| (p.id.0.to_string(), p.cedar_policy))
        .collect();

    if sources.is_empty() {
        tracing::warn!("no enabled policies in database — deny-all is in effect");
    }

    state
        .policy_engine
        .reload_policies(sources)
        .map_err(|e| ApiError::Internal(format!("failed to reload policies: {e}")))?;
    Ok(())
}
