//! Admin REST API routes — CRUD operations for admin users.

mod admin;
mod audit;
pub mod credential_templates;
pub(crate) mod credentials;
mod mcp_proxy;
mod mcp_servers;
pub(crate) mod oidc_auth;
mod oidc_providers;
mod permissions;
pub(crate) mod policies;
pub mod policy_templates;
mod rsop;
mod settings;
mod stats;
pub(crate) mod user_auth;
mod users;
mod vaults;
pub(crate) mod workspaces;

use axum::Router;

use agent_cordon_core::domain::policy::{PolicyDecision, PolicyDecisionResult};
use agent_cordon_core::policy::{PolicyContext, PolicyEngine, PolicyResource};

use crate::extractors::AuthenticatedUser;
use crate::response::ApiError;
use crate::state::AppState;

/// Generic Cedar permission check: evaluate an action on a resource for the
/// authenticated user. Returns the decision on success, or `Forbidden` if denied.
pub(crate) fn check_cedar_permission(
    state: &AppState,
    auth: &AuthenticatedUser,
    action: &str,
    resource: PolicyResource,
) -> Result<PolicyDecision, ApiError> {
    let decision = state.policy_engine.evaluate(
        &agent_cordon_core::policy::PolicyPrincipal::User(&auth.user),
        action,
        &resource,
        &PolicyContext::default(),
    )?;

    if decision.decision == PolicyDecisionResult::Forbid {
        return Err(ApiError::Forbidden("access denied by policy".to_string()));
    }

    Ok(decision)
}

/// API routes for the admin REST API (nested under `/api/v1`).
pub fn routes() -> Router<AppState> {
    Router::new()
        .merge(workspaces::routes())
        .merge(credentials::routes())
        .merge(permissions::routes())
        .merge(policies::routes())
        .merge(audit::routes())
        .merge(user_auth::routes())
        .merge(users::routes())
        .merge(vaults::routes())
        .merge(oidc_auth::routes())
        .merge(oidc_providers::routes())
        .merge(mcp_servers::routes())
        .merge(mcp_proxy::routes())
        .merge(stats::routes())
        .merge(admin::routes())
        .merge(credential_templates::routes())
        .merge(policy_templates::routes())
        .merge(rsop::routes())
        .merge(settings::routes())
}
