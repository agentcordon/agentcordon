//! Admin REST API routes — CRUD operations for admin users.

mod admin;
mod audit;
pub mod credential_templates;
pub(crate) mod credentials;
mod mcp_proxy;
pub(crate) mod mcp_servers;
pub mod mcp_templates;
mod oauth_provider_clients;
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

use agent_cordon_core::domain::policy::PolicyDecision;
use agent_cordon_core::policy::{PolicyPrincipal, PolicyResource};

use crate::authz::PolicyCaller;
use crate::extractors::AuthenticatedUser;
use crate::response::ApiError;
use crate::state::AppState;

/// Generic Cedar permission check: evaluate an action on a resource for the
/// authenticated user. Returns the decision on success, or `Forbidden` if denied.
///
/// Synchronous wrapper that drives `Authz` in a blocking fashion for the
/// many existing call sites that don't have a correlation ID handy. New
/// code should prefer `state.authz.request(...).check(...).await`.
pub(crate) async fn check_cedar_permission(
    state: &AppState,
    auth: &AuthenticatedUser,
    action: &'static str,
    resource: PolicyResource,
) -> Result<PolicyDecision, ApiError> {
    let corr = uuid::Uuid::new_v4().to_string();
    state
        .authz
        .request(
            PolicyCaller::Principal {
                principal: PolicyPrincipal::User(&auth.user),
                oauth_claims: None,
            },
            &corr,
        )
        .check_with_reasons(action, &resource)
        .await
        .and_then(|decision| match decision.decision {
            agent_cordon_core::domain::policy::PolicyDecisionResult::Permit => Ok(decision),
            agent_cordon_core::domain::policy::PolicyDecisionResult::Forbid => {
                Err(ApiError::Forbidden("access denied by policy".to_string()))
            }
        })
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
        .merge(oauth_provider_clients::routes())
        .merge(mcp_proxy::routes())
        .merge(stats::routes())
        .merge(admin::routes())
        .merge(credential_templates::routes())
        .merge(mcp_templates::routes())
        .merge(policy_templates::routes())
        .merge(rsop::routes())
        .merge(settings::routes())
}
