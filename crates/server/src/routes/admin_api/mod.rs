//! Admin REST API routes — CRUD operations for admin users.

mod admin;
mod audit;
pub mod credential_templates;
pub(crate) mod credentials;
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

use crate::state::AppState;

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
        .merge(stats::routes())
        .merge(admin::routes())
        .merge(credential_templates::routes())
        .merge(mcp_templates::routes())
        .merge(policy_templates::routes())
        .merge(rsop::routes())
        .merge(settings::routes())
}
