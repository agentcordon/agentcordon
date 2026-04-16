//! OAuth 2.0 Authorization Server endpoints.
//!
//! Implements the full OAuth 2.0 authorization code flow with PKCE,
//! client credentials grant, token refresh, and revocation.

pub mod authorize;
pub mod clients;
pub mod consent;
pub mod device;
pub mod revoke;
pub mod token;

use axum::{
    middleware::from_fn_with_state,
    routing::{delete, get, post},
    Router,
};

use crate::state::AppState;

/// OAuth 2.0 routes mounted under `/api/v1/oauth`.
pub fn routes(state: AppState) -> Router<AppState> {
    // Per-(IP,user) rate limiter applied only to approve + deny. We build a
    // sub-router for the gated pair, apply the middleware, then merge it back
    // into the main OAuth router so the other endpoints remain unlimited.
    let device_decision_routes = Router::new()
        .route(
            "/oauth/device/approve",
            post(device::device_approve_endpoint),
        )
        .route("/oauth/device/deny", post(device::device_deny_endpoint))
        .layer(from_fn_with_state(
            state,
            crate::middleware::rate_limit_device_approve::rate_limit_device_approve,
        ));

    Router::new()
        // Client registration + admin listing
        .route("/oauth/clients", post(clients::register_client))
        .route("/oauth/clients", get(clients::list_clients))
        .route("/oauth/clients/{id}", delete(clients::revoke_client))
        // Authorization code flow
        .route("/oauth/authorize", get(authorize::authorize_get))
        .route("/oauth/authorize", post(consent::authorize_post))
        // RFC 8628 Device Authorization Grant
        .route("/oauth/device/code", post(device::device_code_endpoint))
        .merge(device_decision_routes)
        // Token endpoint
        .route("/oauth/token", post(token::token_endpoint))
        // Revocation
        .route("/oauth/revoke", post(revoke::revoke_token))
}

// ---------------------------------------------------------------------------
// Re-export core token/hash/PKCE helpers — single source of truth
// ---------------------------------------------------------------------------

pub(crate) use agent_cordon_core::oauth2::tokens::{
    generate_access_token, generate_auth_code, generate_client_secret, generate_refresh_token,
    hash_token, validate_pkce,
};

/// Validate that a redirect URI is localhost-only.
pub(crate) fn is_localhost_uri(uri: &str) -> bool {
    if let Ok(parsed) = url::Url::parse(uri) {
        if parsed.scheme() != "http" {
            return false;
        }
        matches!(
            parsed.host_str(),
            Some("localhost") | Some("127.0.0.1") | Some("[::1]")
        )
    } else {
        false
    }
}

/// Scope description for the consent page.
pub(crate) struct ScopeDisplay {
    pub name: String,
    pub description: String,
}

pub(crate) fn scope_descriptions(
    scopes: &[agent_cordon_core::oauth2::types::OAuthScope],
) -> Vec<ScopeDisplay> {
    use agent_cordon_core::oauth2::types::OAuthScope;
    scopes
        .iter()
        .map(|s| {
            let description = match s {
                OAuthScope::CredentialsDiscover => "Discover available credentials",
                OAuthScope::CredentialsVend => "Retrieve credential values via proxy",
                OAuthScope::McpDiscover => "Discover available MCP servers and tools",
                OAuthScope::McpInvoke => "Invoke MCP tools",
            };
            ScopeDisplay {
                name: s.to_string(),
                description: description.to_string(),
            }
        })
        .collect()
}
