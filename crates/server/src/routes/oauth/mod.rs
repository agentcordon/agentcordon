//! OAuth 2.0 Authorization Server endpoints.
//!
//! Implements the full OAuth 2.0 authorization code flow with PKCE,
//! client credentials grant, token refresh, and revocation.

pub mod authorize;
pub mod clients;
pub mod revoke;
pub mod token;

use axum::{
    routing::{delete, get, post},
    Router,
};

use crate::state::AppState;

/// OAuth 2.0 routes mounted under `/api/v1/oauth`.
pub fn routes() -> Router<AppState> {
    Router::new()
        // Client registration + admin listing
        .route("/oauth/clients", post(clients::register_client))
        .route("/oauth/clients", get(clients::list_clients))
        .route("/oauth/clients/{id}", delete(clients::revoke_client))
        // Authorization code flow
        .route("/oauth/authorize", get(authorize::authorize_get))
        .route("/oauth/authorize", post(authorize::authorize_post))
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
        matches!(parsed.host_str(), Some("localhost") | Some("127.0.0.1") | Some("[::1]"))
    } else {
        false
    }
}

/// Issue a short-lived demo OAuth access token for a workspace.
///
/// Finds (or creates) an OAuth client for the workspace and stores a fresh
/// access token that expires in 5 minutes. Returns the raw (un-hashed) token.
pub(crate) async fn issue_demo_access_token(
    state: &crate::state::AppState,
    workspace: &agent_cordon_core::domain::workspace::Workspace,
) -> Result<String, String> {
    use agent_cordon_core::oauth2::types::{OAuthAccessToken, OAuthScope};

    let pk_hash = workspace
        .pk_hash
        .as_deref()
        .unwrap_or("demo-workspace-key");

    // Find existing client for this workspace, or create a minimal one
    let client = match state
        .store
        .get_oauth_client_by_public_key_hash(pk_hash)
        .await
        .map_err(|e| e.to_string())?
        .filter(|c| c.revoked_at.is_none())
    {
        Some(c) => c,
        None => {
            // Create a minimal demo OAuth client
            let owner_id = workspace
                .owner_id
                .clone()
                .unwrap_or(agent_cordon_core::domain::user::UserId(uuid::Uuid::nil()));
            let client = agent_cordon_core::oauth2::types::OAuthClient {
                id: uuid::Uuid::new_v4(),
                client_id: format!("ac_cli_{}", uuid::Uuid::new_v4().simple()),
                client_secret_hash: None,
                workspace_name: workspace.name.clone(),
                public_key_hash: pk_hash.to_string(),
                redirect_uris: vec!["http://localhost:0/callback".to_string()],
                allowed_scopes: vec![
                    OAuthScope::CredentialsDiscover,
                    OAuthScope::CredentialsVend,
                    OAuthScope::McpInvoke,
                ],
                created_by_user: owner_id,
                created_at: chrono::Utc::now(),
                revoked_at: None,
            };
            state
                .store
                .create_oauth_client(&client)
                .await
                .map_err(|e| e.to_string())?;
            client
        }
    };

    let (raw_token, token_hash_val) = generate_access_token();
    let now = chrono::Utc::now();

    let access_token = OAuthAccessToken {
        token_hash: token_hash_val,
        client_id: client.client_id,
        user_id: workspace
            .owner_id
            .clone()
            .unwrap_or(agent_cordon_core::domain::user::UserId(uuid::Uuid::nil())),
        scopes: vec![
            OAuthScope::CredentialsDiscover,
            OAuthScope::CredentialsVend,
            OAuthScope::McpInvoke,
        ],
        created_at: now,
        expires_at: now + chrono::Duration::seconds(300),
        revoked_at: None,
    };

    state
        .store
        .create_oauth_access_token(&access_token)
        .await
        .map_err(|e| e.to_string())?;

    Ok(raw_token)
}

/// Scope description for the consent page.
pub(crate) struct ScopeDisplay {
    pub name: String,
    pub description: String,
}

pub(crate) fn scope_descriptions(scopes: &[agent_cordon_core::oauth2::types::OAuthScope]) -> Vec<ScopeDisplay> {
    use agent_cordon_core::oauth2::types::OAuthScope;
    scopes
        .iter()
        .map(|s| {
            let description = match s {
                OAuthScope::CredentialsDiscover => "Discover available credentials",
                OAuthScope::CredentialsVend => "Retrieve credential values via proxy",
                OAuthScope::McpInvoke => "Invoke MCP tools",
            };
            ScopeDisplay {
                name: s.to_string(),
                description: description.to_string(),
            }
        })
        .collect()
}
