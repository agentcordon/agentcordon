mod callback;
#[cfg(test)]
mod tests;

use axum::{
    extract::{Query, State},
    http::header::HeaderMap,
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};

use agent_cordon_core::auth::oidc::OidcClient;
use agent_cordon_core::crypto::session::generate_session_token;
use agent_cordon_core::domain::oidc::OidcAuthState;
use agent_cordon_core::domain::user::UserRole;

use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/oidc/authorize", get(authorize))
        .route("/auth/oidc/callback", get(callback::callback))
        .route("/auth/oidc/providers", get(list_public_providers))
}

// --- Request Types ---

#[derive(Deserialize)]
struct AuthorizeQuery {
    provider: uuid::Uuid,
}

#[derive(Deserialize)]
pub(crate) struct CallbackQuery {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
}

// --- Response Types ---

#[derive(Serialize)]
struct PublicProvider {
    id: String,
    name: String,
}

// --- Handlers ---

/// GET /api/v1/auth/oidc/authorize?provider={id}
async fn authorize(
    State(state): State<AppState>,
    axum::Extension(_corr): axum::Extension<CorrelationId>,
    headers: HeaderMap,
    Query(query): Query<AuthorizeQuery>,
) -> Result<Response, ApiError> {
    let provider_id = agent_cordon_core::domain::oidc::OidcProviderId(query.provider);

    // Look up the provider
    let provider = state
        .store
        .get_oidc_provider(&provider_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("OIDC provider not found".to_string()))?;

    if !provider.enabled {
        return Err(ApiError::BadRequest(
            "OIDC provider is disabled".to_string(),
        ));
    }

    // Discover OIDC endpoints
    let oidc_client = OidcClient::new();
    let discovery = oidc_client
        .discover(&provider.issuer_url)
        .await
        .map_err(|e| ApiError::BadGateway(format!("OIDC discovery failed: {}", e)))?;

    // Generate random state and nonce
    let random_state = generate_session_token();
    let nonce = generate_session_token();

    // Build the callback redirect_uri
    let redirect_uri = build_callback_uri(&state, &headers);

    // Store auth state
    let now = chrono::Utc::now();
    let ttl = chrono::Duration::seconds(state.config.oidc_state_ttl_seconds as i64);
    let auth_state = OidcAuthState {
        state: random_state.clone(),
        nonce: nonce.clone(),
        provider_id: provider_id.clone(),
        redirect_uri: redirect_uri.clone(),
        created_at: now,
        expires_at: now + ttl,
    };
    state.store.create_oidc_auth_state(&auth_state).await?;

    // Build the authorization URL
    let scopes = provider.scopes.join(" ");
    let auth_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}",
        discovery.authorization_endpoint,
        urlencoding::encode(&provider.client_id),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(&scopes),
        urlencoding::encode(&random_state),
        urlencoding::encode(&nonce),
    );

    Ok(Redirect::temporary(&auth_url).into_response())
}

/// GET /api/v1/auth/oidc/providers — unauthenticated
async fn list_public_providers(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<PublicProvider>>>, ApiError> {
    let providers = state.store.get_enabled_oidc_providers().await?;
    let public: Vec<PublicProvider> = providers
        .into_iter()
        .map(|p| PublicProvider {
            id: p.id.0.to_string(),
            name: p.name,
        })
        .collect();
    Ok(Json(ApiResponse::ok(public)))
}

// --- Helpers ---

/// Build the OIDC callback URI from config or request headers.
pub(crate) fn build_callback_uri(state: &AppState, headers: &HeaderMap) -> String {
    let base = if let Some(ref base_url) = state.config.base_url {
        base_url.trim_end_matches('/').to_string()
    } else {
        let host = headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("localhost:3140");
        let scheme = headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("https");
        format!("{}://{}", scheme, host)
    };
    format!("{}/api/v1/auth/oidc/callback", base)
}

/// Resolve the username from the ID token using the provider's configured `username_claim`.
pub(crate) fn resolve_username_claim(
    claim_name: &str,
    claims: &agent_cordon_core::auth::oidc::IdTokenClaims,
) -> String {
    let resolved = match claim_name {
        "preferred_username" => claims.preferred_username.clone(),
        "email" => claims.email.clone(),
        "name" => claims.name.clone(),
        "sub" => Some(claims.sub.clone()),
        other => claims
            .extra
            .get(other)
            .and_then(|v| v.as_str().map(|s| s.to_string())),
    };
    resolved
        .or_else(|| claims.preferred_username.clone())
        .or_else(|| claims.email.clone())
        .unwrap_or_else(|| claims.sub.clone())
}

/// Parse a role string into a UserRole enum value.
pub(crate) fn parse_role(role_str: &str) -> UserRole {
    match role_str {
        "admin" => UserRole::Admin,
        "operator" => UserRole::Operator,
        _ => UserRole::Viewer,
    }
}

/// Resolve the user role from the OIDC provider's role_mapping config and the ID token claims.
pub(crate) fn resolve_role(
    role_mapping: &serde_json::Value,
    claims: &agent_cordon_core::auth::oidc::IdTokenClaims,
) -> UserRole {
    let obj = match role_mapping.as_object() {
        Some(o) if !o.is_empty() => o,
        _ => return UserRole::Viewer,
    };

    let default_role = obj
        .get("default_role")
        .and_then(|v| v.as_str())
        .map(parse_role)
        .unwrap_or(UserRole::Viewer);

    let claim_name = match obj.get("claim").and_then(|v| v.as_str()) {
        Some(c) => c,
        None => return default_role,
    };
    let mappings = match obj.get("mappings").and_then(|v| v.as_object()) {
        Some(m) if !m.is_empty() => m,
        _ => return default_role,
    };

    let claim_strings: Vec<String> = match claim_name {
        "sub" => vec![claims.sub.clone()],
        "email" => claims.email.clone().into_iter().collect(),
        "preferred_username" => claims.preferred_username.clone().into_iter().collect(),
        "name" => claims.name.clone().into_iter().collect(),
        other => match claims.extra.get(other) {
            Some(serde_json::Value::String(s)) => vec![s.clone()],
            Some(serde_json::Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            _ => vec![],
        },
    };

    for val in &claim_strings {
        if let Some(role_str) = mappings.get(val).and_then(|r| r.as_str()) {
            return parse_role(role_str);
        }
    }

    default_role
}
