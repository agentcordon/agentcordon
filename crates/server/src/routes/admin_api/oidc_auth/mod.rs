mod callback;

use axum::{
    extract::{Query, State},
    http::{header::HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};

use agent_cordon_core::auth::oidc::OidcClient;

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

    // Build the callback redirect_uri, then mint the single-use state/nonce
    let redirect_uri = build_callback_uri(&state, &headers);
    let auth_state = state
        .services
        .identity_providers
        .create_login_state(&provider_id, &redirect_uri)
        .await?;

    // Build the authorization URL
    let scopes = provider.scopes.join(" ");
    let auth_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}",
        discovery.authorization_endpoint,
        urlencoding::encode(&provider.client_id),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(&scopes),
        urlencoding::encode(&auth_state.state),
        urlencoding::encode(&auth_state.nonce),
    );

    // 302 Found, the status a browser starting an SSO sign-in expects from the
    // login page's link. Built by hand because axum's `Redirect` offers only
    // 303, 307 and 308.
    Ok((
        StatusCode::FOUND,
        [(axum::http::header::LOCATION, auth_url)],
    )
        .into_response())
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
