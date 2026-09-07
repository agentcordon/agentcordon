//! MCP server provisioning via OAuth2 authorization code flow.
//!
//! `POST /api/v1/mcp-servers/oauth/initiate` — start the OAuth flow, returns authorize URL.
//! `GET  /api/v1/mcp-servers/oauth/callback`  — handle the OAuth callback from the IdP.

use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agent_cordon_core::domain::workspace::WorkspaceId;

use crate::oauth_discovery::DiscoveryError;

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::services::mcp_servers::{OAuthFlowStart, OAuthProvisionInput};
use crate::state::AppState;

use super::oauth_token::{exchange_code_for_tokens, generate_pkce, generate_state_token};
use agent_cordon_core::policy::actions;
use agent_cordon_core::policy::PolicyResource;

/// Map a `DiscoveryError` from `ensure_provider_client` into an `ApiError`
/// suitable for returning to admins via the initiate endpoint.
fn map_discovery_error(
    template: &crate::templates::McpServerTemplate,
    e: DiscoveryError,
) -> ApiError {
    match e {
        DiscoveryError::NoDcrSupport => ApiError::BadRequest(format!(
            "Provider '{}' does not support Dynamic Client Registration. \
             Configure it manually in Settings > OAuth Provider Clients.",
            template.name
        )),
        DiscoveryError::MissingResourceUrl => ApiError::BadRequest(format!(
            "Template '{}' has no oauth2_resource_url and its MCP endpoint returned no \
             'WWW-Authenticate: Bearer resource_metadata=...' discovery hint",
            template.key
        )),
        other => ApiError::BadRequest(format!("OAuth discovery failed: {other}")),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InitiateRequest {
    pub template_key: String,
    pub workspace_id: Uuid,
}

#[derive(Serialize)]
pub(crate) struct InitiateResponse {
    pub authorize_url: String,
}

/// `POST /api/v1/mcp-servers/oauth/initiate`
///
/// Start the OAuth2 authorization code flow for an MCP server template.
pub(crate) async fn initiate_oauth(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<InitiateRequest>,
) -> Result<Json<ApiResponse<InitiateResponse>>, ApiError> {
    state
        .authz
        .authorize(&auth, actions::MANAGE_MCP_SERVERS, &PolicyResource::System)
        .await?;

    let template = state
        .catalog
        .mcp_templates
        .iter()
        .find(|t| t.key == req.template_key)
        .ok_or_else(|| {
            ApiError::NotFound(format!("MCP template '{}' not found", req.template_key))
        })?
        .clone();

    if template.auth_method != "oauth2" {
        return Err(ApiError::BadRequest(format!(
            "template '{}' does not use OAuth2 authentication",
            template.key
        )));
    }

    // Resolve OAuth provider client via discovery (RFC 9728 + 8414 + 7591).
    // If a row already exists for the discovered authorization server (manual or
    // DCR), it is reused. Otherwise we attempt DCR.
    let oauth_app = match crate::oauth_discovery::ensure_provider_client(&state, &template).await {
        Ok(app) => app,
        Err(e) => {
            // Emit discovery-failure audit event (sink: audit log)
            state
                .services
                .mcp_servers
                .record_oauth_discovery_failure(&corr.0, &template.key, &format!("{e}"))
                .await;
            return Err(map_discovery_error(&template, e));
        }
    };

    // Verify workspace exists
    let workspace_id = WorkspaceId(req.workspace_id);
    let _workspace = state
        .store
        .get_workspace(&workspace_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("workspace not found".to_string()))?;

    // NOTE: we used to reject a second install of the same template here.
    // Fix #1: allow reuse — the callback will detect an existing credential
    // + MCP server for this (user, template) pair and skip duplicate creation,
    // making the server available to the new workspace via Cedar's same-owner
    // default policy (no new DB rows).

    // Generate state + PKCE
    let oauth_state = generate_state_token();
    let (code_verifier, code_challenge) = generate_pkce();

    // Build redirect_uri
    let base_url = state.config.base_url.as_deref().ok_or_else(|| {
        ApiError::BadRequest("AGTCRDN_BASE_URL must be configured for OAuth2 flows".to_string())
    })?;
    let redirect_uri = format!(
        "{}/api/v1/mcp-servers/oauth/callback",
        base_url.trim_end_matches('/')
    );

    // Store OAuth state
    state
        .services
        .mcp_servers
        .begin_oauth_flow(OAuthFlowStart {
            template_key: &template.key,
            workspace_id: workspace_id.clone(),
            user_id: auth.user.id.clone(),
            redirect_uri: redirect_uri.clone(),
            code_verifier,
            authorization_server_url: oauth_app.authorization_server_url.clone(),
            state_token: oauth_state.clone(),
        })
        .await?;

    // Build authorize URL using app config
    let mut url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&state={}",
        oauth_app.authorize_endpoint,
        urlencoding::encode(&oauth_app.client_id),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(&oauth_state),
    );
    if !oauth_app.requested_scopes.is_empty() {
        url.push_str(&format!(
            "&scope={}",
            urlencoding::encode(&oauth_app.requested_scopes)
        ));
    }
    url.push_str(&format!(
        "&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(&code_challenge),
    ));

    tracing::info!(
        template_key = %template.key,
        workspace_id = %workspace_id.0,
        correlation_id = %corr.0,
        "initiated MCP OAuth2 flow"
    );

    Ok(Json(ApiResponse::ok(InitiateResponse {
        authorize_url: url,
    })))
}

#[derive(Deserialize)]
pub(crate) struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// Browser-safe wrapper for `oauth_callback`. The callback is a redirect target
/// from external IdPs — if the user's session expired during the OAuth flow, we
/// must redirect to login instead of returning a raw JSON/API error.
pub(crate) async fn oauth_callback_wrapper(
    State(app_state): State<AppState>,
    request: axum::extract::Request,
) -> Response {
    use axum::extract::FromRequestParts;
    let (mut parts, _body) = request.into_parts();

    // Try to extract the authenticated user from session cookie.
    let auth = match AuthenticatedUser::from_request_parts(&mut parts, &app_state).await {
        Ok(a) => a,
        Err(_) => {
            tracing::warn!("MCP OAuth callback: session expired or missing — redirecting to login");
            return Redirect::to("/login?reason=session_expired").into_response();
        }
    };
    let corr = parts
        .extensions
        .get::<CorrelationId>()
        .cloned()
        .unwrap_or_else(|| CorrelationId(uuid::Uuid::new_v4().to_string()));
    let query = match Query::<CallbackQuery>::from_request_parts(&mut parts, &app_state).await {
        Ok(q) => q,
        Err(_) => {
            return redirect_with_status("error", Some("invalid_request")).into_response();
        }
    };
    match oauth_callback(State(app_state), auth, axum::Extension(corr), query).await {
        Ok(resp) => resp,
        Err(e) => redirect_with_status("error", Some(&format!("{e:?}"))).into_response(),
    }
}

/// `GET /api/v1/mcp-servers/oauth/callback`
///
/// Handle the OAuth2 callback from the external service.
async fn oauth_callback(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, ApiError> {
    if let Some(error) = &query.error {
        tracing::warn!(
            error = %error,
            description = query.error_description.as_deref().unwrap_or("unknown"),
            "MCP OAuth2 IdP returned error"
        );
        return Ok(redirect_with_status("error", Some(error)));
    }

    let code = query
        .code
        .as_deref()
        .ok_or_else(|| ApiError::BadRequest("missing 'code' parameter".to_string()))?;
    let state_param = query
        .state
        .as_deref()
        .ok_or_else(|| ApiError::BadRequest("missing 'state' parameter".to_string()))?;

    // Consume state (single-use, atomic)
    let mcp_state = state
        .store
        .consume_mcp_oauth_state(state_param)
        .await?
        .ok_or_else(|| ApiError::BadRequest("invalid or expired OAuth state".to_string()))?;

    if mcp_state.expires_at < chrono::Utc::now() {
        return Ok(redirect_with_status("error", Some("session_expired")));
    }
    if mcp_state.user_id != auth.user.id {
        tracing::warn!(
            expected_user = %mcp_state.user_id.0,
            actual_user = %auth.user.id.0,
            "MCP OAuth callback user mismatch"
        );
        return Ok(redirect_with_status("error", Some("user_mismatch")));
    }

    // Resolve template
    let template = state
        .catalog
        .mcp_templates
        .iter()
        .find(|t| t.key == mcp_state.template_key)
        .ok_or_else(|| {
            ApiError::Internal(format!(
                "template '{}' no longer exists",
                mcp_state.template_key
            ))
        })?
        .clone();

    // Load the OAuth provider client by the authorization_server_url that was
    // captured when the flow was initiated. This is the same row that was
    // created/cached by `ensure_provider_client` during initiate.
    let as_url = mcp_state
        .authorization_server_url
        .as_deref()
        .ok_or_else(|| {
            ApiError::Internal("OAuth state missing authorization_server_url".to_string())
        })?;
    let oauth_app = state
        .store
        .get_oauth_provider_client_by_authorization_server_url(as_url)
        .await?
        .ok_or_else(|| {
            ApiError::Internal("OAuth provider client disappeared mid-flow".to_string())
        })?;

    let client_secret_opt = state
        .services
        .identity_providers
        .open_oauth_client_secret(&oauth_app)?;

    // Exchange code for tokens
    let token_response = exchange_code_for_tokens(
        &state.http_client,
        &oauth_app.token_endpoint,
        code,
        &mcp_state.redirect_uri,
        &oauth_app.client_id,
        client_secret_opt.as_deref(),
        mcp_state.code_verifier.as_deref(),
    )
    .await?;

    let refresh_token = token_response.refresh_token.ok_or_else(|| {
        ApiError::BadRequest(
            "OAuth provider did not return a refresh token. \
             Some providers only issue refresh tokens on first authorization."
                .to_string(),
        )
    })?;
    let access_token = token_response.access_token;

    state
        .services
        .mcp_servers
        .provision_from_oauth(
            &auth,
            &corr.0,
            OAuthProvisionInput {
                template: &template,
                workspace_id: &mcp_state.workspace_id,
                token_url: &oauth_app.token_endpoint,
                client_id: &oauth_app.client_id,
                authorization_server_url: &oauth_app.authorization_server_url,
                refresh_token,
                access_token: &access_token,
            },
        )
        .await?;

    Ok(redirect_with_status("success", Some(&template.key)))
}

/// Build a redirect response to the MCP servers page with OAuth status.
fn redirect_with_status(status: &str, detail: Option<&str>) -> Response {
    let mut url = format!("/mcp-servers?oauth={}", urlencoding::encode(status));
    if let Some(d) = detail {
        if status == "success" {
            url.push_str(&format!("&template={}", urlencoding::encode(d)));
        } else {
            url.push_str(&format!("&reason={}", urlencoding::encode(d)));
        }
    }
    Redirect::temporary(&url).into_response()
}
