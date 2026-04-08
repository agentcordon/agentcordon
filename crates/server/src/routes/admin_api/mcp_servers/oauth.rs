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

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::credential::StoredCredential;
use agent_cordon_core::domain::mcp::{McpAuthMethod, McpServer, McpServerId, McpTransport};
use agent_cordon_core::domain::mcp_oauth::McpOAuthState;
use agent_cordon_core::domain::workspace::WorkspaceId;

use crate::oauth_discovery::DiscoveryError;

use crate::credential_service::{self, NewCredentialParams};
use crate::events::UiEvent;
use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

use super::check_manage_mcp_servers;
use super::oauth_token::{exchange_code_for_tokens, generate_pkce, generate_state_token};

/// Map a `DiscoveryError` from `ensure_provider_client` into an `ApiError`
/// suitable for returning to admins via the initiate endpoint.
fn map_discovery_error(
    template: &crate::routes::admin_api::mcp_templates::McpServerTemplate,
    e: DiscoveryError,
) -> ApiError {
    match e {
        DiscoveryError::NoDcrSupport => ApiError::BadRequest(format!(
            "Provider '{}' does not support Dynamic Client Registration. \
             Configure it manually in Settings > OAuth Provider Clients.",
            template.name
        )),
        DiscoveryError::MissingResourceUrl => ApiError::BadRequest(format!(
            "Template '{}' is missing oauth2_resource_url",
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
    check_manage_mcp_servers(&state, &auth)?;

    let template = state
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
            let event = AuditEvent::builder(AuditEventType::OAuthProviderDiscoveryFailed)
                .action("discover")
                .resource("mcp_template", &template.key)
                .correlation_id(&corr.0)
                .details(serde_json::json!({
                    "template_key": template.key,
                    "error": format!("{e}"),
                }))
                .build();
            let _ = state.store.append_audit_event(&event).await;
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
    let now = chrono::Utc::now();
    let ttl = chrono::Duration::seconds(state.config.oidc_state_ttl_seconds as i64);
    let mcp_state = McpOAuthState {
        state: oauth_state.clone(),
        template_key: template.key.clone(),
        workspace_id,
        user_id: auth.user.id.clone(),
        redirect_uri: redirect_uri.clone(),
        code_verifier: Some(code_verifier),
        authorization_server_url: Some(oauth_app.authorization_server_url.clone()),
        created_at: now,
        expires_at: now + ttl,
    };
    state.store.create_mcp_oauth_state(&mcp_state).await?;

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
        workspace_id = %mcp_state.workspace_id.0,
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

    let client_secret_opt: Option<String> = if let (Some(enc), Some(nonce)) = (
        oauth_app.encrypted_client_secret.as_ref(),
        oauth_app.nonce.as_ref(),
    ) {
        let bytes = state
            .encryptor
            .decrypt(enc, nonce, oauth_app.id.0.to_string().as_bytes())?;
        Some(String::from_utf8(bytes).map_err(|_| {
            ApiError::Internal("oauth provider client_secret is not valid UTF-8".to_string())
        })?)
    } else {
        None
    };

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

    // Create or reuse credential + MCP server.
    let workspace = state
        .store
        .get_workspace(&mcp_state.workspace_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("workspace not found".to_string()))?;

    // Fix #1: Reuse an existing oauth2_user_authorization credential for this
    // (user, template) pair if one already exists. Service is set to template.key
    // at creation time, and credential_type is "oauth2_user_authorization".
    let existing_creds = state.store.list_all_stored_credentials().await?;
    let existing_cred = existing_creds.into_iter().find(|c| {
        c.created_by_user.as_ref() == Some(&auth.user.id)
            && c.service == template.key
            && c.credential_type == "oauth2_user_authorization"
    });

    let (cred_id, reused_credential) = if let Some(c) = existing_cred {
        tracing::info!(
            credential_id = %c.id.0,
            template = %template.key,
            user = %auth.user.id.0,
            "reusing existing OAuth credential for second-workspace install"
        );
        (c.id, true)
    } else {
        let cred = create_oauth_credential(
            &state,
            &auth,
            &template,
            &workspace,
            OAuthCredentialParams {
                token_url: &oauth_app.token_endpoint,
                client_id: &oauth_app.client_id,
                authorization_server_url: &oauth_app.authorization_server_url,
                refresh_token,
            },
        )?;
        state.store.store_credential(&cred).await?;
        credential_service::emit_credential_created(&state, cred.id.0, cred.name.clone());
        (cred.id, false)
    };

    // Fix #1: Reuse an existing MCP server for this (user, template) pair if
    // present. The server stays bound to its original workspace_id; Cedar's
    // same-owner default policy makes it usable from the new workspace too.
    let user_servers = state.store.list_mcp_servers_by_user(&auth.user.id).await?;
    let existing_server = user_servers
        .into_iter()
        .find(|s| s.template_key.as_deref() == Some(template.key.as_str()));

    let (server, reused_server) = if let Some(s) = existing_server {
        tracing::info!(
            server_id = %s.id.0,
            template = %template.key,
            user = %auth.user.id.0,
            "reusing existing MCP server for second-workspace install"
        );
        (s, true)
    } else {
        let s = create_mcp_server(
            &template,
            &mcp_state.workspace_id,
            &cred_id,
            &mcp_state.user_id,
        );
        state.store.create_mcp_server(&s).await?;
        (s, false)
    };

    // Best-effort tool discovery
    match super::discover::attempt_tool_discovery(&state, &server, Some(&access_token)).await {
        Ok(tools) if !tools.is_empty() => {
            let mut updated = server.clone();
            updated.allowed_tools = Some(tools.iter().map(|t| t.name.clone()).collect());
            updated.discovered_tools = Some(tools);
            if let Err(e) = state.store.update_mcp_server(&updated).await {
                tracing::warn!(error = %e, server = %server.name, "failed to update discovered tools");
            }
        }
        Ok(_) => {
            tracing::debug!(server = %server.name, "tool discovery returned empty list")
        }
        Err(e) => {
            tracing::debug!(server = %server.name, error = %e, "tool discovery failed (non-fatal)")
        }
    }

    state.ui_event_bus.emit(UiEvent::McpServerChanged {
        server_name: server.name.clone(),
    });

    // Audit
    let server_id_str = server.id.0.to_string();
    let workspace_id_str = mcp_state.workspace_id.0.to_string();
    let event = AuditEvent::builder(AuditEventType::McpServerProvisioned)
        .action("provision")
        .user_actor(&auth.user)
        .resource("mcp_server", &server_id_str)
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("oauth2_user_authorization"))
        .details(serde_json::json!({
            "template_key": template.key,
            "server_name": template.name,
            "workspace_id": workspace_id_str,
            "workspace_name": workspace.name,
            "auth_method": "oauth2",
            "source": "oauth2",
            "reused_credential": reused_credential,
            "reused_server": reused_server,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    Ok(redirect_with_status("success", Some(&template.key)))
}

/// Parameters for creating an OAuth2 authorization code credential.
struct OAuthCredentialParams<'a> {
    token_url: &'a str,
    client_id: &'a str,
    authorization_server_url: &'a str,
    refresh_token: String,
}

/// Build a `StoredCredential` for an OAuth2 authorization code flow.
fn create_oauth_credential(
    state: &AppState,
    auth: &AuthenticatedUser,
    template: &crate::routes::admin_api::mcp_templates::McpServerTemplate,
    workspace: &agent_cordon_core::domain::workspace::Workspace,
    params: OAuthCredentialParams<'_>,
) -> Result<StoredCredential, ApiError> {
    let cred_name = format!("{}-{}", template.key, workspace.name);
    credential_service::build_credential(
        state.encryptor.as_ref(),
        NewCredentialParams {
            name: cred_name,
            service: template.key.clone(),
            secret_value: params.refresh_token,
            credential_type: "oauth2_user_authorization".to_string(),
            scopes: vec![],
            metadata: serde_json::json!({
                "oauth2_token_url": params.token_url,
                "oauth2_client_id": params.client_id,
                "authorization_server_url": params.authorization_server_url,
                "template_key": template.key,
            }),
            tags: vec![format!("mcp:{}", template.key)],
            vault: "default".to_string(),
            created_by: None,
            created_by_user: Some(auth.user.id.clone()),
            allowed_url_pattern: Some(format!("{}*", template.upstream_url)),
            expires_at: None,
            transform_script: None,
            transform_name: Some("bearer".to_string()),
            description: Some(format!(
                "OAuth2 credential for MCP server '{}' on workspace '{}'",
                template.name, workspace.name
            )),
            target_identity: None,
        },
    )
}

/// Create an MCP server record for an OAuth2-provisioned template.
fn create_mcp_server(
    template: &crate::routes::admin_api::mcp_templates::McpServerTemplate,
    workspace_id: &WorkspaceId,
    credential_id: &agent_cordon_core::domain::credential::CredentialId,
    user_id: &agent_cordon_core::domain::user::UserId,
) -> McpServer {
    let now = chrono::Utc::now();
    let transport = McpTransport::from_str_opt(&template.transport).unwrap_or_default();
    McpServer {
        id: McpServerId(Uuid::new_v4()),
        workspace_id: workspace_id.clone(),
        name: template.key.clone(),
        upstream_url: template.upstream_url.clone(),
        transport,
        allowed_tools: None,
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
        tags: template.tags.clone(),
        required_credentials: Some(vec![credential_id.clone()]),
        auth_method: McpAuthMethod::OAuth2,
        template_key: Some(template.key.clone()),
        discovered_tools: None,
        created_by_user: Some(user_id.clone()),
    }
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
