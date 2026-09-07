use agent_cordon_core::auth::oidc::OidcClient;
use agent_cordon_core::crypto::session::generate_csrf_token;
use axum::{
    extract::{Query, State},
    http::header::SET_COOKIE,
    response::{IntoResponse, Redirect, Response},
};

use crate::middleware::request_id::CorrelationId;
use crate::response::ApiError;
use crate::services::identity_providers::LoginState;
use crate::services::users::OidcLoginOutcome;
use crate::state::AppState;

use super::CallbackQuery;

/// GET /api/v1/auth/oidc/callback?code={code}&state={state}
pub(super) async fn callback(
    State(state): State<AppState>,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, ApiError> {
    // Handle error responses from IdP
    if let Some(error) = &query.error {
        let description = query.error_description.as_deref().unwrap_or("unknown");
        tracing::warn!(
            error = %error,
            description = %description,
            "OIDC IdP returned error"
        );

        // Audit the failed login
        state
            .services
            .users
            .record_oidc_idp_error(&corr.0, error)
            .await;

        return Ok(Redirect::temporary(&format!(
            "/?oidc_error={}",
            urlencoding::encode("Sign in was cancelled or denied.")
        ))
        .into_response());
    }

    let code = match query.code.as_deref() {
        Some(c) => c,
        None => {
            return Ok(Redirect::temporary(&format!(
                "/?oidc_error={}",
                urlencoding::encode("Authentication failed. Please try again.")
            ))
            .into_response());
        }
    };
    let state_param = match query.state.as_deref() {
        Some(s) => s,
        None => {
            return Ok(Redirect::temporary(&format!(
                "/?oidc_error={}",
                urlencoding::encode("Authentication failed. Please try again.")
            ))
            .into_response());
        }
    };

    // Look up and consume the auth state (single-use)
    let auth_state = match state
        .services
        .identity_providers
        .consume_login_state(state_param)
        .await?
    {
        LoginState::Valid(s) => s,
        LoginState::Unusable => {
            return Ok(Redirect::temporary(&format!(
                "/?oidc_error={}",
                urlencoding::encode("Authentication session expired. Please try again.")
            ))
            .into_response());
        }
        LoginState::Unavailable => {
            return Ok(Redirect::temporary(&format!(
                "/?oidc_error={}",
                urlencoding::encode("Authentication failed. Please try again.")
            ))
            .into_response());
        }
    };

    // Look up the provider
    let provider = match state.store.get_oidc_provider(&auth_state.provider_id).await {
        Ok(Some(p)) => p,
        _ => {
            return Ok(Redirect::temporary(&format!(
                "/?oidc_error={}",
                urlencoding::encode("Authentication failed. Please try again.")
            ))
            .into_response());
        }
    };

    // Decrypt the client secret
    let Some(client_secret) = state
        .services
        .identity_providers
        .open_oidc_client_secret(&provider)
    else {
        return Ok(Redirect::temporary(&format!(
            "/?oidc_error={}",
            urlencoding::encode("Authentication failed. Please try again.")
        ))
        .into_response());
    };

    // Discover OIDC endpoints
    let oidc_client = OidcClient::new();
    let discovery = match oidc_client.discover(&provider.issuer_url).await {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "OIDC discovery failed");
            return Ok(Redirect::temporary(&format!(
                "/?oidc_error={}",
                urlencoding::encode("Could not connect to identity provider. Please try again.")
            ))
            .into_response());
        }
    };

    // Exchange the authorization code for tokens
    let token_response = match oidc_client
        .exchange_code(
            &discovery.token_endpoint,
            code,
            &auth_state.redirect_uri,
            &provider.client_id,
            &client_secret,
        )
        .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "OIDC token exchange failed");
            return Ok(Redirect::temporary(&format!(
                "/?oidc_error={}",
                urlencoding::encode("Could not connect to identity provider. Please try again.")
            ))
            .into_response());
        }
    };

    let id_token_str = match token_response.id_token {
        Some(t) => t,
        None => {
            tracing::warn!("OIDC token response missing id_token");
            return Ok(Redirect::temporary(&format!(
                "/?oidc_error={}",
                urlencoding::encode("Could not connect to identity provider. Please try again.")
            ))
            .into_response());
        }
    };

    // Validate the ID token
    let claims = match oidc_client
        .validate_id_token(
            &id_token_str,
            &discovery.jwks_uri,
            &discovery.issuer,
            &provider.client_id,
            &auth_state.nonce,
        )
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "OIDC ID token validation failed");

            state
                .services
                .users
                .record_oidc_token_validation_failed(&corr.0, &provider)
                .await;

            return Ok(Redirect::temporary(&format!(
                "/?oidc_error={}",
                urlencoding::encode("Authentication failed. Please try again.")
            ))
            .into_response());
        }
    };

    // Account resolution and the session row belong to the user service:
    // it owns the user and session tables and every audit row they imply.
    let session = match state
        .services
        .users
        .login_with_oidc(&corr.0, &provider, &claims)
        .await?
    {
        OidcLoginOutcome::Session(session) => session,
        OidcLoginOutcome::Rejected(message) => {
            return Ok(Redirect::temporary(&format!(
                "/?oidc_error={}",
                urlencoding::encode(message)
            ))
            .into_response());
        }
    };

    // Build response cookies
    let session_cookie = format!(
        "agtcrdn_session={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
        session.raw_token, state.config.session_ttl_seconds
    );

    let csrf_token = generate_csrf_token();
    let csrf_cookie = format!(
        "agtcrdn_csrf={}; Secure; SameSite=Lax; Path=/; Max-Age={}",
        csrf_token, state.config.session_ttl_seconds
    );

    let mut response = Redirect::temporary("/").into_response();
    response.headers_mut().append(
        SET_COOKIE,
        session_cookie
            .parse()
            .map_err(|_| ApiError::Internal("invalid session cookie header".into()))?,
    );
    response.headers_mut().append(
        SET_COOKIE,
        csrf_cookie
            .parse()
            .map_err(|_| ApiError::Internal("invalid csrf cookie header".into()))?,
    );

    Ok(response)
}
