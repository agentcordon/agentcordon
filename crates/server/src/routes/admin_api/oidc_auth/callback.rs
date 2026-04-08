use axum::{
    extract::{Query, State},
    http::header::SET_COOKIE,
    response::{IntoResponse, Redirect, Response},
};
use uuid::Uuid;

use agent_cordon_core::auth::oidc::OidcClient;
use agent_cordon_core::crypto::password::hash_password_async;
use agent_cordon_core::crypto::session::{
    generate_csrf_token, generate_session_token, hash_session_token_hmac,
};
use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::session::Session;
use agent_cordon_core::domain::user::{User, UserId};

use crate::middleware::request_id::CorrelationId;
use crate::response::ApiError;
use crate::state::AppState;

use super::{resolve_role, resolve_username_claim, CallbackQuery};

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
        let event = AuditEvent::builder(AuditEventType::OidcLoginFailed)
            .action("oidc_login_failed")
            .resource_type("session")
            .correlation_id(&corr.0)
            .decision(
                AuditDecision::Forbid,
                Some(&format!("bypass:idp_error:{}", error)),
            )
            .details(serde_json::json!({
                "error": error,
            }))
            .build();
        if let Err(e) = state.store.append_audit_event(&event).await {
            tracing::warn!(error = %e, "Failed to write audit event");
        }

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
    let auth_state = match state.store.get_oidc_auth_state(state_param).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Ok(Redirect::temporary(&format!(
                "/?oidc_error={}",
                urlencoding::encode("Authentication session expired. Please try again.")
            ))
            .into_response());
        }
        Err(_) => {
            return Ok(Redirect::temporary(&format!(
                "/?oidc_error={}",
                urlencoding::encode("Authentication failed. Please try again.")
            ))
            .into_response());
        }
    };

    // Delete the state immediately (single-use)
    let deleted = state
        .store
        .delete_oidc_auth_state(state_param)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to delete OIDC auth state");
            ApiError::Internal("authentication failed".to_string())
        })?;

    if !deleted {
        tracing::warn!("OIDC auth state already consumed (possible replay)");
        return Ok(Redirect::temporary(&format!(
            "/?oidc_error={}",
            urlencoding::encode("Authentication session expired. Please try again.")
        ))
        .into_response());
    }

    // Check if the state has expired
    if auth_state.expires_at < chrono::Utc::now() {
        return Ok(Redirect::temporary(&format!(
            "/?oidc_error={}",
            urlencoding::encode("Authentication session expired. Please try again.")
        ))
        .into_response());
    }

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
    let client_secret_bytes = match state.encryptor.decrypt(
        &provider.encrypted_client_secret,
        &provider.nonce,
        provider.id.0.to_string().as_bytes(),
    ) {
        Ok(b) => b,
        Err(_) => {
            tracing::error!(
                "Failed to decrypt OIDC client secret for provider {}",
                provider.id.0
            );
            return Ok(Redirect::temporary(&format!(
                "/?oidc_error={}",
                urlencoding::encode("Authentication failed. Please try again.")
            ))
            .into_response());
        }
    };
    let client_secret = match String::from_utf8(client_secret_bytes) {
        Ok(s) => s,
        Err(_) => {
            tracing::error!(
                "OIDC client secret is not valid UTF-8 for provider {}",
                provider.id.0
            );
            return Ok(Redirect::temporary(&format!(
                "/?oidc_error={}",
                urlencoding::encode("Authentication failed. Please try again.")
            ))
            .into_response());
        }
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

            let event = AuditEvent::builder(AuditEventType::OidcLoginFailed)
                .action("oidc_login_failed")
                .resource_type("session")
                .correlation_id(&corr.0)
                .decision(
                    AuditDecision::Forbid,
                    Some("bypass:id_token_validation_failed"),
                )
                .details(serde_json::json!({
                    "provider_id": provider.id.0.to_string(),
                    "provider_name": provider.name,
                }))
                .build();
            let store = state.store.clone();
            tokio::spawn(async move {
                if let Err(e) = store.append_audit_event(&event).await {
                    tracing::warn!(error = %e, "Failed to write audit event");
                }
            });

            return Ok(Redirect::temporary(&format!(
                "/?oidc_error={}",
                urlencoding::encode("Authentication failed. Please try again.")
            ))
            .into_response());
        }
    };

    // Determine username from the provider's configured username_claim
    let username = resolve_username_claim(&provider.username_claim, &claims);

    // Provision or find the user
    let user = match state.store.get_user_by_username(&username).await? {
        Some(existing_user) => {
            if !existing_user.enabled {
                let event = AuditEvent::builder(AuditEventType::OidcLoginFailed)
                    .action("oidc_login_failed")
                    .user_actor(&existing_user)
                    .resource_type("session")
                    .correlation_id(&corr.0)
                    .decision(AuditDecision::Forbid, Some("bypass:user_disabled"))
                    .details(serde_json::json!({
                        "provider_name": provider.name,
                    }))
                    .build();
                if let Err(e) = state.store.append_audit_event(&event).await {
                    tracing::warn!(error = %e, "Failed to write audit event");
                }

                return Ok(Redirect::temporary(&format!(
                    "/?oidc_error={}",
                    urlencoding::encode("Your account is disabled. Contact your administrator.")
                ))
                .into_response());
            }

            let mut user = existing_user;
            user.updated_at = chrono::Utc::now();
            state.store.update_user(&user).await?;
            user
        }
        None => {
            if !provider.auto_provision {
                return Ok(Redirect::temporary(&format!(
                    "/?oidc_error={}",
                    urlencoding::encode(
                        "Your account is not provisioned. Contact your administrator."
                    )
                ))
                .into_response());
            }

            let role = resolve_role(&provider.role_mapping, &claims);

            let random_password = generate_session_token();
            let password_hash = hash_password_async(&random_password)
                .await
                .map_err(|e| ApiError::Internal(e.to_string()))?;

            let now = chrono::Utc::now();
            let new_user = User {
                id: UserId(Uuid::new_v4()),
                username: username.clone(),
                display_name: claims.name.clone(),
                password_hash,
                role,
                is_root: false,
                enabled: true,
                created_at: now,
                updated_at: now,
            };

            state.store.create_user(&new_user).await?;

            let event = AuditEvent::builder(AuditEventType::UserCreated)
                .action("create")
                .user_actor(&new_user)
                .resource("user", &new_user.id.0.to_string())
                .correlation_id(&corr.0)
                .decision(AuditDecision::Permit, Some("bypass:oidc_auto_provisioned"))
                .details(serde_json::json!({
                    "provider_name": provider.name,
                    "oidc_subject": claims.sub,
                }))
                .build();
            if let Err(e) = state.store.append_audit_event(&event).await {
                tracing::warn!(error = %e, "Failed to write audit event");
            }

            new_user
        }
    };

    // Create session
    let raw_token = generate_session_token();
    let token_hash = hash_session_token_hmac(&raw_token, &state.session_hash_key);
    let now = chrono::Utc::now();
    let ttl = chrono::Duration::seconds(state.config.session_ttl_seconds as i64);
    let expires_at = now + ttl;

    let session = Session {
        id: token_hash,
        user_id: user.id.clone(),
        created_at: now,
        expires_at,
        last_seen_at: now,
    };

    state.store.create_session(&session).await?;

    // Audit successful OIDC login
    let event = AuditEvent::builder(AuditEventType::OidcLoginSuccess)
        .action("oidc_login_success")
        .user_actor(&user)
        .resource("session", &user.id.0.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some("bypass:oidc_token_validated"))
        .details(serde_json::json!({
            "provider_name": provider.name,
            "oidc_subject": claims.sub,
            "username": user.username,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    // Build response cookies
    let session_cookie = format!(
        "agtcrdn_session={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
        raw_token, state.config.session_ttl_seconds
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
