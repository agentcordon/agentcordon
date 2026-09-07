//! Integration layer: discovery + DCR + store = `OAuthProviderClient`.
//!
//! `ensure_provider_client` is the single entry point used by the OAuth flow.
//! It walks the discovery chain (RFC 9728 -> RFC 8414), validates origins,
//! reuses an existing provider client row when one exists for the discovered
//! authorization server URL, and otherwise registers a fresh client via
//! Dynamic Client Registration (RFC 7591).

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::audit::{AuditEvent, AuditEventType};
use agent_cordon_core::domain::oauth_provider_client::{
    OAuthProviderClient, OAuthProviderClientId, RegistrationSource,
};
use uuid::Uuid;

use super::error::DiscoveryError;
use super::metadata::{
    fetch_authorization_server_metadata, fetch_protected_resource_metadata_url, guard_fetch_target,
    normalize_as_url, probe_resource_metadata_url, protected_resource_metadata_url,
    validate_endpoint_origin, validate_issuer, ProtectedResourceMetadata,
};
use super::registration::register_client;
use crate::state::AppState;
use crate::templates::McpServerTemplate;

/// Locate and fetch the resource's RFC 9728 protected-resource metadata.
///
/// A template that names `oauth2_resource_url` fixes the document's location.
/// Otherwise the MCP endpoint is asked directly: an unauthenticated request
/// draws a `401` whose `WWW-Authenticate: Bearer` challenge carries
/// `resource_metadata="<url>"`, which is where the server itself says its
/// metadata lives.
async fn fetch_resource_metadata(
    template: &McpServerTemplate,
    allow_loopback: bool,
) -> Result<ProtectedResourceMetadata, DiscoveryError> {
    let metadata_url = match template
        .oauth2_resource_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(resource_url) => protected_resource_metadata_url(resource_url),
        None => {
            let mcp_url = template.upstream_url.trim();
            if mcp_url.is_empty() {
                return Err(DiscoveryError::MissingResourceUrl);
            }
            guard_fetch_target(mcp_url, allow_loopback).await?;
            probe_resource_metadata_url(mcp_url)
                .await
                .ok_or(DiscoveryError::MissingResourceUrl)?
        }
    };

    guard_fetch_target(&metadata_url, allow_loopback).await?;
    fetch_protected_resource_metadata_url(&metadata_url).await
}

/// Ensure an `OAuthProviderClient` exists for the given MCP template.
///
/// Flow:
/// 1. Locate the resource's RFC 9728 metadata — from `oauth2_resource_url`, or
///    from the `resource_metadata` hint on the MCP endpoint's own 401.
/// 2. Read `authorization_servers[0]`; that server may live on any origin.
/// 3. Normalize the AS URL to its origin.
/// 4. If a row already exists for this AS URL and is enabled, return it.
/// 5. Otherwise, fetch authorization-server metadata.
/// 6. Check the AS metadata against itself: `issuer` must identify the URL the
///    metadata came from (RFC 8414), and every endpoint it advertises must be
///    same-origin with that issuer.
/// 7. If DCR is supported and the template prefers DCR, register a new client.
/// 8. Encrypt secrets, persist the row, emit an audit event, return it.
/// 9. If DCR is unavailable, return `DiscoveryError::NoDcrSupport` so the
///    caller can surface a "configure manually" message to the admin.
///
/// Every URL fetched along the way — the metadata documents, the MCP probe —
/// passes [`guard_fetch_target`] first, so a hostile resource server cannot
/// steer discovery onto the internal network.
pub async fn ensure_provider_client(
    state: &AppState,
    template: &McpServerTemplate,
) -> Result<OAuthProviderClient, DiscoveryError> {
    let allow_loopback = state.config.proxy_allow_loopback;

    let pr_meta = fetch_resource_metadata(template, allow_loopback).await?;
    let as_url_raw = pr_meta
        .authorization_servers
        .first()
        .ok_or(DiscoveryError::NoAuthorizationServer)?;
    let as_url = normalize_as_url(as_url_raw)?;

    if let Some(existing) = state
        .store
        .get_oauth_provider_client_by_authorization_server_url(&as_url)
        .await
        .map_err(|e| DiscoveryError::RequestFailed(format!("store lookup: {e}")))?
    {
        if existing.enabled {
            return Ok(existing);
        }
    }

    guard_fetch_target(
        &format!("{as_url}/.well-known/oauth-authorization-server"),
        allow_loopback,
    )
    .await?;
    let as_meta = fetch_authorization_server_metadata(&as_url).await?;

    // The authorization server is allowed to be somewhere else entirely — that
    // is what RFC 9728 `authorization_servers` is for. What it may not do is
    // hand out endpoints belonging to a third party: the token exchange, the
    // consent redirect and the DCR POST all stay on the issuer's own origin,
    // and the issuer has to be the server we just read the metadata from.
    validate_issuer(&as_url, &as_meta.issuer)?;
    validate_endpoint_origin(&as_meta.issuer, &as_meta.authorization_endpoint)?;
    validate_endpoint_origin(&as_meta.issuer, &as_meta.token_endpoint)?;
    if let Some(reg_endpoint) = &as_meta.registration_endpoint {
        validate_endpoint_origin(&as_meta.issuer, reg_endpoint)?;
    }

    let prefer_dcr = template.oauth2_prefer_dcr.unwrap_or(true);
    if as_meta.registration_endpoint.is_none() || !prefer_dcr {
        return Err(DiscoveryError::NoDcrSupport);
    }

    let base_url = state
        .config
        .base_url
        .as_deref()
        .ok_or_else(|| DiscoveryError::RequestFailed("AGTCRDN_BASE_URL not set".to_string()))?;
    let redirect_uri = format!(
        "{}/api/v1/mcp-servers/oauth/callback",
        base_url.trim_end_matches('/')
    );

    // TODO(sub-task 5): replace with `state.config.instance_label`.
    let client_name = "AgentCordon";
    let scopes = template.oauth2_scopes.as_deref();

    let dcr_resp = register_client(&as_meta, &redirect_uri, client_name, scopes).await?;

    let id = OAuthProviderClientId(Uuid::new_v4());
    let aad = id.0.to_string();
    let aad_bytes = aad.as_bytes();

    let (encrypted_client_secret, secret_nonce) =
        if let Some(secret) = dcr_resp.client_secret.as_deref() {
            let (enc, nonce) = state
                .crypto
                .key_ring
                .encrypt(secret.as_bytes(), aad_bytes)
                .map_err(|e| DiscoveryError::RequestFailed(format!("encryption: {e}")))?;
            (Some(enc), Some(nonce))
        } else {
            (None, None)
        };

    let (rat_enc, rat_nonce) = if let Some(rat) = dcr_resp.registration_access_token.as_deref() {
        let (enc, nonce) = state
            .crypto
            .key_ring
            .encrypt(rat.as_bytes(), aad_bytes)
            .map_err(|e| DiscoveryError::RequestFailed(format!("encryption: {e}")))?;
        (Some(enc), Some(nonce))
    } else {
        (None, None)
    };

    let now = chrono::Utc::now();
    let client = OAuthProviderClient {
        id: id.clone(),
        authorization_server_url: as_url.clone(),
        issuer: Some(as_meta.issuer.clone()),
        authorize_endpoint: as_meta.authorization_endpoint.clone(),
        token_endpoint: as_meta.token_endpoint.clone(),
        registration_endpoint: as_meta.registration_endpoint.clone(),
        code_challenge_methods_supported: as_meta.code_challenge_methods_supported.clone(),
        token_endpoint_auth_methods_supported: as_meta
            .token_endpoint_auth_methods_supported
            .clone(),
        scopes_supported: as_meta.scopes_supported.clone(),
        client_id: dcr_resp.client_id.clone(),
        encrypted_client_secret,
        nonce: secret_nonce,
        requested_scopes: template.oauth2_scopes.clone().unwrap_or_default(),
        registration_source: RegistrationSource::Dcr,
        client_id_issued_at: dcr_resp
            .client_id_issued_at
            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0)),
        client_secret_expires_at: dcr_resp
            .client_secret_expires_at
            .filter(|ts| *ts != 0)
            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0)),
        registration_access_token_encrypted: rat_enc,
        registration_access_token_nonce: rat_nonce,
        registration_client_uri: dcr_resp.registration_client_uri.clone(),
        label: template.name.clone(),
        enabled: true,
        created_at: now,
        updated_at: now,
    };

    state
        .store
        .create_oauth_provider_client(&client)
        .await
        .map_err(|e| DiscoveryError::RequestFailed(format!("store create: {e}")))?;

    let event = AuditEvent::builder(AuditEventType::OAuthProviderClientCreated)
        .action("dcr_register")
        .resource("oauth_provider_client", &client.id.0.to_string())
        .details(serde_json::json!({
            "authorization_server_url": &as_url,
            "source": "dcr",
            "client_id": &client.client_id,
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "failed to write DCR audit event");
    }

    Ok(client)
}
