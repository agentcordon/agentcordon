use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;

use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::policy::{actions, PolicyPrincipal, PolicyResource};

use crate::crypto_helpers::parse_broker_public_key;
use crate::extractors::authenticated_workspace;
use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::services::credentials::{VendOutcome, VendTarget};
use crate::state::AppState;

pub(crate) use agent_cordon_core::wire::credentials::{VendRequest, VendResponse};
use agent_cordon_core::wire::EncryptedEnvelopeWire;

/// Shape a completed vend into its wire response. The credential material
/// is ONLY in the ECIES envelope.
fn vend_response(v: VendOutcome) -> VendResponse {
    VendResponse {
        credential_type: v.credential_type,
        transform_name: v.transform_name,
        allowed_url_pattern: v.allowed_url_pattern,
        encrypted_envelope: EncryptedEnvelopeWire {
            version: v.envelope.version,
            ephemeral_public_key: v.envelope.ephemeral_public_key,
            ciphertext: v.envelope.ciphertext,
            nonce: v.envelope.nonce,
            aad: v.envelope.aad,
        },
        vend_id: v.vend_id,
    }
}

/// The request the credential is about to be injected into, as named by the
/// caller. Trimming, the `GET` default and upper-casing are the server's
/// decision, so they live here rather than on the wire type.
fn vend_target(req: &VendRequest) -> Option<VendTarget> {
    let url = req
        .target_url
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())?;
    Some(VendTarget {
        method: req
            .method
            .as_deref()
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .unwrap_or("GET")
            .to_ascii_uppercase(),
        url: url.to_string(),
    })
}

/// POST /credentials/{id}/reveal
///
/// Vault-style secret reveal: decrypts and returns the credential's raw secret
/// value. Only human users (session cookie auth) are allowed. Cedar policy
/// with action `"unprotect"` is evaluated BEFORE decryption. Agents are
/// forbidden from using this endpoint via both extractor and Cedar forbid rule.
pub(crate) async fn reveal_credential(
    State(state): State<AppState>,
    auth_user: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let secret_value = state
        .services
        .credentials
        .reveal(&auth_user, &corr.0, &CredentialId(id))
        .await?;

    Ok(Json(ApiResponse::ok(serde_json::json!({
        "secret_value": secret_value,
    }))))
}

/// POST /credentials/{id}/vend
///
/// Vend a credential to a workspace by credential ID.
/// Auth: workspace JWT (Authorization: Bearer).
pub(crate) async fn vend_credential(
    State(state): State<AppState>,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
    headers: axum::http::HeaderMap,
    body: Option<Json<VendRequest>>,
) -> Result<Json<ApiResponse<VendResponse>>, ApiError> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::Unauthorized("missing Authorization header".to_string()))?;
    let auth = authenticated_workspace::authenticate_workspace(&state, auth_header).await?;
    auth.require_scope(agent_cordon_core::oauth2::types::OAuthScope::CredentialsVend)?;

    let broker_pub = match &body {
        Some(Json(req)) => req
            .broker_public_key
            .as_deref()
            .map(parse_broker_public_key)
            .transpose()?,
        None => None,
    };
    let target = body.as_ref().and_then(|Json(req)| vend_target(req));

    let cred = state.services.credentials.load(&CredentialId(id)).await?;

    let outcome = state
        .services
        .credentials
        .vend(
            &auth.workspace,
            auth.oauth_claims,
            &cred,
            &corr.0,
            broker_pub,
            target.as_ref(),
        )
        .await?;
    Ok(Json(ApiResponse::ok(vend_response(outcome))))
}

/// POST /api/v1/credentials/vend-device/{name}
///
/// Vend a credential to a workspace by credential name.
/// Auth: workspace JWT (Authorization: Bearer).
pub(crate) async fn vend_credential_to_device(
    State(state): State<AppState>,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    headers: axum::http::HeaderMap,
    Path(name): Path<String>,
    body: Option<Json<VendRequest>>,
) -> Result<Json<ApiResponse<VendResponse>>, ApiError> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::Unauthorized("workspace authentication required".to_string()))?;
    let auth = authenticated_workspace::authenticate_workspace(&state, auth_header).await?;
    auth.require_scope(agent_cordon_core::oauth2::types::OAuthScope::CredentialsVend)?;

    let broker_pub = match &body {
        Some(Json(req)) => req
            .broker_public_key
            .as_deref()
            .map(parse_broker_public_key)
            .transpose()?,
        None => None,
    };
    let target = body.as_ref().and_then(|Json(req)| vend_target(req));

    // Resolve credential by name: load only credentials matching this name,
    // then evaluate Cedar authorization on each match.
    let name_matches = state.store.list_stored_credentials_by_name(&name).await?;

    // Cedar check: filter via Authz seam (each item audited).
    let authorized_matches: Vec<StoredCredential> = state
        .authz
        .request(
            crate::authz::PolicyCaller::Principal {
                principal: PolicyPrincipal::Workspace(&auth.workspace),
                oauth_claims: auth.oauth_claims.clone(),
            },
            &corr.0,
        )
        .filter(actions::VEND_CREDENTIAL, name_matches.clone(), |c| {
            PolicyResource::Credential {
                credential: c.clone(),
            }
        })
        .await?;

    let cred = match authorized_matches.len() {
        0 => {
            // No exact-name match. Surface authorized prefix matches as
            // candidates so the caller (CLI) can show the user a list of
            // credentials they likely meant (e.g. `mock` -> `mock-1`,
            // `mock-2`). Only includes credentials the workspace is
            // actually authorized to vend, to avoid leaking names.
            let all = state
                .store
                .list_all_stored_credentials()
                .await
                .unwrap_or_default();
            let prefix = name.as_str();
            let mut prefix_candidates: Vec<serde_json::Value> = Vec::new();
            let candidate_creds: Vec<StoredCredential> = all
                .into_iter()
                .filter(|c| c.name.starts_with(prefix) && c.name != *prefix)
                .collect();
            let allowed_prefix_creds: Vec<StoredCredential> = state
                .authz
                .request(
                    crate::authz::PolicyCaller::Principal {
                        principal: PolicyPrincipal::Workspace(&auth.workspace),
                        oauth_claims: auth.oauth_claims.clone(),
                    },
                    &corr.0,
                )
                .filter(actions::VEND_CREDENTIAL, candidate_creds, |c| {
                    PolicyResource::Credential {
                        credential: c.clone(),
                    }
                })
                .await?;
            for cred in allowed_prefix_creds {
                prefix_candidates.push(serde_json::json!({
                    "id": cred.id.0.to_string(),
                    "name": cred.name,
                    "service": cred.service,
                    "description": cred.description,
                }));
            }
            if !prefix_candidates.is_empty() {
                return Err(ApiError::NotFoundWithCandidates {
                    message: format!(
                        "no credential exactly named '{}'. Did you mean one of these?",
                        name
                    ),
                    candidates: prefix_candidates,
                });
            }
            return Err(ApiError::NotFound(format!(
                "credential '{}' not found or not authorized",
                name
            )));
        }
        1 => authorized_matches.into_iter().next().unwrap(),
        _ => {
            // Multiple authorized credentials match — return candidates
            let candidates: Vec<serde_json::Value> = authorized_matches
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "id": c.id.0.to_string(),
                        "name": c.name,
                        "service": c.service,
                        "description": c.description,
                    })
                })
                .collect();
            return Err(ApiError::MultipleChoices {
                message: format!(
                    "Multiple credentials match name '{}'. Specify by ID or use a unique name.",
                    name
                ),
                candidates,
            });
        }
    };

    let outcome = state
        .services
        .credentials
        .vend(
            &auth.workspace,
            auth.oauth_claims,
            &cred,
            &corr.0,
            broker_pub,
            target.as_ref(),
        )
        .await?;
    Ok(Json(ApiResponse::ok(vend_response(outcome))))
}
