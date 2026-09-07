//! RFC 8628 OAuth 2.0 Device Authorization Grant — `POST /oauth/device/code`.
//!
//! The client (typically a headless CLI) POSTs `client_id` + `scope` and
//! receives a `device_code`, a short user-facing `user_code`, a verification
//! URI, and polling parameters. The user then visits `/activate` in a browser,
//! approves the request, and the client exchanges the `device_code` at
//! `/oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`.

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    Form, Json,
};
use serde::{Deserialize, Serialize};

use agent_cordon_core::oauth2::types::DeviceCode;

use crate::extractors::{AuthenticatedUser, ClientAddr};
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse, OAuthError};
use crate::state::AppState;

pub(crate) use agent_cordon_core::wire::oauth::{
    DeviceAuthorizationRequest, DeviceAuthorizationResponse,
};

fn no_store_headers() -> [(header::HeaderName, &'static str); 2] {
    [
        (header::CACHE_CONTROL, "no-store"),
        (header::PRAGMA, "no-cache"),
    ]
}

/// `POST /oauth/device/code` — initiate the device authorization grant.
pub(crate) async fn device_code_endpoint(
    State(state): State<AppState>,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    ClientAddr(client_addr): ClientAddr,
    Form(req): Form<DeviceAuthorizationRequest>,
) -> axum::response::Response {
    // RFC 6749 §5.2: missing required parameter → 400 invalid_request.
    let client_id = match req.client_id.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => return OAuthError::invalid_request("client_id is required").into_response(),
    };

    // Unauthenticated and row-creating: bound it per source and client so
    // one caller cannot fill the table or mint codes for approvers to
    // mis-approve.
    if let Some(retry_after) = state
        .limits
        .device_code_issue
        .hit(&format!("{client_addr}|{client_id}"))
    {
        let mut resp = OAuthError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "slow_down",
            "too many device authorization requests; retry later",
        )
        .into_response();
        if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after.to_string()) {
            resp.headers_mut().insert("retry-after", v);
        }
        return resp;
    }

    // Empty scope string is allowed (defaults to the client's registered
    // allowed_scopes).
    let scope = req.scope.as_deref().filter(|s| !s.trim().is_empty());

    let workspace_name_prefill = req
        .workspace_name
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    // Bind the broker-supplied public_key_hash at issue time. Accept both the
    // `sha256:<hex>` prefixed form and raw hex; persist raw hex. An empty or
    // whitespace-only value normalizes to None. A present-but-malformed value
    // is a client bug: reject 400 rather than silently dropping it.
    let pk_hash_prefill: Option<String> = match req.public_key_hash.as_deref() {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                let candidate = trimmed.strip_prefix("sha256:").unwrap_or(trimmed);
                let is_lower_hex = candidate.len() == 64
                    && candidate
                        .chars()
                        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
                if !is_lower_hex {
                    return OAuthError::invalid_request(
                        "public_key_hash must be a 64-char hex string",
                    )
                    .into_response();
                }
                Some(candidate.to_string())
            }
        }
        None => None,
    };

    let issued = match state
        .services
        .oauth
        .issue_device_code(
            &corr.0,
            client_id,
            scope,
            workspace_name_prefill,
            pk_hash_prefill,
            state.config.device_code_ttl_secs,
            state.config.device_code_poll_interval_secs,
        )
        .await
    {
        Ok(issued) => issued,
        Err(e) => return e.into_response(),
    };

    let base = state.config.server_base_url();
    let verification_uri = format!("{}/activate", base);
    let verification_uri_complete = format!("{}/activate?user_code={}", base, issued.user_code);

    (
        StatusCode::OK,
        no_store_headers(),
        Json(DeviceAuthorizationResponse {
            device_code: issued.device_code,
            user_code: issued.user_code,
            verification_uri,
            verification_uri_complete: Some(verification_uri_complete),
            expires_in: issued.expires_in,
            interval: Some(issued.interval),
        }),
    )
        .into_response()
}

/// Request body for both `/oauth/device/approve` and `/oauth/device/deny`.
///
/// `deny_unknown_fields` is deliberate: without it, `#[serde(default)]` on
/// `public_key_hash` would cause unrelated fields (e.g. `{"deny": true}`)
/// to be silently dropped — a caller could POST such a body to the approve
/// endpoint and the server would approve regardless. Reject unknown keys so
/// the API contract is explicit.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceDecisionRequest {
    pub user_code: String,
    /// Hex-encoded SHA-256 hash of the workspace's public key. On approve,
    /// required when the device code was issued with a
    /// `workspace_name_prefill` — the server then creates (or re-uses) the
    /// workspace record and binds it to this signing identity. On deny,
    /// required when the device code was issued with a bound
    /// `pk_hash_prefill`, to prevent DoS on other workspaces' enrollments
    /// by any authenticated user who learns a `user_code`.
    #[serde(default)]
    pub public_key_hash: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct DeviceDecisionResponse {
    approved: bool,
    denied: bool,
}

/// `POST /oauth/device/approve` — approve a pending device authorization
/// request by `user_code`. Requires an authenticated session; the approver's
/// user id is recorded on the device_code row and surfaced in the audit trail.
///
/// If the device code was issued with a `workspace_name_prefill` and the
/// caller provides a matching `public_key_hash`, the approve endpoint also
/// creates (or re-uses) the workspace record owned by the approving user so
/// downstream broker-authenticated requests can validate against it.
pub(crate) async fn device_approve_endpoint(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<DeviceDecisionRequest>,
) -> Result<Json<ApiResponse<DeviceDecisionResponse>>, ApiError> {
    state
        .services
        .oauth
        .approve_device_code(
            &auth,
            &corr.0,
            &req.user_code,
            req.public_key_hash.as_deref(),
        )
        .await?;

    Ok(Json(ApiResponse::ok(DeviceDecisionResponse {
        approved: true,
        denied: false,
    })))
}

/// Decide, before the row is flipped to approved, whether this approver may
/// bind the code's key hash. Kept here for the browser `/activate` form,
/// which drives the same steps as [`device_approve_endpoint`] one by one.
pub(crate) async fn refuse_if_bound_workspace_is_not_reregisterable(
    state: &AppState,
    auth: &AuthenticatedUser,
    row: &DeviceCode,
) -> Result<(), ApiError> {
    state
        .services
        .oauth
        .refuse_if_bound_workspace_is_not_reregisterable(auth, row)
        .await
}

/// Provision the workspace record + OAuth client bound to an approved
/// `device_code` row. Callers MUST invoke this AFTER `DeviceCodeService::approve`
/// succeeds. Kept here for the browser `/activate` form.
pub(crate) async fn provision_workspace_for_approved_device_code(
    state: &AppState,
    auth: &AuthenticatedUser,
    row: &DeviceCode,
) -> Result<(), ApiError> {
    state
        .services
        .oauth
        .provision_workspace_for_approved_device_code(auth, row)
        .await
}

/// `POST /oauth/device/deny` — deny a pending device authorization request
/// by `user_code`. Requires an authenticated session.
pub(crate) async fn device_deny_endpoint(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<DeviceDecisionRequest>,
) -> Result<Json<ApiResponse<DeviceDecisionResponse>>, ApiError> {
    state
        .services
        .oauth
        .deny_device_code(
            &auth,
            &corr.0,
            &req.user_code,
            req.public_key_hash.as_deref(),
        )
        .await?;

    Ok(Json(ApiResponse::ok(DeviceDecisionResponse {
        approved: false,
        denied: true,
    })))
}
