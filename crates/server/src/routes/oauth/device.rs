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

use agent_cordon_core::oauth2::eff_wordlist::{generate_user_code, normalize_user_code};
use agent_cordon_core::oauth2::types::{DeviceCode, OAuthScope};

use crate::device_code_service::DeviceCodeService;
use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

/// RFC 8628 §3.2 Device Authorization Response.
#[derive(Serialize)]
struct DeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: i64,
    interval: i64,
}

#[derive(Deserialize)]
pub(crate) struct DeviceAuthorizationRequest {
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    /// AgentCordon extension: the workspace name this device code is for.
    /// Stored on the device_code row so the approver's UI can show the
    /// workspace being authorized and so the approve endpoint can create
    /// the workspace record.
    #[serde(default)]
    workspace_name: Option<String>,
    /// AgentCordon extension: the hex-encoded SHA-256 hash of the
    /// workspace's public key. Bound to the device_code row at issue time
    /// as `pk_hash_prefill`; the approve endpoint verifies the caller
    /// re-presents the same hash before flipping the row to approved.
    #[serde(default)]
    public_key_hash: Option<String>,
}

#[derive(Serialize)]
struct OAuthError {
    error: String,
    error_description: String,
}

fn no_store_headers() -> [(header::HeaderName, &'static str); 2] {
    [
        (header::CACHE_CONTROL, "no-store"),
        (header::PRAGMA, "no-cache"),
    ]
}

fn err(status: StatusCode, error: &str, desc: &str) -> axum::response::Response {
    (
        status,
        no_store_headers(),
        Json(OAuthError {
            error: error.to_string(),
            error_description: desc.to_string(),
        }),
    )
        .into_response()
}

/// `POST /oauth/device/code` — initiate the device authorization grant.
pub(crate) async fn device_code_endpoint(
    State(state): State<AppState>,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Form(req): Form<DeviceAuthorizationRequest>,
) -> axum::response::Response {
    // RFC 6749 §5.2: missing required parameter → 400 invalid_request.
    let client_id = match req.client_id.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "client_id is required",
            );
        }
    };

    // Validate client_id. RFC 6749 §5.2: invalid_client → 401.
    let client = match state.store.get_oauth_client_by_client_id(client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return err(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "unknown client_id",
            );
        }
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "client lookup failed",
            );
        }
    };
    if client.revoked_at.is_some() {
        return err(StatusCode::UNAUTHORIZED, "invalid_client", "client revoked");
    }

    // Parse and validate scopes. Empty scope string is allowed (defaults to
    // the client's registered allowed_scopes).
    let requested_scopes: Vec<OAuthScope> = match req.scope.as_deref() {
        Some(s) if !s.trim().is_empty() => match OAuthScope::parse_scope_string(s) {
            Ok(v) => v,
            Err(_) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    "invalid_scope",
                    "one or more scopes are unknown",
                );
            }
        },
        _ => client.allowed_scopes.clone(),
    };

    // Deny-by-default: every requested scope must be within the client's
    // allowed_scopes. No ad-hoc widening.
    for s in &requested_scopes {
        if !client.allowed_scopes.contains(s) {
            return err(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "requested scope exceeds client allowed_scopes",
            );
        }
    }

    // Generate device_code (256 bits, base64url). `generate_access_token`
    // returns `(plaintext, hash)`; the broker needs the plaintext to poll
    // and we persist the hash as the lookup key so a DB read cannot reveal
    // a usable device_code.
    let (device_code_plain, device_code_hash) =
        agent_cordon_core::oauth2::tokens::generate_access_token();
    let user_code_raw = generate_user_code();
    let user_code = normalize_user_code(&user_code_raw);

    let ttl_secs = state.config.device_code_ttl_secs;
    let interval_secs = state.config.device_code_poll_interval_secs;

    // Issue through the audit-emitting service wrapper. The workspace_name
    // (if provided by the caller, typically the broker) is persisted as
    // `workspace_name_prefill` so the approver's UI and the approve endpoint
    // can reference it.
    let service = DeviceCodeService::new(state.store.clone());
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
                    return err(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "public_key_hash must be a 64-char hex string",
                    );
                }
                Some(candidate.to_string())
            }
        }
        None => None,
    };

    if let Err(e) = service
        .issue(
            device_code_hash.clone(),
            user_code.clone(),
            client_id.to_string(),
            requested_scopes,
            workspace_name_prefill.clone(),
            pk_hash_prefill,
            ttl_secs,
            interval_secs,
            &corr.0,
        )
        .await
    {
        tracing::error!(error = %e, "failed to persist device code");
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "failed to persist device code",
        );
    }

    let base = state.config.server_base_url();
    let verification_uri = format!("{}/activate", base);
    let verification_uri_complete = format!("{}/activate?user_code={}", base, user_code);

    (
        StatusCode::OK,
        no_store_headers(),
        Json(DeviceAuthorizationResponse {
            device_code: device_code_plain,
            user_code,
            verification_uri,
            verification_uri_complete,
            expires_in: ttl_secs,
            interval: interval_secs,
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
    // #2 — Policy gate. MUST be the first statement: any authenticated user
    // could otherwise assume ownership of a prefilled workspace on approval.
    // AuditingPolicyEngine emits audit on both permit and deny.
    crate::routes::admin_api::check_cedar_permission(
        &state,
        &auth,
        agent_cordon_core::policy::actions::MANAGE_WORKSPACES,
        agent_cordon_core::policy::PolicyResource::System,
    )?;

    let user_code = normalize_user_code(req.user_code.trim());
    if user_code.is_empty() {
        return Err(ApiError::BadRequest("user_code is required".to_string()));
    }
    let service = DeviceCodeService::new(state.store.clone());

    // Lookup to apply the pk_hash binding check; provisioning (if any) runs
    // AFTER CAS approval so a stale or double-approve short-circuits first.
    let row = service.get_by_user_code(&user_code).await?.ok_or_else(|| {
        ApiError::BadRequest("user_code is unknown or expired".to_string())
    })?;

    // #3 — pk_hash match check. If the device code was issued with a bound
    // pk_hash, the approver MUST re-present the same hash. Shared helper so
    // the deny endpoint enforces identical binding (without it, any
    // authenticated user who learns a user_code could cancel another
    // workspace's enrollment).
    verify_pk_hash_binding(row.pk_hash_prefill.as_deref(), req.public_key_hash.as_deref())?;

    // #4 — CAS-first: flip the row to approved BEFORE provisioning. On a
    // double-approve or stale row, CAS returns false and we short-circuit.
    let approved = service
        .approve(
            &user_code,
            &auth.user.id.0.to_string(),
            Some(&auth.user.username),
            row.workspace_name_prefill.as_deref(),
            &corr.0,
        )
        .await?;
    if !approved {
        return Err(ApiError::BadRequest(
            "user_code is unknown, already consumed, or not pending".to_string(),
        ));
    }

    // If the issuer asked us to bind a workspace identity, provision the
    // workspace + OAuth client now. A failure here surfaces as 500 to the
    // approver; the subsequent token exchange fails the workspace lookup
    // with `invalid_grant` (safe — the row is already marked approved and
    // CAS consume will prevent any later accidental token issuance).
    provision_workspace_for_approved_device_code(&state, &auth, &row).await?;

    Ok(Json(ApiResponse::ok(DeviceDecisionResponse {
        approved: true,
        denied: false,
    })))
}

/// Provision the workspace record + OAuth client bound to the approved
/// `device_code` row's `workspace_name_prefill` + `pk_hash_prefill`. Callers
/// MUST invoke this AFTER `DeviceCodeService::approve` succeeds, on both the
/// API approve endpoint and the UI `/activate` POST handler, so the token
/// exchange at `/oauth/token` can locate the workspace by name (otherwise the
/// CLI polls forever on `invalid_grant`).
///
/// No-op when the row was issued without a `workspace_name_prefill` (the
/// caller is not asking us to bind a workspace identity). If the row was
/// issued WITH a workspace name but no `pk_hash_prefill`, that is an
/// invariant violation — every broker-issued device_code sets both — and we
/// return a 500 so the approver retries the device flow.
pub(crate) async fn provision_workspace_for_approved_device_code(
    state: &AppState,
    auth: &AuthenticatedUser,
    row: &DeviceCode,
) -> Result<(), ApiError> {
    let Some(workspace_name) = row.workspace_name_prefill.as_deref() else {
        return Ok(());
    };

    // Every broker-issued device_code sets pk_hash_prefill at the same time
    // as workspace_name_prefill (see device_code_endpoint). An approved row
    // with a workspace name but no pk_hash means an unexpected codepath
    // persisted the row — fail loudly so the approver knows to retry.
    let pk_hash_raw = row
        .pk_hash_prefill
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            provisioning_failed(
                workspace_name,
                ApiError::Internal(
                    "device_code row has workspace_name_prefill but no pk_hash_prefill"
                        .to_string(),
                ),
            )
        })?;
    let pk_hash = pk_hash_raw.strip_prefix("sha256:").unwrap_or(pk_hash_raw);

    crate::routes::oauth::authorize::validate_new_workspace_params(pk_hash, workspace_name)
        .map_err(|e| provisioning_failed(workspace_name, e))?;
    if let Err(e) =
        crate::routes::oauth::consent::create_or_reuse_workspace(state, auth, workspace_name, pk_hash)
            .await
    {
        return Err(provisioning_failed(workspace_name, e));
    }

    // Ensure an OAuth client exists bound to this workspace's pk_hash. The
    // access token issued after this approval will reference that client so
    // `AuthenticatedOAuthWorkspace` can locate the workspace via
    // `client.public_key_hash`. Re-registrations of the same pk_hash reuse
    // the existing client.
    let client_exists = state
        .store
        .get_oauth_client_by_public_key_hash(pk_hash)
        .await
        .map_err(|e| provisioning_failed(workspace_name, ApiError::from(e)))?
        .is_some();
    if !client_exists {
        use agent_cordon_core::domain::user::UserId;
        use agent_cordon_core::oauth2::types::OAuthClient;
        let client = OAuthClient {
            id: uuid::Uuid::new_v4(),
            client_id: agent_cordon_core::oauth2::tokens::generate_client_id(),
            client_secret_hash: None,
            workspace_name: workspace_name.to_string(),
            public_key_hash: pk_hash.to_string(),
            redirect_uris: vec![],
            allowed_scopes: row.scopes.clone(),
            created_by_user: UserId(auth.user.id.0),
            created_at: chrono::Utc::now(),
            revoked_at: None,
        };
        if let Err(e) = state.store.create_oauth_client(&client).await {
            return Err(provisioning_failed(workspace_name, ApiError::from(e)));
        }
    }

    Ok(())
}

/// Approve-path provisioning failure: the row is already marked approved,
/// so the subsequent token exchange will fail with `invalid_grant`. We
/// surface a 500 here so the approver knows to retry the device flow.
fn provisioning_failed(workspace_name: &str, e: ApiError) -> ApiError {
    tracing::error!(
        error = ?e,
        workspace_name,
        "device_code approved but workspace provisioning failed"
    );
    ApiError::Internal(
        "approved but workspace provisioning failed — retry device flow".to_string(),
    )
}

/// `POST /oauth/device/deny` — deny a pending device authorization request
/// by `user_code`. Requires an authenticated session.
pub(crate) async fn device_deny_endpoint(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<DeviceDecisionRequest>,
) -> Result<Json<ApiResponse<DeviceDecisionResponse>>, ApiError> {
    // Policy gate — parity with approve. MUST be the first statement.
    crate::routes::admin_api::check_cedar_permission(
        &state,
        &auth,
        agent_cordon_core::policy::actions::MANAGE_WORKSPACES,
        agent_cordon_core::policy::PolicyResource::System,
    )?;

    let user_code = normalize_user_code(req.user_code.trim());
    if user_code.is_empty() {
        return Err(ApiError::BadRequest("user_code is required".to_string()));
    }
    let service = DeviceCodeService::new(state.store.clone());

    // Look up the row so we can (a) verify the pk_hash binding in parity
    // with approve — without this check any authenticated user who learns
    // a user_code could cancel another workspace's enrollment — and
    // (b) populate `workspace_name` on the audit event.
    let row = service.get_by_user_code(&user_code).await?.ok_or_else(|| {
        ApiError::BadRequest("user_code is unknown or expired".to_string())
    })?;
    verify_pk_hash_binding(row.pk_hash_prefill.as_deref(), req.public_key_hash.as_deref())?;

    let denied = service
        .deny(
            &user_code,
            &auth.user.id.0.to_string(),
            Some(&auth.user.username),
            row.workspace_name_prefill.as_deref(),
            &corr.0,
        )
        .await?;
    if !denied {
        return Err(ApiError::BadRequest(
            "user_code is unknown, already consumed, or not pending".to_string(),
        ));
    }
    Ok(Json(ApiResponse::ok(DeviceDecisionResponse {
        approved: false,
        denied: true,
    })))
}

/// Verify the caller re-presents the same `public_key_hash` that was bound to
/// the device code row at issue time. Symmetric across approve and deny so
/// deny-by-user_code can't be used as a DoS on other workspaces' enrollments.
///
/// If the row was issued without a bound pk_hash, no check is performed.
/// Otherwise the presented hash MUST match (normalized: trimmed, `sha256:`
/// prefix stripped).
fn verify_pk_hash_binding(
    bound: Option<&str>,
    presented: Option<&str>,
) -> Result<(), ApiError> {
    let Some(bound) = bound else { return Ok(()) };
    let presented = presented
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            ApiError::BadRequest(
                "public_key_hash does not match the hash bound at device_code issue time"
                    .to_string(),
            )
        })?;
    let presented = presented.strip_prefix("sha256:").unwrap_or(presented);
    let bound = bound.strip_prefix("sha256:").unwrap_or(bound);
    if presented != bound {
        return Err(ApiError::BadRequest(
            "public_key_hash does not match the hash bound at device_code issue time"
                .to_string(),
        ));
    }
    Ok(())
}
