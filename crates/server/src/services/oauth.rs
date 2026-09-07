//! OAuth authorization-server service: client registration, the consent
//! decision, device-code issuance and approval, token issuance for every
//! grant (with refresh rotation and family revocation), and revocation.
//!
//! Token-endpoint methods return [`OAuthError`] because RFC 6749 §5.2 fixes
//! the error body for them; everything else returns [`ApiError`].

use std::sync::Arc;

use axum::http::StatusCode;
use chrono::{Duration, Utc};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::domain::user::UserId;
use agent_cordon_core::domain::workspace::Workspace;
use agent_cordon_core::oauth2::eff_wordlist::{generate_user_code, normalize_user_code};
use agent_cordon_core::oauth2::tokens::{
    generate_access_token, generate_auth_code, generate_client_id, generate_client_secret,
    generate_refresh_token, hash_token, validate_pkce,
};
use agent_cordon_core::oauth2::types::{
    DeviceCode, DeviceCodeStatus, OAuthAccessToken, OAuthAuthCode, OAuthClient, OAuthConsent,
    OAuthRefreshToken, OAuthScope, ScopeNarrowError,
};
use agent_cordon_core::policy::{actions, claim_keys, PolicyPrincipal, PolicyResource};

use crate::authz::{Authz, PolicyCaller};
use crate::extractors::AuthenticatedUser;
use crate::response::{ApiError, OAuthError};
use crate::state::SharedStore;

use super::device_codes::DeviceCodeService;
use super::workspaces::{refuse_reregistration_unless_allowed, ClientBinding, WorkspaceService};
use super::write_audit;

/// Access token TTL: 15 minutes.
pub const ACCESS_TOKEN_TTL_SECS: i64 = 900;
/// Refresh token TTL: 30 days.
const REFRESH_TOKEN_TTL_SECS: i64 = 30 * 24 * 3600;
/// Authorization code TTL: 5 minutes.
const AUTH_CODE_TTL_SECS: i64 = 300;

/// Validate that a redirect URI is localhost-only.
pub fn is_localhost_uri(uri: &str) -> bool {
    if let Ok(parsed) = url::Url::parse(uri) {
        if parsed.scheme() != "http" {
            return false;
        }
        matches!(
            parsed.host_str(),
            Some("localhost") | Some("127.0.0.1") | Some("[::1]")
        )
    } else {
        false
    }
}

/// Validate new workspace registration parameters.
pub fn validate_new_workspace_params(pk_hash: &str, ws_name: &str) -> Result<(), ApiError> {
    if ws_name.is_empty() || ws_name.len() > 255 {
        return Err(ApiError::BadRequest(
            "workspace_name must be 1-255 characters".into(),
        ));
    }
    if pk_hash.len() != 64 || !pk_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest(
            "public_key_hash must be a 64-char hex string".into(),
        ));
    }
    Ok(())
}

/// Verify the caller re-presents the same `public_key_hash` that was bound to
/// the device code row at issue time. Symmetric across approve and deny so
/// deny-by-user_code can't be used as a DoS on other workspaces' enrollments.
///
/// If the row was issued without a bound pk_hash, no check is performed.
/// Otherwise the presented hash MUST match (normalized: trimmed, `sha256:`
/// prefix stripped).
fn verify_pk_hash_binding(bound: Option<&str>, presented: Option<&str>) -> Result<(), ApiError> {
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
            "public_key_hash does not match the hash bound at device_code issue time".to_string(),
        ));
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
    ApiError::Internal("approved but workspace provisioning failed — retry device flow".to_string())
}

// ---------------------------------------------------------------------------
// Inputs and outputs
// ---------------------------------------------------------------------------

/// `POST /oauth/token` form body — defined once in `agent-cordon-core` so
/// the broker builds exactly what this service parses.
pub use agent_cordon_core::wire::oauth::TokenRequest;

/// What a successful token request issued.
pub struct IssuedTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub scopes: Vec<OAuthScope>,
    /// The client_id the tokens are bound to. For workspace-bound
    /// device_code grants this is the per-workspace client, not the
    /// bootstrap client the broker authenticated with.
    pub client_id: String,
    pub expires_in: i64,
}

/// A freshly issued device authorization (RFC 8628 §3.2).
pub struct DeviceAuthorization {
    /// Plaintext device code for the broker to poll with; only its hash is stored.
    pub device_code: String,
    pub user_code: String,
    pub expires_in: i64,
    pub interval: i64,
}

/// Input for [`OAuthService::register_client`].
pub struct RegisterClient {
    pub workspace_name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub public_key_hash: String,
}

/// Input for [`OAuthService::grant_consent`].
pub struct ConsentGrant<'a> {
    pub client_id: &'a str,
    pub client_uuid: Uuid,
    pub redirect_uri: &'a str,
    pub scopes: Vec<OAuthScope>,
    pub code_challenge: &'a str,
    pub is_new_workspace: bool,
}

/// Input for [`OAuthService::register_workspace_on_consent`].
pub struct ConsentRegistration<'a> {
    pub public_key_hash: &'a str,
    pub workspace_name: &'a str,
    pub redirect_uri: &'a str,
    pub scope: &'a str,
}

#[derive(Clone)]
pub struct OAuthService {
    store: SharedStore,
    authz: Arc<Authz>,
    device_codes: DeviceCodeService,
    workspaces: WorkspaceService,
}

impl OAuthService {
    pub fn new(
        store: SharedStore,
        authz: Arc<Authz>,
        device_codes: DeviceCodeService,
        workspaces: WorkspaceService,
    ) -> Self {
        Self {
            store,
            authz,
            device_codes,
            workspaces,
        }
    }

    // ------------------------------------------------------------------
    // Client registration (admin)
    // ------------------------------------------------------------------

    /// Admin-only confidential client registration. Returns the client and
    /// its plaintext secret, shown once.
    pub async fn register_client(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        req: RegisterClient,
    ) -> Result<(OAuthClient, String), ApiError> {
        if !auth.is_root {
            return Err(ApiError::Forbidden("admin access required".into()));
        }

        // Validate workspace_name
        if req.workspace_name.is_empty() || req.workspace_name.len() > 255 {
            return Err(ApiError::BadRequest(
                "workspace_name must be 1-255 characters".into(),
            ));
        }

        // Validate public_key_hash format (64 hex chars = SHA-256)
        if req.public_key_hash.len() != 64
            || !req.public_key_hash.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(ApiError::BadRequest(
                "public_key_hash must be a 64-char hex string".into(),
            ));
        }

        // Validate redirect URIs are localhost-only
        if req.redirect_uris.is_empty() {
            return Err(ApiError::BadRequest(
                "at least one redirect_uri is required".into(),
            ));
        }
        for uri in &req.redirect_uris {
            if !is_localhost_uri(uri) {
                return Err(ApiError::BadRequest(format!(
                    "redirect_uri must be localhost: {uri}"
                )));
            }
        }

        // Parse and validate scopes
        let scopes: Vec<OAuthScope> = req
            .scopes
            .iter()
            .map(|s| s.parse::<OAuthScope>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(ApiError::BadRequest)?;

        // Check for existing client with this public_key_hash
        if let Some(existing) = self
            .store
            .get_oauth_client_by_public_key_hash(&req.public_key_hash)
            .await?
        {
            if existing.revoked_at.is_none() {
                return Err(ApiError::Conflict(
                    "client already registered for this public_key_hash".into(),
                ));
            }
        }

        // Generate client_id and client_secret
        let client_id = generate_client_id();
        let (client_secret, client_secret_hash) = generate_client_secret();

        let now = Utc::now();
        // Bind to the workspace that holds this key, when one does. A client
        // registered ahead of its workspace is bound when the workspace is
        // provisioned through the device flow.
        let workspace_id = self
            .store
            .get_workspace_by_pk_hash(&req.public_key_hash)
            .await?
            .map(|ws| ws.id);
        let client = OAuthClient {
            id: Uuid::new_v4(),
            client_id: client_id.clone(),
            client_secret_hash: Some(client_secret_hash),
            workspace_name: req.workspace_name.clone(),
            public_key_hash: req.public_key_hash.clone(),
            workspace_id,
            redirect_uris: req.redirect_uris.clone(),
            allowed_scopes: scopes,
            created_by_user: auth.user.id.clone(),
            created_at: now,
            revoked_at: None,
        };

        self.store.create_oauth_client(&client).await?;

        let event = AuditEvent::builder(AuditEventType::Oauth2TokenAcquired)
            .action("oauth_client_registered")
            .user_actor(&auth.user)
            .resource("oauth_client", &client.id.to_string())
            .correlation_id(corr)
            .decision(AuditDecision::Permit, Some("admin-registered client"))
            .details(serde_json::json!({
                "client_id": client_id,
                "workspace_name": req.workspace_name,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        tracing::info!(
            client_id = %client_id,
            workspace_name = %req.workspace_name,
            "OAuth client registered (admin)"
        );

        Ok((client, client_secret))
    }

    /// Admin-only: revoke a client (by row UUID) and every token issued to it.
    pub async fn revoke_client(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        id: &str,
    ) -> Result<bool, ApiError> {
        if !auth.is_root {
            return Err(ApiError::Forbidden("admin access required".into()));
        }

        // Look up client by UUID id to find client_id
        let clients = self.store.list_oauth_clients().await?;
        let client = clients
            .iter()
            .find(|c| c.id.to_string() == id)
            .ok_or_else(|| ApiError::NotFound("OAuth client not found".into()))?;

        let client_id = client.client_id.clone();

        // Revoke client and all its tokens
        let revoked = self.store.revoke_oauth_client(&client_id).await?;
        self.store
            .revoke_access_tokens_for_client(&client_id)
            .await?;
        self.store
            .revoke_refresh_tokens_for_client(&client_id)
            .await?;

        let event = AuditEvent::builder(AuditEventType::Oauth2TokenFailed)
            .action("oauth_client_revoked")
            .user_actor(&auth.user)
            .resource("oauth_client", id)
            .correlation_id(corr)
            .decision(AuditDecision::Permit, Some("client revoked by admin"))
            .details(serde_json::json!({
                "client_id": client_id,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        Ok(revoked)
    }

    // ------------------------------------------------------------------
    // Consent (authorization code flow)
    // ------------------------------------------------------------------

    /// Issue a single-use authorization code bound to the client, user,
    /// redirect URI, scopes, and PKCE challenge. Returns the plaintext code.
    pub async fn issue_auth_code(
        &self,
        client_id: &str,
        user_id: &UserId,
        redirect_uri: &str,
        scopes: Vec<OAuthScope>,
        code_challenge: &str,
    ) -> Result<String, ApiError> {
        let (code, code_hash) = generate_auth_code();
        let now = Utc::now();

        let auth_code = OAuthAuthCode {
            code_hash,
            client_id: client_id.to_string(),
            user_id: user_id.clone(),
            redirect_uri: redirect_uri.to_string(),
            scopes,
            code_challenge: Some(code_challenge.to_string()),
            created_at: now,
            expires_at: now + Duration::seconds(AUTH_CODE_TTL_SECS),
            consumed_at: None,
        };
        self.store.create_oauth_auth_code(&auth_code).await?;
        Ok(code)
    }

    /// The user approved the consent form: issue the code, record the
    /// consent, and audit. Returns the plaintext code for the redirect.
    pub async fn grant_consent(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        grant: ConsentGrant<'_>,
    ) -> Result<String, ApiError> {
        let code = self
            .issue_auth_code(
                grant.client_id,
                &auth.user.id,
                grant.redirect_uri,
                grant.scopes.clone(),
                grant.code_challenge,
            )
            .await?;

        // Upsert consent record
        let consent = OAuthConsent {
            client_id: grant.client_id.to_string(),
            user_id: auth.user.id.clone(),
            scopes: grant.scopes.clone(),
            granted_at: Utc::now(),
        };
        self.store.upsert_oauth_consent(&consent).await?;

        // Audit: consent granted (issue #28). Resource shape matches
        // ConsentRevoked's so admins can correlate grant/revoke pairs by
        // (resource_type, resource_id).
        let event = AuditEvent::builder(AuditEventType::ConsentGranted)
            .action("grant")
            .user_actor(&auth.user)
            .resource("oauth_consent", &auth.user.id.0.to_string())
            .correlation_id(corr)
            .decision(AuditDecision::Permit, Some("user approved consent"))
            .details(serde_json::json!({
                "client_id": grant.client_id,
                "client_uuid": grant.client_uuid.to_string(),
                "scopes": OAuthScope::to_scope_string(&grant.scopes),
                "is_new_workspace": grant.is_new_workspace,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        Ok(code)
    }

    /// The user denied the consent form: audit only.
    pub async fn deny_consent(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        client_id: &str,
        workspace_name: &str,
    ) {
        let resource_id = if client_id.is_empty() {
            "new-workspace".to_string()
        } else {
            client_id.to_string()
        };
        let event = AuditEvent::builder(AuditEventType::Oauth2TokenFailed)
            .action("oauth_consent_denied")
            .user_actor(&auth.user)
            .resource("oauth_client", &resource_id)
            .correlation_id(corr)
            .decision(AuditDecision::Forbid, Some("user denied consent"))
            .details(serde_json::json!({
                "client_id": client_id,
                "workspace_name": workspace_name,
            }))
            .build();
        write_audit(&*self.store, &event).await;
    }

    /// Register a workspace through the consent form: bind the key hash to
    /// the user's workspace and mint a fresh public client for it. The
    /// caller has already authorized `manage_workspaces` and decided that
    /// the key hash may be re-registered.
    pub async fn register_workspace_on_consent(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        reg: ConsentRegistration<'_>,
    ) -> Result<OAuthClient, ApiError> {
        validate_new_workspace_params(reg.public_key_hash, reg.workspace_name)?;

        if !is_localhost_uri(reg.redirect_uri) {
            return Err(ApiError::BadRequest(
                "redirect_uri must be localhost".into(),
            ));
        }

        let scopes = OAuthScope::parse_scope_string(reg.scope).map_err(ApiError::BadRequest)?;

        let (_, client) = self
            .workspaces
            .bind_key_hash(
                auth,
                reg.workspace_name,
                reg.public_key_hash,
                ClientBinding::Replace {
                    redirect_uri: reg.redirect_uri,
                    scopes,
                    corr,
                },
            )
            .await?;
        Ok(client)
    }

    // ------------------------------------------------------------------
    // Device authorization grant (RFC 8628)
    // ------------------------------------------------------------------

    /// Issue a device code for `client_id`. `scope` is the raw scope
    /// parameter; `None` (or whitespace, normalized by the caller) means
    /// the client's registered scopes.
    #[allow(clippy::too_many_arguments)]
    pub async fn issue_device_code(
        &self,
        corr: &str,
        client_id: &str,
        scope: Option<&str>,
        workspace_name_prefill: Option<String>,
        pk_hash_prefill: Option<String>,
        ttl_secs: i64,
        interval_secs: i64,
    ) -> Result<DeviceAuthorization, OAuthError> {
        // Validate client_id. RFC 6749 §5.2: invalid_client → 401.
        let client = match self.store.get_oauth_client_by_client_id(client_id).await {
            Ok(Some(c)) => c,
            Ok(None) => return Err(OAuthError::invalid_client("unknown client_id")),
            Err(_) => {
                return Err(OAuthError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "client lookup failed",
                ))
            }
        };
        if client.revoked_at.is_some() {
            return Err(OAuthError::invalid_client("client revoked"));
        }

        // Deny-by-default: every requested scope must be within the client's
        // allowed_scopes. No ad-hoc widening. An absent scope means all of them.
        let requested_scopes =
            OAuthScope::narrow(scope, &client.allowed_scopes).map_err(|e| match e {
                ScopeNarrowError::Unknown(_) => {
                    OAuthError::invalid_scope("one or more scopes are unknown")
                }
                ScopeNarrowError::Exceeds => {
                    OAuthError::invalid_scope("requested scope exceeds client allowed_scopes")
                }
            })?;

        // Generate device_code (256 bits, base64url). `generate_access_token`
        // returns `(plaintext, hash)`; the broker needs the plaintext to poll
        // and we persist the hash as the lookup key so a DB read cannot reveal
        // a usable device_code.
        let (device_code_plain, device_code_hash) = generate_access_token();
        let user_code_raw = generate_user_code();
        let user_code = normalize_user_code(&user_code_raw);

        // Issue through the audit-emitting device-code service. The
        // workspace_name (if provided by the caller, typically the broker) is
        // persisted as `workspace_name_prefill` so the approver's UI and the
        // approve endpoint can reference it.
        if let Err(e) = self
            .device_codes
            .issue(
                device_code_hash,
                user_code.clone(),
                client_id.to_string(),
                requested_scopes,
                workspace_name_prefill,
                pk_hash_prefill,
                ttl_secs,
                interval_secs,
                corr,
            )
            .await
        {
            tracing::error!(error = %e, "failed to persist device code");
            return Err(OAuthError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "failed to persist device code",
            ));
        }

        Ok(DeviceAuthorization {
            device_code: device_code_plain,
            user_code,
            expires_in: ttl_secs,
            interval: interval_secs,
        })
    }

    /// Decide, before the row is flipped to approved, whether this approver may
    /// bind the code's key hash. If the hash already belongs to a workspace,
    /// the same rule as re-registration applies: a revoked or disabled
    /// workspace is never re-bound, and an active one only by its owner or an
    /// admin. Running this before the compare-and-swap keeps a refused
    /// approval from leaving the row approved with no workspace behind it.
    pub async fn refuse_if_bound_workspace_is_not_reregisterable(
        &self,
        auth: &AuthenticatedUser,
        row: &DeviceCode,
    ) -> Result<(), ApiError> {
        let Some(raw) = row
            .pk_hash_prefill
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return Ok(());
        };
        let pk_hash = raw.strip_prefix("sha256:").unwrap_or(raw);
        if let Some(existing) = self.store.get_workspace_by_pk_hash(pk_hash).await? {
            refuse_reregistration_unless_allowed(&existing, auth)?;
        }
        Ok(())
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
    pub async fn provision_workspace_for_approved_device_code(
        &self,
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

        validate_new_workspace_params(pk_hash, workspace_name)
            .map_err(|e| provisioning_failed(workspace_name, e))?;

        self.workspaces
            .bind_key_hash(
                auth,
                workspace_name,
                pk_hash,
                ClientBinding::ReuseOrCreate {
                    scopes: &row.scopes,
                },
            )
            .await
            .map_err(|e| provisioning_failed(workspace_name, e))?;

        Ok(())
    }

    /// Approve a pending device authorization by `user_code` (raw, as
    /// typed). Requires `manage_workspaces`; the approver's user id is
    /// recorded on the row. When the code carries a workspace identity,
    /// the workspace and its OAuth client are provisioned after the
    /// compare-and-swap succeeds.
    pub async fn approve_device_code(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        raw_user_code: &str,
        presented_pk_hash: Option<&str>,
    ) -> Result<(), ApiError> {
        // #2 — Policy gate. MUST be the first statement: any authenticated user
        // could otherwise assume ownership of a prefilled workspace on approval.
        // Authz auto-emits PolicyEvaluated on both permit and deny.
        self.authz
            .authorize(auth, actions::MANAGE_WORKSPACES, &PolicyResource::System)
            .await?;

        let user_code = normalize_user_code(raw_user_code.trim());
        if user_code.is_empty() {
            return Err(ApiError::BadRequest("user_code is required".to_string()));
        }

        // Lookup to apply the pk_hash binding check; provisioning (if any) runs
        // AFTER CAS approval so a stale or double-approve short-circuits first.
        let row = self
            .device_codes
            .get_by_user_code(&user_code)
            .await?
            .ok_or_else(|| ApiError::BadRequest("user_code is unknown or expired".to_string()))?;

        // #3 — pk_hash match check. If the device code was issued with a bound
        // pk_hash, the approver MUST re-present the same hash. Shared helper so
        // the deny endpoint enforces identical binding (without it, any
        // authenticated user who learns a user_code could cancel another
        // workspace's enrollment).
        verify_pk_hash_binding(row.pk_hash_prefill.as_deref(), presented_pk_hash)?;
        self.refuse_if_bound_workspace_is_not_reregisterable(auth, &row)
            .await?;

        // #4 — CAS-first: flip the row to approved BEFORE provisioning. On a
        // double-approve or stale row, CAS returns false and we short-circuit.
        let approved = self
            .device_codes
            .approve(
                &user_code,
                &auth.user.id.0.to_string(),
                Some(&auth.user.username),
                row.workspace_name_prefill.as_deref(),
                corr,
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
        self.provision_workspace_for_approved_device_code(auth, &row)
            .await
    }

    /// Deny a pending device authorization by `user_code` (raw, as typed).
    pub async fn deny_device_code(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        raw_user_code: &str,
        presented_pk_hash: Option<&str>,
    ) -> Result<(), ApiError> {
        // Policy gate — parity with approve. MUST be the first statement.
        self.authz
            .authorize(auth, actions::MANAGE_WORKSPACES, &PolicyResource::System)
            .await?;

        let user_code = normalize_user_code(raw_user_code.trim());
        if user_code.is_empty() {
            return Err(ApiError::BadRequest("user_code is required".to_string()));
        }

        // Look up the row so we can (a) verify the pk_hash binding in parity
        // with approve — without this check any authenticated user who learns
        // a user_code could cancel another workspace's enrollment — and
        // (b) populate `workspace_name` on the audit event.
        let row = self
            .device_codes
            .get_by_user_code(&user_code)
            .await?
            .ok_or_else(|| ApiError::BadRequest("user_code is unknown or expired".to_string()))?;
        verify_pk_hash_binding(row.pk_hash_prefill.as_deref(), presented_pk_hash)?;

        let denied = self
            .device_codes
            .deny(
                &user_code,
                &auth.user.id.0.to_string(),
                Some(&auth.user.username),
                row.workspace_name_prefill.as_deref(),
                corr,
            )
            .await?;
        if !denied {
            return Err(ApiError::BadRequest(
                "user_code is unknown, already consumed, or not pending".to_string(),
            ));
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Token endpoint
    // ------------------------------------------------------------------

    /// `POST /oauth/token`: dispatch on `grant_type`.
    pub async fn token(&self, corr: &str, req: &TokenRequest) -> Result<IssuedTokens, OAuthError> {
        match req.grant_type.as_deref().unwrap_or("") {
            "authorization_code" => self.authorization_code_grant(corr, req).await,
            "refresh_token" => self.refresh_token_grant(corr, req).await,
            "client_credentials" => self.client_credentials_grant(corr, req).await,
            "urn:ietf:params:oauth:grant-type:device_code" => {
                self.device_code_grant(corr, req).await
            }
            _ => Err(OAuthError::new(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "grant_type must be authorization_code, refresh_token, client_credentials, \
                 or urn:ietf:params:oauth:grant-type:device_code",
            )),
        }
    }

    /// Authenticate the client named in `req`: it must exist, not be
    /// revoked, and (when confidential) present its secret.
    async fn authenticate_client(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> Result<OAuthClient, OAuthError> {
        let client = match self.store.get_oauth_client_by_client_id(client_id).await {
            Ok(Some(c)) => c,
            _ => return Err(OAuthError::invalid_client("unknown client")),
        };
        if client.revoked_at.is_some() {
            return Err(OAuthError::invalid_client("client is revoked"));
        }

        // Verify client_secret if confidential
        if let Some(ref secret_hash) = client.client_secret_hash {
            match client_secret {
                Some(secret)
                    if bool::from(hash_token(secret).as_bytes().ct_eq(secret_hash.as_bytes())) => {}
                _ => return Err(OAuthError::invalid_client("invalid client credentials")),
            }
        }
        Ok(client)
    }

    /// Mint a new access + refresh token pair without storing it. Returns
    /// the raw values to hand to the client and the rows to persist.
    /// `family_id` is `None` for a fresh grant (the refresh token roots its
    /// own family).
    fn new_token_pair(
        client_id: &str,
        user_id: &UserId,
        scopes: &[OAuthScope],
        family_id: Option<&str>,
    ) -> (String, String, OAuthAccessToken, OAuthRefreshToken) {
        let now = Utc::now();
        let (access_raw, access_hash) = generate_access_token();
        let (refresh_raw, refresh_hash) = generate_refresh_token();

        let access_token = OAuthAccessToken {
            token_hash: access_hash.clone(),
            client_id: client_id.to_string(),
            user_id: user_id.clone(),
            scopes: scopes.to_vec(),
            created_at: now,
            expires_at: now + Duration::seconds(ACCESS_TOKEN_TTL_SECS),
            revoked_at: None,
        };
        let refresh_token = OAuthRefreshToken {
            family_id: family_id
                .map(str::to_string)
                .unwrap_or_else(|| refresh_hash.clone()),
            token_hash: refresh_hash,
            client_id: client_id.to_string(),
            user_id: user_id.clone(),
            scopes: scopes.to_vec(),
            access_token_hash: access_hash,
            created_at: now,
            expires_at: now + Duration::seconds(REFRESH_TOKEN_TTL_SECS),
            revoked_at: None,
        };
        (access_raw, refresh_raw, access_token, refresh_token)
    }

    /// Store a new access + refresh token pair. `family_id` is `None` for
    /// a fresh grant (the refresh token roots its own family).
    async fn store_token_pair(
        &self,
        client_id: &str,
        user_id: &UserId,
        scopes: &[OAuthScope],
        family_id: Option<&str>,
    ) -> Result<(String, String), OAuthError> {
        let (access_raw, refresh_raw, access_token, refresh_token) =
            Self::new_token_pair(client_id, user_id, scopes, family_id);

        if let Err(e) = self.store.create_oauth_access_token(&access_token).await {
            tracing::error!(error = %e, "failed to store access token");
            return Err(OAuthError::server_error(e));
        }
        if let Err(e) = self.store.create_oauth_refresh_token(&refresh_token).await {
            tracing::error!(error = %e, "failed to store refresh token");
            return Err(OAuthError::server_error(e));
        }
        Ok((access_raw, refresh_raw))
    }

    async fn audit_token_issued(
        &self,
        corr: &str,
        action: &str,
        resource_id: &str,
        client_id: &str,
        grant_type: &str,
        reason: &str,
    ) {
        let event = AuditEvent::builder(AuditEventType::Oauth2TokenAcquired)
            .action(action)
            .resource("oauth_client", resource_id)
            .correlation_id(corr)
            .decision(AuditDecision::Permit, Some(reason))
            .details(serde_json::json!({
                "client_id": client_id,
                "grant_type": grant_type,
            }))
            .build();
        write_audit(&*self.store, &event).await;
    }

    async fn authorization_code_grant(
        &self,
        corr: &str,
        req: &TokenRequest,
    ) -> Result<IssuedTokens, OAuthError> {
        let code = match &req.code {
            Some(c) if !c.is_empty() => c.as_str(),
            _ => return Err(OAuthError::invalid_request("code is required")),
        };

        let client_id = match &req.client_id {
            Some(c) if !c.is_empty() => c.as_str(),
            _ => return Err(OAuthError::invalid_request("client_id is required")),
        };

        let client = self
            .authenticate_client(client_id, req.client_secret.as_deref())
            .await?;

        // Look up auth code by hash
        let code_hash = hash_token(code);
        let auth_code = match self.store.get_oauth_auth_code(&code_hash).await {
            Ok(Some(c)) => c,
            _ => return Err(OAuthError::invalid_grant("invalid authorization code")),
        };

        // Validate: not expired
        if auth_code.expires_at < Utc::now() {
            return Err(OAuthError::invalid_grant("authorization code has expired"));
        }

        // Validate: client_id matches
        if auth_code.client_id != client_id {
            return Err(OAuthError::invalid_grant("client_id mismatch"));
        }

        // Validate: redirect_uri matches
        if let Some(ref redirect_uri) = req.redirect_uri {
            if *redirect_uri != auth_code.redirect_uri {
                return Err(OAuthError::invalid_grant("redirect_uri mismatch"));
            }
        }

        // PKCE validation
        if let Some(ref challenge) = auth_code.code_challenge {
            match &req.code_verifier {
                Some(verifier) if validate_pkce(verifier, challenge) => {}
                Some(_) => return Err(OAuthError::invalid_grant("PKCE verification failed")),
                None => return Err(OAuthError::invalid_request("code_verifier is required")),
            }
        }

        // Consume the code and mint its tokens in one transaction. The
        // consume is a compare-and-swap on `consumed_at IS NULL`, so only
        // the first concurrent request wins; a failed mint leaves the code
        // unconsumed.
        let (access_token, refresh_token, access_row, refresh_row) =
            Self::new_token_pair(client_id, &auth_code.user_id, &auth_code.scopes, None);
        match self
            .store
            .consume_oauth_auth_code_and_issue_tokens(&code_hash, &access_row, &refresh_row)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                return Err(OAuthError::invalid_grant("authorization code already used"));
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to consume auth code and issue tokens");
                return Err(OAuthError::server_error(e));
            }
        }

        self.audit_token_issued(
            corr,
            "oauth_token_issued",
            &client.id.to_string(),
            client_id,
            "authorization_code",
            "authorization_code exchange",
        )
        .await;

        Ok(IssuedTokens {
            access_token,
            refresh_token: Some(refresh_token),
            scopes: auth_code.scopes,
            client_id: client_id.to_string(),
            expires_in: ACCESS_TOKEN_TTL_SECS,
        })
    }

    async fn refresh_token_grant(
        &self,
        corr: &str,
        req: &TokenRequest,
    ) -> Result<IssuedTokens, OAuthError> {
        let refresh_token_raw = match &req.refresh_token {
            Some(t) if !t.is_empty() => t.as_str(),
            _ => return Err(OAuthError::invalid_request("refresh_token is required")),
        };

        let client_id = match &req.client_id {
            Some(c) if !c.is_empty() => c.as_str(),
            _ => return Err(OAuthError::invalid_request("client_id is required")),
        };

        let client = self
            .authenticate_client(client_id, req.client_secret.as_deref())
            .await?;

        // Look up refresh token
        let rt_hash = hash_token(refresh_token_raw);
        let stored_rt = match self.store.get_oauth_refresh_token(&rt_hash).await {
            Ok(Some(t)) => t,
            _ => return Err(OAuthError::invalid_grant("invalid refresh token")),
        };

        if stored_rt.revoked_at.is_some() {
            // A retired refresh token presented again means it leaked, or the
            // legitimate client lost a race with a thief. Either way nothing
            // descended from the same grant can be trusted: revoke the family
            // (RFC 6819 §5.2.2.3) and make the event visible.
            match self
                .store
                .revoke_oauth_refresh_token_family(&stored_rt.family_id)
                .await
            {
                Ok(n) => tracing::warn!(
                    client_id = %client_id,
                    family_id = %stored_rt.family_id,
                    revoked = n,
                    "refresh token reuse detected; family revoked"
                ),
                Err(e) => tracing::error!(error = %e, "failed to revoke refresh token family"),
            }
            let event = AuditEvent::builder(AuditEventType::Oauth2TokenAcquired)
                .action("oauth_refresh_token_reuse_detected")
                .resource("oauth_client", &client.id.to_string())
                .correlation_id(corr)
                .decision(AuditDecision::Forbid, Some("refresh token family revoked"))
                .details(serde_json::json!({
                    "client_id": client_id,
                    "family_id": stored_rt.family_id,
                }))
                .build();
            write_audit(&*self.store, &event).await;
            return Err(OAuthError::invalid_grant("refresh token has been revoked"));
        }

        if stored_rt.expires_at < Utc::now() {
            return Err(OAuthError::invalid_grant("refresh token has expired"));
        }

        if stored_rt.client_id != client_id {
            return Err(OAuthError::invalid_grant("client_id mismatch"));
        }

        // Determine scopes — if requested, must be subset of original
        let scopes =
            OAuthScope::narrow(req.scope.as_deref(), &stored_rt.scopes).map_err(|e| match e {
                ScopeNarrowError::Unknown(msg) => OAuthError::invalid_scope(&msg),
                ScopeNarrowError::Exceeds => {
                    OAuthError::invalid_scope("requested scope exceeds original grant")
                }
            })?;

        // Retire the presented token (rotation). The store update is a
        // compare-and-swap on `revoked_at IS NULL`; if it reports no row
        // changed, a concurrent presentation of the same token already won,
        // and this one must not receive a second token pair.
        match self.store.revoke_oauth_refresh_token(&rt_hash).await {
            Ok(true) => {}
            Ok(false) => {
                return Err(OAuthError::invalid_grant(
                    "refresh token has already been used",
                ));
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to retire refresh token");
                return Err(OAuthError::server_error(e));
            }
        }
        // Revoke the old access token associated with the old refresh token
        let _ = self
            .store
            .revoke_access_tokens_for_refresh_token(&rt_hash)
            .await;

        // Issue new tokens in the same family
        let (access_token, refresh_token) = self
            .store_token_pair(
                client_id,
                &stored_rt.user_id,
                &scopes,
                Some(&stored_rt.family_id),
            )
            .await?;

        self.audit_token_issued(
            corr,
            "oauth_token_refreshed",
            &client.id.to_string(),
            client_id,
            "refresh_token",
            "refresh_token exchange",
        )
        .await;

        Ok(IssuedTokens {
            access_token,
            refresh_token: Some(refresh_token),
            scopes,
            client_id: client_id.to_string(),
            expires_in: ACCESS_TOKEN_TTL_SECS,
        })
    }

    async fn client_credentials_grant(
        &self,
        corr: &str,
        req: &TokenRequest,
    ) -> Result<IssuedTokens, OAuthError> {
        let client_id = match &req.client_id {
            Some(c) if !c.is_empty() => c.as_str(),
            _ => return Err(OAuthError::invalid_request("client_id is required")),
        };
        let client_secret = match &req.client_secret {
            Some(s) if !s.is_empty() => s.as_str(),
            _ => {
                return Err(OAuthError::invalid_request(
                    "client_secret is required for client_credentials",
                ))
            }
        };

        // Authenticate client
        let client = match self.store.get_oauth_client_by_client_id(client_id).await {
            Ok(Some(c)) => c,
            _ => return Err(OAuthError::invalid_client("unknown client")),
        };
        if client.revoked_at.is_some() {
            return Err(OAuthError::invalid_client("client is revoked"));
        }

        match &client.client_secret_hash {
            Some(secret_hash)
                if bool::from(
                    hash_token(client_secret)
                        .as_bytes()
                        .ct_eq(secret_hash.as_bytes()),
                ) => {}
            _ => return Err(OAuthError::invalid_client("invalid client credentials")),
        }

        // Determine scopes
        let scopes = OAuthScope::narrow(req.scope.as_deref(), &client.allowed_scopes).map_err(
            |e| match e {
                ScopeNarrowError::Unknown(msg) => OAuthError::invalid_scope(&msg),
                ScopeNarrowError::Exceeds => {
                    OAuthError::invalid_scope("requested scope not allowed")
                }
            },
        )?;

        // Issue access token only (no refresh for client_credentials)
        let now = Utc::now();
        let (access_raw, access_hash) = generate_access_token();

        let access_token = OAuthAccessToken {
            token_hash: access_hash,
            client_id: client_id.to_string(),
            user_id: client.created_by_user.clone(),
            scopes: scopes.clone(),
            created_at: now,
            expires_at: now + Duration::seconds(ACCESS_TOKEN_TTL_SECS),
            revoked_at: None,
        };

        if let Err(e) = self.store.create_oauth_access_token(&access_token).await {
            tracing::error!(error = %e, "failed to store access token");
            return Err(OAuthError::server_error(e));
        }

        self.audit_token_issued(
            corr,
            "oauth_token_issued",
            &client.id.to_string(),
            client_id,
            "client_credentials",
            "client_credentials grant",
        )
        .await;

        Ok(IssuedTokens {
            access_token: access_raw,
            refresh_token: None,
            scopes,
            client_id: client_id.to_string(),
            expires_in: ACCESS_TOKEN_TTL_SECS,
        })
    }

    // Polling contract per RFC 8628 §3.5:
    //   - `authorization_pending`: user has not yet approved; retry after `interval`.
    //   - `slow_down`: client polled too fast; MUST increase interval by 5s. We
    //     implement this as "double the stored interval" and persist, so a client
    //     that ignores the hint keeps hitting slow_down on subsequent polls.
    //   - `expired_token`: device_code TTL elapsed; row transitioned to `expired`.
    //   - `access_denied`: user denied via `/activate`.
    //   - `invalid_grant`: unknown device_code, client_id mismatch, or the row is
    //     in a terminal state it shouldn't be polled from (denied — covered above
    //     — or already `consumed`, which is invalid_grant to prevent replay).
    //
    // **Secret handling**: the `device_code` sent by the broker is the plaintext
    // issued at `/oauth/device/code`. We persist only its hash, so every lookup
    // MUST call `hash_token` first. A DB dump alone cannot yield a pollable
    // device_code.
    async fn device_code_grant(
        &self,
        corr: &str,
        req: &TokenRequest,
    ) -> Result<IssuedTokens, OAuthError> {
        // --- Parse required fields ---
        let device_code_plain = match req.device_code.as_deref() {
            Some(s) if !s.is_empty() => s,
            _ => return Err(OAuthError::invalid_request("device_code is required")),
        };
        let client_id_req = match req.client_id.as_deref() {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => return Err(OAuthError::invalid_request("client_id is required")),
        };

        let device_code_hash = hash_token(device_code_plain);
        let service = &self.device_codes;

        // --- Lookup by hash ---
        let row = match service.get_by_device_code(&device_code_hash).await {
            Ok(Some(r)) => r,
            Ok(None) => {
                // RFC 6749 §5.2: if the client_id is also unknown, the proper
                // error is invalid_client (401), not invalid_grant.
                let client_exists = matches!(
                    self.store.get_oauth_client_by_client_id(&client_id_req).await,
                    Ok(Some(c)) if c.revoked_at.is_none()
                );
                if !client_exists {
                    return Err(OAuthError::invalid_client("unknown or revoked client"));
                }
                return Err(OAuthError::invalid_grant("unknown device_code"));
            }
            Err(e) => {
                tracing::error!(error = %e, "device_code lookup failed");
                return Err(OAuthError::server_error(e));
            }
        };

        if row.client_id != client_id_req {
            return Err(OAuthError::invalid_grant(
                "client_id does not match device_code",
            ));
        }

        let now = Utc::now();

        // --- Terminal/state dispatch ---
        match row.status {
            DeviceCodeStatus::Denied => Err(OAuthError::new(
                StatusCode::BAD_REQUEST,
                "access_denied",
                "user denied request",
            )),
            DeviceCodeStatus::Expired => Err(OAuthError::new(
                StatusCode::BAD_REQUEST,
                "expired_token",
                "device_code expired",
            )),
            DeviceCodeStatus::Consumed => {
                Err(OAuthError::invalid_grant("device_code already exchanged"))
            }
            DeviceCodeStatus::Pending => {
                // Expiry check: if TTL elapsed, transition to expired and return expired_token.
                // The row won't self-heal otherwise until the sweeper runs.
                if row.expires_at <= now {
                    // Best-effort: mark expired so subsequent polls get expired_token
                    // directly. A failure here just means the sweeper will catch it.
                    if let Err(e) = service.sweep_expired(corr).await {
                        tracing::warn!(error = %e, "failed to transition expired device_code");
                    }
                    return Err(OAuthError::new(
                        StatusCode::BAD_REQUEST,
                        "expired_token",
                        "device_code expired",
                    ));
                }

                // Poll interval enforcement.
                let too_fast = match row.last_polled_at {
                    Some(last) => (now - last).num_seconds() < row.interval_secs,
                    None => false,
                };

                if too_fast {
                    // slow_down: double the stored interval, update poll timestamp.
                    let new_interval = row.interval_secs.saturating_mul(2).min(60);
                    if let Err(e) = service
                        .update_poll(&device_code_hash, Some(new_interval))
                        .await
                    {
                        tracing::warn!(error = %e, "failed to update device_code poll (slow_down)");
                    }
                    return Err(OAuthError::new(
                        StatusCode::BAD_REQUEST,
                        "slow_down",
                        "polling too fast; increase interval",
                    ));
                }

                // Not too fast — bump the last_polled_at timestamp and return pending.
                if let Err(e) = service.update_poll(&device_code_hash, None).await {
                    tracing::warn!(error = %e, "failed to update device_code poll");
                }
                Err(OAuthError::new(
                    StatusCode::BAD_REQUEST,
                    "authorization_pending",
                    "waiting for user approval",
                ))
            }
            DeviceCodeStatus::Approved => {
                // Resolve approving user.
                let approving_user_id_str = match row.approved_user_id.as_deref() {
                    Some(s) => s,
                    None => {
                        return Err(OAuthError::server_error(
                            "approved row missing approved_user_id",
                        ));
                    }
                };
                let approving_user_uuid = match Uuid::parse_str(approving_user_id_str) {
                    Ok(u) => u,
                    Err(_) => {
                        return Err(OAuthError::server_error(
                            "approved_user_id is not a valid UUID",
                        ));
                    }
                };
                let user_id = UserId(approving_user_uuid);

                // If the device code was bound to a workspace identity during
                // approval, look up the workspace-specific OAuth client and issue
                // the token against that client. No silent bootstrap fallback:
                // a workspace-bound row with a missing workspace, missing pk_hash,
                // or missing/revoked client is an inconsistent state and MUST
                // fail with invalid_grant rather than issuing a token against
                // the bootstrap client.
                let token_client_id = if let Some(workspace_name) =
                    row.workspace_name_prefill.as_deref()
                {
                    // Identity is the key hash bound at approval; the name is a
                    // display label that other workspaces may share. Only rows
                    // issued before the hash was recorded fall back to the name.
                    let lookup = match row.pk_hash_prefill.as_deref() {
                        Some(h) if !h.is_empty() => self.store.get_workspace_by_pk_hash(h).await,
                        _ => self.store.get_workspace_by_name(workspace_name).await,
                    };
                    let ws = match lookup {
                        Ok(Some(ws)) => ws,
                        _ => {
                            tracing::error!(%workspace_name, "approved device_code has no workspace row");
                            return Err(OAuthError::invalid_grant(
                                "workspace registration is incomplete; retry device authorization",
                            ));
                        }
                    };
                    let pk_hash = ws.pk_hash.as_deref().unwrap_or("");
                    if pk_hash.is_empty() {
                        tracing::error!(workspace_id = %ws.id.0, "workspace missing pk_hash");
                        return Err(OAuthError::invalid_grant(
                            "workspace registration is incomplete; retry device authorization",
                        ));
                    }
                    let client = match self
                        .store
                        .get_oauth_client_by_public_key_hash(pk_hash)
                        .await
                    {
                        Ok(Some(c)) if c.revoked_at.is_none() => c,
                        _ => {
                            tracing::error!(%pk_hash, "workspace missing OAuth client");
                            return Err(OAuthError::invalid_grant(
                                "workspace OAuth client is missing or revoked",
                            ));
                        }
                    };
                    // Scope intersect defense-in-depth: every device_code scope
                    // must be within the client's allowed_scopes envelope.
                    if !OAuthScope::is_subset(&row.scopes, &client.allowed_scopes) {
                        return Err(OAuthError::invalid_scope(
                            "device_code scope exceeds workspace client allowed_scopes",
                        ));
                    }
                    client.client_id
                } else {
                    // Non-workspace-bound device_code: pin to the device_code's
                    // own client (bootstrap or direct). Legacy path, unchanged.
                    row.client_id.clone()
                };

                // CAS consume and mint in one transaction (parity with the
                // authorization_code arm): strict single-use, so if two
                // pollers race exactly one wins and the other mints nothing;
                // a failed mint leaves the row approved for a retry.
                let (access_token, refresh_token, access_row, refresh_row) =
                    Self::new_token_pair(&token_client_id, &user_id, &row.scopes, None);
                match service
                    .consume_and_issue_tokens(&device_code_hash, &access_row, &refresh_row)
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(OAuthError::invalid_grant("device_code already exchanged"));
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "CAS consume and token mint failed");
                        return Err(OAuthError::server_error(e));
                    }
                }

                self.audit_token_issued(
                    corr,
                    "oauth_token_issued",
                    &row.client_id,
                    &row.client_id,
                    "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code exchange",
                )
                .await;

                Ok(IssuedTokens {
                    access_token,
                    refresh_token: Some(refresh_token),
                    scopes: row.scopes,
                    client_id: token_client_id,
                    expires_in: ACCESS_TOKEN_TTL_SECS,
                })
            }
        }
    }

    // ------------------------------------------------------------------
    // Revocation (RFC 7009)
    // ------------------------------------------------------------------

    /// Revoke a token the client owns. Per RFC 7009 the outcome is reported
    /// but never an error: a token that is unknown, already revoked, or
    /// belongs to another client is simply "not revoked".
    /// Withdraw one user's consent for one workspace's OAuth client, and with
    /// it every access and refresh token issued to that pair.
    ///
    /// The final say is a Cedar self-permit: an admin may withdraw anyone's
    /// consent, a user only their own. The caller has already established
    /// that the caller may manage this workspace at all.
    pub async fn revoke_consent(
        &self,
        auth: &AuthenticatedUser,
        workspace: &Workspace,
        client_id: &str,
        target: &UserId,
    ) -> Result<(), ApiError> {
        let corr = Uuid::new_v4().to_string();
        let decision = self
            .authz
            .request(
                PolicyCaller::Principal {
                    principal: PolicyPrincipal::User(&auth.user),
                    oauth_claims: None,
                },
                &corr,
            )
            .claim(
                claim_keys::CONSENT_USER_ID,
                target.0.hyphenated().to_string(),
            )
            .check_with_reasons(actions::MANAGE_CONSENTS, &PolicyResource::System)
            .await
            .map_err(|e| ApiError::Internal(format!("policy: {e:?}")))?;
        if !matches!(decision.decision, PolicyDecisionResult::Permit) {
            return Err(ApiError::Forbidden("access denied by policy".to_string()));
        }

        let counts = self
            .store
            .delete_consent_and_revoke_tokens(client_id, target)
            .await?
            .ok_or_else(|| ApiError::NotFound("no consent for that user".to_string()))?;

        let event = AuditEvent::builder(AuditEventType::ConsentRevoked)
            .action("delete")
            .user_actor(&auth.user)
            .resource("oauth_consent", &target.0.to_string())
            .decision(AuditDecision::Permit, None)
            .details(serde_json::json!({
                "workspace_id": workspace.id.0.to_string(),
                "client_id": client_id,
                "access_tokens_revoked": counts.access_tokens,
                "refresh_tokens_revoked": counts.refresh_tokens,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        Ok(())
    }

    pub async fn revoke_token(
        &self,
        corr: &str,
        token: &str,
        token_type_hint: Option<&str>,
        client_id: &str,
    ) -> bool {
        let token_hash = hash_token(token);

        // Try to revoke based on hint, falling back to both types.
        // Ownership is verified before revocation: the token must belong to client_id.
        let hint = token_type_hint.unwrap_or("access_token");

        let revoked = match hint {
            "refresh_token" => {
                self.try_revoke_refresh_then_access(&token_hash, client_id)
                    .await
            }
            _ => {
                self.try_revoke_access_then_refresh(&token_hash, client_id)
                    .await
            }
        };

        // Audit event (only if we actually revoked something)
        if revoked {
            let event = AuditEvent::builder(AuditEventType::Oauth2TokenFailed)
                .action("oauth_token_revoked")
                .resource("oauth_token", &token_hash[..16])
                .correlation_id(corr)
                .decision(AuditDecision::Permit, Some("token revoked"))
                .details(serde_json::json!({
                    "token_type_hint": hint,
                    "client_id": client_id,
                }))
                .build();
            write_audit(&*self.store, &event).await;
        }

        revoked
    }

    /// Try revoking as refresh token first (with cascade), then fall back to access token.
    /// Verifies ownership via client_id before revoking.
    async fn try_revoke_refresh_then_access(&self, token_hash: &str, client_id: &str) -> bool {
        // Check refresh token ownership
        if let Ok(Some(rt)) = self.store.get_oauth_refresh_token(token_hash).await {
            if rt.client_id == client_id {
                let rt_revoked = self
                    .store
                    .revoke_oauth_refresh_token(token_hash)
                    .await
                    .unwrap_or(false);
                if rt_revoked {
                    let _ = self
                        .store
                        .revoke_access_tokens_for_refresh_token(token_hash)
                        .await;
                    return true;
                }
            }
            // Token exists but belongs to a different client — silently deny per RFC 7009
            return false;
        }

        // Fallback: try as access token
        self.try_revoke_access_token(token_hash, client_id).await
    }

    /// Try revoking as access token first, then fall back to refresh token (with cascade).
    /// Verifies ownership via client_id before revoking.
    async fn try_revoke_access_then_refresh(&self, token_hash: &str, client_id: &str) -> bool {
        if self.try_revoke_access_token(token_hash, client_id).await {
            return true;
        }

        // Fallback: try as refresh token with cascade
        if let Ok(Some(rt)) = self.store.get_oauth_refresh_token(token_hash).await {
            if rt.client_id == client_id {
                let rt_revoked = self
                    .store
                    .revoke_oauth_refresh_token(token_hash)
                    .await
                    .unwrap_or(false);
                if rt_revoked {
                    let _ = self
                        .store
                        .revoke_access_tokens_for_refresh_token(token_hash)
                        .await;
                }
                return rt_revoked;
            }
        }

        false
    }

    /// Revoke an access token after verifying it belongs to the given client_id.
    async fn try_revoke_access_token(&self, token_hash: &str, client_id: &str) -> bool {
        if let Ok(Some(at)) = self.store.get_oauth_access_token(token_hash).await {
            if at.client_id == client_id {
                return self
                    .store
                    .revoke_oauth_access_token(token_hash)
                    .await
                    .unwrap_or(false);
            }
        }
        false
    }
}
