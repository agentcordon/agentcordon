//! User and session service: user accounts, password changes, and the
//! login/logout session lifecycle with its lockout and audit rows.

use std::sync::Arc;

use uuid::Uuid;

use agent_cordon_core::auth::oidc::IdTokenClaims;
use agent_cordon_core::auth::password::PasswordAuthenticator;
use agent_cordon_core::crypto::password::{hash_password_async, verify_password_async};
use agent_cordon_core::crypto::session::{generate_session_token, hash_session_token_hmac};
use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::oidc::OidcProvider;
use agent_cordon_core::domain::policy::PolicyDecision;
use agent_cordon_core::domain::session::Session;
use agent_cordon_core::domain::user::{User, UserId, UserRole};
use agent_cordon_core::error::AuthError;
use agent_cordon_core::policy::{actions, PolicyResource};

use crate::authz::Authz;
use crate::config::AppConfig;
use crate::events::{UiEvent, UiEventBus};
use crate::extractors::AuthenticatedUser;
use crate::rate_limit::LoginRateLimiter;
use crate::response::ApiError;
use crate::state::SharedStore;

use super::write_audit;

/// Input for [`UserService::create`].
pub struct NewUser {
    pub username: String,
    pub password: String,
    pub display_name: Option<String>,
    pub role: Option<UserRole>,
}

/// Input for [`UserService::update`]; `None` leaves a field unchanged.
pub struct UserChanges {
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub role: Option<UserRole>,
    pub enabled: Option<bool>,
}

/// A freshly created session: the raw token goes into the cookie, nothing
/// else about it is stored in plaintext.
pub struct NewSession {
    pub user: User,
    pub raw_token: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// What [`UserService::login_with_oidc`] decided once the ID token validated:
/// either a session, or the message the browser is sent away with.
pub enum OidcLoginOutcome {
    /// Signed in. The raw token goes into the session cookie.
    Session(NewSession),
    /// Refused. Every one of these is an account-state problem an
    /// administrator fixes, so the message is written for the person.
    Rejected(&'static str),
}

#[derive(Clone)]
pub struct UserService {
    store: SharedStore,
    authz: Arc<Authz>,
    ui_event_bus: UiEventBus,
    login_limiter: Arc<LoginRateLimiter>,
    session_hash_key: [u8; 32],
    config: AppConfig,
}

impl UserService {
    pub fn new(
        store: SharedStore,
        authz: Arc<Authz>,
        ui_event_bus: UiEventBus,
        login_limiter: Arc<LoginRateLimiter>,
        session_hash_key: [u8; 32],
        config: AppConfig,
    ) -> Self {
        Self {
            store,
            authz,
            ui_event_bus,
            login_limiter,
            session_hash_key,
            config,
        }
    }

    /// The user, or 404.
    pub async fn load(&self, id: &UserId) -> Result<User, ApiError> {
        self.store
            .get_user(id)
            .await?
            .ok_or_else(|| ApiError::NotFound("user not found".to_string()))
    }

    /// Check Cedar policy for `manage_users` on `System` resource.
    pub async fn check_manage_users(
        &self,
        auth: &AuthenticatedUser,
    ) -> Result<PolicyDecision, ApiError> {
        self.authz
            .authorize(auth, actions::MANAGE_USERS, &PolicyResource::System)
            .await
    }

    fn validate_password(password: &str) -> Result<(), ApiError> {
        // Minimum 12 for security, maximum 1024 to prevent Argon2id DoS.
        if password.len() < 12 {
            return Err(ApiError::BadRequest(
                "password must be at least 12 characters".to_string(),
            ));
        }
        if password.len() > 1024 {
            return Err(ApiError::BadRequest(
                "password must not exceed 1024 characters".to_string(),
            ));
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Accounts
    // ------------------------------------------------------------------

    pub async fn create(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        new: NewUser,
    ) -> Result<User, ApiError> {
        let policy_decision = self.check_manage_users(auth).await?;

        // Validate username
        let username = new.username.trim().to_string();
        if username.is_empty() || username.len() > 128 {
            return Err(ApiError::BadRequest(
                "username must be 1-128 characters".to_string(),
            ));
        }

        Self::validate_password(&new.password)?;

        // Check for duplicate username
        if let Some(_existing) = self.store.get_user_by_username(&username).await? {
            return Err(ApiError::Conflict("username already exists".to_string()));
        }

        let password_hash = hash_password_async(&new.password)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        let now = chrono::Utc::now();
        let user = User {
            id: UserId(Uuid::new_v4()),
            username,
            display_name: new.display_name,
            password_hash,
            role: new.role.unwrap_or(UserRole::Viewer),
            is_root: false,
            enabled: true,
            created_at: now,
            updated_at: now,
        };

        self.store.create_user(&user).await?;

        let event = AuditEvent::builder(AuditEventType::UserCreated)
            .action("create")
            .user_actor(&auth.user)
            .resource("user", &user.id.0.to_string())
            .correlation_id(corr)
            .decision(
                AuditDecision::Permit,
                Some(&policy_decision.reasons.join(", ")),
            )
            .details(serde_json::json!({ "created_user": user.username }))
            .build();
        write_audit(&*self.store, &event).await;

        self.ui_event_bus
            .emit(UiEvent::UserCreated { user_id: user.id.0 });

        Ok(user)
    }

    pub async fn update(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        target_id: &UserId,
        changes: UserChanges,
    ) -> Result<User, ApiError> {
        let policy_decision = self.check_manage_users(auth).await?;

        let mut user = self.load(target_id).await?;

        // Protect root user's role and enabled status
        if user.is_root {
            if let Some(ref role) = changes.role {
                if *role != UserRole::Admin {
                    return Err(ApiError::Forbidden(
                        "cannot change root user's role".to_string(),
                    ));
                }
            }
            if let Some(false) = changes.enabled {
                return Err(ApiError::Forbidden("cannot disable root user".to_string()));
            }
        }

        if let Some(username) = changes.username {
            let trimmed = username.trim().to_string();
            if trimmed.is_empty() || trimmed.len() > 128 {
                return Err(ApiError::BadRequest(
                    "username must be 1-128 characters".to_string(),
                ));
            }
            // Check for duplicate
            if trimmed != user.username {
                if let Some(_existing) = self.store.get_user_by_username(&trimmed).await? {
                    return Err(ApiError::Conflict("username already exists".to_string()));
                }
            }
            user.username = trimmed;
        }
        if let Some(display_name) = changes.display_name {
            user.display_name = Some(display_name);
        }
        if let Some(role) = changes.role {
            user.role = role;
        }
        if let Some(enabled) = changes.enabled {
            user.enabled = enabled;
        }
        user.updated_at = chrono::Utc::now();

        self.store.update_user(&user).await?;

        let event = AuditEvent::builder(AuditEventType::UserUpdated)
            .action("update")
            .user_actor(&auth.user)
            .resource("user", &user.id.0.to_string())
            .correlation_id(corr)
            .decision(
                AuditDecision::Permit,
                Some(&policy_decision.reasons.join(", ")),
            )
            .details(serde_json::json!({ "updated_user": user.username }))
            .build();
        write_audit(&*self.store, &event).await;

        self.ui_event_bus
            .emit(UiEvent::UserUpdated { user_id: user.id.0 });

        Ok(user)
    }

    pub async fn delete(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        target_id: &UserId,
    ) -> Result<(), ApiError> {
        let policy_decision = self.check_manage_users(auth).await?;

        // Load the target user to check if it's root
        let target_user = self.load(target_id).await?;

        // Cannot delete root user
        if target_user.is_root {
            return Err(ApiError::Forbidden("cannot delete root user".to_string()));
        }

        // Cannot delete self
        if auth.user.id == *target_id {
            return Err(ApiError::Conflict(
                "cannot delete your own account".to_string(),
            ));
        }

        // Delete all sessions for the user first
        let _ = self.store.delete_user_sessions(target_id).await;

        let deleted = self.store.delete_user(target_id).await?;
        if !deleted {
            return Err(ApiError::NotFound("user not found".to_string()));
        }

        let event = AuditEvent::builder(AuditEventType::UserDeleted)
            .action("delete")
            .user_actor(&auth.user)
            .resource("user", &target_id.0.to_string())
            .correlation_id(corr)
            .decision(
                AuditDecision::Permit,
                Some(&policy_decision.reasons.join(", ")),
            )
            .details(serde_json::json!({ "deleted_user": target_user.username }))
            .build();
        write_audit(&*self.store, &event).await;

        self.ui_event_bus.emit(UiEvent::UserDeleted {
            user_id: target_id.0,
        });

        Ok(())
    }

    /// Change a password. Self-service always requires the current
    /// password; an admin changing another user's does not. Only root may
    /// change root's. Every session of the target user is invalidated.
    pub async fn change_password(
        &self,
        auth: &AuthenticatedUser,
        corr: &str,
        target_id: &UserId,
        current_password: Option<&str>,
        new_password: &str,
    ) -> Result<(), ApiError> {
        let is_self = auth.user.id == *target_id;

        // Self-service password change is always allowed; otherwise check Cedar manage_users policy
        if !is_self {
            self.check_manage_users(auth).await?;
        }

        Self::validate_password(new_password)?;

        let mut user = self.load(target_id).await?;

        // Root bypasses Cedar entirely, so root's password is the one secret an
        // admin must not be able to reset. Only root changes root's password.
        if user.is_root && !auth.is_root {
            return Err(ApiError::Forbidden(
                "only root can change the root user's password".to_string(),
            ));
        }

        // Self-service password change: ALWAYS require current password when
        // changing your own password, regardless of role. This prevents account
        // takeover if an admin session is hijacked or left unattended.
        // Admin users changing ANOTHER user's password do NOT need current_password.
        if is_self {
            let current_password = current_password.ok_or_else(|| {
                ApiError::BadRequest(
                    "current_password is required when changing your own password".to_string(),
                )
            })?;

            let matches = verify_password_async(current_password, &user.password_hash)
                .await
                .map_err(|e| ApiError::Internal(e.to_string()))?;

            if !matches {
                return Err(ApiError::Unauthorized(
                    "current password is incorrect".to_string(),
                ));
            }
        }

        let new_hash = hash_password_async(new_password)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        user.password_hash = new_hash;
        user.updated_at = chrono::Utc::now();

        self.store.update_user(&user).await?;

        // Invalidate all sessions for the target user. After a password change,
        // all existing sessions should be terminated to prevent continued access
        // by anyone who may have compromised the old password or a session token.
        let _ = self.store.delete_user_sessions(target_id).await;

        let reason = if is_self {
            "bypass:self-service"
        } else {
            "bypass:admin"
        };
        let event = AuditEvent::builder(AuditEventType::UserUpdated)
            .action("change_password")
            .user_actor(&auth.user)
            .resource("user", &user.id.0.to_string())
            .correlation_id(corr)
            .decision(AuditDecision::Permit, Some(reason))
            .details(serde_json::json!({
                "target_user": user.username,
                "changed_by": if is_self { "self" } else { "admin" },
            }))
            .build();
        write_audit(&*self.store, &event).await;

        Ok(())
    }

    // ------------------------------------------------------------------
    // Sessions
    // ------------------------------------------------------------------

    /// Password login: lockout check, credential verification, session
    /// creation, and the audit row for each outcome. `client_addr` keys the
    /// lockout together with the username.
    pub async fn login(
        &self,
        corr: &str,
        client_addr: &str,
        username: &str,
        password: &str,
    ) -> Result<NewSession, ApiError> {
        // Failed attempts are counted per (client address, username): a burst
        // of bad passwords from one place locks that place out of the account
        // without locking the account's owner out from everywhere else.
        let limiter_key = format!("{client_addr}|{username}");

        // Check rate limit before attempting authentication
        if self.login_limiter.is_rate_limited(&limiter_key) {
            // Audit the rate-limited attempt
            let event = AuditEvent::builder(AuditEventType::LoginRateLimited)
                .action("login_rate_limited")
                .user_name_only(username)
                .resource_type("session")
                .correlation_id(corr)
                .decision(
                    AuditDecision::Forbid,
                    Some(&format!(
                        "bypass:rate_limited (max {})",
                        self.config.login_max_attempts
                    )),
                )
                .details(serde_json::json!({
                    "username": username,
                    "lockout_seconds": self.config.login_lockout_seconds,
                }))
                .build();
            write_audit(&*self.store, &event).await;

            metrics::counter!("login_attempts_total", "result" => "rate_limited").increment(1);
            return Err(ApiError::TooManyRequests(
                "too many failed login attempts, please try again later".to_string(),
            ));
        }

        let authenticator = PasswordAuthenticator::new(self.store.clone());

        let user = match authenticator.authenticate(username, password).await {
            Ok(user) => user,
            Err(err) => {
                // Record the failed attempt in the rate limiter
                self.login_limiter.record_failure(&limiter_key);

                // Extract the failure reason for audit logging. The error message
                // shown to the client is always generic to prevent user enumeration.
                let reason = match &err {
                    AuthError::LoginFailed(r) => r.as_audit_str(),
                    _ => "unknown",
                };

                let event = AuditEvent::builder(AuditEventType::UserLoginFailed)
                    .action("login_failed")
                    .user_name_only(username)
                    .resource_type("session")
                    .correlation_id(corr)
                    .decision(AuditDecision::Forbid, Some(reason))
                    .details(serde_json::json!({
                        "username": username,
                        "reason": reason,
                    }))
                    .build();
                write_audit(&*self.store, &event).await;

                metrics::counter!("login_attempts_total", "result" => "failed").increment(1);
                return Err(ApiError::Unauthorized(
                    "invalid username or password".to_string(),
                ));
            }
        };

        metrics::counter!("login_attempts_total", "result" => "success").increment(1);

        // Successful login — reset the rate limiter for this user
        self.login_limiter.reset(&limiter_key);

        // Create session
        let raw_token = generate_session_token();
        let token_hash = hash_session_token_hmac(&raw_token, &self.session_hash_key);
        let now = chrono::Utc::now();
        let ttl = chrono::Duration::seconds(self.config.session_ttl_seconds as i64);
        let expires_at = now + ttl;

        let session = Session {
            id: token_hash.clone(),
            user_id: user.id.clone(),
            created_at: now,
            expires_at,
            last_seen_at: now,
        };

        self.store.create_session(&session).await?;

        // Audit successful login
        let event = AuditEvent::builder(AuditEventType::UserLoginSuccess)
            .action("login_success")
            .user_actor(&user)
            .resource("session", &user.id.0.to_string())
            .correlation_id(corr)
            .decision(AuditDecision::Permit, Some("bypass:credentials_verified"))
            .details(serde_json::json!({
                "username": user.username,
                "user_id": user.id.0.to_string(),
            }))
            .build();
        write_audit(&*self.store, &event).await;

        Ok(NewSession {
            user,
            raw_token,
            expires_at,
        })
    }

    /// Record activity on a session (its `last_seen_at`). Best effort: a
    /// failure here must not turn an authenticated request into an error.
    pub async fn touch_session(&self, token_hash: &str) {
        if let Err(e) = self.store.touch_session(token_hash).await {
            tracing::debug!(error = %e, "failed to touch session");
        }
    }

    /// Delete every session of the user (logout everywhere). Returns how
    /// many were deleted.
    pub async fn logout(&self, auth: &AuthenticatedUser, corr: &str) -> Result<u32, ApiError> {
        let deleted_count = self.store.delete_user_sessions(&auth.user.id).await?;

        let event = AuditEvent::builder(AuditEventType::UserLogout)
            .action("user_logout")
            .user_actor(&auth.user)
            .resource_type("session")
            .correlation_id(corr)
            .decision(AuditDecision::Permit, Some("bypass:self-service"))
            .details(serde_json::json!({
                "sessions_deleted": deleted_count,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        Ok(deleted_count)
    }

    // ------------------------------------------------------------------
    // OIDC login
    // ------------------------------------------------------------------

    /// The IdP itself reported an error on the callback (the person cancelled,
    /// or consent was denied). Nothing was resolved, so the audit row names no
    /// actor.
    pub async fn record_oidc_idp_error(&self, corr: &str, error: &str) {
        let event = AuditEvent::builder(AuditEventType::OidcLoginFailed)
            .action("oidc_login_failed")
            .resource_type("session")
            .correlation_id(corr)
            .decision(
                AuditDecision::Forbid,
                Some(&format!("bypass:idp_error:{}", error)),
            )
            .details(serde_json::json!({
                "error": error,
            }))
            .build();
        write_audit(&*self.store, &event).await;
    }

    /// The ID token did not validate against the provider's JWKS, issuer,
    /// audience, or nonce.
    pub async fn record_oidc_token_validation_failed(&self, corr: &str, provider: &OidcProvider) {
        let event = AuditEvent::builder(AuditEventType::OidcLoginFailed)
            .action("oidc_login_failed")
            .resource_type("session")
            .correlation_id(corr)
            .decision(
                AuditDecision::Forbid,
                Some("bypass:id_token_validation_failed"),
            )
            .details(serde_json::json!({
                "provider_id": provider.id.0.to_string(),
                "provider_name": provider.name,
            }))
            .build();
        write_audit(&*self.store, &event).await;
    }

    /// Resolve a validated ID token to a local account and open a session for
    /// it: subject lookup, auto-provisioning or adoption of an unprivileged
    /// same-named account, the session row, and the audit event for each
    /// outcome. The caller has already validated the token; this is the
    /// account half of the flow.
    pub async fn login_with_oidc(
        &self,
        corr: &str,
        provider: &OidcProvider,
        claims: &IdTokenClaims,
    ) -> Result<OidcLoginOutcome, ApiError> {
        let user = match self.resolve_oidc_account(corr, provider, claims).await? {
            OidcAccount::Resolved(user) => user,
            OidcAccount::Rejected(message) => return Ok(OidcLoginOutcome::Rejected(message)),
        };

        // Create session
        let raw_token = generate_session_token();
        let token_hash = hash_session_token_hmac(&raw_token, &self.session_hash_key);
        let now = chrono::Utc::now();
        let ttl = chrono::Duration::seconds(self.config.session_ttl_seconds as i64);
        let expires_at = now + ttl;

        let session = Session {
            id: token_hash,
            user_id: user.id.clone(),
            created_at: now,
            expires_at,
            last_seen_at: now,
        };

        self.store.create_session(&session).await?;

        // Audit successful OIDC login
        let event = AuditEvent::builder(AuditEventType::OidcLoginSuccess)
            .action("oidc_login_success")
            .user_actor(&user)
            .resource("session", &user.id.0.to_string())
            .correlation_id(corr)
            .decision(AuditDecision::Permit, Some("bypass:oidc_token_validated"))
            .details(serde_json::json!({
                "provider_name": provider.name,
                "oidc_subject": claims.sub,
                "username": user.username,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        Ok(OidcLoginOutcome::Session(NewSession {
            user,
            raw_token,
            expires_at,
        }))
    }

    /// The account half of [`Self::login_with_oidc`]: find, adopt, or create
    /// the local account this subject signs in as.
    async fn resolve_oidc_account(
        &self,
        corr: &str,
        provider: &OidcProvider,
        claims: &IdTokenClaims,
    ) -> Result<OidcAccount, ApiError> {
        // Resolve the account by the provider's stable subject. A username
        // claim never selects an existing account: that is how an IdP user
        // named `root` used to become root.
        let linked = self
            .store
            .get_user_by_oidc_identity(&provider.id, &claims.sub)
            .await?;

        if let Some(existing_user) = linked {
            if !existing_user.enabled {
                let event = AuditEvent::builder(AuditEventType::OidcLoginFailed)
                    .action("oidc_login_failed")
                    .user_actor(&existing_user)
                    .resource_type("session")
                    .correlation_id(corr)
                    .decision(AuditDecision::Forbid, Some("bypass:user_disabled"))
                    .details(serde_json::json!({
                        "provider_name": provider.name,
                    }))
                    .build();
                write_audit(&*self.store, &event).await;

                return Ok(OidcAccount::Rejected(ACCOUNT_DISABLED));
            }

            let mut user = existing_user;
            user.updated_at = chrono::Utc::now();
            self.store.update_user(&user).await?;
            return Ok(OidcAccount::Resolved(user));
        }

        if !provider.auto_provision {
            return Ok(OidcAccount::Rejected(
                "Your account is not provisioned. Contact your administrator.",
            ));
        }

        let Some(username) = resolve_username_claim(&provider.username_claim, claims) else {
            tracing::warn!(
                provider = %provider.name,
                claim = %provider.username_claim,
                "OIDC ID token lacks the configured username claim"
            );
            return Ok(OidcAccount::Rejected(
                "Your identity provider did not send a username. Contact your administrator.",
            ));
        };

        // First login for this subject. If the username is already taken,
        // this may be an account provisioned before subject binding existed.
        // Adopt it only when it holds no privilege: root and admin accounts
        // are never claimed by a username match.
        let new_user = match self.store.get_user_by_username(&username).await? {
            Some(existing) if existing.is_admin() => {
                let event = AuditEvent::builder(AuditEventType::OidcLoginFailed)
                    .action("oidc_login_failed")
                    .resource_type("session")
                    .correlation_id(corr)
                    .decision(
                        AuditDecision::Forbid,
                        Some("bypass:privileged_username_match"),
                    )
                    .details(serde_json::json!({
                        "provider_name": provider.name,
                        "oidc_subject": claims.sub,
                        "username": username,
                    }))
                    .build();
                write_audit(&*self.store, &event).await;
                return Ok(OidcAccount::Rejected(
                    "This username belongs to a privileged local account. \
                     Ask an administrator to link your identity.",
                ));
            }
            Some(existing) => {
                if !existing.enabled {
                    return Ok(OidcAccount::Rejected(ACCOUNT_DISABLED));
                }
                self.store
                    .link_oidc_identity(&existing.id, &provider.id, &claims.sub)
                    .await?;
                existing
            }
            None => {
                let role = resolve_role(&provider.role_mapping, claims);

                let random_password = generate_session_token();
                let password_hash = hash_password_async(&random_password)
                    .await
                    .map_err(|e| ApiError::Internal(e.to_string()))?;

                let now = chrono::Utc::now();
                let created = User {
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

                self.store.create_user(&created).await?;
                self.store
                    .link_oidc_identity(&created.id, &provider.id, &claims.sub)
                    .await?;
                created
            }
        };

        let event = AuditEvent::builder(AuditEventType::UserCreated)
            .action("create")
            .user_actor(&new_user)
            .resource("user", &new_user.id.0.to_string())
            .correlation_id(corr)
            .decision(AuditDecision::Permit, Some("bypass:oidc_auto_provisioned"))
            .details(serde_json::json!({
                "provider_name": provider.name,
                "oidc_subject": claims.sub,
            }))
            .build();
        write_audit(&*self.store, &event).await;

        Ok(OidcAccount::Resolved(new_user))
    }
}

/// Shown for both ways a disabled account is reached by OIDC: the linked
/// account is disabled, or the same-named local account being adopted is.
const ACCOUNT_DISABLED: &str = "Your account is disabled. Contact your administrator.";

/// Outcome of resolving an OIDC subject to a local account.
enum OidcAccount {
    Resolved(User),
    Rejected(&'static str),
}

/// Resolve the username for a newly provisioned account from the ID token,
/// using exactly the provider's configured `username_claim`.
///
/// No fallback to other claims: a provider configured for
/// `preferred_username` that sends none has not named the account, and
/// silently using `email` or `sub` instead makes the resolved name depend
/// on what the token happened to omit.
pub fn resolve_username_claim(claim_name: &str, claims: &IdTokenClaims) -> Option<String> {
    match claim_name {
        "preferred_username" => claims.preferred_username.clone(),
        "email" => claims.email.clone(),
        "name" => claims.name.clone(),
        "sub" => Some(claims.sub.clone()),
        other => claims
            .extra
            .get(other)
            .and_then(|v| v.as_str().map(|s| s.to_string())),
    }
    .filter(|s| !s.trim().is_empty())
}

/// Parse a role string into a `UserRole`.
pub fn parse_role(role_str: &str) -> UserRole {
    match role_str {
        "admin" => UserRole::Admin,
        "operator" => UserRole::Operator,
        _ => UserRole::Viewer,
    }
}

/// Resolve the user role from the OIDC provider's `role_mapping` config and
/// the ID token claims.
pub fn resolve_role(role_mapping: &serde_json::Value, claims: &IdTokenClaims) -> UserRole {
    let obj = match role_mapping.as_object() {
        Some(o) if !o.is_empty() => o,
        _ => return UserRole::Viewer,
    };

    let default_role = obj
        .get("default_role")
        .and_then(|v| v.as_str())
        .map(parse_role)
        .unwrap_or(UserRole::Viewer);

    let claim_name = match obj.get("claim").and_then(|v| v.as_str()) {
        Some(c) => c,
        None => return default_role,
    };
    let mappings = match obj.get("mappings").and_then(|v| v.as_object()) {
        Some(m) if !m.is_empty() => m,
        _ => return default_role,
    };

    let claim_strings: Vec<String> = match claim_name {
        "sub" => vec![claims.sub.clone()],
        "email" => claims.email.clone().into_iter().collect(),
        "preferred_username" => claims.preferred_username.clone().into_iter().collect(),
        "name" => claims.name.clone().into_iter().collect(),
        other => match claims.extra.get(other) {
            Some(serde_json::Value::String(s)) => vec![s.clone()],
            Some(serde_json::Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            _ => vec![],
        },
    };

    for val in &claim_strings {
        if let Some(role_str) = mappings.get(val).and_then(|r| r.as_str()) {
            return parse_role(role_str);
        }
    }

    default_role
}

/// The OIDC role and username-claim mapping: a pure function over the ID
/// token and the provider's configured mapping.
#[cfg(test)]
mod tests {
    use super::resolve_role;
    use agent_cordon_core::auth::oidc::IdTokenClaims;
    use agent_cordon_core::domain::user::UserRole;
    use serde_json::json;
    use std::collections::HashMap;

    /// Build a minimal IdTokenClaims with optional extra claims.
    fn make_claims(extra: HashMap<String, serde_json::Value>) -> IdTokenClaims {
        IdTokenClaims {
            sub: "test-sub".to_string(),
            iss: "https://idp.example.com".to_string(),
            aud: json!("test-client"),
            exp: 9999999999,
            iat: Some(1000000000),
            nonce: Some("test-nonce".to_string()),
            email: Some("user@example.com".to_string()),
            name: Some("Test User".to_string()),
            preferred_username: Some("testuser".to_string()),
            extra,
        }
    }

    #[test]
    fn test_resolve_role_with_group_claim_match() {
        let mut extra = HashMap::new();
        extra.insert("groups".to_string(), json!("AgentCordon-Admins"));

        let claims = make_claims(extra);
        let role_mapping = json!({
            "claim": "groups",
            "mappings": {
                "AgentCordon-Admins": "admin",
                "AgentCordon-Ops": "operator"
            },
            "default_role": "viewer"
        });

        let role = resolve_role(&role_mapping, &claims);
        assert_eq!(role, UserRole::Admin);
    }

    #[test]
    fn test_resolve_role_with_no_match_uses_default() {
        let mut extra = HashMap::new();
        extra.insert("groups".to_string(), json!("SomeOtherGroup"));

        let claims = make_claims(extra);
        let role_mapping = json!({
            "claim": "groups",
            "mappings": {
                "AgentCordon-Admins": "admin",
                "AgentCordon-Ops": "operator"
            },
            "default_role": "operator"
        });

        let role = resolve_role(&role_mapping, &claims);
        assert_eq!(role, UserRole::Operator);
    }

    #[test]
    fn test_resolve_role_with_empty_mapping() {
        let claims = make_claims(HashMap::new());
        let role_mapping = json!({});

        let role = resolve_role(&role_mapping, &claims);
        assert_eq!(role, UserRole::Viewer);
    }

    #[test]
    fn test_resolve_role_with_array_claim() {
        let mut extra = HashMap::new();
        extra.insert(
            "groups".to_string(),
            json!(["Users", "AgentCordon-Ops", "Developers"]),
        );

        let claims = make_claims(extra);
        let role_mapping = json!({
            "claim": "groups",
            "mappings": {
                "AgentCordon-Admins": "admin",
                "AgentCordon-Ops": "operator"
            },
            "default_role": "viewer"
        });

        let role = resolve_role(&role_mapping, &claims);
        assert_eq!(role, UserRole::Operator);
    }

    #[test]
    fn test_resolve_role_with_string_claim() {
        let mut extra = HashMap::new();
        extra.insert("department".to_string(), json!("engineering"));

        let claims = make_claims(extra);
        let role_mapping = json!({
            "claim": "department",
            "mappings": {
                "engineering": "operator",
                "security": "admin"
            },
            "default_role": "viewer"
        });

        let role = resolve_role(&role_mapping, &claims);
        assert_eq!(role, UserRole::Operator);
    }

    #[test]
    fn test_resolve_role_no_claim_no_mappings_with_default() {
        let claims = make_claims(HashMap::new());
        let role_mapping = json!({
            "default_role": "admin"
        });

        let role = resolve_role(&role_mapping, &claims);
        assert_eq!(role, UserRole::Admin);
    }

    #[test]
    fn test_resolve_role_claim_missing_from_token() {
        let claims = make_claims(HashMap::new());
        let role_mapping = json!({
            "claim": "groups",
            "mappings": {
                "AgentCordon-Admins": "admin"
            },
            "default_role": "operator"
        });

        let role = resolve_role(&role_mapping, &claims);
        assert_eq!(role, UserRole::Operator);
    }

    #[test]
    fn test_resolve_role_first_match_wins() {
        let mut extra = HashMap::new();
        extra.insert(
            "roles".to_string(),
            json!(["viewer-role", "admin-role", "operator-role"]),
        );

        let claims = make_claims(extra);
        let role_mapping = json!({
            "claim": "roles",
            "mappings": {
                "admin-role": "admin",
                "operator-role": "operator",
                "viewer-role": "viewer"
            },
            "default_role": "viewer"
        });

        // "viewer-role" appears first in the array and maps to viewer
        let role = resolve_role(&role_mapping, &claims);
        assert_eq!(role, UserRole::Viewer);
    }

    #[test]
    fn test_resolve_role_null_role_mapping() {
        let claims = make_claims(HashMap::new());
        let role_mapping = serde_json::Value::Null;

        let role = resolve_role(&role_mapping, &claims);
        assert_eq!(role, UserRole::Viewer);
    }

    #[test]
    fn test_resolve_role_with_well_known_email_claim() {
        let claims = make_claims(HashMap::new());
        let role_mapping = json!({
            "claim": "email",
            "mappings": {
                "user@example.com": "admin",
                "other@example.com": "operator"
            },
            "default_role": "viewer"
        });

        let role = resolve_role(&role_mapping, &claims);
        assert_eq!(role, UserRole::Admin);
    }

    #[test]
    fn test_resolve_role_no_default_role_no_match_defaults_viewer() {
        let mut extra = HashMap::new();
        extra.insert("groups".to_string(), json!("Unknown-Group"));

        let claims = make_claims(extra);
        let role_mapping = json!({
            "claim": "groups",
            "mappings": {
                "AgentCordon-Admins": "admin"
            }
        });

        let role = resolve_role(&role_mapping, &claims);
        assert_eq!(role, UserRole::Viewer);
    }
}
