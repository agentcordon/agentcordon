use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agent_cordon_core::crypto::password::{hash_password_async, verify_password_async};
use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::user::{User, UserId, UserRole};
use agent_cordon_core::policy::actions;

use crate::events::UiEvent;
use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/users", get(list_users).post(create_user))
        .route(
            "/users/{id}",
            get(get_user).put(update_user).delete(delete_user),
        )
        .route("/users/{id}/change-password", post(change_password))
}

// --- Request/Response Types ---

#[derive(Serialize)]
struct UserResponse {
    id: String,
    username: String,
    display_name: Option<String>,
    role: UserRole,
    is_root: bool,
    enabled: bool,
    created_at: String,
    updated_at: String,
}

impl From<&User> for UserResponse {
    fn from(user: &User) -> Self {
        Self {
            id: user.id.0.to_string(),
            username: user.username.clone(),
            display_name: user.display_name.clone(),
            role: user.role.clone(),
            is_root: user.is_root,
            enabled: user.enabled,
            created_at: user.created_at.to_rfc3339(),
            updated_at: user.updated_at.to_rfc3339(),
        }
    }
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
    display_name: Option<String>,
    role: Option<UserRole>,
}

#[derive(Deserialize)]
struct UpdateUserRequest {
    username: Option<String>,
    display_name: Option<String>,
    role: Option<UserRole>,
    enabled: Option<bool>,
    /// Rejected if present — password changes must go through the dedicated
    /// `/users/{id}/change-password` endpoint so the proper flow (current
    /// password verification, session invalidation, audit) is enforced.
    #[serde(default)]
    password: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    current_password: Option<String>,
    new_password: String,
}

use agent_cordon_core::policy::PolicyResource;

use super::check_cedar_permission;

/// Check Cedar policy for `manage_users` on `System` resource.
fn check_manage_users(
    state: &AppState,
    auth: &AuthenticatedUser,
) -> Result<agent_cordon_core::domain::policy::PolicyDecision, ApiError> {
    check_cedar_permission(state, auth, actions::MANAGE_USERS, PolicyResource::System)
}

// --- Handlers ---

async fn list_users(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<ApiResponse<Vec<UserResponse>>>, ApiError> {
    // Policy check: manage_users on System
    check_manage_users(&state, &auth)?;

    // Tenant scoping: non-admin users only see themselves
    let is_admin = auth.user.role == UserRole::Admin || auth.is_root;
    let users = if is_admin {
        state.store.list_users().await?
    } else {
        match state.store.get_user(&auth.user.id).await? {
            Some(u) => vec![u],
            None => vec![],
        }
    };
    let response: Vec<UserResponse> = users.iter().map(UserResponse::from).collect();
    Ok(Json(ApiResponse::ok(response)))
}

async fn get_user(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<UserResponse>>, ApiError> {
    let target_id = UserId(id);

    // Self-view is always allowed; otherwise check Cedar manage_users policy
    let is_self = auth.user.id == target_id;
    if !is_self {
        check_manage_users(&state, &auth)?;
    }

    let user = state
        .store
        .get_user(&target_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("user not found".to_string()))?;

    Ok(Json(ApiResponse::ok(UserResponse::from(&user))))
}

async fn create_user(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<ApiResponse<UserResponse>>, ApiError> {
    // Policy check: manage_users on System
    let policy_decision = check_manage_users(&state, &auth)?;

    // Validate username
    let username = req.username.trim().to_string();
    if username.is_empty() || username.len() > 128 {
        return Err(ApiError::BadRequest(
            "username must be 1-128 characters".to_string(),
        ));
    }

    // Validate password length.
    // Minimum 12 for security, maximum 1024 to prevent Argon2id DoS.
    if req.password.len() < 12 {
        return Err(ApiError::BadRequest(
            "password must be at least 12 characters".to_string(),
        ));
    }
    if req.password.len() > 1024 {
        return Err(ApiError::BadRequest(
            "password must not exceed 1024 characters".to_string(),
        ));
    }

    // Check for duplicate username
    if let Some(_existing) = state.store.get_user_by_username(&username).await? {
        return Err(ApiError::Conflict("username already exists".to_string()));
    }

    let password_hash = hash_password_async(&req.password)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let now = chrono::Utc::now();
    let user = User {
        id: UserId(Uuid::new_v4()),
        username,
        display_name: req.display_name,
        password_hash,
        role: req.role.unwrap_or(UserRole::Viewer),
        is_root: false,
        enabled: true,
        created_at: now,
        updated_at: now,
    };

    state.store.create_user(&user).await?;

    // Audit
    let event = AuditEvent::builder(AuditEventType::UserCreated)
        .action("create")
        .user_actor(&auth.user)
        .resource("user", &user.id.0.to_string())
        .correlation_id(&corr.0)
        .decision(
            AuditDecision::Permit,
            Some(&policy_decision.reasons.join(", ")),
        )
        .details(serde_json::json!({ "created_user": user.username }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    // Emit UI event for browser auto-refresh
    state
        .ui_event_bus
        .emit(UiEvent::UserCreated { user_id: user.id.0 });

    Ok(Json(ApiResponse::ok(UserResponse::from(&user))))
}

async fn update_user(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<ApiResponse<UserResponse>>, ApiError> {
    // Policy check: manage_users on System
    let policy_decision = check_manage_users(&state, &auth)?;

    // Reject password updates on this endpoint — they have a dedicated route
    // that enforces current-password verification and session invalidation.
    if req.password.is_some() {
        return Err(ApiError::BadRequest(
            "password cannot be updated via PUT /users/{id}; use POST /users/{id}/change-password"
                .to_string(),
        ));
    }

    let target_id = UserId(id);

    let mut user = state
        .store
        .get_user(&target_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("user not found".to_string()))?;

    // Protect root user's role and enabled status
    if user.is_root {
        if let Some(ref role) = req.role {
            if *role != UserRole::Admin {
                return Err(ApiError::Forbidden(
                    "cannot change root user's role".to_string(),
                ));
            }
        }
        if let Some(false) = req.enabled {
            return Err(ApiError::Forbidden("cannot disable root user".to_string()));
        }
    }

    if let Some(username) = req.username {
        let trimmed = username.trim().to_string();
        if trimmed.is_empty() || trimmed.len() > 128 {
            return Err(ApiError::BadRequest(
                "username must be 1-128 characters".to_string(),
            ));
        }
        // Check for duplicate
        if trimmed != user.username {
            if let Some(_existing) = state.store.get_user_by_username(&trimmed).await? {
                return Err(ApiError::Conflict("username already exists".to_string()));
            }
        }
        user.username = trimmed;
    }
    if let Some(display_name) = req.display_name {
        user.display_name = Some(display_name);
    }
    if let Some(role) = req.role {
        user.role = role;
    }
    if let Some(enabled) = req.enabled {
        user.enabled = enabled;
    }
    user.updated_at = chrono::Utc::now();

    state.store.update_user(&user).await?;

    // Audit
    let event = AuditEvent::builder(AuditEventType::UserUpdated)
        .action("update")
        .user_actor(&auth.user)
        .resource("user", &user.id.0.to_string())
        .correlation_id(&corr.0)
        .decision(
            AuditDecision::Permit,
            Some(&policy_decision.reasons.join(", ")),
        )
        .details(serde_json::json!({ "updated_user": user.username }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    // Emit UI event for browser auto-refresh
    state
        .ui_event_bus
        .emit(UiEvent::UserUpdated { user_id: user.id.0 });

    Ok(Json(ApiResponse::ok(UserResponse::from(&user))))
}

async fn delete_user(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    // Policy check: manage_users on System
    let policy_decision = check_manage_users(&state, &auth)?;

    let target_id = UserId(id);

    // Load the target user to check if it's root
    let target_user = state
        .store
        .get_user(&target_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("user not found".to_string()))?;

    // Cannot delete root user
    if target_user.is_root {
        return Err(ApiError::Forbidden("cannot delete root user".to_string()));
    }

    // Cannot delete self
    if auth.user.id == target_id {
        return Err(ApiError::Conflict(
            "cannot delete your own account".to_string(),
        ));
    }

    // Delete all sessions for the user first
    let _ = state.store.delete_user_sessions(&target_id).await;

    let deleted = state.store.delete_user(&target_id).await?;
    if !deleted {
        return Err(ApiError::NotFound("user not found".to_string()));
    }

    // Audit
    let event = AuditEvent::builder(AuditEventType::UserDeleted)
        .action("delete")
        .user_actor(&auth.user)
        .resource("user", &target_id.0.to_string())
        .correlation_id(&corr.0)
        .decision(
            AuditDecision::Permit,
            Some(&policy_decision.reasons.join(", ")),
        )
        .details(serde_json::json!({ "deleted_user": target_user.username }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    // Emit UI event for browser auto-refresh
    state.ui_event_bus.emit(UiEvent::UserDeleted {
        user_id: target_id.0,
    });

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "deleted": true }),
    )))
}

async fn change_password(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let target_id = UserId(id);

    let is_self = auth.user.id == target_id;

    // Self-service password change is always allowed; otherwise check Cedar manage_users policy
    if !is_self {
        check_manage_users(&state, &auth)?;
    }

    // Validate new password length.
    // Minimum 12 for security, maximum 1024 to prevent Argon2id DoS.
    if req.new_password.len() < 12 {
        return Err(ApiError::BadRequest(
            "password must be at least 12 characters".to_string(),
        ));
    }
    if req.new_password.len() > 1024 {
        return Err(ApiError::BadRequest(
            "password must not exceed 1024 characters".to_string(),
        ));
    }

    let mut user = state
        .store
        .get_user(&target_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("user not found".to_string()))?;

    // Self-service password change: ALWAYS require current password when
    // changing your own password, regardless of role. This prevents account
    // takeover if an admin session is hijacked or left unattended.
    // Admin users changing ANOTHER user's password do NOT need current_password.
    if is_self {
        let current_password = req.current_password.as_deref().ok_or_else(|| {
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

    let new_hash = hash_password_async(&req.new_password)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    user.password_hash = new_hash;
    user.updated_at = chrono::Utc::now();

    state.store.update_user(&user).await?;

    // Invalidate all sessions for the target user. After a password change,
    // all existing sessions should be terminated to prevent continued access
    // by anyone who may have compromised the old password or a session token.
    let _ = state.store.delete_user_sessions(&target_id).await;

    // Audit
    let reason = if is_self {
        "bypass:self-service"
    } else {
        "bypass:admin"
    };
    let event = AuditEvent::builder(AuditEventType::UserUpdated)
        .action("change_password")
        .user_actor(&auth.user)
        .resource("user", &user.id.0.to_string())
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some(reason))
        .details(serde_json::json!({
            "target_user": user.username,
            "changed_by": if is_self { "self" } else { "admin" },
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "password_changed": true }),
    )))
}
