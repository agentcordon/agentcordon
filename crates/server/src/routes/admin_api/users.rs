use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agent_cordon_core::domain::user::{User, UserId, UserRole};

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::services::users::{NewUser, UserChanges};
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

// --- Handlers ---

async fn list_users(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<ApiResponse<Vec<UserResponse>>>, ApiError> {
    // Policy check: manage_users on System
    state.services.users.check_manage_users(&auth).await?;

    // Tenant scoping: non-admin users only see themselves
    let is_admin = auth.is_admin();
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
        state.services.users.check_manage_users(&auth).await?;
    }

    let user = state.services.users.load(&target_id).await?;

    Ok(Json(ApiResponse::ok(UserResponse::from(&user))))
}

async fn create_user(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<ApiResponse<UserResponse>>, ApiError> {
    let user = state
        .services
        .users
        .create(
            &auth,
            &corr.0,
            NewUser {
                username: req.username,
                password: req.password,
                display_name: req.display_name,
                role: req.role,
            },
        )
        .await?;

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
    state.services.users.check_manage_users(&auth).await?;

    // Reject password updates on this endpoint — they have a dedicated route
    // that enforces current-password verification and session invalidation.
    if req.password.is_some() {
        return Err(ApiError::BadRequest(
            "password cannot be updated via PUT /users/{id}; use POST /users/{id}/change-password"
                .to_string(),
        ));
    }

    let user = state
        .services
        .users
        .update(
            &auth,
            &corr.0,
            &UserId(id),
            UserChanges {
                username: req.username,
                display_name: req.display_name,
                role: req.role,
                enabled: req.enabled,
            },
        )
        .await?;

    Ok(Json(ApiResponse::ok(UserResponse::from(&user))))
}

async fn delete_user(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    state
        .services
        .users
        .delete(&auth, &corr.0, &UserId(id))
        .await?;

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
    state
        .services
        .users
        .change_password(
            &auth,
            &corr.0,
            &UserId(id),
            req.current_password.as_deref(),
            &req.new_password,
        )
        .await?;

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "password_changed": true }),
    )))
}
