//! Settings API endpoints for user preferences.

use axum::{routing::put, Json, Router};
use serde::Deserialize;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/settings/advanced-mode", put(set_advanced_mode))
}

#[derive(Deserialize)]
struct AdvancedModeRequest {
    enabled: bool,
}

/// `PUT /api/v1/settings/advanced-mode` — toggle the authenticated user's
/// `show_advanced` preference. No policy check required: users can always
/// change their own UI preferences.
async fn set_advanced_mode(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
    Json(req): Json<AdvancedModeRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let old_value = auth.user.show_advanced;
    let mut user = auth.user;
    user.show_advanced = req.enabled;
    user.updated_at = chrono::Utc::now();

    state.store.update_user(&user).await?;

    // Audit event
    let event = AuditEvent::builder(AuditEventType::UserUpdated)
        .action("settings_updated")
        .resource("user", &user.id.0.to_string())
        .user_actor(&user)
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, None)
        .details(serde_json::json!({
            "setting": "show_advanced",
            "old_value": old_value,
            "new_value": req.enabled,
        }))
        .build();
    state.store.append_audit_event(&event).await.ok();

    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "show_advanced": req.enabled }),
    )))
}
