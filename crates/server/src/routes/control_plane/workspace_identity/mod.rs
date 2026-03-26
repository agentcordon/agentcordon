mod challenge;
mod management;
mod provision;
mod registration;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use axum::{
    routing::{get, post},
    Router,
};

use crate::state::AppState;

/// Rate limit: max challenges per pk_hash per minute.
pub(crate) const MAX_CHALLENGES_PER_MINUTE: u32 = 10;
/// Challenge TTL in seconds.
pub(crate) const CHALLENGE_TTL_SECONDS: i64 = 60;
/// Identity JWT TTL in seconds.
pub(crate) const IDENTITY_JWT_TTL_SECONDS: i64 = 300;
/// Registration code TTL in seconds (5 minutes).
pub(crate) const REGISTRATION_TTL_SECONDS: i64 = 300;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/agents/identify", post(challenge::request_challenge))
        .route("/agents/identify/verify", post(challenge::verify_challenge))
        .route("/agents/register", post(registration::code_exchange))
        .route(
            "/agents/{id}/workspace-identity",
            axum::routing::delete(management::revoke_workspace_identity),
        )
        .route(
            "/agents/identity/rotate",
            post(management::rotate_workspace_key_by_jwt),
        )
        // Workspace aliases — the device/CLI uses /workspaces/ paths
        .route("/workspaces/identify", post(challenge::request_challenge))
        .route(
            "/workspaces/identify/verify",
            post(challenge::verify_challenge),
        )
        .route("/workspaces/register", post(registration::code_exchange))
        .route(
            "/workspaces/provision",
            post(provision::create_provisioning_token),
        )
        .route(
            "/workspaces/provision/complete",
            post(provision::complete_provisioning),
        )
        // Frontend management routes
        .route(
            "/workspace-identities",
            get(management::list_workspace_identities),
        )
        .route(
            "/workspace-identities/{id}/approve",
            post(management::approve_workspace_identity),
        )
        .route(
            "/workspace-identities/{id}",
            axum::routing::delete(management::revoke_workspace_identity_by_id),
        )
        .route(
            "/workspace-identities/register",
            post(management::json_approve_registration),
        )
        // Registration polling (CLI polls for approval)
        .route(
            "/workspaces/registration-status",
            get(registration::poll_registration_status),
        )
        // Registration browser flow
        .route(
            "/register",
            get(registration::render_register_page).post(registration::approve_registration),
        )
}

/// Validate an optional P-256 encryption public key (JWK).
///
/// If `jwk` is `Some`, the value must be a JSON object with `kty: "EC"` and `crv: "P-256"`.
/// Returns `Ok(())` if valid or absent, `Err(message)` with a user-facing error otherwise.
pub(crate) fn validate_encryption_key(jwk: Option<&serde_json::Value>) -> Result<(), String> {
    let jwk = match jwk {
        Some(v) => v,
        None => return Ok(()),
    };

    let obj = jwk
        .as_object()
        .ok_or_else(|| "encryption_key must be a JSON object (JWK format)".to_string())?;

    let kty = obj
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "encryption_key JWK must contain a \"kty\" field".to_string())?;
    if kty != "EC" {
        return Err(format!(
            "encryption_key JWK kty must be \"EC\", got \"{}\"",
            kty
        ));
    }

    let crv = obj
        .get("crv")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "encryption_key JWK must contain a \"crv\" field".to_string())?;
    if crv != "P-256" {
        return Err(format!(
            "encryption_key JWK crv must be \"P-256\", got \"{}\"",
            crv
        ));
    }

    Ok(())
}

/// Helper: audit workspace auth failure.
pub(crate) async fn audit_workspace_auth_failed(
    state: &AppState,
    correlation_id: &str,
    pk_hash: &str,
    reason: &str,
) {
    let event = AuditEvent::builder(AuditEventType::WorkspaceAuthFailed)
        .action("workspace_authenticate")
        .resource_type("workspace_identity")
        .correlation_id(correlation_id)
        .decision(AuditDecision::Forbid, Some(reason))
        .details(serde_json::json!({ "pk_hash": pk_hash }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }
}
