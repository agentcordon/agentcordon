use axum::{extract::State, routing::post, Json, Router};

use agent_cordon_core::crypto::SecretEncryptor;
use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent, AuditEventType};
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::policy::{
    actions, PolicyContext, PolicyEngine, PolicyPrincipal, PolicyResource,
};

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::{ApiError, ApiResponse};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/admin/rotate-key", post(rotate_encryption_key))
}

/// Re-encrypt all credentials under the current encryption key.
///
/// This admin-only endpoint reads every credential's encrypted value,
/// decrypts it with the current key, and re-encrypts it. This is useful
/// after a key rotation to ensure all credentials use the latest key.
///
/// Only admin users can call this endpoint. Agent JWTs are rejected.
async fn rotate_encryption_key(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    axum::Extension(corr): axum::Extension<CorrelationId>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    // Cedar policy check: rotate_encryption_key on System resource
    let decision = state.policy_engine.evaluate(
        &PolicyPrincipal::User(&auth.user),
        actions::ROTATE_ENCRYPTION_KEY,
        &PolicyResource::System,
        &PolicyContext {
            target_url: None,
            requested_scopes: vec![],
            ..Default::default()
        },
    )?;

    if decision.decision == PolicyDecisionResult::Forbid {
        return Err(ApiError::Forbidden("access denied by policy".to_string()));
    }

    // List all credentials
    let credentials = state.store.list_credentials().await?;
    let mut re_encrypted_count = 0u32;
    let mut errors = Vec::new();

    for cred_summary in &credentials {
        let cred = match state.store.get_credential(&cred_summary.id).await? {
            Some(c) => c,
            None => continue,
        };

        // Decrypt with current key using credential ID as AAD
        let cred_aad = cred.id.0.to_string();
        let plaintext =
            match state
                .encryptor
                .decrypt(&cred.encrypted_value, &cred.nonce, cred_aad.as_bytes())
            {
                Ok(pt) => pt,
                Err(e) => {
                    errors.push(format!("credential {}: decrypt failed: {}", cred.id.0, e));
                    continue;
                }
            };

        // Re-encrypt with current key (generates new nonce), same credential ID as AAD
        let (new_encrypted, new_nonce) =
            match state.encryptor.encrypt(&plaintext, cred_aad.as_bytes()) {
                Ok(pair) => pair,
                Err(e) => {
                    errors.push(format!("credential {}: encrypt failed: {}", cred.id.0, e));
                    continue;
                }
            };

        // Update the credential in the database, incrementing key_version
        let update = agent_cordon_core::domain::credential::CredentialUpdate {
            name: None,
            service: None,
            scopes: None,
            metadata: None,
            allowed_url_pattern: None,
            expires_at: None,
            transform_script: None,
            transform_name: None,
            vault: None,
            tags: None,
            description: None,
            target_identity: None,
            encrypted_value: Some(new_encrypted),
            nonce: Some(new_nonce),
            key_version: Some(cred.key_version + 1),
        };

        match state.store.update_credential(&cred.id, &update).await {
            Ok(true) => re_encrypted_count += 1,
            Ok(false) => errors.push(format!("credential {}: update returned false", cred.id.0)),
            Err(e) => errors.push(format!("credential {}: update failed: {}", cred.id.0, e)),
        }
    }

    // Audit the rotation
    let event = AuditEvent::builder(AuditEventType::CredentialSecretRotated)
        .action("rotate_encryption_key")
        .user_actor(&auth.user)
        .resource_type("system")
        .correlation_id(&corr.0)
        .decision(AuditDecision::Permit, Some(&decision.reasons.join(", ")))
        .details(serde_json::json!({
            "re_encrypted_count": re_encrypted_count,
            "error_count": errors.len(),
        }))
        .build();
    if let Err(e) = state.store.append_audit_event(&event).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    let result = serde_json::json!({
        "re_encrypted_count": re_encrypted_count,
        "total_credentials": credentials.len(),
        "errors": errors,
    });

    Ok(Json(ApiResponse::ok(result)))
}
