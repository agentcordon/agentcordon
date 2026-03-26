//! Cedar policy evaluation middleware.
//!
//! Provides an opt-in Axum middleware layer that evaluates Cedar policy before
//! the route handler runs. Routes declare their policy requirements via
//! [`PolicyRequired`] metadata injected into request extensions.
//!
//! ## Usage
//!
//! Apply to a route group by wrapping it in a helper that adds both the
//! metadata and the evaluation middleware:
//!
//! ```text
//! use crate::middleware::policy::{with_policy, PolicyResourceType};
//!
//! fn routes(app_state: AppState) -> Router<AppState> {
//!     with_policy(
//!         "manage_agents",
//!         PolicyResourceType::System,
//!         app_state,
//!         Router::new()
//!             .route("/agents", get(list_agents))
//!             .route("/agents/{id}", get(get_agent)),
//!     )
//! }
//! ```
//!
//! Handlers can access the pre-computed decision via `Extension<PolicyDecisionExt>`.

use axum::{
    extract::{FromRequestParts, Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    Router,
};

use agent_cordon_core::domain::audit::{
    enrich_metadata_with_policy_reasoning, AuditDecision, AuditEvent, AuditEventType,
};
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::policy::{PolicyContext, PolicyEngine, PolicyPrincipal, PolicyResource};

use crate::extractors::AuthenticatedUser;
use crate::middleware::request_id::CorrelationId;
use crate::response::ApiError;
use crate::state::AppState;

/// Describes the type of resource for policy evaluation.
#[derive(Debug, Clone)]
pub enum PolicyResourceType {
    /// System-level resource (e.g., listing all agents, creating credentials).
    System,
}

/// Route-level metadata declaring that Cedar policy evaluation is required.
///
/// Injected into request extensions by the metadata injection layer.
/// Consumed by [`evaluate_policy`].
#[derive(Debug, Clone)]
pub struct PolicyRequired {
    /// The Cedar action name (e.g., "manage_agents", "manage_credentials").
    pub action: String,
    /// The resource type to evaluate against.
    pub resource_type: PolicyResourceType,
}

/// The result of a successful policy evaluation, available to handlers
/// via `Extension<PolicyDecisionExt>`.
///
/// When the policy middleware allows the request, this is inserted into
/// request extensions so handlers can access the decision (e.g., for audit
/// logging) without re-evaluating.
#[derive(Debug, Clone)]
pub struct PolicyDecisionExt {
    pub decision: agent_cordon_core::domain::policy::PolicyDecision,
}

/// Wrap a router with Cedar policy enforcement.
///
/// This is the primary public API for applying policy middleware to a group
/// of routes. It:
/// 1. Injects [`PolicyRequired`] metadata into each request
/// 2. Evaluates Cedar policy using [`evaluate_policy`]
/// 3. On deny: returns 403 and emits an audit event
/// 4. On allow: injects [`PolicyDecisionExt`] into extensions
///
/// Layers are applied outside-in: the evaluate layer runs first (outermost),
/// then the metadata injection (innermost, closest to the handler).
pub fn with_policy(
    action: &str,
    resource_type: PolicyResourceType,
    app_state: AppState,
    router: Router<AppState>,
) -> Router<AppState> {
    let action = action.to_string();
    router
        .layer(axum::middleware::from_fn_with_state(
            app_state,
            evaluate_policy,
        ))
        .layer(axum::middleware::from_fn(
            move |mut req: Request, next: Next| {
                let meta = PolicyRequired {
                    action: action.clone(),
                    resource_type: resource_type.clone(),
                };
                async move {
                    req.extensions_mut().insert(meta);
                    next.run(req).await
                }
            },
        ))
}

/// Axum middleware that evaluates Cedar policy based on [`PolicyRequired`]
/// metadata in request extensions.
///
/// **Opt-in**: if no [`PolicyRequired`] metadata is present, the request passes
/// through unchanged. This makes it safe to apply broadly.
///
/// On policy deny: returns 403 Forbidden and emits an audit event.
/// On policy allow: injects [`PolicyDecisionExt`] into request extensions,
/// then continues to the handler.
/// On policy error: returns 403 Forbidden (deny-by-default).
pub async fn evaluate_policy(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    // Check if this route requires policy evaluation
    let policy_req = match request.extensions().get::<PolicyRequired>() {
        Some(req) => req.clone(),
        None => return next.run(request).await,
    };

    // Extract the authenticated user from request parts.
    let (mut parts, body) = request.into_parts();

    let auth = match AuthenticatedUser::from_request_parts(&mut parts, &state).await {
        Ok(auth) => auth,
        Err(err) => return err.into_response(),
    };

    // Build the policy resource
    let resource = match &policy_req.resource_type {
        PolicyResourceType::System => PolicyResource::System,
    };

    // Evaluate Cedar policy
    let result = state.policy_engine.evaluate(
        &PolicyPrincipal::User(&auth.user),
        &policy_req.action,
        &resource,
        &PolicyContext {
            target_url: None,
            requested_scopes: vec![],
            ..Default::default()
        },
    );

    let corr = parts
        .extensions
        .get::<CorrelationId>()
        .cloned()
        .unwrap_or_else(|| CorrelationId("unknown".to_string()));

    match result {
        Ok(decision) if decision.decision == PolicyDecisionResult::Forbid => {
            // Emit audit event for denied access with policy reasoning
            let mut metadata = serde_json::json!({});
            enrich_metadata_with_policy_reasoning(&mut metadata, &decision, None, None);
            let event = AuditEvent {
                id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                correlation_id: corr.0,
                event_type: AuditEventType::PolicyEvaluated,
                workspace_id: None,
                workspace_name: None,
                user_id: Some(auth.user.id.0.to_string()),
                user_name: Some(auth.user.username.clone()),
                action: policy_req.action.clone(),
                resource_type: format!("{:?}", policy_req.resource_type),
                resource_id: None,
                decision: AuditDecision::Forbid,
                decision_reason: Some(decision.reasons.join(", ")),
                metadata,
            };
            if let Err(e) = state.store.append_audit_event(&event).await {
                tracing::error!(error = %e, "failed to write policy-deny audit event");
            }

            ApiError::Forbidden("access denied by policy".to_string()).into_response()
        }
        Ok(decision) => {
            // Inject decision into extensions so handlers can use it for audit
            parts.extensions.insert(PolicyDecisionExt { decision });

            let request = Request::from_parts(parts, body);
            next.run(request).await
        }
        Err(e) => {
            tracing::error!(error = %e, action = %policy_req.action, "policy evaluation error in middleware");
            ApiError::Forbidden("policy evaluation failed".to_string()).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_required_clone() {
        let pr = PolicyRequired {
            action: "manage_agents".to_string(),
            resource_type: PolicyResourceType::System,
        };
        let pr2 = pr.clone();
        assert_eq!(pr2.action, "manage_agents");
    }

    #[test]
    fn policy_decision_ext_debug() {
        let ext = PolicyDecisionExt {
            decision: agent_cordon_core::domain::policy::PolicyDecision {
                decision: PolicyDecisionResult::Permit,
                reasons: vec![],
                errors: vec![],
            },
        };
        assert!(format!("{:?}", ext).contains("Permit"));
    }
}
