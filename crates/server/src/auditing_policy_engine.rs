//! Decorator around [`CedarPolicyEngine`] that automatically emits an
//! [`AuditEvent`] for every `evaluate()` call.
//!
//! This centralises policy-decision audit so that individual route handlers
//! never need to hand-build `PolicyEvaluated` events.

use std::sync::Arc;

use agent_cordon_core::domain::audit::{
    enrich_metadata_with_policy_reasoning, AuditDecision, AuditEvent, AuditEventType,
};
use agent_cordon_core::domain::policy::{
    PolicyDecision, PolicyDecisionResult, PolicyValidationError,
};
use agent_cordon_core::error::PolicyError;
use agent_cordon_core::policy::cedar::CedarPolicyEngine;
use agent_cordon_core::policy::{PolicyContext, PolicyEngine, PolicyPrincipal, PolicyResource};
use agent_cordon_core::storage::Store;

/// A [`PolicyEngine`] wrapper that delegates to [`CedarPolicyEngine`] and
/// emits an audit event on every `evaluate()` call (fire-and-forget).
pub struct AuditingPolicyEngine {
    inner: Arc<CedarPolicyEngine>,
    store: Arc<dyn Store + Send + Sync>,
}

impl std::fmt::Debug for AuditingPolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditingPolicyEngine")
            .finish_non_exhaustive()
    }
}

impl AuditingPolicyEngine {
    pub fn new(inner: Arc<CedarPolicyEngine>, store: Arc<dyn Store + Send + Sync>) -> Self {
        Self { inner, store }
    }

    /// Access the inner [`CedarPolicyEngine`] for operations that don't need
    /// audit (e.g. `reload_policies`).
    pub fn inner(&self) -> &CedarPolicyEngine {
        &self.inner
    }
}

// ---------------------------------------------------------------------------
// Helper: extract actor fields from PolicyPrincipal
// ---------------------------------------------------------------------------

struct ActorFields {
    workspace_id: Option<agent_cordon_core::domain::workspace::WorkspaceId>,
    workspace_name: Option<String>,
    user_id: Option<String>,
    user_name: Option<String>,
}

fn extract_actor(principal: &PolicyPrincipal) -> ActorFields {
    match principal {
        PolicyPrincipal::User(u) => ActorFields {
            workspace_id: None,
            workspace_name: None,
            user_id: Some(u.id.0.to_string()),
            user_name: Some(u.username.clone()),
        },
        PolicyPrincipal::Workspace(w) => ActorFields {
            workspace_id: Some(w.id.clone()),
            workspace_name: Some(w.name.clone()),
            user_id: None,
            user_name: None,
        },
        PolicyPrincipal::Server(_s) => ActorFields {
            workspace_id: None,
            workspace_name: None,
            user_id: None,
            user_name: None,
        },
    }
}

// ---------------------------------------------------------------------------
// Helper: extract resource fields from PolicyResource
// ---------------------------------------------------------------------------

fn extract_resource(resource: &PolicyResource) -> (&'static str, Option<String>) {
    match resource {
        PolicyResource::System => ("system", None),
        PolicyResource::Credential { credential } => {
            ("credential", Some(credential.id.0.to_string()))
        }
        PolicyResource::PolicyAdmin => ("policy", None),
        PolicyResource::WorkspaceResource { workspace } => {
            ("workspace", Some(workspace.id.0.to_string()))
        }
        PolicyResource::McpServer { id, .. } => ("mcp_server", Some(id.clone())),
    }
}

// ---------------------------------------------------------------------------
// PolicyEngine implementation
// ---------------------------------------------------------------------------

impl PolicyEngine for AuditingPolicyEngine {
    fn evaluate(
        &self,
        principal: &PolicyPrincipal,
        action: &str,
        resource: &PolicyResource,
        context: &PolicyContext,
    ) -> Result<PolicyDecision, PolicyError> {
        let decision = self.inner.evaluate(principal, action, resource, context)?;

        // Build audit event
        let actor = extract_actor(principal);
        let (resource_type, resource_id) = extract_resource(resource);

        let audit_decision = match decision.decision {
            PolicyDecisionResult::Permit => AuditDecision::Permit,
            PolicyDecisionResult::Forbid => AuditDecision::Forbid,
        };

        let decision_reason = if decision.reasons.is_empty() {
            None
        } else {
            Some(decision.reasons.join(", "))
        };

        let correlation_id = context
            .correlation_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let mut metadata = serde_json::json!({});
        enrich_metadata_with_policy_reasoning(&mut metadata, &decision, Some(context), None);

        // Include OAuth token claims in audit metadata when present.
        // This ensures every access decision log contains the full token context.
        if let Some(ref claims) = context.oauth_claims {
            metadata["oauth_claims"] = claims.clone();
        }

        let mut builder = AuditEvent::builder(AuditEventType::PolicyEvaluated)
            .action(action)
            .resource_type(resource_type)
            .correlation_id(&correlation_id)
            .decision(audit_decision, decision_reason.as_deref())
            .details(metadata)
            .actor_fields(
                actor.workspace_id,
                actor.workspace_name,
                actor.user_id,
                actor.user_name,
            );

        if let Some(ref rid) = resource_id {
            builder = builder.resource(resource_type, rid);
        }

        let event = builder.build();

        // Write audit event synchronously so it is persisted before the
        // caller continues.  `evaluate` is a sync trait method called from
        // async handlers, so we bridge into async via a blocking thread.
        // This works on both multi-threaded and current-thread runtimes.
        let store = self.store.clone();
        let handle = tokio::runtime::Handle::current();
        std::thread::scope(|s| {
            s.spawn(|| {
                if let Err(e) = handle.block_on(store.append_audit_event(&event)) {
                    tracing::error!(error = %e, "failed to write policy audit event");
                }
            });
        });

        Ok(decision)
    }

    fn reload_policies(&self, policies: Vec<(String, String)>) -> Result<(), PolicyError> {
        self.inner.reload_policies(policies)
    }

    fn validate_policy_text(&self, cedar_source: &str) -> Result<(), PolicyError> {
        self.inner.validate_policy_text(cedar_source)
    }

    fn validate_policy_text_detailed(
        &self,
        cedar_source: &str,
    ) -> Result<(), Vec<PolicyValidationError>> {
        self.inner.validate_policy_text_detailed(cedar_source)
    }
}
