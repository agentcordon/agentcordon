//! `Authz` — single front door for policy evaluation.
//!
//! `Authz` is the only path to a Cedar policy evaluation in the server.
//! Handlers use the fluent builder API:
//!
//! ```ignore
//! state.authz.request(&actor, &corr_id)
//!     .claim(claim_keys::TOOL_NAME, "send_message")
//!     .require_scope(OAuthScope::McpInvoke)
//!     .check(actions::MCP_TOOL_CALL, &resource)
//!     .await?;
//! ```
//!
//! Three terminal methods are available:
//!
//! - [`AuthzRequest::check`] — returns `Ok(())` on permit, raises
//!   `ApiError::Forbidden("access denied by policy")` on deny. The opaque
//!   error message never leaks policy IDs, statement indices or reasons.
//!   This is the default for the 39-handler population that does not need
//!   to inspect the decision.
//! - [`AuthzRequest::check_with_reasons`] — returns the full
//!   [`PolicyDecision`] for handlers that need to fork on the decision
//!   internally (e.g. the broker-facing `mcp-authorize` endpoint). The
//!   reasons are intended for audit and internal handler logic only —
//!   never serialize them into HTTP responses to untrusted callers.
//! - [`AuthzRequest::filter`] — per-item evaluation that silently drops
//!   denied items. For list endpoints.
//!
//! All three terminals auto-emit a `PolicyEvaluated` audit event,
//! including OAuth claims pulled off the actor, the correlation ID, and
//! the contributing policy reasons. They short-circuit on missing OAuth
//! scopes for workspace actors before invoking Cedar; user actors bypass
//! the scope check (scopes are a workspace concept).
//!
//! Authz does **not** implement the [`PolicyEngine`] trait. There is no
//! public `evaluate(...)` method. The auditing decorator that previously
//! lived in the deleted `auditing_policy_engine.rs` is subsumed here.

use std::sync::Arc;

use agent_cordon_core::domain::audit::{
    enrich_metadata_with_policy_reasoning, AuditDecision, AuditEvent, AuditEventType,
};
use agent_cordon_core::domain::policy::{
    PolicyDecision, PolicyDecisionResult, PolicyValidationError,
};
use agent_cordon_core::domain::workspace::WorkspaceId;
use agent_cordon_core::error::PolicyError;
use agent_cordon_core::oauth2::types::OAuthScope;
use agent_cordon_core::policy::cedar::CedarPolicyEngine;
use agent_cordon_core::policy::{PolicyContext, PolicyEngine, PolicyPrincipal, PolicyResource};
use agent_cordon_core::storage::Store;

use crate::extractors::AuthenticatedActor;
use crate::response::ApiError;

/// What kind of caller is making the policy request. The seam supports
/// both authenticated-actor flows (workspace or user, scope-aware) and
/// raw `PolicyPrincipal` flows for handlers that have already extracted
/// the principal (e.g. background workspace-sync code that operates over
/// a stored `Workspace` without an `AuthenticatedActor`).
pub enum PolicyCaller<'a> {
    Actor(&'a AuthenticatedActor),
    Principal {
        principal: PolicyPrincipal<'a>,
        oauth_claims: Option<serde_json::Value>,
    },
}

impl<'a> From<&'a AuthenticatedActor> for PolicyCaller<'a> {
    fn from(a: &'a AuthenticatedActor) -> Self {
        PolicyCaller::Actor(a)
    }
}

/// Single front door for policy evaluation.
///
/// Holds a Cedar engine and a `Store` for audit emission. Construct via
/// [`Authz::new`]. Use the fluent [`request`](Self::request) method to
/// start an evaluation.
pub struct Authz {
    inner: Arc<CedarPolicyEngine>,
    store: Arc<dyn Store + Send + Sync>,
}

impl std::fmt::Debug for Authz {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authz").finish_non_exhaustive()
    }
}

impl Authz {
    /// Construct a new `Authz` from the underlying Cedar engine and the
    /// store used for audit emission.
    pub fn new(inner: Arc<CedarPolicyEngine>, store: Arc<dyn Store + Send + Sync>) -> Self {
        Self { inner, store }
    }

    /// Begin a fluent evaluation. The caller's OAuth claims (if any) are
    /// auto-attached to the evaluation context. Pass either an
    /// [`AuthenticatedActor`] (preferred — scope checks light up) or a
    /// raw [`PolicyPrincipal`] via [`PolicyCaller::Principal`] for
    /// background flows that operate over a stored principal.
    pub fn request<'a, C: Into<PolicyCaller<'a>>>(
        &'a self,
        caller: C,
        correlation_id: &str,
    ) -> AuthzRequest<'a> {
        let caller = caller.into();
        let oauth_claims = match &caller {
            PolicyCaller::Actor(a) => a.oauth_claims().cloned(),
            PolicyCaller::Principal { oauth_claims, .. } => oauth_claims.clone(),
        };
        let ctx = PolicyContext {
            correlation_id: Some(correlation_id.to_string()),
            oauth_claims,
            ..Default::default()
        };
        AuthzRequest {
            authz: self,
            caller,
            ctx,
            required_scope: None,
        }
    }

    /// Reload the policy set (admin operation). Pass-through to the
    /// underlying Cedar engine; not subject to audit.
    pub fn reload_policies(&self, policies: Vec<(String, String)>) -> Result<(), PolicyError> {
        self.inner.reload_policies(policies)
    }

    /// Validate Cedar source text against the schema (boolean).
    pub fn validate_policy_text(&self, cedar_source: &str) -> Result<(), PolicyError> {
        self.inner.validate_policy_text(cedar_source)
    }

    /// Validate Cedar source text against the schema (detailed).
    pub fn validate_policy_text_detailed(
        &self,
        cedar_source: &str,
    ) -> Result<(), Vec<PolicyValidationError>> {
        self.inner.validate_policy_text_detailed(cedar_source)
    }
}

/// Fluent builder for a single policy evaluation. Built by
/// [`Authz::request`].
pub struct AuthzRequest<'a> {
    authz: &'a Authz,
    caller: PolicyCaller<'a>,
    ctx: PolicyContext,
    required_scope: Option<OAuthScope>,
}

impl<'a> AuthzRequest<'a> {
    /// Add a key/value pair to the policy context's claim bag. Cedar
    /// policies referencing `context.<key>` will see this value.
    pub fn claim<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<serde_json::Value>,
    {
        self.ctx.claims.insert(key.into(), value.into());
        self
    }

    /// Builder-style alias of [`claim`](Self::claim) — kept for symmetry
    /// with the underlying `PolicyContext::with_claim` and to ease
    /// migration of code that constructed contexts inline.
    pub fn with_claim<K, V>(self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<serde_json::Value>,
    {
        self.claim(key, value)
    }

    /// Require an OAuth scope. The terminal methods short-circuit with
    /// [`ApiError::Forbidden`] if a workspace actor lacks the scope. User
    /// actors bypass this check.
    pub fn require_scope(mut self, scope: OAuthScope) -> Self {
        self.required_scope = Some(scope);
        self
    }

    /// Permit-or-403 terminal. Returns `Ok(())` on permit, raises
    /// `ApiError::Forbidden("access denied by policy")` on deny. The
    /// error message is opaque to callers — no leaked reasons or policy
    /// IDs.
    pub async fn check(self, action: &str, resource: &PolicyResource) -> Result<(), ApiError> {
        match self.check_with_reasons(action, resource).await? {
            d if matches!(d.decision, PolicyDecisionResult::Permit) => Ok(()),
            _ => Err(ApiError::Forbidden("access denied by policy".to_string())),
        }
    }

    /// Permit-or-decision terminal. Returns the full
    /// [`PolicyDecision`] including reasons for handlers that need to
    /// fork on the decision (e.g. broker-facing endpoints). Reasons are
    /// for audit and internal handler logic only — never serialize them
    /// into HTTP responses to untrusted callers.
    pub async fn check_with_reasons(
        self,
        action: &str,
        resource: &PolicyResource,
    ) -> Result<PolicyDecision, ApiError> {
        self.evaluate_with_audit(action, resource).await
    }

    /// Synchronous variant of [`check_with_reasons`](Self::check_with_reasons).
    ///
    /// Necessary for callers stuck in synchronous closures (e.g. inside
    /// `Iterator::filter`) where introducing `.await` would require
    /// rewriting the surrounding code. Internally it drives the same
    /// async pipeline and is therefore a single front door, not a
    /// parallel path. Only call from within a tokio runtime.
    pub fn check_with_reasons_blocking(
        self,
        action: &str,
        resource: &PolicyResource,
    ) -> Result<PolicyDecision, ApiError> {
        // Run scope check + Cedar evaluate inline, then bridge the audit
        // emission through the same blocking helper used in async paths.
        self.check_required_scope()?;
        let decision = self.evaluate_one(action, resource);
        self.emit_audit(action, resource, &decision);
        Ok(decision)
    }

    /// Filter terminal. For each item, evaluates with the resource
    /// derived from a closure; only items that permit pass through.
    /// Denied items are silently dropped. A single audit event is
    /// emitted per item.
    pub async fn filter<I, F>(
        self,
        action: &str,
        items: Vec<I>,
        resource_for: F,
    ) -> Result<Vec<I>, ApiError>
    where
        F: Fn(&I) -> PolicyResource,
    {
        // Run scope check once up front; if scopes are wrong we drop the
        // entire batch (and audit zero items, since no Cedar evaluation
        // ran).
        self.check_required_scope()?;
        let mut kept = Vec::with_capacity(items.len());
        for item in items {
            let resource = resource_for(&item);
            let decision = self.evaluate_one(action, &resource);
            self.emit_audit(action, &resource, &decision);
            if matches!(decision.decision, PolicyDecisionResult::Permit) {
                kept.push(item);
            }
        }
        Ok(kept)
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    fn check_required_scope(&self) -> Result<(), ApiError> {
        let Some(ref scope) = self.required_scope else {
            return Ok(());
        };
        match &self.caller {
            PolicyCaller::Actor(AuthenticatedActor::User(_)) => Ok(()),
            PolicyCaller::Actor(AuthenticatedActor::Workspace { scopes, .. }) => {
                if scopes.contains(scope) {
                    Ok(())
                } else {
                    Err(ApiError::Forbidden(format!(
                        "insufficient OAuth scope: requires {scope}"
                    )))
                }
            }
            PolicyCaller::Principal { .. } => {
                // Raw-principal callers carry no scope context; require_scope
                // is a no-op for them. They're internal callers (background
                // sync, etc.) and have already done whatever auth they need.
                Ok(())
            }
        }
    }

    fn caller_principal(&self) -> PolicyPrincipal<'_> {
        match &self.caller {
            PolicyCaller::Actor(a) => a.policy_principal(),
            PolicyCaller::Principal { principal, .. } => match principal {
                PolicyPrincipal::User(u) => PolicyPrincipal::User(u),
                PolicyPrincipal::Workspace(w) => PolicyPrincipal::Workspace(w),
                PolicyPrincipal::Server(s) => PolicyPrincipal::Server(s),
            },
        }
    }

    fn evaluate_one(&self, action: &str, resource: &PolicyResource) -> PolicyDecision {
        let principal = self.caller_principal();
        match self
            .authz
            .inner
            .evaluate(&principal, action, resource, &self.ctx)
        {
            Ok(d) => d,
            Err(e) => {
                tracing::error!(error = %e, action = %action, "policy evaluation error");
                PolicyDecision {
                    decision: PolicyDecisionResult::Forbid,
                    reasons: vec![format!("evaluation_error: {e}")],
                    errors: vec![e.to_string()],
                }
            }
        }
    }

    async fn evaluate_with_audit(
        self,
        action: &str,
        resource: &PolicyResource,
    ) -> Result<PolicyDecision, ApiError> {
        // Scope check short-circuits before Cedar.
        self.check_required_scope()?;
        let decision = self.evaluate_one(action, resource);
        self.emit_audit(action, resource, &decision);
        Ok(decision)
    }

    fn emit_audit(&self, action: &str, resource: &PolicyResource, decision: &PolicyDecision) {
        let principal = self.caller_principal();
        let actor = extract_actor(&principal);
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

        let correlation_id = self
            .ctx
            .correlation_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let mut metadata = serde_json::json!({});
        enrich_metadata_with_policy_reasoning(&mut metadata, decision, Some(&self.ctx), None);

        // Include OAuth claims in audit metadata when present.
        if let Some(ref claims) = self.ctx.oauth_claims {
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
        // caller continues. We bridge into async via a blocking thread
        // because this can be called from sync paths (filter loop).
        let store = self.authz.store.clone();
        let handle = tokio::runtime::Handle::current();
        std::thread::scope(|s| {
            s.spawn(|| {
                if let Err(e) = handle.block_on(store.append_audit_event(&event)) {
                    tracing::error!(error = %e, "failed to write policy audit event");
                }
            });
        });
    }
}

// ---------------------------------------------------------------------------
// Helpers (lifted from the deleted auditing_policy_engine.rs)
// ---------------------------------------------------------------------------

struct ActorFields {
    workspace_id: Option<WorkspaceId>,
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

#[cfg(test)]
mod tests;
