mod entity_builders;

use std::sync::RwLock;

use cedar_policy::{
    Authorizer, Decision, Entities, PolicyId, PolicySet, Request, Schema, ValidationMode, Validator,
};

use crate::domain::policy::{PolicyDecision, PolicyDecisionResult, PolicyValidationError};
use crate::error::PolicyError;

use super::schema::CEDAR_SCHEMA_JSON;
use super::{PolicyContext, PolicyEngine, PolicyPrincipal, PolicyResource};

/// Cedar-backed implementation of `PolicyEngine`.
///
/// Holds a parsed schema, a `Validator` for schema validation, and a
/// `RwLock`-protected `PolicySet` that can be atomically replaced via
/// `reload_policies`.
pub struct CedarPolicyEngine {
    schema: Schema,
    validator: Validator,
    policy_set: RwLock<PolicySet>,
}

impl std::fmt::Debug for CedarPolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CedarPolicyEngine").finish_non_exhaustive()
    }
}

impl CedarPolicyEngine {
    /// Create a new engine with the embedded schema and an initial set of policies.
    ///
    /// `initial_policies` is a list of `(id, cedar_source)` pairs.
    /// Returns an error if the schema cannot be parsed or any policy is invalid.
    pub fn new(initial_policies: Vec<(String, String)>) -> Result<Self, PolicyError> {
        let schema = Schema::from_json_str(CEDAR_SCHEMA_JSON)
            .map_err(|e| PolicyError::Schema(format!("{e}")))?;

        let validator = Validator::new(schema.clone());

        let policy_set = Self::parse_policies(&initial_policies)?;

        Ok(Self {
            schema,
            validator,
            policy_set: RwLock::new(policy_set),
        })
    }

    /// Parse a list of `(id_prefix, source)` pairs into a `PolicySet`.
    ///
    /// Each source may contain multiple Cedar statements. Policies within a
    /// source are given ids `{prefix}_{n}` to avoid collisions.
    fn parse_policies(policies: &[(String, String)]) -> Result<PolicySet, PolicyError> {
        let mut combined = PolicySet::new();
        for (id_prefix, source) in policies {
            // Parse the source text as a full PolicySet (supports multiple statements).
            let parsed: PolicySet = source.parse().map_err(|e: cedar_policy::ParseErrors| {
                PolicyError::Parse(format!("policy '{id_prefix}': {e}"))
            })?;

            // Re-id each policy with the prefix to avoid collisions across sources.
            for (idx, policy) in parsed.policies().enumerate() {
                let new_id = PolicyId::new(format!("{id_prefix}_{idx}"));
                let policy_with_id = policy.new_id(new_id);
                combined
                    .add(policy_with_id)
                    .map_err(|e| PolicyError::Parse(format!("policy '{id_prefix}': {e}")))?;
            }
        }
        Ok(combined)
    }
}

impl PolicyEngine for CedarPolicyEngine {
    fn evaluate(
        &self,
        principal: &PolicyPrincipal,
        action: &str,
        resource: &PolicyResource,
        context: &PolicyContext,
    ) -> Result<PolicyDecision, PolicyError> {
        // Root bypass: if the principal is a root user, allow immediately
        // without Cedar evaluation. Root users have unrestricted access.
        if let PolicyPrincipal::User(user) = principal {
            if user.is_root {
                metrics::counter!("policy_evaluations_total", "decision" => "permit").increment(1);
                return Ok(PolicyDecision {
                    decision: PolicyDecisionResult::Permit,
                    reasons: vec!["root_bypass".to_string()],
                    errors: vec![],
                });
            }
        }

        // Build principal entity and UID based on principal type
        let (principal_uid, principal_entity) = match principal {
            PolicyPrincipal::Workspace(workspace) => {
                let entity = Self::build_workspace_entity(workspace)?;
                let uid = Self::workspace_uid(workspace);
                (uid, entity)
            }
            PolicyPrincipal::User(user) => {
                let entity = Self::build_user_entity(user)?;
                let uid = Self::user_uid(user);
                (uid, entity)
            }
            PolicyPrincipal::Server(server) => {
                let entity = Self::build_server_entity(server)?;
                let uid = Self::server_uid(server);
                (uid, entity)
            }
        };

        let (resource_uid, resource_entity) = Self::build_resource_entity(resource)?;

        let action_uid = Self::action_uid(action);

        let cedar_context = Self::build_context(action, context)?;

        // Assemble entity store
        let entities =
            Entities::from_entities(vec![principal_entity, resource_entity], Some(&self.schema))
                .map_err(|e| PolicyError::Evaluation(format!("entities: {e}")))?;

        // Build request
        let request = Request::new(
            principal_uid,
            action_uid,
            resource_uid,
            cedar_context,
            Some(&self.schema),
        )
        .map_err(|e| PolicyError::Evaluation(format!("request: {e}")))?;

        // Evaluate
        let authorizer = Authorizer::new();
        let policy_set = self
            .policy_set
            .read()
            .map_err(|e| PolicyError::Evaluation(format!("lock poisoned: {e}")))?;
        let response = authorizer.is_authorized(&request, &policy_set, &entities);

        // Map decision
        let decision = match response.decision() {
            Decision::Allow => {
                metrics::counter!("policy_evaluations_total", "decision" => "permit").increment(1);
                PolicyDecisionResult::Permit
            }
            Decision::Deny => {
                metrics::counter!("policy_evaluations_total", "decision" => "forbid").increment(1);
                PolicyDecisionResult::Forbid
            }
        };

        let diagnostics = response.diagnostics();
        let reasons: Vec<String> = diagnostics.reason().map(|pid| pid.to_string()).collect();
        let errors: Vec<String> = diagnostics.errors().map(|e| e.to_string()).collect();

        Ok(PolicyDecision {
            decision,
            reasons,
            errors,
        })
    }

    fn reload_policies(&self, policies: Vec<(String, String)>) -> Result<(), PolicyError> {
        // Parse all new policies first; if any fail, return error without
        // modifying the current set.
        let new_set = Self::parse_policies(
            &policies
                .iter()
                .map(|(id, src)| (id.clone(), src.clone()))
                .collect::<Vec<_>>(),
        )?;

        let mut ps = self
            .policy_set
            .write()
            .map_err(|e| PolicyError::Evaluation(format!("lock poisoned: {e}")))?;
        *ps = new_set;
        Ok(())
    }

    fn validate_policy_text(&self, cedar_source: &str) -> Result<(), PolicyError> {
        // Parse the policy text first (syntax check).
        let policy_set: PolicySet =
            cedar_source
                .parse()
                .map_err(|e: cedar_policy::ParseErrors| {
                    PolicyError::Parse(format!("syntax error: {e}"))
                })?;

        // Validate against the schema in strict mode.
        let result = self.validator.validate(&policy_set, ValidationMode::Strict);

        if !result.validation_passed() {
            let errors: Vec<String> = result.validation_errors().map(|e| format!("{e}")).collect();
            return Err(PolicyError::Validation(format!(
                "policy validation failed: {}",
                errors.join("; ")
            )));
        }

        Ok(())
    }

    fn validate_policy_text_detailed(
        &self,
        cedar_source: &str,
    ) -> Result<(), Vec<PolicyValidationError>> {
        // Parse the policy text first (syntax check).
        let policy_set: PolicySet = match cedar_source.parse() {
            Ok(ps) => ps,
            Err(e) => {
                let parse_errors: cedar_policy::ParseErrors = e;
                return Err(vec![PolicyValidationError {
                    message: format!("{parse_errors}"),
                    severity: "error".to_string(),
                    policy_index: None,
                }]);
            }
        };

        // Validate against the schema in strict mode.
        let result = self.validator.validate(&policy_set, ValidationMode::Strict);

        if !result.validation_passed() {
            let errors: Vec<PolicyValidationError> = result
                .validation_errors()
                .map(|e| PolicyValidationError {
                    message: format!("{e}"),
                    severity: "error".to_string(),
                    policy_index: None,
                })
                .collect();
            let warnings: Vec<PolicyValidationError> = result
                .validation_warnings()
                .map(|w| PolicyValidationError {
                    message: format!("{w}"),
                    severity: "warning".to_string(),
                    policy_index: None,
                })
                .collect();
            let mut all = errors;
            all.extend(warnings);
            if all.is_empty() {
                all.push(PolicyValidationError {
                    message: "policy validation failed".to_string(),
                    severity: "error".to_string(),
                    policy_index: None,
                });
            }
            return Err(all);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests;
