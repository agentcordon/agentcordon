use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyId(pub Uuid);

#[derive(Debug, Clone, Serialize)]
pub struct StoredPolicy {
    pub id: PolicyId,
    pub name: String,
    pub description: Option<String>,
    pub cedar_policy: String,
    pub enabled: bool,
    pub is_system: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub description: Option<String>,
    pub cedar_policy: String,
}

#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub decision: PolicyDecisionResult,
    pub reasons: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecisionResult {
    Permit,
    Forbid,
}

/// A structured validation error from Cedar policy validation.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyValidationError {
    pub message: String,
    pub severity: String,
    pub policy_index: Option<usize>,
}
