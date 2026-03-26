use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::workspace::WorkspaceId;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentSessionStatus {
    Pending,
    Approved,
    Claimed,
    Expired,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentSession {
    pub id: Uuid,
    /// SHA-256 of the 256-bit session token (never store plaintext).
    #[serde(skip_serializing)]
    pub session_token_hash: String,
    /// Short reference for the approval URL (not the session token).
    pub approval_ref: String,
    /// Human-readable approval code (e.g. XKCD-7829).
    pub approval_code: String,
    pub agent_name: String,
    pub agent_description: Option<String>,
    pub agent_tags: Vec<String>,
    pub status: EnrollmentSessionStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub approved_by: Option<String>,
    pub approved_at: Option<DateTime<Utc>>,
    pub claimed_at: Option<DateTime<Utc>>,
    pub client_ip: Option<String>,
    pub claim_attempts: u32,
    /// The workspace that mediated this enrollment session (if any).
    pub workspace_id: Option<WorkspaceId>,
}
