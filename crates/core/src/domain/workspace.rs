use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use uuid::Uuid;

use super::user::UserId;

/// Unique identifier for a workspace.
///
/// This is the unified identity type that replaces the former AgentId,
/// DeviceId, and WorkspaceIdentityId. Every autonomous entity in the
/// system is a Workspace.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkspaceId(pub Uuid);

/// Status of a workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceStatus {
    /// Registered but not yet approved.
    Pending,
    /// May authenticate and act.
    Active,
    /// Switched off by an operator; may be switched back on.
    Disabled,
    /// Final. A revoked identity never comes back; register a new key.
    Revoked,
}

impl WorkspaceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            WorkspaceStatus::Pending => "pending",
            WorkspaceStatus::Active => "active",
            WorkspaceStatus::Disabled => "disabled",
            WorkspaceStatus::Revoked => "revoked",
        }
    }
}

impl FromStr for WorkspaceStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(WorkspaceStatus::Pending),
            "active" => Ok(WorkspaceStatus::Active),
            "disabled" => Ok(WorkspaceStatus::Disabled),
            "revoked" => Ok(WorkspaceStatus::Revoked),
            _ => Err(()),
        }
    }
}

/// A lifecycle transition the workspace's current status does not allow.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("workspace is {from}; cannot {action}")]
pub struct WorkspaceTransitionError {
    pub from: WorkspaceStatus,
    pub action: &'static str,
}

impl std::fmt::Display for WorkspaceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A unified workspace entity.
///
/// Replaces the former Agent, Device, and WorkspaceIdentity types.
/// Every autonomous entity (CLI agent, device proxy, CI runner, etc.)
/// is represented as a Workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub name: String,
    /// The one lifecycle field. Change it through the transition methods so
    /// the rules (revocation is final, pending needs approval) hold everywhere.
    pub status: WorkspaceStatus,
    /// SHA-256 hex digest of the raw 32-byte Ed25519 public key.
    pub pk_hash: Option<String>,
    /// P-256 encryption public key (JWK format) for ECIES credential vending.
    pub encryption_public_key: Option<String>,
    pub tags: Vec<String>,
    /// The user who owns this workspace.
    pub owner_id: Option<UserId>,
    /// For future sub-workspace delegation.
    pub parent_id: Option<WorkspaceId>,
    /// Informational: "claude-code", "cursor", etc.
    pub tool_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Workspace {
    /// Whether the workspace may authenticate and act right now.
    pub fn is_active(&self) -> bool {
        self.status == WorkspaceStatus::Active
    }

    fn transition(
        &mut self,
        action: &'static str,
        allowed_from: &[WorkspaceStatus],
        to: WorkspaceStatus,
    ) -> Result<(), WorkspaceTransitionError> {
        if self.status == to {
            return Ok(());
        }
        if !allowed_from.contains(&self.status) {
            return Err(WorkspaceTransitionError {
                from: self.status.clone(),
                action,
            });
        }
        self.status = to;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Pending → Active. Approval of a registration.
    pub fn activate(&mut self) -> Result<(), WorkspaceTransitionError> {
        if self.status == WorkspaceStatus::Active {
            return Err(WorkspaceTransitionError {
                from: self.status.clone(),
                action: "activate",
            });
        }
        self.transition(
            "activate",
            &[WorkspaceStatus::Pending],
            WorkspaceStatus::Active,
        )
    }

    /// Disabled → Active. Idempotent when already active.
    pub fn enable(&mut self) -> Result<(), WorkspaceTransitionError> {
        self.transition(
            "enable",
            &[WorkspaceStatus::Disabled],
            WorkspaceStatus::Active,
        )
    }

    /// Active → Disabled. Idempotent when already disabled.
    pub fn disable(&mut self) -> Result<(), WorkspaceTransitionError> {
        self.transition(
            "disable",
            &[WorkspaceStatus::Active],
            WorkspaceStatus::Disabled,
        )
    }

    /// Any non-revoked status → Revoked. Final; revoking twice is an error
    /// so a caller notices it is acting on a dead identity.
    pub fn revoke(&mut self) -> Result<(), WorkspaceTransitionError> {
        if self.status == WorkspaceStatus::Revoked {
            return Err(WorkspaceTransitionError {
                from: self.status.clone(),
                action: "revoke",
            });
        }
        self.transition(
            "revoke",
            &[
                WorkspaceStatus::Pending,
                WorkspaceStatus::Active,
                WorkspaceStatus::Disabled,
            ],
            WorkspaceStatus::Revoked,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- WorkspaceStatus roundtrip ---

    #[test]
    fn test_workspace_status_roundtrip() {
        for status in &[
            WorkspaceStatus::Pending,
            WorkspaceStatus::Active,
            WorkspaceStatus::Revoked,
        ] {
            let s = status.as_str();
            let parsed = WorkspaceStatus::from_str(s);
            assert_eq!(
                parsed.as_ref(),
                Ok(status),
                "roundtrip failed for {:?}",
                status
            );
        }
    }

    #[test]
    fn test_workspace_status_from_str_unknown_returns_err() {
        assert!(WorkspaceStatus::from_str("unknown").is_err());
        assert!(WorkspaceStatus::from_str("").is_err());
        assert!(
            WorkspaceStatus::from_str("Active").is_err(),
            "mixed case should not match"
        );
        assert!(
            WorkspaceStatus::from_str("PENDING").is_err(),
            "uppercase should not match"
        );
    }

    // --- Backward compatibility type aliases ---

    #[test]
    fn test_backward_compat_agent_alias() {
        // Verify that domain::agent::Agent is the same type as Workspace
        fn accepts_workspace(_w: &Workspace) {}
        let agent: crate::domain::agent::Agent = crate::domain::agent::Agent {
            id: WorkspaceId(Uuid::new_v4()),
            name: "test".to_string(),
            status: WorkspaceStatus::Active,
            pk_hash: None,
            encryption_public_key: None,
            tags: vec![],
            owner_id: None,
            parent_id: None,
            tool_name: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        accepts_workspace(&agent);
    }

    #[test]
    fn test_backward_compat_device_alias() {
        // Verify that domain::device::Device is the same type as Workspace
        fn accepts_workspace(_w: &Workspace) {}
        let device: crate::domain::device::Device = crate::domain::device::Device {
            id: WorkspaceId(Uuid::new_v4()),
            name: "test-device".to_string(),
            status: WorkspaceStatus::Active,
            pk_hash: None,
            encryption_public_key: None,
            tags: vec![],
            owner_id: None,
            parent_id: None,
            tool_name: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        accepts_workspace(&device);
    }

    // --- Lifecycle transitions ---

    fn active_workspace() -> Workspace {
        Workspace {
            id: WorkspaceId(Uuid::new_v4()),
            name: "ws".to_string(),
            status: WorkspaceStatus::Active,
            pk_hash: None,
            encryption_public_key: None,
            tags: vec![],
            owner_id: None,
            parent_id: None,
            tool_name: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn disable_and_enable_round_trip() {
        let mut ws = active_workspace();
        assert!(ws.is_active());
        ws.disable().expect("active -> disabled");
        assert_eq!(ws.status, WorkspaceStatus::Disabled);
        assert!(!ws.is_active());
        ws.enable().expect("disabled -> active");
        assert!(ws.is_active());
    }

    #[test]
    fn enable_and_disable_are_idempotent() {
        let mut ws = active_workspace();
        ws.enable().expect("already active");
        ws.disable().expect("active -> disabled");
        ws.disable().expect("already disabled");
    }

    #[test]
    fn revoke_is_final() {
        let mut ws = active_workspace();
        ws.revoke().expect("active -> revoked");
        assert_eq!(ws.status, WorkspaceStatus::Revoked);
        assert!(ws.enable().is_err(), "revoked stays revoked");
        assert!(ws.disable().is_err(), "revoked stays revoked");
        assert!(ws.revoke().is_err(), "already revoked");
    }

    #[test]
    fn pending_is_activated_not_enabled() {
        let mut ws = active_workspace();
        ws.status = WorkspaceStatus::Pending;
        assert!(ws.enable().is_err(), "pending must go through activation");
        assert!(ws.disable().is_err());
        ws.activate().expect("pending -> active");
        assert!(ws.is_active());
        assert!(ws.activate().is_err(), "only pending activates");
    }

    #[test]
    fn disabled_parses_and_prints() {
        assert_eq!(
            "disabled".parse::<WorkspaceStatus>(),
            Ok(WorkspaceStatus::Disabled)
        );
        assert_eq!(WorkspaceStatus::Disabled.as_str(), "disabled");
    }
}
