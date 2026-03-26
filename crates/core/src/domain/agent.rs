// Agent domain types — now re-exported from workspace.
//
// The Agent entity has been unified into Workspace as part of v2.0.
// These re-exports maintain backward compatibility during migration.

pub use super::workspace::{
    Workspace as Agent, WorkspaceId as AgentId, WorkspaceId, WorkspaceStatus as AgentStatus,
};
