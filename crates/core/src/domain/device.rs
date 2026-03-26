// Device domain types — now re-exported from workspace.
//
// The Device entity has been unified into Workspace as part of v2.0.
// These re-exports maintain backward compatibility during migration.

pub use super::workspace::{
    Workspace as Device, WorkspaceId as DeviceId, WorkspaceId, WorkspaceStatus as DeviceStatus,
};
