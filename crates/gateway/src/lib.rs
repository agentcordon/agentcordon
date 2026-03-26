//! AgentCordon Gateway — library interface for integration tests.
//!
//! Re-exports public modules so that `crates/gateway/tests/*.rs` can
//! reference types, traits, and helpers defined in the gateway binary.

#![allow(dead_code, clippy::too_many_arguments)]

pub mod audit;
pub mod cp_client;
pub mod credential_transform;
pub mod http_mcp;
pub mod identity;
pub mod mcp_sync;
pub mod stdio;
pub mod vend;

/// CLI workspace state — re-exported for integration tests.
///
/// Points directly at `cli/state.rs` without pulling in the full `cli`
/// module (which depends on binary-only types like `clap::Subcommand`).
#[path = "cli/state.rs"]
pub mod cli_state;
