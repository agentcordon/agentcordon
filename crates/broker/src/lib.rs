//! AgentCordon broker library.
//!
//! The binary in `main.rs` is a thin wrapper around [`daemon::run`]. Everything
//! else is exposed here so integration tests can build the router in-process
//! (see `tests/common/mod.rs`) without binding a socket or touching the
//! user's home directory.

pub mod auth;
pub mod config;
pub mod credential_transform;
pub mod daemon;
pub mod mcp_sync;
pub mod routes;
pub mod server_client;
pub mod state;
pub mod tls;
pub mod token_refresh;
pub mod token_store;
pub mod upstream;
pub mod vend;
