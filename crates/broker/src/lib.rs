// AgentCordon — credential brokering and policy enforcement for AI agents.
// Copyright (C) 2026 The AgentCordon Authors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero
// General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

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
