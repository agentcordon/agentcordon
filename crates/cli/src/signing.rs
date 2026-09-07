//! Workspace key access for the CLI.
//!
//! The key format, permission policy, and signing payloads live in
//! `agentcordon-identity` (shared with the broker). This module only
//! resolves where the key directory is and maps the crate's errors onto
//! `CliError` with the messages users have always seen.

use std::path::PathBuf;

use agentcordon_identity::{KeyFileError, SignedHeaders, WorkspaceKey, WORKSPACE_DIR_NAME};

use crate::error::CliError;

/// Resolve the `.agentcordon/` directory from `AGTCRDN_WORKSPACE_DIR` or cwd.
pub fn workspace_dir() -> PathBuf {
    let base = std::env::var("AGTCRDN_WORKSPACE_DIR").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(base).join(WORKSPACE_DIR_NAME)
}

/// Load the Ed25519 keypair from `.agentcordon/`, enforcing file permissions.
pub fn load_keypair() -> Result<WorkspaceKey, CliError> {
    agentcordon_identity::load_workspace_key(&workspace_dir()).map_err(|e| match e {
        KeyFileError::NotFound { .. } => {
            CliError::general("no keypair found. Run: agentcordon init")
        }
        other => CliError::general(other.to_string()),
    })
}

/// Sign a broker request with the current time.
///
/// `path` MUST already be in the canonical path-and-query form produced by
/// [`agentcordon_identity::canonicalise_path_and_query`]; callers in
/// `broker.rs` apply it before invoking this. The broker verifier
/// reconstructs the same canonical form from the incoming `Uri`, so
/// signatures round-trip.
pub fn sign_request(
    key: &WorkspaceKey,
    method: &str,
    path: &str,
    body: &str,
) -> Result<SignedHeaders, CliError> {
    agentcordon_identity::sign_request(key, method, path, body.as_bytes())
        .map_err(|e| CliError::general(format!("system clock error: {e}")))
}
