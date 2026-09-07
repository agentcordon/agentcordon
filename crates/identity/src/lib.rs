//! Workspace identity for AgentCordon: the one place the CLI and the broker
//! agree on what a workspace key looks like on disk, how it is named, and
//! exactly which bytes are signed.
//!
//! Scope is deliberately narrow — Ed25519, SHA-256, hex, and the file
//! system. No HTTP, no async, no clock beyond reading the current time for
//! [`sign_request`]. Anything that needs a network or a database lives in
//! the crate that owns it.
//!
//! What lives here:
//!
//! - [`WorkspaceKey`]: the Ed25519 key, its hex public key, its `pk_hash`
//!   (SHA-256 of the raw 32-byte public key, lowercase hex) and the
//!   `sha256:<hex>` identity string.
//! - [`load_workspace_key`] / [`create_workspace_key`]: the on-disk format
//!   (`workspace.key` = hex seed, `workspace.pub` = hex public key) and the
//!   permission policy (`0700` directory, `0600` private key).
//! - [`canonicalise_path_and_query`]: the path form both sides sign.
//! - [`signing_payload`], [`sign_request`], [`verify_request`]: the
//!   `METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY` request signature.
//! - [`register_payload`], [`sign_register`], [`verify_register`]: the
//!   self-signature on `agentcordon register`, over
//!   `NAME\nPUBLIC_KEY\nSCOPES\nTIMESTAMP\nNONCE`.
//! - [`generate_nonce`] / [`validate_nonce`]: the 16-byte hex nonce both
//!   payloads carry. Replay detection needs state and lives in the broker.
//!
//! `tests/vectors.rs` freezes every one of these as literals.

mod canonical;
mod key;
mod keyfile;
mod register;
mod request;

pub use canonical::canonicalise_path_and_query;
pub use key::{identity_string, pk_hash_from_hex, pk_hash_of, WorkspaceKey, IDENTITY_PREFIX};
pub use keyfile::{
    create_workspace_key, load_workspace_key, read_public_key_hex, workspace_key_exists,
    KeyFileError, DIR_MODE, KEY_FILE_NAME, KEY_MODE, PUB_FILE_NAME, PUB_MODE, WORKSPACE_DIR_NAME,
};
pub use register::{
    register_payload, sign_register, sign_register_at, verify_register, RegisterPayload,
};
pub use request::{
    generate_nonce, sign_request, sign_request_at, sign_request_with, signing_payload,
    validate_nonce, verify_request, SignedHeaders, VerifyError, MAX_CLOCK_SKEW_SECS, NONCE_HEX_LEN,
};
