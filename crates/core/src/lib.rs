pub mod auth;
pub mod crypto;
pub mod domain;
pub mod error;
#[cfg(feature = "http-client")]
pub mod oauth2;
pub mod policy;
pub mod proxy;
pub mod storage;
#[cfg(feature = "transforms")]
pub mod transform;
pub mod wire;

/// How the AgentCordon control plane identifies itself on every outbound
/// request: token exchanges, OAuth and MCP discovery, OIDC.
///
/// One constant, carrying the running build's version, because a provider
/// that rate-limits or logs by user agent must be able to tell which
/// AgentCordon it is talking to. The version is the workspace version every
/// crate here shares, so the server and this crate cannot disagree.
pub const USER_AGENT: &str = concat!("AgentCordon/", env!("CARGO_PKG_VERSION"));

/// [`USER_AGENT`] with a component tag, for a client whose calls are worth
/// telling apart in a provider's log — `AgentCordon/0.4.0 (oauth-discovery)`.
pub fn user_agent_for(component: &str) -> String {
    format!("{USER_AGENT} ({component})")
}
