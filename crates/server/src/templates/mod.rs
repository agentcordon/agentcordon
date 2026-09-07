//! Template catalogs: the credential, MCP server, and policy templates an
//! operator can pick from. Pure data plus loaders; no HTTP here.

mod credential;
mod mcp;
mod policy;

pub use credential::{
    load_credential_templates, ClientSubstitution, CredentialTemplate, FieldSpec,
};
pub use mcp::{
    load_mcp_templates, load_mcp_templates_reporting, McpServerTemplate, McpTemplateLoad,
    TemplateDirLoad, TemplateFileProblems,
};
pub use policy::{load_policy_templates, PolicyTemplate};
