//! The tools `mcp-serve` publishes: the six fixed ones, and the naming rule
//! for an opt-in re-export.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub(crate) const STATUS: &str = "agentcordon_status";
pub(crate) const CREDENTIALS: &str = "agentcordon_credentials";
pub(crate) const PROXY: &str = "agentcordon_proxy";
pub(crate) const MCP_SERVERS: &str = "agentcordon_mcp_servers";
pub(crate) const MCP_TOOLS: &str = "agentcordon_mcp_tools";
pub(crate) const MCP_CALL: &str = "agentcordon_mcp_call";

/// An MCP client loads every tool's name, description and schema into the
/// model's context at session start, so this list is the whole per-session
/// cost of the integration — about 800 tokens, the same for a workspace with
/// one upstream MCP server and one with twenty. That is why the brokered
/// tools are reached *through* `agentcordon_mcp_tools` and
/// `agentcordon_mcp_call` rather than re-exported by default (issue #54's
/// amendment); `--expose` is the opt-out from the opt-out.
pub(crate) fn fixed_tools() -> Vec<Value> {
    vec![
        tool(
            STATUS,
            "Report this workspace's AgentCordon status: the broker it is talking to, the \
             workspace identity, whether it is registered, its scopes and its token. Run this \
             first when an AgentCordon call fails.",
            no_arguments(),
        ),
        tool(
            CREDENTIALS,
            "List the credentials this workspace may use, as JSON: name, service, \
             credential_type, allowed_url_pattern (the URL fence) and expires_at. The secret \
             values are never returned — the broker injects them.",
            no_arguments(),
        ),
        tool(
            PROXY,
            "Make an authenticated HTTP call. The broker injects the credential, so this tool \
             never returns or receives a secret. Omit `credential` to use the one whose URL \
             fence covers `url`; naming one is only needed when several fences cover it. \
             Returns {status, headers, body}.",
            json!({
                "type": "object",
                "properties": {
                    "credential": {
                        "type": "string",
                        "description": "Credential name. Omit to select by URL fence.",
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method, e.g. GET or POST.",
                    },
                    "url": {
                        "type": "string",
                        "description": "Absolute target URL.",
                    },
                    "headers": {
                        "type": "object",
                        "description": "Extra request headers.",
                        "additionalProperties": { "type": "string" },
                    },
                    "body": {
                        "type": "string",
                        "description": "Request body, sent verbatim.",
                    },
                },
                "required": ["method", "url"],
            }),
        ),
        tool(
            MCP_SERVERS,
            "List the MCP servers this workspace may call through the broker. They are not \
             interchangeable: each fronts one upstream with its own credential and its own \
             tools.",
            no_arguments(),
        ),
        tool(
            MCP_TOOLS,
            "List one MCP server's tools, with each tool's inputSchema. Read a tool's schema \
             before calling it rather than guessing argument names.",
            json!({
                "type": "object",
                "properties": {
                    "server": {
                        "type": "string",
                        "description": "MCP server name, from agentcordon_mcp_servers.",
                    },
                },
                "required": ["server"],
            }),
        ),
        tool(
            MCP_CALL,
            "Call one tool on one MCP server through the broker, which authorizes the call and \
             injects the upstream credential. Returns the tool's own result.",
            json!({
                "type": "object",
                "properties": {
                    "server": {
                        "type": "string",
                        "description": "MCP server name, from agentcordon_mcp_servers.",
                    },
                    "tool": {
                        "type": "string",
                        "description": "Tool name, from agentcordon_mcp_tools.",
                    },
                    "arguments": {
                        "type": "object",
                        "description": "The tool's arguments, per its inputSchema.",
                    },
                },
                "required": ["server", "tool"],
            }),
        ),
    ]
}

fn tool(name: &str, description: &str, input_schema: Value) -> Value {
    json!({ "name": name, "description": description, "inputSchema": input_schema })
}

/// The schema for a tool that takes nothing. Spelled out rather than
/// omitted: a client that validates arguments needs an object schema to
/// validate against.
fn no_arguments() -> Value {
    json!({ "type": "object", "properties": {}, "additionalProperties": false })
}

/// The longest a re-exported tool name may be.
const MAX_NAME: usize = 64;

/// How many characters the collision suffix takes, including its `_`.
const SUFFIX_LEN: usize = 7;

/// One upstream tool, re-exported under `--expose`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Exposed {
    /// The name this server publishes it under.
    pub(crate) name: String,
    pub(crate) server: String,
    pub(crate) tool: String,
    pub(crate) description: Option<String>,
    pub(crate) input_schema: Option<Value>,
}

impl Exposed {
    /// The MCP tool object, with the upstream `inputSchema` verbatim.
    pub(crate) fn to_tool(&self) -> Value {
        let described = format!(
            "[{}] {}",
            self.server,
            self.description.as_deref().unwrap_or("")
        );
        json!({
            "name": self.name,
            "description": described.trim_end(),
            "inputSchema": self
                .input_schema
                .clone()
                .unwrap_or_else(|| json!({ "type": "object" })),
        })
    }
}

/// Name every re-exported tool `<server>__<tool>`, sanitised to
/// `[a-z0-9_]` and capped at 64 characters.
///
/// Two upstream names can collide once sanitised and truncated
/// (`search-code` and `search.code`; two long names sharing a prefix), and a
/// client keys its permissions by tool name, so a collision must not let one
/// tool answer for another. Every member of a colliding group takes a suffix
/// derived from its own `server/tool` — not its position in the list — so the
/// name a tool gets is the same on every refresh, whatever order the broker
/// listed them in.
pub(crate) fn name_exposed(
    entries: Vec<(String, String, Option<String>, Option<Value>)>,
) -> Vec<Exposed> {
    let bases: Vec<String> = entries
        .iter()
        .map(|(server, tool, _, _)| base_name(server, tool))
        .collect();

    entries
        .into_iter()
        .zip(bases.iter())
        .map(|((server, tool, description, input_schema), base)| {
            let collides = bases.iter().filter(|b| *b == base).count() > 1;
            let name = if collides {
                format!(
                    "{}_{}",
                    truncate(base, MAX_NAME - SUFFIX_LEN),
                    digest(&server, &tool)
                )
            } else {
                base.clone()
            };
            Exposed {
                name,
                server,
                tool,
                description,
                input_schema,
            }
        })
        .collect()
}

fn base_name(server: &str, tool: &str) -> String {
    truncate(
        &format!("{}__{}", sanitise(server), sanitise(tool)),
        MAX_NAME,
    )
}

/// Lowercase, with everything outside `[a-z0-9_]` replaced by `_` — replaced
/// rather than dropped, so `create-issue` and `createissue` stay different
/// names.
fn sanitise(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn truncate(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Six hex characters of SHA-256 over the pair, which is what makes the
/// suffix stable across refreshes and independent of listing order.
fn digest(server: &str, tool: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(server.as_bytes());
    hasher.update(b"/");
    hasher.update(tool.as_bytes());
    hex::encode(hasher.finalize())[..6].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(server: &str, tool: &str) -> (String, String, Option<String>, Option<Value>) {
        (server.into(), tool.into(), None, None)
    }

    #[test]
    fn the_fixed_surface_is_six_tools() {
        let published = fixed_tools();
        let names: Vec<&str> = published
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [STATUS, CREDENTIALS, PROXY, MCP_SERVERS, MCP_TOOLS, MCP_CALL]
        );
    }

    #[test]
    fn an_exposed_tool_is_server_then_tool() {
        let named = name_exposed(vec![entry("github", "create_issue")]);
        assert_eq!(named[0].name, "github__create_issue");
    }

    /// A name a client would refuse — an upstream is free to use hyphens,
    /// dots and capitals — is mapped into `[a-z0-9_]`.
    #[test]
    fn characters_outside_the_allowed_set_become_underscores() {
        let named = name_exposed(vec![entry("My-Server.1", "search code!")]);
        assert_eq!(named[0].name, "my_server_1__search_code_");
        assert!(named[0]
            .name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'));
    }

    #[test]
    fn a_long_name_is_capped_at_sixty_four_characters() {
        let named = name_exposed(vec![entry(&"s".repeat(40), &"t".repeat(40))]);
        assert_eq!(named[0].name.len(), MAX_NAME);
    }

    /// Two upstream names that sanitise to the same string must not become
    /// one tool: a client keys its permissions by name.
    #[test]
    fn colliding_names_are_disambiguated() {
        let named = name_exposed(vec![entry("gh", "search-code"), entry("gh", "search.code")]);
        assert_ne!(named[0].name, named[1].name);
        assert!(named[0].name.starts_with("gh__search_code_"), "{named:?}");
        assert!(named.iter().all(|e| e.name.len() <= MAX_NAME));
    }

    /// The suffix comes from the pair, not its position, so a refresh that
    /// lists the same tools in another order publishes the same names.
    #[test]
    fn the_disambiguated_name_does_not_depend_on_listing_order() {
        let forwards = name_exposed(vec![entry("gh", "a-b"), entry("gh", "a.b")]);
        let backwards = name_exposed(vec![entry("gh", "a.b"), entry("gh", "a-b")]);
        assert_eq!(forwards[0].name, backwards[1].name);
        assert_eq!(forwards[1].name, backwards[0].name);
    }

    /// The description says which server the tool belongs to, because two
    /// servers' `search` tools are not the same tool.
    #[test]
    fn the_description_is_prefixed_with_the_server() {
        let named = name_exposed(vec![(
            "github".into(),
            "create_issue".into(),
            Some("Create an issue".into()),
            Some(json!({"type": "object", "properties": {"repo": {"type": "string"}}})),
        )]);
        let tool = named[0].to_tool();
        assert_eq!(tool["description"], "[github] Create an issue");
        assert_eq!(
            tool["inputSchema"],
            json!({"type": "object", "properties": {"repo": {"type": "string"}}}),
            "the upstream schema is passed through verbatim"
        );
    }

    /// An upstream that publishes no schema still gets a usable one: a
    /// client that cannot parse `inputSchema` drops the tool entirely.
    #[test]
    fn a_tool_without_a_schema_still_declares_an_object() {
        let named = name_exposed(vec![entry("s", "t")]);
        assert_eq!(named[0].to_tool()["inputSchema"], json!({"type": "object"}));
    }
}
