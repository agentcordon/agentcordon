use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::broker::BrokerClient;
use crate::commands::mcp_args::{
    build_arguments, build_error_envelope, classify_cli_error, filter_tools, resolve_args_json,
    ErrorKind,
};
use crate::error::CliError;

// --- MCP Servers ---

#[derive(Deserialize)]
struct McpServersResponse {
    data: Vec<McpServer>,
}

#[derive(Deserialize)]
struct McpServer {
    name: String,
    description: Option<String>,
    tools: Vec<String>,
    transport: String,
}

/// List available MCP servers, deduplicated by name.
///
/// Multiple workspaces may import the same server, so the server-side catalog
/// can contain duplicates. We deduplicate by keeping the first occurrence of
/// each server name.
pub async fn list_servers() -> Result<(), CliError> {
    let client = BrokerClient::connect().await?;
    let resp: McpServersResponse = client
        .post("/mcp/list-servers", &serde_json::json!({}))
        .await?;

    if resp.data.is_empty() {
        println!("No MCP servers available.");
        return Ok(());
    }

    // Deduplicate by server name (keep first occurrence)
    let mut seen = HashSet::new();
    let deduped: Vec<&McpServer> = resp.data.iter().filter(|s| seen.insert(&s.name)).collect();

    let name_w = deduped
        .iter()
        .map(|s| s.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let desc_w = deduped
        .iter()
        .map(|s| s.description.as_deref().unwrap_or("-").len())
        .max()
        .unwrap_or(11)
        .max(11);

    println!(
        "{:<name_w$}  {:<desc_w$}  TRANSPORT  TOOLS",
        "NAME", "DESCRIPTION"
    );

    for server in &deduped {
        let desc = server.description.as_deref().unwrap_or("-");
        let tools = server.tools.join(", ");
        println!(
            "{:<name_w$}  {:<desc_w$}  {:<9}  {tools}",
            server.name, desc, server.transport
        );
    }

    Ok(())
}

// --- MCP Tools ---

#[derive(Deserialize)]
struct McpToolsResponseRaw {
    data: Vec<serde_json::Value>,
}

/// List all available MCP tools.
///
/// When `schema` is set, emits the raw JSON-RPC `tools/list` response shape
/// (one object per tool, including `input_schema`) so an agent can introspect
/// before calling. Otherwise prints the existing human-readable table.
pub async fn list_tools(
    schema: bool,
    server: Option<String>,
    tool: Option<String>,
) -> Result<(), CliError> {
    let client = BrokerClient::connect().await?;
    let resp: McpToolsResponseRaw = client
        .post("/mcp/list-tools", &serde_json::json!({}))
        .await?;

    if schema {
        let filtered = filter_tools(&resp.data, server.as_deref(), tool.as_deref());
        let pretty = serde_json::to_string_pretty(&filtered)
            .map_err(|e| CliError::general(format!("failed to serialize schema: {e}")))?;
        println!("{pretty}");
        return Ok(());
    }

    if resp.data.is_empty() {
        println!("No MCP tools available.");
        return Ok(());
    }

    let entries: Vec<(String, String, String)> = resp
        .data
        .iter()
        .map(|t| {
            let s = t
                .get("server")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();
            let n = t
                .get("tool")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();
            let d = t
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_string();
            (s, n, d)
        })
        .collect();

    let server_w = entries
        .iter()
        .map(|(s, _, _)| s.len())
        .max()
        .unwrap_or(6)
        .max(6);
    let tool_w = entries
        .iter()
        .map(|(_, n, _)| n.len())
        .max()
        .unwrap_or(4)
        .max(4);

    println!("{:<server_w$}  {:<tool_w$}  DESCRIPTION", "SERVER", "TOOL");

    for (s, n, d) in &entries {
        println!("{:<server_w$}  {:<tool_w$}  {d}", s, n);
    }

    Ok(())
}

// --- MCP Call ---

#[derive(Serialize)]
struct McpCallRequest {
    server: String,
    tool: String,
    arguments: serde_json::Value,
}

#[derive(Deserialize)]
struct McpCallResponse {
    /// The `tools/call` result, kept whole: `--json` hands it back
    /// unchanged, and the default output is a projection of it. Reading it
    /// as a typed struct would silently drop every block type the struct
    /// does not name, which is how an embedded resource used to come back
    /// as an empty answer.
    data: serde_json::Value,
}

/// The tool's answer as text, and nothing else.
///
/// MCP content is a list of blocks. A `text` block is its text; an embedded
/// resource is the text inside it; a block that carries no text at all
/// (an image, a binary resource) is named rather than dropped, because a
/// silently empty answer reads as a broken tool. Anything unrecognised is
/// printed as itself.
fn flatten_content(content: &[serde_json::Value]) -> String {
    content
        .iter()
        .map(flatten_block)
        .collect::<Vec<_>>()
        .join("\n")
}

fn flatten_block(block: &serde_json::Value) -> String {
    let str_at = |path: &[&str]| -> Option<&str> {
        let mut cur = block;
        for key in path {
            cur = cur.get(key)?;
        }
        cur.as_str()
    };
    if let Some(text) = str_at(&["text"]).or_else(|| str_at(&["resource", "text"])) {
        return text.to_string();
    }
    let kind = str_at(&["type"]);
    match kind {
        Some("image") | Some("audio") => format!(
            "[{} {}]",
            kind.unwrap_or("blob"),
            str_at(&["mimeType"]).unwrap_or("?")
        ),
        Some("resource") | Some("resource_link") => format!(
            "[resource {}]",
            str_at(&["resource", "uri"])
                .or_else(|| str_at(&["uri"]))
                .unwrap_or("?")
        ),
        _ => serde_json::to_string(block).unwrap_or_default(),
    }
}

/// The whole result, on one line, for `--json`.
fn render_json(result: &serde_json::Value) -> String {
    serde_json::to_string(result).unwrap_or_else(|_| "null".to_string())
}

/// Failure of an `mcp-call` invocation, separated so the caller can distinguish
/// "the MCP tool itself returned an error" (tool_error) from everything else
/// (validation/transport/unauthorized) without string-matching.
enum CallFailure {
    Pre(CliError),
    Tool(String),
}

impl From<CliError> for CallFailure {
    fn from(e: CliError) -> Self {
        CallFailure::Pre(e)
    }
}

/// Call an MCP tool.
///
/// On any failure, prints the agent-facing JSON error envelope (issue #26) to
/// stdout before returning. The exit code is still non-zero; main() also writes
/// a human-readable `Error: ...` to stderr for interactive use.
pub async fn call(
    server: String,
    tool: String,
    args: Vec<String>,
    args_json: Option<String>,
    json_output: bool,
) -> Result<(), CliError> {
    let tool_name = tool.clone();
    match call_inner(server, tool, args, args_json, json_output).await {
        Ok(()) => Ok(()),
        Err(CallFailure::Pre(e)) => {
            emit_envelope(classify_cli_error(&e), &tool_name, &e.message);
            Err(e)
        }
        Err(CallFailure::Tool(msg)) => {
            emit_envelope(ErrorKind::ToolError, &tool_name, &msg);
            Err(CliError::upstream_error(msg))
        }
    }
}

fn emit_envelope(kind: ErrorKind, tool: &str, message: &str) {
    let env = build_error_envelope(kind, Some(tool), message, None);
    println!("{}", serde_json::to_string_pretty(&env).unwrap());
}

async fn call_inner(
    server: String,
    tool: String,
    args: Vec<String>,
    args_json: Option<String>,
    json_output: bool,
) -> Result<(), CallFailure> {
    let client = BrokerClient::connect().await?;

    let args_json_value = match args_json.as_deref() {
        Some(spec) => Some(resolve_args_json(spec, &mut std::io::stdin().lock())?),
        None => None,
    };
    let arguments = build_arguments(args_json_value, &args)?;

    let req = McpCallRequest {
        server,
        tool,
        arguments,
    };

    let resp: McpCallResponse = client
        .post("/mcp/call", &req)
        .await
        .map_err(CallFailure::Pre)?;

    let result = resp.data;
    let content = result
        .get("content")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();
    let body = flatten_content(&content);
    let is_error = result
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);

    if is_error {
        let detail = if body.is_empty() {
            "MCP tool returned an error result".to_string()
        } else {
            body
        };
        return Err(CallFailure::Tool(detail));
    }

    if json_output {
        println!("{}", render_json(&result));
    } else if !body.is_empty() {
        println!("{body}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocks(v: serde_json::Value) -> Vec<serde_json::Value> {
        v.as_array().expect("array").clone()
    }

    /// The default output is the tool's text and nothing else — no envelope,
    /// no block types, no quoting.
    #[test]
    fn text_blocks_are_flattened_to_their_text() {
        let content = blocks(serde_json::json!([
            {"type": "text", "text": "first"},
            {"type": "text", "text": "second"},
        ]));
        assert_eq!(flatten_content(&content), "first\nsecond");
    }

    /// An embedded resource carries its text in a nested object; an agent
    /// that asked for the tool's answer should get the answer, not the
    /// wrapper.
    #[test]
    fn an_embedded_text_resource_is_flattened_to_its_text() {
        let content = blocks(serde_json::json!([
            {"type": "resource", "resource": {"uri": "file:///a.txt", "text": "inside"}},
        ]));
        assert_eq!(flatten_content(&content), "inside");
    }

    /// A block with no text at all is named rather than dropped: a silent
    /// empty answer reads as a broken tool.
    #[test]
    fn a_block_with_no_text_is_named_by_its_type_and_uri() {
        let content = blocks(serde_json::json!([
            {"type": "image", "mimeType": "image/png", "data": "iVBOR"},
            {"type": "resource", "resource": {"uri": "file:///b.bin", "blob": "AAAA"}},
        ]));
        assert_eq!(
            flatten_content(&content),
            "[image image/png]\n[resource file:///b.bin]"
        );
    }

    /// An unknown block type is still reported, as itself.
    #[test]
    fn an_unknown_block_falls_back_to_its_json() {
        let content = blocks(serde_json::json!([{"type": "future", "shape": 1}]));
        assert_eq!(flatten_content(&content), r#"{"type":"future","shape":1}"#);
    }

    /// `--json` is the whole result, unflattened, on one line.
    #[test]
    fn json_output_is_the_whole_result_compact() {
        let result = serde_json::json!({
            "content": [{"type": "text", "text": "hi"}],
            "isError": false,
        });
        let rendered = render_json(&result);
        assert_eq!(rendered.lines().count(), 1, "{rendered}");
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["content"][0]["text"], "hi");
        assert_eq!(parsed["isError"], false);
    }
}
