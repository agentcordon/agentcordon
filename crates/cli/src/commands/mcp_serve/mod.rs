//! `agentcordon mcp-serve` — the CLI's own MCP server, over stdio.
//!
//! A runtime that speaks MCP gets AgentCordon as **native tools** instead of
//! prose telling it to shell out (ADR-0013 tier 3). The surface lives here,
//! in the CLI, and not on the broker: every broker route requires a request
//! signed with the workspace key (ADR-0008), which a runtime's MCP client
//! cannot produce, so an HTTP MCP endpoint on the broker would need a bearer
//! secret held by the runtime — the class of secret ADR-0006 keeps out of an
//! agent's hands. The CLI already holds the key and the `BrokerClient`, so
//! every tool here is the same signed call the matching command makes.
//!
//! Transport: stdio, newline-delimited JSON-RPC 2.0 (MCP 2025-06-18). stdout
//! carries JSON-RPC and nothing else; everything else this process wants to
//! say goes to stderr.

mod protocol;
mod tools;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use crate::broker::BrokerClient;
use crate::commands::{credentials, mcp, proxy, status};
use crate::error::{CliError, ExitCode};
use crate::signing;

/// What `agentcordon mcp-serve` was asked to publish.
pub struct ServeArgs {
    /// `--expose <server>`, repeatable: re-export this server's tools as
    /// `<server>__<tool>`.
    pub expose: Vec<String>,
}

/// Serve MCP over stdin/stdout until stdin closes.
pub async fn run(args: ServeArgs) -> Result<(), CliError> {
    Server::new(args.expose).serve().await
}

struct Server {
    /// Servers named by `--expose`, in the order given.
    expose: Vec<String>,
    /// The broker connection, made on the first tool call that needs one and
    /// kept for the session. `initialize` and a `tools/list` with no
    /// `--expose` never touch it.
    client: Option<BrokerClient>,
    out: tokio::io::Stdout,
}

/// Why a tool call produced no result.
enum ToolFailure {
    /// The request itself was wrong — an unknown tool, a missing argument —
    /// so it comes back as a JSON-RPC error.
    Protocol(String),
    /// The call was well-formed and did not succeed. That is a *result* with
    /// `isError`, in the CLI's own words: a broker refusal is an answer, and
    /// a session that saw it as a protocol failure would have nothing to
    /// tell the model.
    Failed(String),
}

impl From<CliError> for ToolFailure {
    fn from(e: CliError) -> Self {
        ToolFailure::Failed(e.message)
    }
}

impl Server {
    fn new(expose: Vec<String>) -> Self {
        Self {
            expose,
            client: None,
            out: tokio::io::stdout(),
        }
    }

    /// The read loop. Requests are served one at a time, in arrival order:
    /// an agent's tool calls are sequential by construction, and one task
    /// writing to stdout is what keeps two messages from interleaving on a
    /// line-delimited channel.
    async fn serve(&mut self) -> Result<(), CliError> {
        let (tx, mut rx) = mpsc::channel::<String>(16);
        tokio::spawn(async move {
            let mut stdin = BufReader::new(tokio::io::stdin()).lines();
            while let Ok(Some(line)) = stdin.next_line().await {
                if tx.send(line).await.is_err() {
                    return;
                }
            }
            // Stdin closed: the sender drops with this task, which is what
            // ends the read loop and the process.
        });

        while let Some(line) = rx.recv().await {
            self.handle_line(&line).await;
        }
        Ok(())
    }

    async fn handle_line(&mut self, line: &str) {
        let incoming = match protocol::decode(line) {
            Ok(incoming) => incoming,
            Err(Some(response)) => return self.write(&response).await,
            Err(None) => return,
        };

        match incoming {
            protocol::Incoming::Request { id, method, params } => {
                let response = match self.dispatch(&method, params).await {
                    Ok(result) => protocol::result(id, result),
                    Err((code, message)) => protocol::error(id, code, message),
                };
                self.write(&response).await;
            }
            // `notifications/initialized` and the rest are acknowledged by
            // not answering them, which is what a notification means.
            protocol::Incoming::Notification { method } => {
                tracing::debug!(%method, "notification");
            }
        }
    }

    /// Answer one request, or say why not. `Err` is a JSON-RPC protocol
    /// error: the request itself was wrong. A call that reached the broker
    /// and failed is a *result* with `isError`, not this.
    async fn dispatch(&mut self, method: &str, params: Value) -> Result<Value, (i64, String)> {
        match method {
            "initialize" => Ok(self.initialize(&params)),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": self.tool_list().await })),
            "tools/call" => self.call_tool(&params).await,
            other => Err((
                protocol::METHOD_NOT_FOUND,
                format!("Method not found: {other}"),
            )),
        }
    }

    /// `initialize` never touches the broker: a runtime starts its MCP
    /// servers when the session opens, which is routinely before any broker
    /// is running, and a session that cannot even describe itself is worse
    /// than one whose tools fail when called.
    fn initialize(&self, params: &Value) -> Value {
        let requested = params.get("protocolVersion").and_then(Value::as_str);
        json!({
            "protocolVersion": protocol::negotiated_version(requested),
            "capabilities": { "tools": { "listChanged": true } },
            "serverInfo": {
                "name": "agentcordon",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "instructions": instructions(),
        })
    }

    /// The tools this session publishes.
    async fn tool_list(&mut self) -> Vec<Value> {
        tools::fixed_tools()
    }

    async fn call_tool(&mut self, params: &Value) -> Result<Value, (i64, String)> {
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return Err((
                protocol::INVALID_PARAMS,
                "tools/call requires a tool name".to_string(),
            ));
        };
        let name = name.to_string();
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));

        match self.run_tool(&name, &arguments).await {
            Ok(result) => Ok(result),
            Err(ToolFailure::Protocol(message)) => Err((protocol::INVALID_PARAMS, message)),
            Err(ToolFailure::Failed(message)) => Ok(failed(message)),
        }
    }

    /// Run one tool. Every branch is the same signed broker call the
    /// matching CLI command makes, through the same function.
    async fn run_tool(&mut self, name: &str, args: &Value) -> Result<Value, ToolFailure> {
        match name {
            tools::STATUS => {
                let client = self.broker().await?;
                Ok(answered(status::report(client).await?))
            }
            tools::CREDENTIALS => {
                let client = self.broker().await?;
                let listing: Vec<Value> = credentials::fetch(client)
                    .await?
                    .iter()
                    .map(credentials::Credential::agent_view)
                    .collect();
                Ok(answered(render(&Value::Array(listing))))
            }
            tools::PROXY => self.proxy(args).await,
            tools::MCP_SERVERS => {
                let client = self.broker().await?;
                let servers = mcp::fetch_servers(client).await?;
                Ok(answered(render(&Value::Array(servers))))
            }
            tools::MCP_TOOLS => self.mcp_tools(args).await,
            tools::MCP_CALL => {
                let server = required_str(args, "server")?;
                let tool = required_str(args, "tool")?;
                let arguments = object_arg(args, "arguments")?.unwrap_or_else(|| json!({}));
                self.mcp_call(&server, &tool, arguments).await
            }
            other => Err(ToolFailure::Protocol(format!(
                "Unknown tool: {other}. Call tools/list for what this server publishes."
            ))),
        }
    }

    /// `agentcordon_proxy`: the same call `agentcordon proxy` makes, rendered
    /// as the same `{status, headers, body}` object `--json` prints.
    ///
    /// An upstream that answered 400 or more is `isError` with that envelope
    /// intact, which is the CLI's exit code 6 by another name: the call
    /// happened, and the model needs both facts.
    async fn proxy(&mut self, args: &Value) -> Result<Value, ToolFailure> {
        let method = required_str(args, "method")?;
        let url = required_str(args, "url")?;
        let credential = optional_str(args, "credential")?;
        let headers = string_map(args, "headers")?;
        let body = optional_str(args, "body")?;

        let client = self.broker().await?;
        let (_, data) = proxy::execute(client, credential, &method, &url, headers, body).await?;
        let envelope = proxy::json_envelope(&data);
        let upstream_failed = envelope["status"].as_u64().unwrap_or(0) >= 400;
        Ok(json!({
            "content": [{ "type": "text", "text": envelope.to_string() }],
            "isError": upstream_failed,
        }))
    }

    /// `agentcordon_mcp_tools`: one server's tools, with the upstream
    /// `inputSchema` under the name MCP gives it.
    async fn mcp_tools(&mut self, args: &Value) -> Result<Value, ToolFailure> {
        let server = required_str(args, "server")?;
        let client = self.broker().await?;
        let listed: Vec<Value> = mcp::fetch_tools(client)
            .await?
            .iter()
            .filter(|t| t.get("server").and_then(Value::as_str) == Some(server.as_str()))
            .map(|t| {
                json!({
                    "name": t.get("tool").cloned().unwrap_or(Value::Null),
                    "description": t.get("description").cloned().unwrap_or(Value::Null),
                    "inputSchema": t.get("input_schema").cloned().unwrap_or(Value::Null),
                })
            })
            .collect();

        if listed.is_empty() {
            // An empty array reads as "this server does nothing", which is
            // almost always a misspelled name instead.
            return Err(ToolFailure::Failed(format!(
                "MCP server '{server}' has no tools available to this workspace. \
                 Call agentcordon_mcp_servers for the servers it may use."
            )));
        }
        Ok(answered(render(&Value::Array(listed))))
    }

    /// `agentcordon_mcp_call`: the upstream tool's own result, unchanged,
    /// with the correlation id that ties it to the policy decision in the
    /// server's audit log.
    async fn mcp_call(
        &mut self,
        server: &str,
        tool: &str,
        arguments: Value,
    ) -> Result<Value, ToolFailure> {
        let client = self.broker().await?;
        let data = mcp::call_tool(client, server, tool, arguments).await?;

        let mut result = json!({
            "content": data.get("content").cloned().unwrap_or_else(|| json!([])),
            "isError": data.get("isError").and_then(Value::as_bool).unwrap_or(false),
        });
        if let Some(correlation_id) = data.get("correlation_id") {
            result["_meta"] = json!({ "correlation_id": correlation_id });
        }
        Ok(result)
    }

    /// The broker connection, made once per session on the first tool call
    /// that needs it.
    async fn broker(&mut self) -> Result<&BrokerClient, CliError> {
        if self.client.is_none() {
            self.client = Some(connect().await?);
        }
        Ok(self.client.as_ref().expect("just connected"))
    }

    /// Write one message, on one line. The transport forbids an embedded
    /// newline, and `serde_json` escapes every one it is given.
    async fn write(&mut self, message: &Value) {
        let mut line = serde_json::to_string(message).unwrap_or_else(|e| {
            serde_json::to_string(&protocol::error(
                Value::Null,
                protocol::INVALID_REQUEST,
                format!("failed to render a response: {e}"),
            ))
            .expect("the error envelope always renders")
        });
        line.push('\n');
        if let Err(e) = self.out.write_all(line.as_bytes()).await {
            tracing::error!(error = %e, "failed to write to stdout");
            return;
        }
        let _ = self.out.flush().await;
    }
}

/// A tool result carrying one text block.
fn answered(text: String) -> Value {
    json!({ "content": [{ "type": "text", "text": text }], "isError": false })
}

/// A tool result that failed, carrying the CLI's own one-line message.
fn failed(message: String) -> Value {
    json!({ "content": [{ "type": "text", "text": message }], "isError": true })
}

/// JSON for a model to read: indented, because the listings are short and a
/// misread field costs more than the whitespace does.
fn render(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

/// A required string argument, or the protocol error naming it.
fn required_str(args: &Value, key: &str) -> Result<String, ToolFailure> {
    match args.get(key) {
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(s.clone()),
        None | Some(Value::Null) | Some(Value::String(_)) => Err(ToolFailure::Protocol(format!(
            "missing required argument: {key}"
        ))),
        Some(other) => Err(ToolFailure::Protocol(format!(
            "argument {key} must be a string, not {other}"
        ))),
    }
}

/// An optional string argument. Present but not a string is the model
/// misreading the schema, so it is a protocol error rather than a silent
/// coercion.
fn optional_str(args: &Value, key: &str) -> Result<Option<String>, ToolFailure> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(other) => Err(ToolFailure::Protocol(format!(
            "argument {key} must be a string, not {other}"
        ))),
    }
}

/// An optional object argument, kept whole.
fn object_arg(args: &Value, key: &str) -> Result<Option<Value>, ToolFailure> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value @ Value::Object(_)) => Ok(Some(value.clone())),
        Some(other) => Err(ToolFailure::Protocol(format!(
            "argument {key} must be an object, not {other}"
        ))),
    }
}

/// An optional object of string values — the shape `headers` declares.
fn string_map(args: &Value, key: &str) -> Result<std::collections::HashMap<String, String>, ToolFailure> {
    let Some(object) = object_arg(args, key)? else {
        return Ok(std::collections::HashMap::new());
    };
    let mut map = std::collections::HashMap::new();
    for (name, value) in object.as_object().expect("checked above") {
        let Value::String(value) = value else {
            return Err(ToolFailure::Protocol(format!(
                "argument {key}.{name} must be a string, not {value}"
            )));
        };
        map.insert(name.clone(), value.clone());
    }
    Ok(map)
}

/// Connect to the broker, starting one if none is running.
///
/// The autostart is the one `init` and `register` do, through the same
/// function, so a workspace enrolled by `init` and one served by `mcp-serve`
/// end up with the same broker. With no server URL configured anywhere there
/// is nothing to point a broker at, so the original "broker is not running"
/// message stands — it is the one that names the fix.
async fn connect() -> Result<BrokerClient, CliError> {
    match BrokerClient::connect().await {
        Err(e) if e.code == ExitCode::BrokerNotRunning => {
            let Some(server) = crate::config::resolve_server_url(None) else {
                return Err(e);
            };
            tracing::info!(server = %server.url, "no broker running; starting one");
            crate::broker_autostart::ensure_broker_running(&server.url).await?;
            BrokerClient::connect().await
        }
        other => other,
    }
}

/// The paragraph a runtime puts in front of the model once, at session
/// start. It says what this workspace *is* — the name and the identity are
/// read from `.agentcordon/`, not from the broker, so they are here even
/// when nothing is running — and the two things a model gets wrong without
/// being told: that `agentcordon_proxy` picks the credential itself, and
/// that MCP servers are not a pool to choose from.
fn instructions() -> String {
    let name = workspace_name();
    let identity = signing::load_keypair()
        .map(|key| key.identity())
        .unwrap_or_else(|_| "not set up yet — run `agentcordon init`".to_string());
    format!(
        "These tools belong to the AgentCordon workspace '{name}' ({identity}). Its credentials \
         are held by the AgentCordon broker and never by you: call agentcordon_proxy to make an \
         authenticated HTTP request and the broker injects the credential on the way out, so no \
         secret ever enters this conversation — omit `credential` and the one whose URL fence \
         covers the target is chosen for you, and name one only when agentcordon_credentials \
         shows several fences covering that URL. The MCP servers behind agentcordon_mcp_servers, \
         agentcordon_mcp_tools and agentcordon_mcp_call are not interchangeable: each fronts one \
         upstream with its own credential, its own tools and its own policy, so call the one the \
         task names rather than the first that answers. A refusal here is a policy decision, not \
         an obstacle to route around with a raw HTTP client; agentcordon_status says whether this \
         workspace is registered and which broker it is talking to."
    )
}

/// The workspace's display name: the directory `.agentcordon/` sits in,
/// which is what `register` defaults to and therefore what the server has on
/// record for it.
fn workspace_name() -> String {
    let root = signing::workspace_dir();
    let root = root.parent().unwrap_or(&root).to_path_buf();
    std::fs::canonicalize(&root)
        .unwrap_or(root)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "workspace".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three things the paragraph exists to say. The identity and the
    /// name come from the workspace directory, so they are asserted at the
    /// CLI seam in `tests/mcp_serve.rs`; what is checked here is that the
    /// two rules a model gets wrong are actually stated.
    #[test]
    fn the_instructions_state_the_two_rules() {
        let text = instructions();
        assert!(text.contains("agentcordon_proxy"), "{text}");
        assert!(text.contains("URL fence"), "{text}");
        assert!(text.contains("not interchangeable"), "{text}");
        assert_eq!(text.lines().count(), 1, "one paragraph, one line");
    }
}
