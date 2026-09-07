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

// AgentCordon Thin CLI — lightweight workspace agent
// Manages Ed25519 keypairs, signs requests to broker, never touches credentials

mod agents;
mod broker;
mod broker_autostart;
mod commands;
mod error;
mod pin;
mod platform;
mod signing;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use crate::error::CliError;

#[derive(Parser)]
#[command(
    name = "agentcordon",
    about = "AgentCordon workspace CLI — identity, credentials, and MCP through the broker",
    version
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate the Ed25519 keypair and install the AgentCordon skill
    Init {
        /// Agent runtime to install the skill for. Repeatable. Also accepts
        /// `auto` (every runtime detected in this workspace or your home
        /// directory — the default), `all`, and `none` (the portable skill
        /// only). With no `--agent`, `init` reuses the choice remembered in
        /// `.agentcordon/agents.toml`, or asks when it is on a terminal.
        #[arg(long = "agent", num_args = 1)]
        agents: Vec<String>,

        /// Ignore the remembered choice and pick the runtimes again.
        #[arg(long)]
        reconfigure: bool,
    },

    /// Register this workspace with the broker
    Register {
        /// OAuth scopes to request (default: credentials:discover credentials:vend)
        #[arg(long = "scope", num_args = 1)]
        scopes: Vec<String>,

        /// Clear any existing broker registration before re-registering.
        /// Use when the server-side workspace was deleted but the broker
        /// still holds stale state (409 Conflict on register).
        #[arg(long)]
        force: bool,

        /// AgentCordon server URL (e.g. http://server:3140). If provided
        /// and the broker is not already running, `register` will start
        /// a broker daemon pointed at this server before initiating the
        /// RFC 8628 device flow. If the broker is already running this
        /// flag is ignored.
        #[arg(long = "server-url", env = "AGTCRDN_SERVER_URL")]
        server_url: Option<String>,

        /// Workspace display name. If omitted, defaults to the current
        /// working directory's basename. Names are not unique — two
        /// workspaces can share the same name as long as they're
        /// registered with different keypairs.
        #[arg(long = "name")]
        name: Option<String>,
    },

    /// Check workspace and broker status
    Status,

    /// List available credentials (or manage them with subcommands)
    Credentials {
        #[command(subcommand)]
        action: Option<CredentialsAction>,
    },

    /// Proxy an HTTP request through the broker with credential injection
    Proxy {
        /// Credential name to use
        credential: String,

        /// HTTP method (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS)
        method: String,

        /// Target URL
        url: String,

        /// Additional headers (KEY:VALUE, repeatable)
        #[arg(long = "header", num_args = 1)]
        headers: Vec<String>,

        /// Request body (string or @file to read from file)
        #[arg(long)]
        body: Option<String>,

        /// Pretty-print response body as JSON
        #[arg(long)]
        json: bool,

        /// Print only response body (for piping)
        #[arg(long)]
        raw: bool,
    },

    /// List available MCP servers
    McpServers,

    /// List all available MCP tools
    McpTools {
        /// Emit the raw JSON list (including each tool's input_schema) instead
        /// of the human-friendly text table. Designed for agent consumption.
        #[arg(long)]
        schema: bool,

        /// When --schema is set, restrict output to one server.
        #[arg(long)]
        server: Option<String>,

        /// When --schema is set, restrict output to one tool.
        #[arg(long)]
        tool: Option<String>,
    },

    /// Call an MCP tool
    McpCall {
        /// MCP server name
        server: String,

        /// Tool name
        tool: String,

        /// Tool arguments (KEY=VALUE, repeatable). Convenience layer.
        /// For structured input (nested objects, arrays), prefer --args-json.
        #[arg(long = "arg", num_args = 1)]
        args: Vec<String>,

        /// Pass the full MCP tools/call.arguments object as JSON.
        /// SRC may be `@<path>` to read a file, or `-` to read stdin.
        /// On conflict, individual --arg values override fields from this object.
        #[arg(long = "args-json", value_name = "SRC")]
        args_json: Option<String>,
    },
}

#[derive(Subcommand)]
enum CredentialsAction {
    /// Create a new credential in the vault via the broker
    Create {
        /// Credential name (unique within workspace)
        #[arg(long)]
        name: String,

        /// Service identifier (e.g. "github", "openai")
        #[arg(long)]
        service: String,

        /// Secret value (the credential to store)
        #[arg(long)]
        value: String,

        /// Restrict the URLs this credential may be proxied to, e.g.
        /// `https://api.github.com/*`. Without it the credential is
        /// unrestricted and can be sent to any URL.
        #[arg(long)]
        allowed_url_pattern: Option<String>,
    },
}

fn main() -> std::process::ExitCode {
    // Initialize logging from AGTCRDN_LOG_LEVEL or default to warn
    let filter =
        EnvFilter::try_from_env("AGTCRDN_LOG_LEVEL").unwrap_or_else(|_| EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    let result = match cli.command {
        Command::Init {
            ref agents,
            reconfigure,
        } => commands::init::run(commands::init::InitArgs {
            agents: agents.clone(),
            reconfigure,
        }),
        _ => {
            // All other commands are async
            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            rt.block_on(run_async(cli.command))
        }
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            e.code.into()
        }
    }
}

async fn run_async(command: Command) -> Result<(), CliError> {
    match command {
        Command::Init { .. } => unreachable!(),
        Command::Register {
            scopes,
            force,
            server_url,
            name,
        } => commands::register::run(scopes, force, server_url, name).await,
        Command::Status => commands::status::run().await,
        Command::Credentials { action } => match action {
            None => commands::credentials::run().await,
            Some(CredentialsAction::Create {
                name,
                service,
                value,
                allowed_url_pattern,
            }) => commands::credentials::create(name, service, value, allowed_url_pattern).await,
        },
        Command::Proxy {
            credential,
            method,
            url,
            headers,
            body,
            json,
            raw,
        } => commands::proxy::run(credential, method, url, headers, body, json, raw).await,
        Command::McpServers => commands::mcp::list_servers().await,
        Command::McpTools {
            schema,
            server,
            tool,
        } => commands::mcp::list_tools(schema, server, tool).await,
        Command::McpCall {
            server,
            tool,
            args,
            args_json,
        } => commands::mcp::call(server, tool, args, args_json).await,
    }
}
