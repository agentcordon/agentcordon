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
mod config;
mod error;
#[cfg(test)]
mod fake_broker;
mod pin;
mod platform;
mod signing;
#[cfg(test)]
mod test_env;

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
    /// Set this workspace up end to end: keypair, AgentCordon skill, enrollment
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

        /// Set this directory up and stop: no broker, no device flow. For
        /// scripts and air-gapped setups. `agentcordon register` enrolls
        /// later.
        #[arg(long = "no-register")]
        no_register: bool,

        /// Install the skill but register no MCP server in any runtime's
        /// configuration. Remembered in `.agentcordon/agents.toml`.
        #[arg(long = "no-mcp")]
        no_mcp: bool,

        /// Brokered MCP server whose tools `mcp-serve` re-exports as typed
        /// tools. Repeatable; remembered in `.agentcordon/agents.toml`.
        #[arg(long = "expose", num_args = 1)]
        expose: Vec<String>,

        /// AgentCordon server URL to enroll with. Optional: without it the
        /// CLI falls back to `AGTCRDN_SERVER_URL` and then to `server_url`
        /// in `~/.agentcordon/config.toml`, which your server's installer
        /// wrote.
        #[arg(long = "server-url")]
        server_url: Option<String>,

        /// Workspace display name for the enrollment. Defaults to the
        /// current directory's basename, exactly as for `register`.
        #[arg(long = "name")]
        name: Option<String>,
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

        /// AgentCordon server URL (e.g. http://server:3140). Optional:
        /// without it the CLI falls back to `AGTCRDN_SERVER_URL` and then
        /// to `server_url` in `~/.agentcordon/config.toml`, which your
        /// server's installer wrote. When a server URL is known and no
        /// broker is running, `register` starts one pointed at it before
        /// initiating the RFC 8628 device flow. If the broker is already
        /// running the URL is only used for reporting.
        #[arg(long = "server-url")]
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

    /// Update the CLI and broker to the server's pinned version
    Update {
        /// Report the current and available versions and exit; change
        /// nothing.
        #[arg(long)]
        check: bool,

        /// Reinstall even when already on the server's pinned version.
        #[arg(long)]
        force: bool,

        /// AgentCordon server URL to learn the target version from.
        /// Optional: without it the CLI falls back to `AGTCRDN_SERVER_URL`
        /// and then to `server_url` in `~/.agentcordon/config.toml`, exactly
        /// as `init` and `register` do.
        #[arg(long = "server-url")]
        server_url: Option<String>,

        /// Skip the confirmation prompt (for scripts). The CLI also never
        /// prompts when stdin is not a terminal.
        #[arg(long)]
        yes: bool,
    },

    /// List available credentials (or manage them with subcommands)
    Credentials {
        #[command(subcommand)]
        action: Option<CredentialsAction>,

        /// Emit the listing as JSON instead of a table, for filtering.
        #[arg(long)]
        json: bool,
    },

    /// Proxy an HTTP request through the broker with credential injection
    Proxy {
        /// `<CREDENTIAL> <METHOD> <URL>`, or `<METHOD> <URL>` with `--auto`.
        #[arg(value_names = ["CREDENTIAL", "METHOD", "URL"], num_args = 2..=3)]
        args: Vec<String>,

        /// Pick the credential whose URL fence covers the target, instead of
        /// naming one. Refuses rather than guessing when no fence covers the
        /// URL, or when more than one does.
        #[arg(long)]
        auto: bool,

        /// Additional headers (KEY:VALUE, repeatable)
        #[arg(long = "header", num_args = 1)]
        headers: Vec<String>,

        /// Request body (string or @file to read from file)
        #[arg(long)]
        body: Option<String>,

        /// Emit one compact JSON object: {status, headers, body}
        #[arg(long)]
        json: bool,

        /// Print only the response body, with no summary line on stderr
        #[arg(long)]
        raw: bool,

        /// Print the status line and every response header above the body
        #[arg(long = "headers")]
        show_headers: bool,
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

    /// Serve AgentCordon as an MCP server over stdio, so a runtime gets
    /// native tools instead of shelling out to this CLI
    McpServe {
        /// Also publish one tool per upstream tool of this MCP server, named
        /// `<server>__<tool>`. Repeatable. Off by default: every tool's
        /// schema is loaded into the model's context at session start, so a
        /// re-export is worth its tokens only for a server an agent calls
        /// constantly.
        #[arg(long = "expose", num_args = 1)]
        expose: Vec<String>,
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

        /// Emit the whole tools/call result as one compact JSON object
        /// instead of just the tool's text
        #[arg(long)]
        json: bool,
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

    // `init` used to be the one synchronous command. It now finishes
    // enrollment — a broker autostart and the RFC 8628 device flow — so every
    // command goes through the runtime.
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    let result = rt.block_on(run_async(cli.command));

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
        Command::Init {
            agents,
            reconfigure,
            no_register,
            no_mcp,
            expose,
            server_url,
            name,
        } => {
            commands::init::run(commands::init::InitArgs {
                agents,
                reconfigure,
                no_register,
                no_mcp,
                expose,
                server_url,
                name,
            })
            .await
        }
        Command::Register {
            scopes,
            force,
            server_url,
            name,
        } => commands::register::run(scopes, force, server_url, name).await,
        Command::Status => commands::status::run().await,
        Command::Update {
            check,
            force,
            server_url,
            yes,
        } => {
            commands::update::run(commands::update::UpdateArgs {
                check,
                force,
                server_url,
                yes,
            })
            .await
        }
        Command::Credentials { action, json } => match action {
            None => commands::credentials::run(json).await,
            Some(CredentialsAction::Create {
                name,
                service,
                value,
                allowed_url_pattern,
            }) => commands::credentials::create(name, service, value, allowed_url_pattern).await,
        },
        Command::Proxy {
            args,
            auto,
            headers,
            body,
            json,
            raw,
            show_headers,
        } => {
            commands::proxy::run(commands::proxy::ProxyArgs {
                args,
                auto,
                headers,
                body,
                json,
                raw,
                show_headers,
            })
            .await
        }
        Command::McpServers => commands::mcp::list_servers().await,
        Command::McpTools {
            schema,
            server,
            tool,
        } => commands::mcp::list_tools(schema, server, tool).await,
        Command::McpServe { expose } => {
            commands::mcp_serve::run(commands::mcp_serve::ServeArgs { expose }).await
        }
        Command::McpCall {
            server,
            tool,
            args,
            args_json,
            json,
        } => commands::mcp::call(server, tool, args, args_json, json).await,
    }
}
