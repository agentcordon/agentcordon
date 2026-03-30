// AgentCordon Thin CLI — lightweight workspace agent
// Manages Ed25519 keypairs, signs requests to broker, never touches credentials

mod broker;
mod commands;
mod error;
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
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate Ed25519 keypair and prepare workspace
    Init,

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
    },

    /// Check workspace and broker status
    Status,

    /// List available credentials
    Credentials,

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

    /// One-command setup: start broker, generate keys, register workspace
    Setup {
        /// AgentCordon server URL (e.g. http://server:3140)
        server_url: String,
    },

    /// List all available MCP tools
    McpTools,

    /// Call an MCP tool
    McpCall {
        /// MCP server name
        server: String,

        /// Tool name
        tool: String,

        /// Tool arguments (KEY=VALUE, repeatable)
        #[arg(long = "arg", num_args = 1)]
        args: Vec<String>,
    },
}

fn main() -> std::process::ExitCode {
    // Initialize logging from AGTCRDN_LOG_LEVEL or default to warn
    let filter = EnvFilter::try_from_env("AGTCRDN_LOG_LEVEL")
        .unwrap_or_else(|_| EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    let result = match cli.command {
        Command::Init => commands::init::run(),
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
        Command::Init => unreachable!(),
        Command::Setup { server_url } => commands::setup::run(server_url).await,
        Command::Register { scopes, force } => commands::register::run(scopes, force).await,
        Command::Status => commands::status::run().await,
        Command::Credentials => commands::credentials::run().await,
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
        Command::McpTools => commands::mcp::list_tools().await,
        Command::McpCall { server, tool, args } => commands::mcp::call(server, tool, args).await,
    }
}
